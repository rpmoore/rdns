#!/usr/bin/env bash
# Checks the bundled DNSSEC root trust anchors (src/config/root-anchor.txt)
# against IANA's authoritative root-anchors.xml (RFC 9718), verifying the
# CMS signature over the XML before trusting its contents. Meant to run on a
# schedule (see .github/workflows/dnssec-anchor-staleness.yml), not on every
# PR: IANA endpoint flakiness must not block unrelated work, so a fetch or
# CMS-verification failure is reported as a distinct "couldn't confirm
# freshness" finding, separate from an actual staleness finding.
#
# RFC 5011 automated rollover is out of scope; this script only detects
# drift and alerts a human, it never rewrites the bundled file itself.
#
# Manually verified against src/config/root-anchor.txt: a clean run passes;
# a deliberately corrupted digest is flagged as "does not match IANA's
# published digest"; a deliberately deleted entry is flagged as "bundle is
# missing an anchor". See section-02-dnssec-trust-anchor's implementation
# notes for the plan's A3 acceptance check this satisfies.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundled_file="$repo_root/src/config/root-anchor.txt"
warning_threshold_days=60

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

curl_opts=(--fail --silent --show-error --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30)

xml_url="https://data.iana.org/root-anchors/root-anchors.xml"
p7s_url="https://data.iana.org/root-anchors/root-anchors.p7s"
pem_url="https://data.iana.org/root-anchors/icannbundle.pem"

xml_file="$tmp_dir/root-anchors.xml"
p7s_file="$tmp_dir/root-anchors.p7s"
pem_file="$tmp_dir/icannbundle.pem"

fetch_failed=0
fetch_urls=("$xml_url" "$p7s_url" "$pem_url")
fetch_dests=("$xml_file" "$p7s_file" "$pem_file")
for i in "${!fetch_urls[@]}"; do
  if ! curl "${curl_opts[@]}" "${fetch_urls[$i]}" -o "${fetch_dests[$i]}"; then
    echo "::error::Could not confirm trust-anchor freshness: failed to fetch ${fetch_urls[$i]}"
    fetch_failed=1
  fi
done
if [[ "$fetch_failed" -ne 0 ]]; then
  exit 1
fi

# IANA's documented verification recipe for root-anchors.xml (see
# https://data.iana.org/root-anchors/README): the .p7s is a DER-encoded
# detached CMS/PKCS7 signature over the XML, signed by the ICANN bundle.
if ! openssl smime -verify -CAfile "$pem_file" -inform DER -in "$p7s_file" \
  -content "$xml_file" -noout > "$tmp_dir/verify.log" 2>&1; then
  echo "::error::Could not confirm trust-anchor freshness: CMS signature verification failed"
  cat "$tmp_dir/verify.log"
  exit 1
fi

echo "CMS signature verified against $pem_url"

status=0

# Extract (key_tag, algorithm, digest_type, digest) tuples currently bundled
# in root-anchor.txt. Zonefile-format DS line:
# <owner> <ttl> IN DS <key_tag> <algorithm> <digest_type> <digest>
# Comparing the full tuple (not just key_tag+digest) matters because a
# 16-bit key tag alone cannot uniquely identify an anchor, and an edit that
# changes algorithm or digest_type while leaving the digest string
# untouched would otherwise pass unnoticed.
declare -A bundled_tuple_by_tag=()
while IFS= read -r line; do
  line="${line%%;*}"
  line="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [[ -z "$line" ]] && continue
  read -r -a fields <<< "$line"
  [[ "${#fields[@]}" -eq 8 ]] || continue
  key_tag="${fields[4]}"
  algorithm="${fields[5]}"
  digest_type="${fields[6]}"
  digest="${fields[7]}"
  bundled_tuple_by_tag["$key_tag"]="${algorithm}:${digest_type}:${digest^^}"
done < "$bundled_file"

if [[ "${#bundled_tuple_by_tag[@]}" -eq 0 ]]; then
  echo "::error::No DS entries found in $bundled_file to compare"
  exit 1
fi

now_epoch="$(date -u +%s)"
warning_seconds=$((warning_threshold_days * 86400))

# `date -d` failing under `set -e` would abort the whole script instead of
# reporting the same "couldn't confirm freshness" finding as a fetch or
# CMS-verification failure. Parse into the caller's named variable and
# report a parse failure the same way.
parse_epoch() {
  local input="$1" out_var="$2" parsed
  if ! parsed="$(date -u -d "$input" +%s 2>/dev/null)"; then
    return 1
  fi
  printf -v "$out_var" '%s' "$parsed"
}

# Key tags seen in IANA's XML at all (valid or expired), so we can flag a
# bundled anchor IANA has dropped from the feed entirely (revoked/retired)
# -- distinct from one that's merely past its validUntil.
declare -A seen_iana_tags=()
records_processed=0

# Each <KeyDigest> element is emitted on its own opening tag line by IANA's
# XML, with KeyTag/Digest as child elements on subsequent lines - reformat
# so each KeyDigest's full record (tag line + children up to </KeyDigest>)
# is on one line, then process record by record.
while IFS= read -r record; do
  key_tag="$(echo "$record" | grep -oP '<KeyTag>\K[0-9]+' || true)"
  algorithm="$(echo "$record" | grep -oP '<Algorithm>\K[0-9]+' || true)"
  digest_type="$(echo "$record" | grep -oP '<DigestType>\K[0-9]+' || true)"
  digest="$(echo "$record" | grep -oP '<Digest>\K[0-9A-Fa-f]+' || true)"
  valid_from="$(echo "$record" | grep -oP 'validFrom="\K[^"]+' || true)"
  valid_until="$(echo "$record" | grep -oP 'validUntil="\K[^"]+' || true)"

  if [[ -z "$key_tag" || -z "$algorithm" || -z "$digest_type" || -z "$digest" ]]; then
    echo "::error::Could not confirm trust-anchor freshness: failed to parse a KeyDigest record from $xml_url"
    status=1
    continue
  fi

  records_processed=$((records_processed + 1))
  seen_iana_tags["$key_tag"]=1
  iana_tuple="${algorithm}:${digest_type}:${digest^^}"

  bundled_tuple="${bundled_tuple_by_tag[$key_tag]:-}"

  currently_valid=1
  if [[ -n "$valid_until" ]]; then
    if ! parse_epoch "$valid_until" valid_until_epoch; then
      echo "::error::Could not confirm trust-anchor freshness: failed to parse validUntil=\"$valid_until\" for key tag $key_tag"
      status=1
      continue
    fi
    if [[ "$now_epoch" -ge "$valid_until_epoch" ]]; then
      currently_valid=0
    fi
  fi

  if [[ -z "$bundled_tuple" ]]; then
    if [[ "$currently_valid" -eq 1 ]]; then
      echo "::error::IANA key tag $key_tag (validFrom=$valid_from) is currently valid but not present in $bundled_file - bundle is missing an anchor"
      status=1
    fi
    continue
  fi

  if [[ "$bundled_tuple" != "$iana_tuple" ]]; then
    echo "::error::Bundled key tag $key_tag (algorithm:digest_type:digest = $bundled_tuple) does not match IANA's published record ($iana_tuple) - refresh $bundled_file from $xml_url"
    status=1
    continue
  fi

  if [[ "$currently_valid" -eq 0 ]]; then
    echo "::error::Bundled key tag $key_tag expired on $valid_until - refresh $bundled_file from $xml_url"
    status=1
  elif [[ -n "$valid_until" ]]; then
    remaining=$((valid_until_epoch - now_epoch))
    if [[ "$remaining" -le "$warning_seconds" ]]; then
      remaining_days=$((remaining / 86400))
      echo "::warning::Bundled key tag $key_tag expires in $remaining_days day(s) ($valid_until) - plan a refresh of $bundled_file"
      # Scheduled runs only notify operators via GitHub's
      # scheduled-workflow-failure email on nonzero exit; a warning
      # annotation alone on a green run gives no proactive signal, so
      # entering the window fails the check even though it isn't yet a
      # hard mismatch.
      status=1
    fi
  fi
done < <(grep -Pzo '(?s)<KeyDigest[^>]*>.*?</KeyDigest>' "$xml_file" | tr '\0' '\n' | tr '\n' ' ' | sed 's/<KeyDigest/\n<KeyDigest/g' | tail -n +2; echo)

if [[ "$records_processed" -eq 0 ]]; then
  echo "::error::Could not confirm trust-anchor freshness: no KeyDigest records parsed from $xml_url - IANA may have changed the XML format"
  status=1
fi

for key_tag in "${!bundled_tuple_by_tag[@]}"; do
  if [[ -z "${seen_iana_tags[$key_tag]:-}" ]]; then
    echo "::error::Bundled key tag $key_tag is not present in IANA's published root-anchors.xml at all - IANA may have revoked/retired this anchor; verify and remove it from $bundled_file if so"
    status=1
  fi
done

if [[ "$status" -eq 0 ]]; then
  echo "Trust anchor staleness check passed: bundled digests match IANA and are within the ${warning_threshold_days}-day warning window"
fi

exit "$status"
