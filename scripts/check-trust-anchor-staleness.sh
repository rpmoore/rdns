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

# Extract (key_tag, digest) pairs currently bundled in root-anchor.txt.
# Zonefile-format DS line: <owner> <ttl> IN DS <key_tag> <algorithm> <digest_type> <digest>
declare -A bundled_digest_by_tag=()
while IFS= read -r line; do
  line="${line%%;*}"
  line="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [[ -z "$line" ]] && continue
  read -r -a fields <<< "$line"
  [[ "${#fields[@]}" -eq 8 ]] || continue
  key_tag="${fields[4]}"
  digest="${fields[7]}"
  bundled_digest_by_tag["$key_tag"]="$digest"
done < "$bundled_file"

if [[ "${#bundled_digest_by_tag[@]}" -eq 0 ]]; then
  echo "::error::No DS entries found in $bundled_file to compare"
  exit 1
fi

now_epoch="$(date -u +%s)"
warning_seconds=$((warning_threshold_days * 86400))

# Each <KeyDigest> element is emitted on its own opening tag line by IANA's
# XML, with KeyTag/Digest as child elements on subsequent lines - reformat
# so each KeyDigest's full record (tag line + children up to </KeyDigest>)
# is on one line, then process record by record.
while IFS= read -r record; do
  key_tag="$(echo "$record" | grep -oP '<KeyTag>\K[0-9]+' || true)"
  digest="$(echo "$record" | grep -oP '<Digest>\K[0-9A-Fa-f]+' || true)"
  valid_from="$(echo "$record" | grep -oP 'validFrom="\K[^"]+' || true)"
  valid_until="$(echo "$record" | grep -oP 'validUntil="\K[^"]+' || true)"

  if [[ -z "$key_tag" || -z "$digest" ]]; then
    echo "::error::Could not confirm trust-anchor freshness: failed to parse a KeyDigest record from $xml_url"
    status=1
    continue
  fi

  bundled_digest="${bundled_digest_by_tag[$key_tag]:-}"

  currently_valid=1
  if [[ -n "$valid_until" ]]; then
    valid_until_epoch="$(date -u -d "$valid_until" +%s)"
    if [[ "$now_epoch" -ge "$valid_until_epoch" ]]; then
      currently_valid=0
    fi
  fi

  if [[ -z "$bundled_digest" ]]; then
    if [[ "$currently_valid" -eq 1 ]]; then
      echo "::error::IANA key tag $key_tag (validFrom=$valid_from) is currently valid but not present in $bundled_file - bundle is missing an anchor"
      status=1
    fi
    continue
  fi

  if [[ "${bundled_digest^^}" != "${digest^^}" ]]; then
    echo "::error::Bundled digest for key tag $key_tag does not match IANA's published digest - refresh $bundled_file from $xml_url"
    status=1
    continue
  fi

  if [[ "$currently_valid" -eq 0 ]]; then
    echo "::error::Bundled key tag $key_tag expired on $valid_until - refresh $bundled_file from $xml_url"
    status=1
  elif [[ -n "$valid_until" ]]; then
    valid_until_epoch="$(date -u -d "$valid_until" +%s)"
    remaining=$((valid_until_epoch - now_epoch))
    if [[ "$remaining" -le "$warning_seconds" ]]; then
      remaining_days=$((remaining / 86400))
      echo "::warning::Bundled key tag $key_tag expires in $remaining_days day(s) ($valid_until) - plan a refresh of $bundled_file"
    fi
  fi
done < <(grep -Pzo '(?s)<KeyDigest[^>]*>.*?</KeyDigest>' "$xml_file" | tr '\0' '\n' | tr '\n' ' ' | sed 's/<KeyDigest/\n<KeyDigest/g' | tail -n +2; echo)

if [[ "$status" -eq 0 ]]; then
  echo "Trust anchor staleness check passed: bundled digests match IANA and are within the ${warning_threshold_days}-day warning window"
fi

exit "$status"
