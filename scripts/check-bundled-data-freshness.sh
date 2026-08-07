#!/usr/bin/env bash
# Checks that the bundled IANA root-hints and TLD-list snapshots match
# upstream. Exits non-zero (with a diff) if either has drifted.
#
# Comparison ignores comments and whitespace, so upstream re-publishing a
# byte-identical payload under a new version/date header (IANA bumps the
# `# Version ...` line and named.root's `; last update:` line on every
# publish) is not treated as drift. Both parsers in src/config/mod.rs
# discard comments, so a comment-only change cannot alter behavior.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

curl_opts=(--fail --silent --show-error --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30)

status=0

normalize() {
  "$repo_root/scripts/normalize-bundled-data.sh" "$1" "$2"
}

check() {
  local url="$1" bundled="$2" format="$3" refresh_cmd="$4"
  local fetched="$tmp_dir/${bundled//\//_}"

  if ! curl "${curl_opts[@]}" "$url" -o "$fetched"; then
    echo "::error file=$bundled::Failed to fetch upstream copy from $url for freshness check. Refresh manually once reachable with: $refresh_cmd"
    status=1
    return
  fi

  if diff -q "$repo_root/$bundled" "$fetched" > /dev/null; then
    return
  fi

  if diff -q \
    <(normalize "$format" "$repo_root/$bundled") \
    <(normalize "$format" "$fetched") > /dev/null; then
    echo "::notice file=$bundled::Upstream differs only in comments/metadata (e.g. version or date header); bundled data is still current, no refresh needed."
    return
  fi

  echo "::error file=$bundled::Bundled file is stale - upstream has changed. Refresh with: $refresh_cmd"
  diff -u "$repo_root/$bundled" "$fetched" || true
  status=1
}

check "https://www.internic.net/domain/named.root" \
  "src/config/named.root" \
  "zonefile" \
  "(cd \"$repo_root\" && just update-iana-data)"

check "https://data.iana.org/TLD/tlds-alpha-by-domain.txt" \
  "src/config/tlds-alpha-by-domain.txt" \
  "tld-list" \
  "(cd \"$repo_root\" && just update-iana-data)"

exit "$status"
