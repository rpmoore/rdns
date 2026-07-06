#!/usr/bin/env bash
# Checks that the bundled IANA root-hints and TLD-list snapshots match
# upstream. Exits non-zero (with a diff) if either has drifted.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

curl_opts=(--fail --silent --show-error --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30)

status=0

check() {
  local url="$1" bundled="$2" refresh_cmd="$3"
  local fetched="$tmp_dir/${bundled//\//_}"

  if ! curl "${curl_opts[@]}" "$url" -o "$fetched"; then
    echo "::error file=$bundled::Failed to fetch upstream copy from $url for freshness check. Refresh manually once reachable with: $refresh_cmd"
    status=1
    return
  fi

  if ! diff -q "$repo_root/$bundled" "$fetched" > /dev/null; then
    echo "::error file=$bundled::Bundled file is stale - upstream has changed. Refresh with: $refresh_cmd"
    diff -u "$repo_root/$bundled" "$fetched" || true
    status=1
  fi
}

check "https://www.internic.net/domain/named.root" \
  "src/config/named.root" \
  "(cd \"$repo_root\" && curl ${curl_opts[*]} https://www.internic.net/domain/named.root -o src/config/named.root)"

check "https://data.iana.org/TLD/tlds-alpha-by-domain.txt" \
  "src/config/tlds-alpha-by-domain.txt" \
  "(cd \"$repo_root\" && curl ${curl_opts[*]} https://data.iana.org/TLD/tlds-alpha-by-domain.txt -o src/config/tlds-alpha-by-domain.txt)"

exit "$status"
