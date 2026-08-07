fmt:
    cargo fmt

bench:
    cargo test --locked --release --test recursive_perf --test cache_concurrency_bench -- --ignored --nocapture --test-threads=1

coverage:
    cargo llvm-cov --locked --summary-only

coverage-html:
    cargo llvm-cov --locked --html --open

# Refreshes the bundled IANA snapshots. Files whose only upstream change is
# a comment (the version/date header both sources bump on every publish) are
# left alone, so refreshing never produces a no-op diff. Run
# `just update-iana-data 1` to take upstream's bytes regardless.
update-iana-data force="0":
    #!/usr/bin/env bash
    set -euo pipefail
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT
    curl_opts=(--fail --silent --show-error --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30)
    curl "${curl_opts[@]}" https://www.internic.net/domain/named.root -o "$tmp_dir/named.root"
    curl "${curl_opts[@]}" https://data.iana.org/TLD/tlds-alpha-by-domain.txt -o "$tmp_dir/tlds-alpha-by-domain.txt"

    # Normalized output goes to files, not process substitutions: bash does
    # not propagate a process substitution's exit status, so a failed
    # normalizer would compare two empty streams and look "unchanged".
    # `set -e` is suspended inside a function used as an `if` condition, so
    # each normalizer run is checked explicitly. A failed normalization means
    # "not provably comments-only", which installs upstream's copy — the safe
    # direction when we cannot tell a header bump from real drift.
    comments_only_change() {
      local format="$1" fetched="$2" bundled="$3"
      if ! ./scripts/normalize-bundled-data.sh "$format" "$bundled" > "$tmp_dir/bundled.normalized" \
        || ! ./scripts/normalize-bundled-data.sh "$format" "$fetched" > "$tmp_dir/upstream.normalized"; then
        echo "$bundled: normalization failed, falling back to installing upstream copy" >&2
        return 1
      fi
      diff -q "$tmp_dir/bundled.normalized" "$tmp_dir/upstream.normalized" > /dev/null
    }

    install_if_changed() {
      local format="$1" fetched="$2" bundled="$3"
      if [[ "{{force}}" != "1" ]] && comments_only_change "$format" "$fetched" "$bundled"; then
        echo "$bundled: unchanged apart from comments, keeping bundled copy"
        return
      fi
      mv "$fetched" "$bundled"
      echo "$bundled: updated"
    }

    install_if_changed zonefile "$tmp_dir/named.root" src/config/named.root
    install_if_changed tld-list "$tmp_dir/tlds-alpha-by-domain.txt" src/config/tlds-alpha-by-domain.txt

check-bundled-data-freshness:
    ./scripts/check-bundled-data-freshness.sh

check-trust-anchor-staleness:
    ./scripts/check-trust-anchor-staleness.sh
