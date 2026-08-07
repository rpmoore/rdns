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

    install_if_changed() {
      local format="$1" fetched="$2" bundled="$3"
      if [[ "{{force}}" != "1" ]] && diff -q \
        <(./scripts/normalize-bundled-data.sh "$format" "$bundled") \
        <(./scripts/normalize-bundled-data.sh "$format" "$fetched") > /dev/null; then
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
