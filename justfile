fmt:
    cargo fmt

bench:
    cargo test --locked --release --test recursive_perf --test cache_concurrency_bench -- --ignored --nocapture --test-threads=1

coverage:
    cargo llvm-cov --locked --summary-only

coverage-html:
    cargo llvm-cov --locked --html --open

update-iana-data:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT
    curl_opts=(--fail --silent --show-error --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30)
    curl "${curl_opts[@]}" https://www.internic.net/domain/named.root -o "$tmp_dir/named.root"
    curl "${curl_opts[@]}" https://data.iana.org/TLD/tlds-alpha-by-domain.txt -o "$tmp_dir/tlds-alpha-by-domain.txt"
    mv "$tmp_dir/named.root" src/config/named.root
    mv "$tmp_dir/tlds-alpha-by-domain.txt" src/config/tlds-alpha-by-domain.txt

check-bundled-data-freshness:
    ./scripts/check-bundled-data-freshness.sh

check-trust-anchor-staleness:
    ./scripts/check-trust-anchor-staleness.sh
