fmt:
    cargo fmt

bench:
    cargo test --locked --release --test recursive_perf --test cache_concurrency_bench -- --ignored --nocapture --test-threads=1

coverage:
    cargo llvm-cov --locked --summary-only

coverage-html:
    cargo llvm-cov --locked --html --open

update-iana-data:
    curl --fail --silent --show-error --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30 \
        https://www.internic.net/domain/named.root -o src/config/named.root
    curl --fail --silent --show-error --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30 \
        https://data.iana.org/TLD/tlds-alpha-by-domain.txt -o src/config/tlds-alpha-by-domain.txt

check-bundled-data-freshness:
    ./scripts/check-bundled-data-freshness.sh
