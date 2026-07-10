fmt:
    cargo fmt

bench:
    cargo test --locked --release --test recursive_perf --test cache_concurrency_bench -- --ignored --nocapture --test-threads=1

coverage:
    cargo llvm-cov --locked --summary-only

coverage-html:
    cargo llvm-cov --locked --html --open
