bench:
    cargo test --locked --release --test recursive_perf -- --ignored --nocapture --test-threads=1
