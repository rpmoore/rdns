#![no_main]

use libfuzzer_sys::fuzz_target;
use rdns::protocol::decode_tcp_frame;

// Invariant under test: `decode_tcp_frame` must return `Ok`/`Err`, never panic, for any
// length-prefix byte sequence and any `max_size` cap (see `docs/knowledge/delivery/
// tcp-listener.md`). The first byte selects among a small/mid/max cap so the fuzzer
// exercises the too-large, need-more-bytes, and complete-frame paths, not just one.
fuzz_target!(|data: &[u8]| {
    let Some((&cap_selector, frame)) = data.split_first() else {
        return;
    };
    let max_size = match cap_selector % 3 {
        0 => 4,
        1 => 512,
        _ => u16::MAX as usize,
    };
    let _ = decode_tcp_frame(frame, max_size);
});
