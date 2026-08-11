#![no_main]

use libfuzzer_sys::fuzz_target;
use rdns::protocol::Message;

// Invariant under test (Milestone 1's parser gate, `docs/plan/08-implementation-roadmap.md`):
// arbitrary bytes must return `Ok`/`Err`, never panic -- covers header/question/record
// decoding, compression-pointer following and loop detection, and EDNS option parsing,
// since `Message::parse` is the single entry point for all of them.
fuzz_target!(|data: &[u8]| {
    let _ = Message::parse(data);
});
