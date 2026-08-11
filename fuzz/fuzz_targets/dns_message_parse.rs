#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rdns::protocol::Message;

// Invariant under test (Milestone 1's parser gate, `docs/plan/08-implementation-roadmap.md`):
// arbitrary bytes must return `Ok`/`Err`, never panic -- covers header/question/record
// decoding, compression-pointer following and loop detection, and EDNS option parsing,
// since `Message::parse` is the single entry point for all of them.
//
// `parse_standard_query_owned_with_recovery` is fuzzed alongside it, not instead of it:
// it's the actual production entry point for untrusted network bytes
// (`StandardProtocolCodec::decode_query_owned`, `src/resolver/mod.rs:7158-7159`) and has its
// own header-validation-failure recovery path (`recover_query_context`,
// `recovery_additional_is_opt`) that `Message::parse` alone never exercises.
fuzz_target!(|data: &[u8]| {
    let _ = Message::parse(data);
    let _ = Message::parse_standard_query_owned_with_recovery(Bytes::copy_from_slice(data));
});
