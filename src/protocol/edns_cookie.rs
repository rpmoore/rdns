// Copyright 2026 Ryan Moore
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! RFC 7873 DNS Cookie EDNS option parsing, cache-admission narrowing, and
//! RFC 9018 server-cookie construction.
//!
//! This module never validates an incoming server cookie's hash or
//! timestamp (no BADCOOKIE handling, no secret rotation) -- see the parent
//! plan's non-goals. It only extracts the client cookie from a query and
//! computes a fresh server cookie to attach to every response.

use std::net::IpAddr;
use std::time::SystemTime;

use domain::base::Serial;
use domain::base::opt::cookie::{ClientCookie as DomainClientCookie, StandardServerCookie};
use rand::Rng;

const COOKIE_OPTION_CODE: u16 = 10;

/// The 8-byte client cookie extracted from an incoming query's COOKIE
/// option.
///
/// `pub`, not `pub(crate)`: it appears in `QueryFeatures.client_cookie`, a
/// public field on a public struct, so it must be nameable from outside
/// this crate too.
pub type ClientCookie = [u8; 8];

/// The resolver's one random, process-lifetime server-cookie secret
/// (RFC 9018 §4.2: SHOULD be >= 128 bits). Constructed once at process
/// startup, mirroring `SystemClock`'s role as the one process-lifetime
/// side-effect-holding value. Held behind an `Arc<CookieSecret>` at call
/// sites that need it, exactly like `Arc<dyn Clock>`.
///
/// `pub`, not `pub(crate)`: `src/main.rs` (a separate binary crate) must
/// construct one via `generate()` and hand it to
/// `ResolveQuery::with_cookie_secret`, mirroring how it constructs
/// `SystemClock` -- re-exported at `crate::resolver::CookieSecret` for that
/// call site. Every other item in this module stays `pub(crate)`: nothing
/// else needs to cross the crate boundary.
///
/// Deliberately does not derive/implement `Debug`, `Display`, or
/// `Serialize` -- doing so would risk printing or serializing the raw
/// secret bytes.
pub struct CookieSecret {
    bytes: [u8; 16],
}

impl CookieSecret {
    /// Generates a fresh, CSPRNG-backed secret. Called exactly once, in
    /// `src/main.rs`, alongside where `SystemClock` is constructed.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        CookieSecret { bytes }
    }
}

/// Scans `options` for exactly one well-formed COOKIE option, returning its
/// client cookie and whether the option was the *only* thing present in
/// `options`. Returns `None` if no COOKIE option is present, more than one
/// is present, the COOKIE option's length is malformed (RFC 7873 §4: must
/// be 8, or 16-40 inclusive), or the options blob itself is truncated.
fn locate_cookie_option(options: &[u8]) -> Option<(ClientCookie, bool)> {
    let mut cursor = 0usize;
    let mut found: Option<ClientCookie> = None;
    let mut other_option_present = false;

    while cursor < options.len() {
        if options.len() - cursor < 4 {
            return None;
        }
        let code = u16::from_be_bytes([options[cursor], options[cursor + 1]]);
        let len = u16::from_be_bytes([options[cursor + 2], options[cursor + 3]]) as usize;
        let data_start = cursor + 4;
        let data_end = data_start.checked_add(len)?;
        if data_end > options.len() {
            return None;
        }
        let data = &options[data_start..data_end];

        if code == COOKIE_OPTION_CODE {
            if found.is_some() {
                return None;
            }
            if !(len == 8 || (16..=40).contains(&len)) {
                return None;
            }
            let mut client_cookie = [0u8; 8];
            client_cookie.copy_from_slice(&data[0..8]);
            found = Some(client_cookie);
        } else {
            other_option_present = true;
        }

        cursor = data_end;
    }

    found.map(|client_cookie| (client_cookie, !other_option_present))
}

/// Scans the raw EDNS options TLV blob (the same `edns.options: Vec<u8>`
/// field already populated by `parse_opt_record`) for exactly one option
/// with code 10 (COOKIE). Returns `Some(client_cookie)` only when the
/// option is present exactly once and has a well-formed RFC 7873 §4 length
/// (8, or 16-40 inclusive) -- extracting just the first 8 bytes (the
/// client cookie) and discarding any server-cookie bytes present (this
/// implementation never validates an incoming server cookie, per the
/// plan's decided non-goals).
///
/// Returns `None` when: no COOKIE option is present, more than one COOKIE
/// option is present, or the option's length is malformed.
///
/// This answers "is there a client cookie to echo on the response" -- a
/// query can have a well-formed Cookie *and* some other EDNS option (e.g.
/// NSID) and this function still returns `Some` in that case. See
/// `is_solely_cookie_option` for the stricter cache-admission question.
pub(crate) fn parse_cookie_option(options: &[u8]) -> Option<ClientCookie> {
    locate_cookie_option(options).map(|(client_cookie, _)| client_cookie)
}

/// The cache-admission predicate -- used only by `cache_supported()`
/// (narrowed in section-03). Returns `Some(client_cookie)` only when the
/// *entire* raw `options` byte slice is consumed by exactly one
/// well-formed COOKIE option and nothing else -- any trailing bytes (e.g.
/// another option such as NSID or Padding) means `None`.
///
/// Deliberately stricter than `parse_cookie_option`: a query with a
/// well-formed Cookie *and* another option must extract/echo the cookie
/// (so `parse_cookie_option` returns `Some`) while still NOT being treated
/// as cache-admissible (so this function returns `None` for the identical
/// input).
pub(crate) fn is_solely_cookie_option(options: &[u8]) -> Option<ClientCookie> {
    locate_cookie_option(options)
        .and_then(|(client_cookie, is_sole)| is_sole.then_some(client_cookie))
}

/// Computes the RFC 9018 §4.4 16-byte server cookie: 1-byte Version(1),
/// 3-byte Reserved(0), 4-byte big-endian Unix timestamp, 8-byte
/// SipHash-2-4 output (serialized little-endian). Hash input is
/// `client_cookie(8) | version(1) | reserved(3) | timestamp(4) |
/// client_ip(4 or 16, depending on v4/v6)`, keyed by `secret`.
///
/// Delegates to `domain::base::opt::cookie::StandardServerCookie::calculate`
/// so this module never has to import `siphasher` itself or implement the
/// little-endian-hash-serialization gotcha by hand.
pub(crate) fn build_server_cookie(
    secret: &CookieSecret,
    client_cookie: ClientCookie,
    client_ip: IpAddr,
    now: SystemTime,
) -> [u8; 16] {
    let timestamp_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;

    let cookie = StandardServerCookie::calculate(
        DomainClientCookie::from_octets(client_cookie),
        Serial(timestamp_secs),
        client_ip,
        &secret.bytes,
    );

    let mut out = [0u8; 16];
    out[0] = cookie.version();
    out[1..4].copy_from_slice(&cookie.reserved());
    out[4..8].copy_from_slice(&cookie.timestamp().into_int().to_be_bytes());
    out[8..16].copy_from_slice(&cookie.hash());
    out
}

/// Serializes a full COOKIE option's RDATA-option-TLV bytes (option code
/// 10, length 24, client cookie followed by the 16-byte server cookie),
/// ready to be appended into an OPT record's `options` bytes.
pub(crate) fn build_cookie_option(client_cookie: ClientCookie, server_cookie: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + client_cookie.len() + server_cookie.len());
    out.extend_from_slice(&COOKIE_OPTION_CODE.to_be_bytes());
    out.extend_from_slice(&((client_cookie.len() + server_cookie.len()) as u16).to_be_bytes());
    out.extend_from_slice(&client_cookie);
    out.extend_from_slice(&server_cookie);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const CLIENT_COOKIE: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
    const SERVER_COOKIE_TAIL: [u8; 8] = [9, 10, 11, 12, 13, 14, 15, 16];

    fn option_bytes(code: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn cookie_option_bytes(
        client_cookie: ClientCookie,
        server_cookie_tail: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut data = client_cookie.to_vec();
        if let Some(tail) = server_cookie_tail {
            data.extend_from_slice(tail);
        }
        option_bytes(COOKIE_OPTION_CODE, &data)
    }

    fn nsid_option_bytes() -> Vec<u8> {
        // NSID (option code 3) with empty payload -- a real, distinct
        // EDNS option unrelated to COOKIE.
        option_bytes(3, &[])
    }

    #[test]
    fn parse_cookie_option_client_only_8_bytes() {
        let options = cookie_option_bytes(CLIENT_COOKIE, None);
        assert_eq!(parse_cookie_option(&options), Some(CLIENT_COOKIE));
    }

    #[test]
    fn parse_cookie_option_client_and_server_cookie() {
        let options = cookie_option_bytes(CLIENT_COOKIE, Some(&SERVER_COOKIE_TAIL));
        // Only the client cookie is extracted; server-cookie bytes are
        // discarded, never validated.
        assert_eq!(parse_cookie_option(&options), Some(CLIENT_COOKIE));
    }

    #[test]
    fn parse_cookie_option_rejects_malformed_lengths() {
        for malformed_len in [9usize, 15, 41] {
            let data = vec![0u8; malformed_len];
            let options = option_bytes(COOKIE_OPTION_CODE, &data);
            assert_eq!(
                parse_cookie_option(&options),
                None,
                "expected None for malformed length {malformed_len}"
            );
        }
    }

    #[test]
    fn parse_cookie_option_absent() {
        assert_eq!(parse_cookie_option(&[]), None);
        let options = nsid_option_bytes();
        assert_eq!(parse_cookie_option(&options), None);
    }

    #[test]
    fn parse_cookie_option_rejects_truncated_tlv_bytes() {
        // Dangling option header (fewer than 4 bytes remaining) and a
        // declared option length that overruns the buffer must both
        // return None rather than panic -- this scans attacker-controlled
        // wire bytes.
        assert_eq!(parse_cookie_option(&[0, 10]), None);
        assert_eq!(parse_cookie_option(&[0, 10, 0, 8, 1, 2, 3]), None);
    }

    #[test]
    fn parse_cookie_option_rejects_duplicates() {
        let mut options = cookie_option_bytes(CLIENT_COOKIE, None);
        options.extend_from_slice(&cookie_option_bytes(CLIENT_COOKIE, None));
        assert_eq!(parse_cookie_option(&options), None);
    }

    #[test]
    fn parse_cookie_option_extracts_alongside_other_option() {
        let mut options = cookie_option_bytes(CLIENT_COOKIE, None);
        options.extend_from_slice(&nsid_option_bytes());
        assert_eq!(parse_cookie_option(&options), Some(CLIENT_COOKIE));
    }

    #[test]
    fn is_solely_cookie_option_true_for_lone_well_formed_cookie() {
        let options = cookie_option_bytes(CLIENT_COOKIE, None);
        assert_eq!(is_solely_cookie_option(&options), Some(CLIENT_COOKIE));
    }

    #[test]
    fn is_solely_cookie_option_false_when_other_option_present() {
        // Identical fixture to
        // `parse_cookie_option_extracts_alongside_other_option`, pinning
        // the intentional divergence between extraction and
        // cache-admission.
        let mut options = cookie_option_bytes(CLIENT_COOKIE, None);
        options.extend_from_slice(&nsid_option_bytes());
        assert_eq!(is_solely_cookie_option(&options), None);
    }

    #[test]
    fn is_solely_cookie_option_rejects_malformed_absent_duplicate() {
        let data = vec![0u8; 9];
        let malformed = option_bytes(COOKIE_OPTION_CODE, &data);
        assert_eq!(is_solely_cookie_option(&malformed), None);

        assert_eq!(is_solely_cookie_option(&[]), None);

        let mut duplicate = cookie_option_bytes(CLIENT_COOKIE, None);
        duplicate.extend_from_slice(&cookie_option_bytes(CLIENT_COOKIE, None));
        assert_eq!(is_solely_cookie_option(&duplicate), None);
    }

    #[test]
    fn build_server_cookie_has_correct_byte_layout() {
        let secret = CookieSecret::generate();
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let cookie = build_server_cookie(
            &secret,
            CLIENT_COOKIE,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            now,
        );

        assert_eq!(cookie[0], 1, "version must be 1");
        assert_eq!(cookie[1..4], [0, 0, 0], "reserved must be zero");
        assert_eq!(
            cookie[4..8],
            1_700_000_000u32.to_be_bytes(),
            "timestamp must be big-endian seconds"
        );
    }

    #[test]
    fn build_server_cookie_differs_by_client_ip() {
        let secret = CookieSecret::generate();
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);

        let v4_a = build_server_cookie(
            &secret,
            CLIENT_COOKIE,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            now,
        );
        let v4_b = build_server_cookie(
            &secret,
            CLIENT_COOKIE,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            now,
        );
        let v6 = build_server_cookie(
            &secret,
            CLIENT_COOKIE,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            now,
        );

        assert_ne!(
            v4_a[8..],
            v4_b[8..],
            "hash must depend on client IP, not just family"
        );
        assert_ne!(
            v4_a[8..],
            v6[8..],
            "hash must differ between v4 and v6 client IPs"
        );
    }

    #[test]
    fn build_server_cookie_matches_rfc_9018_appendix_a1_vector() {
        // RFC 9018 Appendix A.1 "Learning a New Server Cookie": fixed
        // secret, client cookie, timestamp, and client IP, with a
        // published expected 16-byte server cookie. Pins the manual
        // version/reserved/timestamp/hash byte reassembly in
        // `build_server_cookie` against a known-correct absolute value,
        // not just internal self-consistency.
        let secret = CookieSecret {
            bytes: [
                0xe5, 0xe9, 0x73, 0xe5, 0xa6, 0xb2, 0xa4, 0x3f, 0x48, 0xe7, 0xdc, 0x84, 0x9e, 0x37,
                0xbf, 0xcf,
            ],
        };
        let client_cookie: ClientCookie = [0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57];
        let client_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 100));
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_559_731_985);

        let cookie = build_server_cookie(&secret, client_cookie, client_ip, now);

        assert_eq!(
            cookie,
            [
                0x01, 0x00, 0x00, 0x00, 0x5c, 0xf7, 0x9f, 0x11, 0x1f, 0x81, 0x30, 0xc3, 0xee, 0xe2,
                0x94, 0x80,
            ]
        );
    }

    #[test]
    fn build_cookie_option_serializes_expected_tlv() {
        let server_cookie = [0u8; 16];
        let bytes = build_cookie_option(CLIENT_COOKIE, server_cookie);

        assert_eq!(bytes.len(), 4 + 8 + 16);
        assert_eq!(&bytes[0..2], &COOKIE_OPTION_CODE.to_be_bytes());
        assert_eq!(&bytes[2..4], &24u16.to_be_bytes());
        assert_eq!(&bytes[4..12], &CLIENT_COOKIE);
        assert_eq!(&bytes[12..28], &server_cookie);
    }

    #[test]
    fn cookie_secret_generate_has_expected_length() {
        let secret = CookieSecret::generate();
        assert_eq!(secret.bytes.len(), 16);
    }

    #[test]
    fn cookie_secret_generate_produces_distinct_secrets() {
        let a = CookieSecret::generate();
        let b = CookieSecret::generate();
        assert_ne!(a.bytes, b.bytes);
    }
}
