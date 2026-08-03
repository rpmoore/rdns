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
//! This module itself only extracts the client cookie from a query
//! (`parse_cookie_option`/`locate_cookie_option`) and computes a fresh
//! server cookie to attach to every response (`build_server_cookie`) --
//! no secret rotation is implemented (see the parent plan's non-goals).
//! Incoming server-cookie *verification* (recompute-and-compare,
//! BADCOOKIE rejection) is not done here: `locate_cookie_for_verification`
//! and `server_cookie_matches` below are the building blocks, but the
//! transport-conditional gating decision (UDP rejects an invalid cookie,
//! TCP doesn't -- RFC 7873 §5.2.3/§5.2.4) lives in
//! `src/resolver/mod.rs`'s `invalid_server_cookie`, called from
//! `probe_cache`.

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

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
/// client cookie) and discarding any server-cookie bytes present. This
/// function itself never validates a presented server cookie; that check
/// (recompute-and-compare, transport-conditional BADCOOKIE gating) is
/// `locate_cookie_for_verification`/`server_cookie_matches` below plus
/// `src/resolver/mod.rs`'s `invalid_server_cookie`, not this function.
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

/// The result of scanning `options` for a COOKIE option at the granularity
/// BADCOOKIE detection needs -- unlike `locate_cookie_option`, which
/// collapses every failure mode to `None`, this distinguishes "no server
/// cookie presented at all" (never an error -- RFC 7873 §5.2.3 first
/// contact) from "a server-cookie tail was presented but is structurally
/// malformed" (must be routed to BADCOOKIE, RFC 7873 §5.2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CookieVerification {
    /// No option with code 10 anywhere in `options`.
    NoCookieOption,
    /// More than one COOKIE option present. Collapsed the same way
    /// `locate_cookie_option`/`is_solely_cookie_option` already do -- RFC
    /// 7873 defines no combining rule for duplicates. Deliberately does
    /// NOT trigger BADCOOKIE (pins unchanged, pre-BADCOOKIE behavior).
    Duplicate,
    /// A single well-formed (length 8) COOKIE option: client cookie only,
    /// no server-cookie tail -- RFC 7873 §5.2.3 first contact. Never
    /// triggers BADCOOKIE.
    ClientOnly(ClientCookie),
    /// A single well-formed (length 16-40) COOKIE option: client cookie
    /// plus a server-cookie tail to verify against a fresh recompute.
    ClientAndServer {
        client_cookie: ClientCookie,
        server_cookie_tail: Vec<u8>,
    },
    /// A single COOKIE option present but structurally invalid (length not
    /// 8 and not in 16-40) -- RFC 7873 §5.2.4 treats a `Some` here the same
    /// as an invalid server cookie (routed to BADCOOKIE by
    /// `resolver::invalid_server_cookie`), never the same as
    /// `NoCookieOption`. `client_cookie` is `Some` whenever at least 8
    /// bytes of option data were available to read: every malformed length
    /// of 9-15 or 16+ (`validate_edns_options` already guarantees
    /// TLV-length consistency, so "malformed" here only ever means "wrong
    /// length", never "truncated"). `None` for the 0-7-byte case -- this
    /// **is** reachable from a real decoded wire message (a COOKIE option
    /// declaring, and fully providing, e.g. 3 bytes of data is a
    /// structurally valid TLV, just semantically too short for a client
    /// cookie), not merely a synthetic test case. `resolver::probe_cache`
    /// checks for this specific `None` case ahead of and independently of
    /// `invalid_server_cookie`/BADCOOKIE: there is no client cookie
    /// available to echo, so RFC 7873 §5.2.4's BADCOOKIE response format
    /// cannot be constructed at all here -- this must be FORMERR instead
    /// (RFC 7873 §5.2.2).
    Malformed { client_cookie: Option<ClientCookie> },
}

fn extract_client_cookie(data: &[u8]) -> Option<ClientCookie> {
    (data.len() >= 8).then(|| {
        let mut client_cookie = [0u8; 8];
        client_cookie.copy_from_slice(&data[0..8]);
        client_cookie
    })
}

/// Scans the raw EDNS options TLV blob for exactly one COOKIE option (code
/// 10), reusing the same cursor/code/len/bounds-check loop shape as
/// `locate_cookie_option`, but preserving the distinction between "no
/// cookie", "malformed", and "well-formed" that BADCOOKIE detection needs
/// and `locate_cookie_option` deliberately discards. A COOKIE option whose
/// declared length overruns the remaining bytes is `Malformed` (using
/// whatever bytes actually remain to recover a client cookie if possible)
/// rather than aborting the whole scan -- `validate_edns_options` already
/// guarantees this can't happen for a real decoded wire message, so this
/// path only exists for directly-constructed test byte vectors. Trailing
/// bytes too short to even hold a 4-byte option header are ambiguous (no
/// code to read) and are silently ignored, same as `locate_cookie_option`.
pub(crate) fn locate_cookie_for_verification(options: &[u8]) -> CookieVerification {
    let mut cursor = 0usize;
    let mut found: Option<CookieVerification> = None;

    while cursor + 4 <= options.len() {
        let code = u16::from_be_bytes([options[cursor], options[cursor + 1]]);
        let len = u16::from_be_bytes([options[cursor + 2], options[cursor + 3]]) as usize;
        let data_start = cursor + 4;
        let declared_end = data_start + len;
        let truncated = declared_end > options.len();
        let data_end = declared_end.min(options.len());
        let data = &options[data_start..data_end];

        if code == COOKIE_OPTION_CODE {
            let verification = if truncated {
                CookieVerification::Malformed {
                    client_cookie: extract_client_cookie(data),
                }
            } else if len == 8 {
                CookieVerification::ClientOnly(
                    extract_client_cookie(data).expect("len == 8 guarantees 8 bytes of data"),
                )
            } else if (16..=40).contains(&len) {
                CookieVerification::ClientAndServer {
                    client_cookie: extract_client_cookie(data)
                        .expect("16..=40 guarantees at least 8 bytes of data"),
                    server_cookie_tail: data[8..].to_vec(),
                }
            } else {
                CookieVerification::Malformed {
                    client_cookie: extract_client_cookie(data),
                }
            };

            if found.is_some() {
                return CookieVerification::Duplicate;
            }
            found = Some(verification);
        }

        if truncated {
            break;
        }
        cursor = declared_end;
    }

    found.unwrap_or(CookieVerification::NoCookieOption)
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

/// Whether `presented_tail` is exactly the 16-byte RFC 9018 Standard
/// Server Cookie this resolver would have issued for `client_cookie` +
/// `client_ip`, reusing `presented_tail`'s own embedded version/
/// reserved/timestamp fields for the recompute rather than the
/// verification-time instant.
///
/// This distinction matters: `build_server_cookie`'s hash input includes
/// the timestamp (RFC 9018 §4.4), so recomputing with "now" and comparing
/// byte-for-byte against a cookie issued at an earlier "now" would never
/// match -- rejecting every legitimately-reused, still-fresh cookie a
/// client presents on its second and subsequent queries, defeating RFC
/// 7873's entire point (obtain one server cookie, reuse it across many
/// queries without a round trip). Delegates to
/// `StandardServerCookie::check_hash`, which recomputes the hash from
/// `self`'s own version/reserved/timestamp bytes (taken from
/// `presented_tail`, via `StandardServerCookie::new` below) plus the given
/// `client_cookie`/`client_ip`/`secret`, and compares against `self`'s own
/// hash bytes (also taken from `presented_tail`) -- so the presented
/// cookie's timestamp is what's reused, never `now`.
///
/// Returns `false` for any `presented_tail` that isn't exactly 16 bytes:
/// this resolver only ever issues 16-byte RFC 9018 "Standard Server
/// Cookies" (`build_server_cookie` has no other output shape), so a
/// different-length tail can never be one this resolver issued.
/// RFC 9018 §4.3: a server SHOULD treat a Standard Server Cookie whose
/// embedded timestamp is too far in the past or future as invalid, bounding
/// how long a captured/replayed cookie stays accepted. 1 hour past / 5
/// minutes future are the values BIND9 and Unbound both use in practice;
/// RFC 9018 leaves the exact window to the implementation. Not yet
/// exercised by anything else in this module -- `rdns` never rotates its
/// cookie secret (see this module's doc comment), so a hash-valid cookie is
/// otherwise accepted indefinitely regardless of this check; this becomes
/// load-bearing the moment secret rotation is added.
const MAX_SERVER_COOKIE_AGE: Duration = Duration::from_secs(3600);
const MAX_SERVER_COOKIE_FUTURE_SKEW: Duration = Duration::from_secs(300);

/// Whether `timestamp` (the server cookie's embedded RFC 9018 §4.4 Unix
/// timestamp) is within `now`'s acceptable age/future-skew window. Compares
/// as plain `i64` seconds-since-epoch (not `Serial`'s wraparound-safe
/// arithmetic): with a multi-decade validity horizon nowhere near the u32
/// timestamp field's ~2106 rollover, a direct `i64` difference is exact and
/// simpler than reasoning about RFC 1982 serial-number wraparound for a
/// window this narrow.
fn timestamp_within_acceptable_window(timestamp: Serial, now: SystemTime) -> bool {
    let now_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let timestamp_secs = i64::from(timestamp.into_int());
    let age_secs = now_secs - timestamp_secs;
    age_secs <= MAX_SERVER_COOKIE_AGE.as_secs() as i64
        && age_secs >= -(MAX_SERVER_COOKIE_FUTURE_SKEW.as_secs() as i64)
}

pub(crate) fn server_cookie_matches(
    secret: &CookieSecret,
    client_cookie: ClientCookie,
    presented_tail: &[u8],
    client_ip: IpAddr,
    now: SystemTime,
) -> bool {
    let Ok(tail): Result<[u8; 16], _> = presented_tail.try_into() else {
        return false;
    };
    let version = tail[0];
    if version != 1 {
        // RFC 9018 §4.3: a server MUST treat any server cookie whose
        // version isn't 1 as invalid. Forging a matching hash for a
        // different version would require the secret anyway (`version` is
        // part of `check_hash`'s input below), so this check is
        // belt-and-suspenders, not the only thing standing between an
        // attacker and a forged cookie -- but it makes the version
        // invariant an explicit, spec-literal check rather than an
        // incidental side effect of the hash comparison.
        return false;
    }
    let reserved = [tail[1], tail[2], tail[3]];
    let timestamp = Serial::from_be_bytes([tail[4], tail[5], tail[6], tail[7]]);
    if !timestamp_within_acceptable_window(timestamp, now) {
        return false;
    }
    let mut hash = [0u8; 8];
    hash.copy_from_slice(&tail[8..16]);

    let presented = StandardServerCookie::new(version, reserved, timestamp, hash);
    presented.check_hash(
        DomainClientCookie::from_octets(client_cookie),
        client_ip,
        &secret.bytes,
    )
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

    #[test]
    fn locate_cookie_for_verification_absent() {
        assert_eq!(
            locate_cookie_for_verification(&[]),
            CookieVerification::NoCookieOption
        );
        assert_eq!(
            locate_cookie_for_verification(&nsid_option_bytes()),
            CookieVerification::NoCookieOption
        );
    }

    #[test]
    fn locate_cookie_for_verification_client_only() {
        let options = cookie_option_bytes(CLIENT_COOKIE, None);
        assert_eq!(
            locate_cookie_for_verification(&options),
            CookieVerification::ClientOnly(CLIENT_COOKIE)
        );
    }

    #[test]
    fn locate_cookie_for_verification_client_and_server() {
        let options = cookie_option_bytes(CLIENT_COOKIE, Some(&SERVER_COOKIE_TAIL));
        assert_eq!(
            locate_cookie_for_verification(&options),
            CookieVerification::ClientAndServer {
                client_cookie: CLIENT_COOKIE,
                server_cookie_tail: SERVER_COOKIE_TAIL.to_vec(),
            }
        );
    }

    #[test]
    fn locate_cookie_for_verification_malformed_length_recovers_client_cookie() {
        // Length 9: one byte past the well-formed 8-byte client-only case,
        // short of the 16-byte minimum server-cookie tail -- structurally
        // invalid per RFC 7873 §4, but the client cookie is still fully
        // present and recoverable.
        let data = vec![0u8; 9];
        let options = option_bytes(COOKIE_OPTION_CODE, &data);
        match locate_cookie_for_verification(&options) {
            CookieVerification::Malformed { client_cookie } => {
                assert_eq!(client_cookie, Some([0u8; 8]));
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn locate_cookie_for_verification_truncated_tlv_is_malformed_none() {
        // Declared length 8 but only 3 bytes of data actually present --
        // not enough to recover even a client cookie. Mirrors
        // `parse_cookie_option_rejects_truncated_tlv_bytes`'s fixture;
        // unreachable from real traffic (`validate_edns_options` already
        // rejects this at decode time), exercised only for this
        // function's defensive completeness.
        let options = [0, 10, 0, 8, 1, 2, 3];
        assert_eq!(
            locate_cookie_for_verification(&options),
            CookieVerification::Malformed {
                client_cookie: None
            }
        );
    }

    #[test]
    fn locate_cookie_for_verification_short_but_tlv_consistent_option_is_malformed_none() {
        // Unlike `locate_cookie_for_verification_truncated_tlv_is_malformed_none`
        // above (whose 3-byte-short-of-its-own-declared-length shape is
        // unreachable past `validate_edns_options`), this is a genuinely
        // reachable real-traffic shape: a COOKIE option that declares
        // length 3 and fully provides exactly 3 bytes of data is a
        // structurally valid TLV (nothing overruns the buffer), just
        // semantically too short to ever hold an 8-byte client cookie.
        // `resolver::probe_cache` must route this to FORMERR, not silently
        // process it as if no cookie were presented at all.
        let options = [0, 10, 0, 3, 1, 2, 3];
        assert_eq!(
            locate_cookie_for_verification(&options),
            CookieVerification::Malformed {
                client_cookie: None
            }
        );
    }

    #[test]
    fn locate_cookie_for_verification_rejects_duplicates() {
        let mut options = cookie_option_bytes(CLIENT_COOKIE, None);
        options.extend_from_slice(&cookie_option_bytes(CLIENT_COOKIE, None));
        assert_eq!(
            locate_cookie_for_verification(&options),
            CookieVerification::Duplicate
        );
    }

    #[test]
    fn server_cookie_matches_accepts_its_own_issued_cookie() {
        let secret = CookieSecret::generate();
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let tail = build_server_cookie(&secret, CLIENT_COOKIE, client_ip, now);

        assert!(server_cookie_matches(
            &secret,
            CLIENT_COOKIE,
            &tail,
            client_ip,
            now
        ));
    }

    #[test]
    fn server_cookie_matches_rejects_tampered_hash() {
        let secret = CookieSecret::generate();
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let mut tail = build_server_cookie(&secret, CLIENT_COOKIE, client_ip, now);
        tail[15] ^= 0xFF;

        assert!(!server_cookie_matches(
            &secret,
            CLIENT_COOKIE,
            &tail,
            client_ip,
            now
        ));
    }

    #[test]
    fn server_cookie_matches_rejects_wrong_length() {
        let secret = CookieSecret::generate();
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert!(!server_cookie_matches(
            &secret,
            CLIENT_COOKIE,
            &SERVER_COOKIE_TAIL, // 8 bytes, not 16
            client_ip,
            now
        ));
    }

    #[test]
    fn server_cookie_matches_rejects_wrong_secret() {
        let issuing_secret = CookieSecret::generate();
        let verifying_secret = CookieSecret::generate();
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let tail = build_server_cookie(&issuing_secret, CLIENT_COOKIE, client_ip, now);

        assert!(!server_cookie_matches(
            &verifying_secret,
            CLIENT_COOKIE,
            &tail,
            client_ip,
            now
        ));
    }

    /// Regression test: a naive "recompute with verification-time `now`"
    /// implementation would make every previously-issued cookie appear
    /// invalid the instant a second elapses, since the timestamp is part
    /// of the hash input. Issues at one instant, verifies 30 minutes later
    /// (comfortably inside `MAX_SERVER_COOKIE_AGE`'s 1-hour window, so this
    /// exercises only the hash-recompute behavior, not the age check) --
    /// must still match, proving the recompute reuses the presented
    /// cookie's own embedded timestamp rather than the verification-time
    /// `now`.
    #[test]
    fn server_cookie_matches_accepts_cookie_after_time_has_advanced() {
        let secret = CookieSecret::generate();
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let issued_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let tail = build_server_cookie(&secret, CLIENT_COOKIE, client_ip, issued_at);
        let verified_at = issued_at + Duration::from_secs(1800);

        assert!(server_cookie_matches(
            &secret,
            CLIENT_COOKIE,
            &tail,
            client_ip,
            verified_at
        ));
    }

    #[test]
    fn server_cookie_matches_reuses_ip_normalization_for_mapped_v6() {
        let secret = CookieSecret::generate();
        let client_ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201)); // ::ffff:192.0.2.1
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let tail = build_server_cookie(&secret, CLIENT_COOKIE, client_ip, now);

        assert!(server_cookie_matches(
            &secret,
            CLIENT_COOKIE,
            &tail,
            client_ip,
            now
        ));
    }

    #[test]
    fn server_cookie_matches_rejects_a_cookie_older_than_the_max_age_window() {
        // Regression coverage for a PR review finding: `server_cookie_matches`
        // used to check only version+hash, with no timestamp/age check at
        // all -- a validly-hashed but stale server cookie stayed accepted
        // indefinitely, when RFC 9018 §4.3 says the embedded timestamp
        // should be checked against a permitted age window.
        let secret = CookieSecret::generate();
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let issued_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let tail = build_server_cookie(&secret, CLIENT_COOKIE, client_ip, issued_at);

        // One second past MAX_SERVER_COOKIE_AGE (1 hour) -- hash is still
        // perfectly valid, only the age check should reject this.
        let verified_at = issued_at + MAX_SERVER_COOKIE_AGE + Duration::from_secs(1);
        assert!(!server_cookie_matches(
            &secret,
            CLIENT_COOKIE,
            &tail,
            client_ip,
            verified_at
        ));
    }

    #[test]
    fn server_cookie_matches_rejects_a_cookie_timestamped_too_far_in_the_future() {
        let secret = CookieSecret::generate();
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let issued_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let tail = build_server_cookie(&secret, CLIENT_COOKIE, client_ip, issued_at);

        // Verifying one second *before* MAX_SERVER_COOKIE_FUTURE_SKEW ahead
        // of the issue time -- from the verifier's perspective, this cookie
        // claims to have been issued in the future, beyond tolerable clock
        // skew.
        let verified_at = issued_at - MAX_SERVER_COOKIE_FUTURE_SKEW - Duration::from_secs(1);
        assert!(!server_cookie_matches(
            &secret,
            CLIENT_COOKIE,
            &tail,
            client_ip,
            verified_at
        ));
    }

    #[test]
    fn server_cookie_matches_accepts_a_cookie_at_the_edge_of_the_age_window() {
        // Boundary check: exactly at the age limit must still be accepted
        // (the check is `>`, not `>=`, on the age itself).
        let secret = CookieSecret::generate();
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let issued_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let tail = build_server_cookie(&secret, CLIENT_COOKIE, client_ip, issued_at);

        let verified_at = issued_at + MAX_SERVER_COOKIE_AGE;
        assert!(server_cookie_matches(
            &secret,
            CLIENT_COOKIE,
            &tail,
            client_ip,
            verified_at
        ));
    }
}
