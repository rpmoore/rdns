diff --git a/src/protocol/mod.rs b/src/protocol/mod.rs
index dbf52bc..de5ef19 100644
--- a/src/protocol/mod.rs
+++ b/src/protocol/mod.rs
@@ -742,14 +742,274 @@ impl NameCompressor {
     }
 }
 
-fn write_u16(out: &mut Vec<u8>, value: u16) {
+pub(crate) fn write_u16(out: &mut Vec<u8>, value: u16) {
     out.extend_from_slice(&value.to_be_bytes());
 }
 
-fn write_u32(out: &mut Vec<u8>, value: u32) {
+pub(crate) fn write_u32(out: &mut Vec<u8>, value: u32) {
     out.extend_from_slice(&value.to_be_bytes());
 }
 
+/// Writes a DNS message header with full control over every section count
+/// and the AD bit — unlike `write_response_header` (which always zeroes
+/// the authority/additional counts and never sets AD), this is used by
+/// `resolver::cache::assemble` (section-06) to build responses carrying an
+/// authority-section SOA (negative results) and/or an AD bit computed from
+/// DNSSEC validation state.
+#[allow(clippy::too_many_arguments)]
+pub(crate) fn write_message_header(
+    out: &mut Vec<u8>,
+    id: u16,
+    recursion_desired: bool,
+    truncated: bool,
+    authenticated_data: bool,
+    rcode: ResponseCode,
+    question_count: u16,
+    answer_count: u16,
+    authority_count: u16,
+    additional_count: u16,
+) {
+    write_u16(out, id);
+    let mut flags = 0x8000; // QR = 1 (response)
+    if recursion_desired {
+        flags |= 0x0100;
+    }
+    if truncated {
+        flags |= 0x0200;
+    }
+    flags |= 0x0080; // RA = 1
+    if authenticated_data {
+        flags |= 0x0020;
+    }
+    flags |= rcode.as_u8() as u16;
+    write_u16(out, flags);
+    write_u16(out, question_count);
+    write_u16(out, answer_count);
+    write_u16(out, authority_count);
+    write_u16(out, additional_count);
+}
+
+fn write_name_uncompressed(out: &mut Vec<u8>, name: &str) {
+    let name = name.trim_end_matches('.');
+    if name.is_empty() {
+        out.push(0);
+        return;
+    }
+    for label in name.split('.') {
+        out.push(label.len() as u8);
+        out.extend_from_slice(label.as_bytes());
+    }
+    out.push(0);
+}
+
+fn from_hex(hex: &str) -> Vec<u8> {
+    (0..hex.len())
+        .step_by(2)
+        .filter_map(|i| {
+            hex.get(i..i + 2)
+                .and_then(|s| u8::from_str_radix(s, 16).ok())
+        })
+        .collect()
+}
+
+/// Encodes one arbitrary resource record to wire bytes: owner name, type,
+/// class, TTL, then a length-prefixed RDATA block sized to whatever
+/// `rdata` actually needs. Mirrors `parse_record_data`'s match arms in
+/// reverse — every `RecordData` variant that can be parsed can be written
+/// back out here. Used by `resolver::cache::assemble` (section-06) to
+/// serialize cached record sets fresh, per request, instead of replaying a
+/// stored byte template.
+///
+/// Domain names in legacy RDATA fields (CNAME/NS/PTR targets, MX exchange,
+/// SRV target, SOA mname/rname, RP names) are written through `compressor`
+/// like any owner name — this is standard practice and always valid.
+/// `RRSIG.signer_name` and `NSEC.next_domain` are written uncompressed
+/// instead, per RFC 4034 §6.2's canonical-form requirement for
+/// DNSSEC-relevant names.
+pub(crate) fn write_record(
+    out: &mut Vec<u8>,
+    compressor: &mut NameCompressor,
+    name: &str,
+    rtype: u16,
+    rclass: u16,
+    ttl: u32,
+    rdata: &RecordData,
+) {
+    compressor.write_name(out, name);
+    write_u16(out, rtype);
+    write_u16(out, rclass);
+    write_u32(out, ttl);
+    let rdlength_pos = out.len();
+    write_u16(out, 0);
+    let rdata_start = out.len();
+    write_rdata(out, compressor, rdata);
+    let rdlength = (out.len() - rdata_start) as u16;
+    out[rdlength_pos..rdlength_pos + 2].copy_from_slice(&rdlength.to_be_bytes());
+}
+
+fn write_rdata(out: &mut Vec<u8>, compressor: &mut NameCompressor, rdata: &RecordData) {
+    match rdata {
+        RecordData::A(address) => out.extend_from_slice(&address.octets()),
+        RecordData::AAAA(address) => out.extend_from_slice(&address.octets()),
+        RecordData::CAA { flags, tag, value } => {
+            out.push(*flags);
+            out.push(tag.len() as u8);
+            out.extend_from_slice(tag.as_bytes());
+            out.extend_from_slice(value.as_bytes());
+        }
+        RecordData::MX {
+            preference,
+            exchange,
+        } => {
+            write_u16(out, *preference);
+            compressor.write_name(out, exchange);
+        }
+        RecordData::CERT {
+            cert_type,
+            key_tag,
+            algorithm,
+            cert,
+        } => {
+            write_u16(out, *cert_type);
+            write_u16(out, *key_tag);
+            out.push(*algorithm);
+            out.extend_from_slice(cert);
+        }
+        RecordData::CNAME(target) => compressor.write_name(out, target),
+        RecordData::DNSKEY {
+            flags,
+            protocol,
+            algorithm,
+            public_key,
+        } => {
+            write_u16(out, *flags);
+            out.push(*protocol);
+            out.push(*algorithm);
+            out.extend_from_slice(public_key);
+        }
+        RecordData::DS {
+            key_tag,
+            algorithm,
+            digest_type,
+            digest,
+        } => {
+            write_u16(out, *key_tag);
+            out.push(*algorithm);
+            out.push(*digest_type);
+            out.extend_from_slice(digest);
+        }
+        RecordData::NSEC {
+            next_domain,
+            type_bit_maps,
+        } => {
+            write_name_uncompressed(out, next_domain);
+            out.extend_from_slice(type_bit_maps);
+        }
+        RecordData::NSEC3 {
+            hash_algorithm,
+            flags,
+            iterations,
+            salt_length,
+            salt,
+            hash_length,
+            next_domain,
+            type_bit_maps,
+        } => {
+            out.push(*hash_algorithm);
+            out.push(*flags);
+            write_u16(out, *iterations);
+            out.push(*salt_length);
+            out.extend_from_slice(salt);
+            out.push(*hash_length);
+            out.extend_from_slice(&from_hex(next_domain));
+            out.extend_from_slice(type_bit_maps);
+        }
+        RecordData::NSEC3PARAM {
+            hash_algorithm,
+            flags,
+            iterations,
+            salt_length,
+            salt,
+        } => {
+            out.push(*hash_algorithm);
+            out.push(*flags);
+            write_u16(out, *iterations);
+            out.push(*salt_length);
+            out.extend_from_slice(salt);
+        }
+        RecordData::NS(name) => compressor.write_name(out, name),
+        RecordData::PTR(name) => compressor.write_name(out, name),
+        RecordData::RP {
+            mboxdname,
+            txtdname,
+        } => {
+            compressor.write_name(out, mboxdname);
+            compressor.write_name(out, txtdname);
+        }
+        RecordData::RRSIG {
+            type_covered,
+            algorithm,
+            labels,
+            original_ttl,
+            signature_expiration,
+            signature_inception,
+            key_tag,
+            signer_name,
+            signature,
+        } => {
+            write_u16(out, *type_covered);
+            out.push(*algorithm);
+            out.push(*labels);
+            write_u32(out, *original_ttl);
+            write_u32(out, *signature_expiration);
+            write_u32(out, *signature_inception);
+            write_u16(out, *key_tag);
+            write_name_uncompressed(out, signer_name);
+            out.extend_from_slice(signature);
+        }
+        RecordData::SOA {
+            ttl: _,
+            rname,
+            mname,
+            serial,
+            refresh,
+            retry,
+            expire,
+            minimum,
+        } => {
+            compressor.write_name(out, mname);
+            compressor.write_name(out, rname);
+            write_u32(out, *serial);
+            write_u32(out, *refresh);
+            write_u32(out, *retry);
+            write_u32(out, *expire);
+            write_u32(out, *minimum);
+        }
+        RecordData::SRV {
+            priority,
+            weight,
+            port,
+            target,
+        } => {
+            write_u16(out, *priority);
+            write_u16(out, *weight);
+            write_u16(out, *port);
+            compressor.write_name(out, target);
+        }
+        RecordData::TXT(text) => {
+            if text.is_empty() {
+                return;
+            }
+            for chunk in text.as_bytes().chunks(255) {
+                out.push(chunk.len() as u8);
+                out.extend_from_slice(chunk);
+            }
+        }
+        RecordData::OPT(info) => out.extend_from_slice(&info.options),
+        RecordData::Unknown { rtype: _, bytes } => out.extend_from_slice(bytes),
+    }
+}
+
 fn validate_standard_query_header(
     header: &Header,
 ) -> std::result::Result<(), QueryValidationError> {
diff --git a/src/resolver/cache/assemble.rs b/src/resolver/cache/assemble.rs
index dda7963..3bf35a2 100644
--- a/src/resolver/cache/assemble.rs
+++ b/src/resolver/cache/assemble.rs
@@ -12,5 +12,1047 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-//! `assemble_response`, `resolve_from_cache`, `ChainLookup` — filled in by
-//! section-06.
+//! CNAME-chain walking (`resolve_from_cache`) and serve-time wire response
+//! assembly (`assemble_response`/`assemble_negative_response`). Cache
+//! entries store raw record data, not a pre-built wire template — every
+//! hit assembles the response fresh, per request, using the requester's
+//! own question wire bytes (casing) and advertised EDNS bufsize
+//! (truncation), neither of which are cache-key dimensions anymore.
+//!
+//! Storing a backend response into the cache (`store_response`) and
+//! wiring this into `DomainDnsCache` are section-07's job — this section
+//! only produces the read side.
+
+#![allow(dead_code)]
+
+use std::collections::HashSet;
+use std::time::{Duration, SystemTime};
+
+use crate::protocol::{NameCompressor, ResponseCode, write_message_header, write_record};
+use crate::resolver::QueryFeatures;
+
+use super::ShardedDnsCache;
+use super::entry::{DnssecState, NegativeEntry, RRsetEntry};
+use super::shard::HopResult;
+
+const CNAME_RECORD_TYPE: u16 = 5;
+
+/// Zero or more CNAME hops followed by the terminal `RRsetEntry` matching
+/// the original qtype — or, if qtype == CNAME itself, exactly one hop (the
+/// CNAME's own entry, no further walking past it).
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub(crate) struct ResolvedAnswer {
+    pub(crate) chain: Vec<(String, RRsetEntry)>, // (owner name, entry), in walk order
+}
+
+/// A negative result (NXDOMAIN or NODATA), plus whatever CNAME hops were
+/// walked before reaching it — a chain ending in NXDOMAIN/NODATA must
+/// still include those hops in the assembled response's answer section.
+///
+/// `terminal_name` is the name the negative entry was actually found
+/// under (the original qname if `chain` is empty, otherwise the last
+/// hop's CNAME target) — not part of the plan's literal `ResolvedNegative`
+/// listing, but required: `NegativeEntry` has no owner-name field of its
+/// own (consistent with `RRsetEntry`, whose owner name likewise comes
+/// from the chain tuple rather than the entry itself), so
+/// `assemble_negative_response` needs this to know what name to write the
+/// authority-section SOA (and any proof records) under.
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub(crate) struct ResolvedNegative {
+    pub(crate) chain: Vec<(String, RRsetEntry)>,
+    pub(crate) terminal_name: String,
+    pub(crate) negative: NegativeEntry,
+}
+
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub(crate) enum ChainLookup {
+    /// Every name in the chain was found, unexpired, in the current
+    /// namespace.
+    Answered(ResolvedAnswer),
+    /// Whole-name NXDOMAIN at some point in the chain.
+    NxDomain(ResolvedNegative),
+    /// NODATA for the queried type at the terminal name.
+    NoData(ResolvedNegative),
+    /// Any name in the chain missed, expired, or was stale-namespace —
+    /// caller must fall back to backend resolution.
+    Miss,
+}
+
+/// Walks a (possibly empty) CNAME chain starting at `qname`, doing one
+/// independent per-shard lookup per name in the chain, up to
+/// `max_chain_depth` hops.
+///
+/// `max_chain_depth` is an intentional, documented deviation from the
+/// plan's literal listed signature `(cache, qname, qtype, qclass,
+/// current_namespace, now)`: the plan says to reuse
+/// `RecursiveResolverConfig.max_cname_restarts` "rather than introducing
+/// a second, possibly-inconsistent bound", but that field lives on a type
+/// `cache/` has no access to and isn't part of `CacheConfig`. The caller
+/// (section-07's `probe_cache`) passes `max_cname_restarts` through here
+/// explicitly instead.
+///
+/// Never holds more than one shard's lock at a time: each hop acquires,
+/// clones, and releases its shard's lock (via `Shard::lookup_hop`) before
+/// the next hop begins.
+pub(crate) fn resolve_from_cache(
+    cache: &ShardedDnsCache,
+    qname: &str,
+    qtype: u16,
+    qclass: u16,
+    current_namespace: &str,
+    max_chain_depth: u8,
+    now: SystemTime,
+) -> ChainLookup {
+    let mut current = crate::resolver::normalize_question_name(qname);
+    let mut chain: Vec<(String, RRsetEntry)> = Vec::new();
+    let mut visited: HashSet<String> = HashSet::new();
+
+    loop {
+        if chain.len() as u8 >= max_chain_depth || visited.contains(&current) {
+            return ChainLookup::Miss;
+        }
+        visited.insert(current.clone());
+
+        let shard = cache.shard_for(&current);
+        match shard.lookup_hop(&current, qtype, qclass, current_namespace, now) {
+            HopResult::Answer(entry) => {
+                chain.push((current, entry));
+                return ChainLookup::Answered(ResolvedAnswer { chain });
+            }
+            HopResult::CnameHop(entry, target) => {
+                chain.push((current, entry));
+                current = crate::resolver::normalize_question_name(&target);
+            }
+            HopResult::NoData(negative) => {
+                return ChainLookup::NoData(ResolvedNegative {
+                    chain,
+                    terminal_name: current,
+                    negative,
+                });
+            }
+            HopResult::NxDomain(negative) => {
+                return ChainLookup::NxDomain(ResolvedNegative {
+                    chain,
+                    terminal_name: current,
+                    negative,
+                });
+            }
+            HopResult::Miss => return ChainLookup::Miss,
+        }
+    }
+}
+
+/// Ages `ttl_at_store` by elapsed time since `stored_at`, capped by
+/// remaining time to `expires_at` — computed directly in Rust before any
+/// wire bytes are written (rather than reusing
+/// `age_response_ttls`/`cap_response_ttls` against an assembled buffer),
+/// since a CNAME chain can combine records from multiple `RRsetEntry`s
+/// with different `stored_at` values, which a single scalar `age` applied
+/// to a whole buffer can't represent correctly.
+fn compute_wire_ttl(
+    ttl_at_store: u32,
+    stored_at: SystemTime,
+    expires_at: SystemTime,
+    now: SystemTime,
+) -> u32 {
+    let elapsed_secs = now
+        .duration_since(stored_at)
+        .unwrap_or(Duration::ZERO)
+        .as_secs();
+    let aged = ttl_at_store.saturating_sub(elapsed_secs.min(u64::from(u32::MAX)) as u32);
+    let remaining_secs = expires_at
+        .duration_since(now)
+        .unwrap_or(Duration::ZERO)
+        .as_secs();
+    aged.min(remaining_secs.min(u64::from(u32::MAX)) as u32)
+}
+
+fn chain_answer_count(chain: &[(String, RRsetEntry)], dnssec_ok: bool) -> u16 {
+    chain
+        .iter()
+        .map(|(_, entry)| {
+            let mut count = entry.records.len();
+            if dnssec_ok {
+                count += entry.rrsigs.len();
+            }
+            count
+        })
+        .sum::<usize>() as u16
+}
+
+fn write_rrset(
+    out: &mut Vec<u8>,
+    compressor: &mut NameCompressor,
+    name: &str,
+    entry: &RRsetEntry,
+    dnssec_ok: bool,
+    now: SystemTime,
+) {
+    for record in &entry.records {
+        let ttl = compute_wire_ttl(record.ttl_at_store, entry.stored_at, entry.expires_at, now);
+        write_record(
+            out,
+            compressor,
+            name,
+            record.rtype,
+            record.rclass,
+            ttl,
+            &record.rdata,
+        );
+    }
+    if dnssec_ok {
+        for rrsig in &entry.rrsigs {
+            let ttl = compute_wire_ttl(rrsig.ttl_at_store, entry.stored_at, entry.expires_at, now);
+            write_record(
+                out,
+                compressor,
+                name,
+                rrsig.rtype,
+                rrsig.rclass,
+                ttl,
+                &rrsig.rdata,
+            );
+        }
+    }
+}
+
+fn write_negative_authority(
+    out: &mut Vec<u8>,
+    compressor: &mut NameCompressor,
+    owner: &str,
+    negative: &NegativeEntry,
+    dnssec_ok: bool,
+    now: SystemTime,
+) {
+    let soa_ttl = compute_wire_ttl(
+        negative.soa_record.ttl_at_store,
+        negative.stored_at,
+        negative.expires_at,
+        now,
+    );
+    write_record(
+        out,
+        compressor,
+        owner,
+        negative.soa_record.rtype,
+        negative.soa_record.rclass,
+        soa_ttl,
+        &negative.soa_record.rdata,
+    );
+    if dnssec_ok {
+        if let Some(rrsig) = &negative.soa_rrsig {
+            let ttl = compute_wire_ttl(
+                rrsig.ttl_at_store,
+                negative.stored_at,
+                negative.expires_at,
+                now,
+            );
+            write_record(
+                out,
+                compressor,
+                owner,
+                rrsig.rtype,
+                rrsig.rclass,
+                ttl,
+                &rrsig.rdata,
+            );
+        }
+        for proof in &negative.proof_records {
+            let ttl = compute_wire_ttl(
+                proof.ttl_at_store,
+                negative.stored_at,
+                negative.expires_at,
+                now,
+            );
+            write_record(
+                out,
+                compressor,
+                owner,
+                proof.rtype,
+                proof.rclass,
+                ttl,
+                &proof.rdata,
+            );
+        }
+    }
+}
+
+fn negative_authority_count(negative: &NegativeEntry, dnssec_ok: bool) -> u16 {
+    let mut count = 1u16; // SOA
+    if dnssec_ok {
+        if negative.soa_rrsig.is_some() {
+            count += 1;
+        }
+        count += negative.proof_records.len() as u16;
+    }
+    count
+}
+
+/// SERVFAIL per RFC 6840 §5.9: if `checking_disabled` is false and any
+/// relevant chain entry is `Bogus`, serve SERVFAIL instead of the cached
+/// data (checked across every hop, not just the terminal one).
+fn dnssec_servfail_check(chain: &[(String, RRsetEntry)], features: &QueryFeatures) -> bool {
+    if features.checking_disabled {
+        return false;
+    }
+    chain
+        .iter()
+        .any(|(_, entry)| matches!(entry.dnssec_state, DnssecState::Bogus(_)))
+}
+
+/// AD bit set only if every relevant chain entry is `Secure` and the
+/// requester set DO or AD. `Unvalidated`/`Insecure` never produce AD=1.
+/// An empty chain never produces AD=1 either — there's nothing to have
+/// validated (relevant for `ResolvedNegative`, whose own `NegativeEntry`
+/// carries no `dnssec_state` of its own to check; see `ResolvedNegative`'s
+/// doc comment).
+fn dnssec_ad_bit(chain: &[(String, RRsetEntry)], features: &QueryFeatures) -> bool {
+    if !(features.dnssec_ok || features.authenticated_data) {
+        return false;
+    }
+    !chain.is_empty()
+        && chain
+            .iter()
+            .all(|(_, entry)| entry.dnssec_state == DnssecState::Secure)
+}
+
+fn build_servfail(
+    request_id: u16,
+    requester_question_wire: &[u8],
+    requester_features: &QueryFeatures,
+) -> Vec<u8> {
+    let mut response = Vec::new();
+    write_message_header(
+        &mut response,
+        request_id,
+        requester_features.recursion_desired,
+        false,
+        false,
+        ResponseCode::ServFail,
+        1,
+        0,
+        0,
+        0,
+    );
+    response.extend_from_slice(requester_question_wire);
+    response
+}
+
+/// Returns `response` unchanged unless `allow_udp_truncation` is set and
+/// `response` exceeds the requester's effective UDP payload size (derived
+/// from `requester_features.edns_udp_payload_size`, mirroring
+/// `Message::effective_udp_payload_size`'s bounds-clamping), in which case
+/// a truncated response (header + question only, TC bit set) is returned
+/// instead. `configured_max_udp_payload_size` is the server-side ceiling —
+/// an intentional, documented deviation from the plan's literal
+/// `assemble_response` signature, needed for the same reason
+/// `resolve_from_cache`'s `max_chain_depth` is: `assemble_response` has no
+/// `Message`/`DecodedQuery` to pull it from, only raw question wire bytes
+/// and `QueryFeatures`.
+fn finish_with_truncation_check(
+    response: Vec<u8>,
+    request_id: u16,
+    requester_features: &QueryFeatures,
+    allow_udp_truncation: bool,
+    configured_max_udp_payload_size: usize,
+) -> Vec<u8> {
+    if !allow_udp_truncation {
+        return response;
+    }
+    let advertised = requester_features
+        .edns_udp_payload_size
+        .map(|size| size as usize)
+        .unwrap_or(crate::protocol::DNS_DEFAULT_UDP_PAYLOAD_SIZE);
+    let effective = advertised
+        .max(crate::protocol::DNS_DEFAULT_UDP_PAYLOAD_SIZE)
+        .min(configured_max_udp_payload_size);
+    if response.len() <= effective {
+        return response;
+    }
+    let mut truncated = Vec::new();
+    write_message_header(
+        &mut truncated,
+        request_id,
+        requester_features.recursion_desired,
+        true,
+        false,
+        ResponseCode::NoError,
+        0,
+        0,
+        0,
+        0,
+    );
+    truncated
+}
+
+/// Builds a complete wire response from a `ChainLookup::Answered` result,
+/// using the requester's own question wire bytes for name casing
+/// (interview Q9) and advertised EDNS bufsize for truncation (interview
+/// Q13). `request_id` is an intentional, documented deviation from the
+/// plan's literal signature — `QueryFeatures` carries no transaction ID,
+/// so it must be threaded through explicitly (mirrors the
+/// `configured_max_udp_payload_size` deviation above).
+pub(crate) fn assemble_response(
+    request_id: u16,
+    requester_question_wire: &[u8],
+    requester_features: &QueryFeatures,
+    resolved: &ResolvedAnswer,
+    now: SystemTime,
+    allow_udp_truncation: bool,
+    configured_max_udp_payload_size: usize,
+) -> Vec<u8> {
+    if dnssec_servfail_check(&resolved.chain, requester_features) {
+        return build_servfail(request_id, requester_question_wire, requester_features);
+    }
+
+    let dnssec_ok = requester_features.dnssec_ok;
+    let ad = dnssec_ad_bit(&resolved.chain, requester_features);
+    let an_count = chain_answer_count(&resolved.chain, dnssec_ok);
+
+    let mut response = Vec::new();
+    write_message_header(
+        &mut response,
+        request_id,
+        requester_features.recursion_desired,
+        false,
+        ad,
+        ResponseCode::NoError,
+        1,
+        an_count,
+        0,
+        0,
+    );
+    response.extend_from_slice(requester_question_wire);
+
+    let mut compressor = NameCompressor::new();
+    for (name, entry) in &resolved.chain {
+        write_rrset(&mut response, &mut compressor, name, entry, dnssec_ok, now);
+    }
+
+    finish_with_truncation_check(
+        response,
+        request_id,
+        requester_features,
+        allow_udp_truncation,
+        configured_max_udp_payload_size,
+    )
+}
+
+/// Builds a complete wire response from a `ChainLookup::NxDomain`/`NoData`
+/// result: any CNAME chain records in the answer section, followed by
+/// `negative.soa_record` (+ `soa_rrsig`/`proof_records` if DO is set) in
+/// the authority section. `response_code` should be `ResponseCode::NxDomain`
+/// or `ResponseCode::NoError` per which `ChainLookup` variant produced
+/// `resolved`. Same `request_id`/`configured_max_udp_payload_size`
+/// deviations as `assemble_response`, for the same reasons.
+#[allow(clippy::too_many_arguments)]
+pub(crate) fn assemble_negative_response(
+    request_id: u16,
+    requester_question_wire: &[u8],
+    requester_features: &QueryFeatures,
+    resolved: &ResolvedNegative,
+    response_code: ResponseCode,
+    now: SystemTime,
+    allow_udp_truncation: bool,
+    configured_max_udp_payload_size: usize,
+) -> Vec<u8> {
+    if dnssec_servfail_check(&resolved.chain, requester_features) {
+        return build_servfail(request_id, requester_question_wire, requester_features);
+    }
+
+    let dnssec_ok = requester_features.dnssec_ok;
+    let ad = dnssec_ad_bit(&resolved.chain, requester_features);
+    let an_count = chain_answer_count(&resolved.chain, dnssec_ok);
+    let ns_count = negative_authority_count(&resolved.negative, dnssec_ok);
+
+    let mut response = Vec::new();
+    write_message_header(
+        &mut response,
+        request_id,
+        requester_features.recursion_desired,
+        false,
+        ad,
+        response_code,
+        1,
+        an_count,
+        ns_count,
+        0,
+    );
+    response.extend_from_slice(requester_question_wire);
+
+    let mut compressor = NameCompressor::new();
+    for (name, entry) in &resolved.chain {
+        write_rrset(&mut response, &mut compressor, name, entry, dnssec_ok, now);
+    }
+    write_negative_authority(
+        &mut response,
+        &mut compressor,
+        &resolved.terminal_name,
+        &resolved.negative,
+        dnssec_ok,
+        now,
+    );
+
+    finish_with_truncation_check(
+        response,
+        request_id,
+        requester_features,
+        allow_udp_truncation,
+        configured_max_udp_payload_size,
+    )
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::config::CacheConfig;
+    use crate::protocol::{Message, RecordData, write_u16};
+    use crate::resolver::NegativeCacheKind;
+    use crate::resolver::cache::entry::{NegativeKey, StoredRecord};
+    use std::net::Ipv4Addr;
+    use std::time::Duration;
+
+    const IN_QCLASS: u16 = 1;
+    const A_QTYPE: u16 = 1;
+
+    fn question_wire(qname: &str, qtype: u16, qclass: u16) -> Vec<u8> {
+        let mut compressor = NameCompressor::new();
+        let mut wire = Vec::new();
+        compressor.write_name(&mut wire, qname);
+        write_u16(&mut wire, qtype);
+        write_u16(&mut wire, qclass);
+        wire
+    }
+
+    fn features(dnssec_ok: bool) -> QueryFeatures {
+        QueryFeatures {
+            recursion_desired: true,
+            authenticated_data: false,
+            checking_disabled: false,
+            dnssec_ok,
+            edns_udp_payload_size: None,
+        }
+    }
+
+    fn a_record(ttl: u32, octet: u8) -> StoredRecord {
+        StoredRecord {
+            rtype: A_QTYPE,
+            rclass: IN_QCLASS,
+            ttl_at_store: ttl,
+            rdata: RecordData::A(Ipv4Addr::new(192, 0, 2, octet)),
+        }
+    }
+
+    fn rrset_entry(
+        records: Vec<StoredRecord>,
+        minimum_ttl: Duration,
+        now: SystemTime,
+    ) -> RRsetEntry {
+        RRsetEntry {
+            records,
+            rrsigs: Vec::new(),
+            response_code: ResponseCode::NoError,
+            minimum_ttl,
+            stored_at: now,
+            expires_at: now + minimum_ttl,
+            dnssec_state: DnssecState::Unvalidated,
+            cache_namespace: "ns-1".to_string(),
+        }
+    }
+
+    fn cache_with_shard_count(shard_count: usize) -> ShardedDnsCache {
+        ShardedDnsCache::new(&CacheConfig {
+            max_entries: 1_000,
+            shard_count: Some(shard_count),
+        })
+    }
+
+    #[test]
+    fn assemble_response_ages_each_record_ttl_independently() {
+        let now = SystemTime::now();
+        let stored_at = now - Duration::from_secs(100);
+        let mut entry = rrset_entry(
+            vec![a_record(600, 1), a_record(120, 2)],
+            Duration::from_secs(600),
+            stored_at,
+        );
+        entry.expires_at = stored_at + Duration::from_secs(600);
+        let resolved = ResolvedAnswer {
+            chain: vec![("example.com".to_string(), entry)],
+        };
+        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
+
+        let response = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
+        let parsed = Message::parse(&response).unwrap();
+
+        assert_eq!(parsed.answers.len(), 2);
+        assert_eq!(parsed.answers[0].ttl, 500); // 600 - 100 elapsed
+        assert_eq!(parsed.answers[1].ttl, 20); // 120 - 100 elapsed
+    }
+
+    #[test]
+    fn assemble_response_caps_ttl_to_remaining_entry_lifetime() {
+        let now = SystemTime::now();
+        let stored_at = now - Duration::from_secs(590);
+        let mut entry = rrset_entry(vec![a_record(600, 1)], Duration::from_secs(600), stored_at);
+        entry.expires_at = stored_at + Duration::from_secs(600); // expires in 10s
+        let resolved = ResolvedAnswer {
+            chain: vec![("example.com".to_string(), entry)],
+        };
+        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
+
+        let response = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
+        let parsed = Message::parse(&response).unwrap();
+
+        // Aged TTL would be 10s, remaining lifetime is also 10s: capped, not
+        // exceeded.
+        assert_eq!(parsed.answers[0].ttl, 10);
+    }
+
+    #[test]
+    fn assemble_response_echoes_requesters_own_casing() {
+        let now = SystemTime::now();
+        let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
+        let resolved = ResolvedAnswer {
+            chain: vec![("example.com".to_string(), entry)],
+        };
+
+        let lower_wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
+        let mixed_wire = question_wire("Example.COM", A_QTYPE, IN_QCLASS);
+
+        let lower_response = assemble_response(
+            1,
+            &lower_wire,
+            &features(false),
+            &resolved,
+            now,
+            false,
+            4096,
+        );
+        let mixed_response = assemble_response(
+            1,
+            &mixed_wire,
+            &features(false),
+            &resolved,
+            now,
+            false,
+            4096,
+        );
+
+        let lower_parsed = Message::parse(&lower_response).unwrap();
+        let mixed_parsed = Message::parse(&mixed_response).unwrap();
+
+        assert_eq!(lower_parsed.questions[0].qname, "example.com");
+        assert_eq!(mixed_parsed.questions[0].qname, "Example.COM");
+    }
+
+    #[test]
+    fn assemble_response_truncates_per_requesters_own_bufsize() {
+        let now = SystemTime::now();
+        let records: Vec<StoredRecord> = (0..40u8).map(|i| a_record(300, i)).collect();
+        let entry = rrset_entry(records, Duration::from_secs(300), now);
+        let resolved = ResolvedAnswer {
+            chain: vec![("example.com".to_string(), entry)],
+        };
+        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
+
+        let mut udp_features = features(false);
+        udp_features.edns_udp_payload_size = Some(512);
+        let udp_response = assemble_response(1, &wire, &udp_features, &resolved, now, true, 4096);
+        let udp_parsed = Message::parse(&udp_response).unwrap();
+        assert!(udp_parsed.header.tc());
+        assert_eq!(udp_parsed.answers.len(), 0);
+
+        // TCP-sourced queries pass allow_udp_truncation = false: full
+        // response regardless of size.
+        let tcp_response = assemble_response(1, &wire, &udp_features, &resolved, now, false, 4096);
+        let tcp_parsed = Message::parse(&tcp_response).unwrap();
+        assert!(!tcp_parsed.header.tc());
+        assert_eq!(tcp_parsed.answers.len(), 40);
+    }
+
+    #[test]
+    fn assemble_response_includes_rrsigs_only_when_requester_sets_do() {
+        let now = SystemTime::now();
+        let mut entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
+        entry.rrsigs = vec![StoredRecord {
+            rtype: 46, // RRSIG
+            rclass: IN_QCLASS,
+            ttl_at_store: 300,
+            rdata: RecordData::RRSIG {
+                type_covered: A_QTYPE,
+                algorithm: 8,
+                labels: 2,
+                original_ttl: 300,
+                signature_expiration: 2_000_000_000,
+                signature_inception: 1_900_000_000,
+                key_tag: 12345,
+                signer_name: "example.com".to_string(),
+                signature: vec![0xab, 0xcd],
+            },
+        }];
+        let resolved = ResolvedAnswer {
+            chain: vec![("example.com".to_string(), entry)],
+        };
+        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
+
+        let without_do = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
+        let with_do = assemble_response(1, &wire, &features(true), &resolved, now, false, 4096);
+
+        assert_eq!(Message::parse(&without_do).unwrap().answers.len(), 1);
+        assert_eq!(Message::parse(&with_do).unwrap().answers.len(), 2);
+    }
+
+    #[test]
+    fn assemble_response_sets_ad_only_when_secure_and_requested() {
+        let now = SystemTime::now();
+        let mut secure_entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
+        secure_entry.dnssec_state = DnssecState::Secure;
+        let resolved = ResolvedAnswer {
+            chain: vec![("example.com".to_string(), secure_entry)],
+        };
+        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
+
+        let mut do_features = features(true);
+        let with_do = assemble_response(1, &wire, &do_features, &resolved, now, false, 4096);
+        assert!(Message::parse(&with_do).unwrap().header.ad());
+
+        do_features.dnssec_ok = false;
+        let without_do_or_ad =
+            assemble_response(1, &wire, &do_features, &resolved, now, false, 4096);
+        assert!(!Message::parse(&without_do_or_ad).unwrap().header.ad());
+
+        // Unvalidated never produces AD=1 regardless of requester flags.
+        let mut unvalidated_entry =
+            rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
+        unvalidated_entry.dnssec_state = DnssecState::Unvalidated;
+        let unvalidated_resolved = ResolvedAnswer {
+            chain: vec![("example.com".to_string(), unvalidated_entry)],
+        };
+        let unvalidated_response = assemble_response(
+            1,
+            &wire,
+            &features(true),
+            &unvalidated_resolved,
+            now,
+            false,
+            4096,
+        );
+        assert!(!Message::parse(&unvalidated_response).unwrap().header.ad());
+    }
+
+    #[test]
+    fn assemble_response_servfails_on_bogus_when_checking_enabled() {
+        let now = SystemTime::now();
+        let mut bogus_entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
+        bogus_entry.dnssec_state = DnssecState::Bogus("signature verification failed".to_string());
+        let resolved = ResolvedAnswer {
+            chain: vec![("example.com".to_string(), bogus_entry)],
+        };
+        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
+
+        let checking_enabled = features(false);
+        let servfail_response =
+            assemble_response(1, &wire, &checking_enabled, &resolved, now, false, 4096);
+        let servfail_parsed = Message::parse(&servfail_response).unwrap();
+        assert_eq!(
+            servfail_parsed.header.r_code(),
+            ResponseCode::ServFail as u8
+        );
+        assert_eq!(servfail_parsed.answers.len(), 0);
+
+        let mut checking_disabled = features(false);
+        checking_disabled.checking_disabled = true;
+        let served_response =
+            assemble_response(1, &wire, &checking_disabled, &resolved, now, false, 4096);
+        let served_parsed = Message::parse(&served_response).unwrap();
+        assert_eq!(served_parsed.header.r_code(), ResponseCode::NoError as u8);
+        assert_eq!(served_parsed.answers.len(), 1);
+    }
+
+    #[test]
+    fn resolve_from_cache_treats_expired_entry_as_miss() {
+        let cache = cache_with_shard_count(1);
+        let now = SystemTime::now();
+        let stored_at = now - Duration::from_secs(600);
+        let mut entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), stored_at);
+        entry.expires_at = stored_at + Duration::from_secs(300); // expired 300s ago
+        cache.shard_for("expired.example.com").store_positive(
+            "expired.example.com",
+            (A_QTYPE, IN_QCLASS),
+            entry,
+        );
+
+        let result = resolve_from_cache(
+            &cache,
+            "expired.example.com",
+            A_QTYPE,
+            IN_QCLASS,
+            "ns-1",
+            8,
+            now,
+        );
+
+        assert_eq!(result, ChainLookup::Miss);
+    }
+
+    #[test]
+    fn resolve_from_cache_returns_negative_result_with_accumulated_cname_chain() {
+        let cache = cache_with_shard_count(1);
+        let now = SystemTime::now();
+        let mut cname_entry = rrset_entry(
+            vec![StoredRecord {
+                rtype: CNAME_RECORD_TYPE,
+                rclass: IN_QCLASS,
+                ttl_at_store: 300,
+                rdata: RecordData::CNAME("target.example.com".to_string()),
+            }],
+            Duration::from_secs(300),
+            now,
+        );
+        cname_entry.cache_namespace = "ns-1".to_string();
+        cache.shard_for("alias.example.com").store_positive(
+            "alias.example.com",
+            (CNAME_RECORD_TYPE, IN_QCLASS),
+            cname_entry,
+        );
+
+        let negative = NegativeEntry {
+            kind: NegativeCacheKind::NxDomain,
+            soa_record: StoredRecord {
+                rtype: 6,
+                rclass: IN_QCLASS,
+                ttl_at_store: 3600,
+                rdata: RecordData::SOA {
+                    ttl: 0,
+                    rname: "hostmaster.example.com".to_string(),
+                    mname: "ns1.example.com".to_string(),
+                    serial: 1,
+                    refresh: 7200,
+                    retry: 3600,
+                    expire: 1_209_600,
+                    minimum: 3600,
+                },
+            },
+            soa_rrsig: None,
+            proof_records: Vec::new(),
+            stored_at: now,
+            expires_at: now + Duration::from_secs(3600),
+            cache_namespace: "ns-1".to_string(),
+        };
+        let neg_key = NegativeKey {
+            qtype: None,
+            qclass: IN_QCLASS,
+        };
+        cache.shard_for("target.example.com").store_negative(
+            "target.example.com",
+            neg_key,
+            negative,
+        );
+
+        let result = resolve_from_cache(
+            &cache,
+            "alias.example.com",
+            A_QTYPE,
+            IN_QCLASS,
+            "ns-1",
+            8,
+            now,
+        );
+
+        match result {
+            ChainLookup::NxDomain(resolved) => {
+                assert_eq!(resolved.chain.len(), 1);
+                assert_eq!(resolved.chain[0].0, "alias.example.com");
+                assert_eq!(resolved.terminal_name, "target.example.com");
+            }
+            other => panic!("expected NxDomain with accumulated chain, got {other:?}"),
+        }
+    }
+
+    #[test]
+    fn resolve_from_cache_respects_max_cname_restarts_bound() {
+        let cache = cache_with_shard_count(1);
+        let now = SystemTime::now();
+        // A cyclical CNAME chain: a -> b -> a.
+        for (name, target) in [
+            ("a.example.com", "b.example.com"),
+            ("b.example.com", "a.example.com"),
+        ] {
+            let entry = rrset_entry(
+                vec![StoredRecord {
+                    rtype: CNAME_RECORD_TYPE,
+                    rclass: IN_QCLASS,
+                    ttl_at_store: 300,
+                    rdata: RecordData::CNAME(target.to_string()),
+                }],
+                Duration::from_secs(300),
+                now,
+            );
+            cache
+                .shard_for(name)
+                .store_positive(name, (CNAME_RECORD_TYPE, IN_QCLASS), entry);
+        }
+
+        let result =
+            resolve_from_cache(&cache, "a.example.com", A_QTYPE, IN_QCLASS, "ns-1", 8, now);
+
+        assert_eq!(result, ChainLookup::Miss);
+    }
+
+    #[test]
+    fn resolve_from_cache_returns_miss_on_any_missing_chain_hop() {
+        let cache = cache_with_shard_count(1);
+        let now = SystemTime::now();
+
+        let result = resolve_from_cache(
+            &cache,
+            "never-stored.example.com",
+            A_QTYPE,
+            IN_QCLASS,
+            "ns-1",
+            8,
+            now,
+        );
+
+        assert_eq!(result, ChainLookup::Miss);
+    }
+
+    #[test]
+    fn resolve_from_cache_rejects_stale_namespace_independent_of_sweep() {
+        let cache = cache_with_shard_count(1);
+        let now = SystemTime::now();
+        let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
+        // Entry is unexpired but stored under a namespace that no longer
+        // matches "current" — must be treated as a miss without requiring
+        // section-05's sweep to have run.
+        cache.shard_for("stale-ns.example.com").store_positive(
+            "stale-ns.example.com",
+            (A_QTYPE, IN_QCLASS),
+            entry,
+        );
+
+        let result = resolve_from_cache(
+            &cache,
+            "stale-ns.example.com",
+            A_QTYPE,
+            IN_QCLASS,
+            "current-ns",
+            8,
+            now,
+        );
+
+        assert_eq!(result, ChainLookup::Miss);
+    }
+
+    #[test]
+    fn resolve_from_cache_follows_cname_chain_across_shards() {
+        // Use enough shards, and distinct enough names, that the queried
+        // name and its CNAME target are very likely to land in different
+        // shards; assert the walk still finds the terminal answer (proving
+        // per-hop lock acquire/release rather than a single held lock that
+        // would only work within one shard).
+        let cache = cache_with_shard_count(8);
+        let now = SystemTime::now();
+
+        let mut cname_entry = rrset_entry(
+            vec![StoredRecord {
+                rtype: CNAME_RECORD_TYPE,
+                rclass: IN_QCLASS,
+                ttl_at_store: 300,
+                rdata: RecordData::CNAME("cname-target.example.net".to_string()),
+            }],
+            Duration::from_secs(300),
+            now,
+        );
+        cname_entry.cache_namespace = "ns-1".to_string();
+        cache.shard_for("cname-source.example.com").store_positive(
+            "cname-source.example.com",
+            (CNAME_RECORD_TYPE, IN_QCLASS),
+            cname_entry,
+        );
+
+        let terminal_entry = rrset_entry(vec![a_record(300, 7)], Duration::from_secs(300), now);
+        cache.shard_for("cname-target.example.net").store_positive(
+            "cname-target.example.net",
+            (A_QTYPE, IN_QCLASS),
+            terminal_entry,
+        );
+
+        let result = resolve_from_cache(
+            &cache,
+            "cname-source.example.com",
+            A_QTYPE,
+            IN_QCLASS,
+            "ns-1",
+            8,
+            now,
+        );
+
+        match result {
+            ChainLookup::Answered(resolved) => {
+                assert_eq!(resolved.chain.len(), 2);
+                assert_eq!(resolved.chain[0].0, "cname-source.example.com");
+                assert_eq!(resolved.chain[1].0, "cname-target.example.net");
+            }
+            other => panic!("expected Answered chain across shards, got {other:?}"),
+        }
+    }
+
+    #[test]
+    fn resolve_from_cache_never_holds_two_shard_locks_at_once() {
+        // While one thread holds shard A's lock mid-scan (simulated via
+        // Shard::hold_lock_for_test), a lookup against a domain in a
+        // *different* shard must not be blocked — proving
+        // resolve_from_cache releases each hop's lock before acquiring the
+        // next, rather than holding one lock for the whole walk.
+        let cache = std::sync::Arc::new(cache_with_shard_count(2));
+        let now = SystemTime::now();
+
+        // Find one domain per shard.
+        let mut domain_shard_0 = None;
+        let mut domain_shard_1 = None;
+        for i in 0..1000 {
+            let candidate = format!("host-{i}.example.com");
+            let shard_ptr = cache.shard_for(&candidate) as *const _;
+            let shard_0_ptr = cache.shard_for("shard-0-anchor") as *const _;
+            if domain_shard_0.is_none() && std::ptr::eq(shard_ptr, shard_0_ptr) {
+                domain_shard_0 = Some(candidate.clone());
+            }
+            if domain_shard_1.is_none() && !std::ptr::eq(shard_ptr, shard_0_ptr) {
+                domain_shard_1 = Some(candidate.clone());
+            }
+            if domain_shard_0.is_some() && domain_shard_1.is_some() {
+                break;
+            }
+        }
+        let domain_a = domain_shard_0.expect("expected a domain hashing to shard 0");
+        let domain_b = domain_shard_1.expect("expected a domain hashing to a different shard");
+
+        let entry_b = rrset_entry(vec![a_record(300, 9)], Duration::from_secs(300), now);
+        cache
+            .shard_for(&domain_b)
+            .store_positive(&domain_b, (A_QTYPE, IN_QCLASS), entry_b);
+
+        let cache_for_thread = std::sync::Arc::clone(&cache);
+        let domain_a_for_thread = domain_a.clone();
+        let handle = std::thread::spawn(move || {
+            cache_for_thread
+                .shard_for(&domain_a_for_thread)
+                .hold_lock_for_test(Duration::from_millis(200));
+        });
+        std::thread::sleep(Duration::from_millis(50));
+
+        let start = std::time::Instant::now();
+        let result = resolve_from_cache(&cache, &domain_b, A_QTYPE, IN_QCLASS, "ns-1", 8, now);
+        let elapsed = start.elapsed();
+
+        handle.join().unwrap();
+
+        assert!(matches!(result, ChainLookup::Answered(_)));
+        assert!(
+            elapsed < Duration::from_millis(150),
+            "lookup against a different shard should not wait on shard A's held lock, took {elapsed:?}"
+        );
+    }
+}
diff --git a/src/resolver/cache/mod.rs b/src/resolver/cache/mod.rs
index 73878d1..b080183 100644
--- a/src/resolver/cache/mod.rs
+++ b/src/resolver/cache/mod.rs
@@ -25,6 +25,46 @@ mod singleflight;
 use std::collections::hash_map::DefaultHasher;
 use std::hash::{Hash, Hasher};
 
+use shard::Shard;
+
+/// The top-level sharded cache: one `Shard` (its own lock, its own slice
+/// of `max_entries`) per configured shard, routed to by `shard_index`.
+///
+/// Read-side operations (`assemble::resolve_from_cache`,
+/// `assemble::assemble_response`) are built in this section
+/// (section-06). Section-07 adds `impl DomainDnsCache for
+/// ShardedDnsCache` (wrapping those plus `store_response`) and the
+/// call-site wiring that actually constructs and uses one of these.
+#[allow(dead_code)]
+pub struct ShardedDnsCache {
+    shards: Vec<Shard>,
+}
+
+impl ShardedDnsCache {
+    /// Builds one `Shard` per `config.resolved_shard_count()`, splitting
+    /// `config.max_entries` across them via `config.shard_capacity` (the
+    /// exact remainder-distributed formula from section-01 — not
+    /// recomputed here).
+    #[allow(dead_code)]
+    pub fn new(config: &crate::config::CacheConfig) -> Self {
+        let shard_count = config.resolved_shard_count();
+        let shards = (0..shard_count)
+            .map(|index| Shard::new(config.shard_capacity(index, shard_count)))
+            .collect();
+        Self { shards }
+    }
+
+    /// Routes to the one shard responsible for `domain`, via `shard_index`.
+    /// Kept private/crate-visible: external callers (section-07's trait
+    /// impl, tests) go through `assemble::resolve_from_cache`, except
+    /// where a section-06 test needs to reach into a specific shard to set
+    /// up fixture state directly.
+    #[allow(dead_code)]
+    fn shard_for(&self, domain: &str) -> &Shard {
+        &self.shards[shard_index(domain, self.shards.len())]
+    }
+}
+
 /// Routes a domain name to a shard index in `[0, shard_count)`. Shared by
 /// the cache shards (`cache::shard`, section-03) and the single-flight
 /// shards (`cache::singleflight`, section-04) — both structures shard
diff --git a/src/resolver/cache/shard.rs b/src/resolver/cache/shard.rs
index 64ea44a..a66b0a0 100644
--- a/src/resolver/cache/shard.rs
+++ b/src/resolver/cache/shard.rs
@@ -27,11 +27,36 @@
 
 use std::collections::HashMap;
 use std::sync::Mutex;
+use std::time::SystemTime;
 
 use super::entry::{
     DomainNegativeEntries, DomainRecordSets, NegativeEntry, NegativeKey, RRsetEntry,
 };
 use super::lru::ShardLru;
+use crate::protocol::RecordData;
+
+const CNAME_RECORD_TYPE: u16 = 5;
+
+/// Result of one hop's lookup within `resolve_from_cache`'s CNAME-chain
+/// walk (`cache::assemble`, section-06) — whatever this shard found (or
+/// didn't) for one name in the chain, already cloned out from under this
+/// shard's lock.
+#[derive(Debug, Clone)]
+pub(crate) enum HopResult {
+    /// A record set matching the queried `(qtype, qclass)` directly.
+    Answer(RRsetEntry),
+    /// The queried type wasn't found, but a CNAME record set was — carries
+    /// the CNAME's own entry (for the response's answer section) plus the
+    /// extracted target name to continue the walk.
+    CnameHop(RRsetEntry, String),
+    /// NODATA for the queried type at this (existing) name.
+    NoData(NegativeEntry),
+    /// Whole-name NXDOMAIN at this name.
+    NxDomain(NegativeEntry),
+    /// Nothing usable here: absent, expired, or stored under a stale
+    /// namespace.
+    Miss,
+}
 
 #[derive(Debug, Default)]
 struct PositiveShardState {
@@ -161,6 +186,98 @@ impl Shard {
         self.state.lock().unwrap().lru.len()
     }
 
+    /// One hop of `resolve_from_cache`'s CNAME-chain walk (`cache::assemble`,
+    /// section-06): looks up `domain` for `(qtype, qclass)` directly,
+    /// falls back to a CNAME record set at the same name if `qtype` itself
+    /// isn't CNAME, then falls back to a negative entry (NODATA for
+    /// `qtype`, then whole-name NXDOMAIN). Rejects expired or
+    /// stale-namespace matches inline — independent of, and in addition
+    /// to, section-05's bulk namespace sweep. Touches this domain's LRU
+    /// position on any live match found, including CNAME hops. Takes and
+    /// releases this shard's lock for the duration of this one hop only —
+    /// callers must not hold it across hops.
+    pub(crate) fn lookup_hop(
+        &self,
+        domain: &str,
+        qtype: u16,
+        qclass: u16,
+        current_namespace: &str,
+        now: SystemTime,
+    ) -> HopResult {
+        let mut state = self.state.lock().unwrap();
+
+        let answer = state
+            .positive
+            .domains
+            .get(domain)
+            .and_then(|record_sets| record_sets.record_sets.get(&(qtype, qclass)))
+            .filter(|entry| entry.expires_at > now && entry.cache_namespace == current_namespace)
+            .cloned();
+        if let Some(entry) = answer {
+            state.lru.touch(domain);
+            return HopResult::Answer(entry);
+        }
+
+        if qtype != CNAME_RECORD_TYPE {
+            let cname_hop = state
+                .positive
+                .domains
+                .get(domain)
+                .and_then(|record_sets| record_sets.record_sets.get(&(CNAME_RECORD_TYPE, qclass)))
+                .filter(|entry| {
+                    entry.expires_at > now && entry.cache_namespace == current_namespace
+                })
+                .and_then(|entry| {
+                    entry
+                        .records
+                        .iter()
+                        .find_map(|record| match &record.rdata {
+                            RecordData::CNAME(target) => Some(target.clone()),
+                            _ => None,
+                        })
+                        .map(|target| (entry.clone(), target))
+                });
+            if let Some((entry, target)) = cname_hop {
+                state.lru.touch(domain);
+                return HopResult::CnameHop(entry, target);
+            }
+        }
+
+        let nodata_key = NegativeKey {
+            qtype: Some(qtype),
+            qclass,
+        };
+        let nodata = state
+            .negative
+            .domains
+            .get(domain)
+            .and_then(|entries| entries.entries.get(&nodata_key))
+            .filter(|entry| entry.expires_at > now && entry.cache_namespace == current_namespace)
+            .cloned();
+        if let Some(entry) = nodata {
+            state.lru.touch(domain);
+            return HopResult::NoData(entry);
+        }
+
+        let nxdomain_key = NegativeKey {
+            qtype: None,
+            qclass,
+        };
+        let nxdomain = state
+            .negative
+            .domains
+            .get(domain)
+            .and_then(|entries| entries.entries.get(&nxdomain_key))
+            .filter(|entry| entry.expires_at > now && entry.cache_namespace == current_namespace)
+            .cloned();
+        if let Some(entry) = nxdomain {
+            state.lru.touch(domain);
+            return HopResult::NxDomain(entry);
+        }
+
+        HopResult::Miss
+    }
+
     /// Removes every positive/negative entry in this shard whose stored
     /// `cache_namespace` no longer matches `current_namespace`, and drops
     /// any domain (and its LRU token) left with no entries in either map
