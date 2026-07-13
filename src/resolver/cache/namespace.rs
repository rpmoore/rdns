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

//! Epoch sweep: the one deliberate O(n) operation in the cache design
//! (n = total cached entries, not domains), run once after a reload
//! publishes a new `cache_epoch`. Every other cache operation is
//! O(log n) or better per shard. `ResolveQuery::publish_reload` calls
//! this (via `DomainDnsCache::sweep_stale_namespace` on
//! `ShardedDnsCache`, `src/resolver/cache/mod.rs`) after releasing
//! `reload_gate`, only when the epoch actually changed.

use super::shard::Shard;

/// Walks every shard and removes any entry whose stored `cache_epoch`
/// no longer matches `current_epoch`, dropping any domain left with no
/// remaining entries in either map (and its LRU token along with it). Each
/// shard's lock is held only for the duration of that shard's own scan —
/// never a lock shared across shards, so concurrent lookups against
/// already-swept or not-yet-swept shards proceed normally throughout.
///
/// Takes `shards` directly rather than the `ShardedDnsCache` container so
/// this stays testable against hand-constructed shard state without
/// building a full cache. `ShardedDnsCache::sweep_stale_namespace`
/// (`src/resolver/cache/mod.rs`) is the only production caller, passing
/// its own `self.shards`.
///
/// Returns the total number of entries removed across all shards, used
/// directly in the tests below and available to callers for logging/metrics.
pub(crate) fn sweep_stale_namespace(shards: &[Shard], current_epoch: u64) -> usize {
    shards
        .iter()
        .map(|shard| shard.sweep_stale_namespace(current_epoch))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{RecordData, ResponseCode};
    use crate::resolver::NegativeCacheKind;
    use crate::resolver::cache::entry::{NegativeEntry, NegativeKey, RRsetEntry, StoredRecord};
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant, SystemTime};

    const IN_QCLASS: u16 = 1;
    const A_QTYPE: u16 = 1;
    const AAAA_QTYPE: u16 = 28;

    fn stored_record() -> StoredRecord {
        StoredRecord {
            rtype: A_QTYPE,
            rclass: IN_QCLASS,
            ttl_at_store: 300,
            rdata: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }
    }

    fn rrset_entry(epoch: u64) -> RRsetEntry {
        let now = SystemTime::now();
        RRsetEntry {
            records: vec![stored_record()],
            rrsigs: Vec::new(),
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(300),
            stored_at: now,
            expires_at: now + Duration::from_secs(300),
            dnssec_state: Default::default(),
            cache_epoch: epoch,
            dnssec_complete: true,
            authoritative: false,
        }
    }

    fn negative_entry(epoch: u64) -> NegativeEntry {
        let now = SystemTime::now();
        NegativeEntry {
            kind: NegativeCacheKind::NxDomain,
            soa_owner: "example.com".to_string(),
            soa_record: stored_record(),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_epoch: epoch,
            dnssec_complete: true,
            dnssec_state: Default::default(),
            authoritative: false,
        }
    }

    #[test]
    fn sweep_removes_only_entries_from_stale_epoch() {
        let shard = Shard::new(4);
        shard.store_positive("stale.example.com", (A_QTYPE, IN_QCLASS), rrset_entry(0));
        shard.store_positive("current.example.com", (A_QTYPE, IN_QCLASS), rrset_entry(1));
        shard.store_positive(
            "also-current.example.com",
            (A_QTYPE, IN_QCLASS),
            rrset_entry(1),
        );
        let before = shard.lru_order_for_test();

        let removed = sweep_stale_namespace(std::slice::from_ref(&shard), 1);

        assert_eq!(removed, 1);
        assert!(!shard.has_any_data("stale.example.com"));
        assert!(shard.has_any_data("current.example.com"));
        assert!(shard.contains_positive("current.example.com", (A_QTYPE, IN_QCLASS)));
        let after = shard.lru_order_for_test();
        assert_eq!(
            before[1..],
            after[..],
            "surviving domains' relative LRU order must be unchanged by the sweep"
        );
    }

    #[test]
    fn sweep_removes_domain_entirely_when_all_its_record_sets_are_stale() {
        let shard = Shard::new(4);
        let domain = "fully-stale.example.com";
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry(0));
        shard.store_positive(domain, (AAAA_QTYPE, IN_QCLASS), rrset_entry(0));
        let neg_key = NegativeKey {
            qtype: Some(15),
            qclass: IN_QCLASS,
        };
        shard.store_negative(domain, neg_key.clone(), negative_entry(0));

        let removed = sweep_stale_namespace(std::slice::from_ref(&shard), 1);

        assert_eq!(removed, 3);
        assert!(!shard.has_any_data(domain));
        assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
        assert!(!shard.contains_positive(domain, (AAAA_QTYPE, IN_QCLASS)));
        assert!(!shard.contains_negative(domain, &neg_key));
        assert_eq!(shard.domain_count(), 0);
    }

    #[test]
    fn sweep_keeps_domain_partially_when_some_record_sets_are_current() {
        let shard = Shard::new(4);
        let domain = "mixed.example.com";
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry(0));
        shard.store_positive(domain, (AAAA_QTYPE, IN_QCLASS), rrset_entry(1));
        shard.store_positive("other.example.com", (A_QTYPE, IN_QCLASS), rrset_entry(1));
        let before = shard.lru_order_for_test();

        let removed = sweep_stale_namespace(std::slice::from_ref(&shard), 1);

        assert_eq!(removed, 1);
        assert!(shard.has_any_data(domain));
        assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
        assert!(shard.contains_positive(domain, (AAAA_QTYPE, IN_QCLASS)));
        assert_eq!(shard.domain_count(), 2);
        assert_eq!(
            before,
            shard.lru_order_for_test(),
            "a domain that keeps any surviving entry must not have its LRU position altered by the sweep"
        );
    }

    #[test]
    fn sweep_stale_epoch_walks_every_shard_in_the_slice() {
        let shard_a = Shard::new(4);
        let shard_b = Shard::new(4);
        let shard_c = Shard::new(4);
        shard_a.store_positive("a.example.com", (A_QTYPE, IN_QCLASS), rrset_entry(0));
        shard_b.store_positive("b.example.com", (A_QTYPE, IN_QCLASS), rrset_entry(0));
        shard_c.store_positive("c.example.com", (A_QTYPE, IN_QCLASS), rrset_entry(1));
        let shards = vec![shard_a, shard_b, shard_c];

        let removed = sweep_stale_namespace(&shards, 1);

        assert_eq!(
            removed, 2,
            "stale entries in every shard in the slice must be swept, not just the first"
        );
        assert!(!shards[0].has_any_data("a.example.com"));
        assert!(!shards[1].has_any_data("b.example.com"));
        assert!(shards[2].has_any_data("c.example.com"));
    }

    #[test]
    fn sweep_removes_domain_with_only_stale_negative_entry() {
        let shard = Shard::new(4);
        let domain = "nxdomain-only.example.com";
        let neg_key = NegativeKey {
            qtype: None,
            qclass: IN_QCLASS,
        };
        shard.store_negative(domain, neg_key.clone(), negative_entry(0));

        let removed = sweep_stale_namespace(std::slice::from_ref(&shard), 1);

        assert_eq!(removed, 1);
        assert!(!shard.has_any_data(domain));
        assert!(!shard.contains_negative(domain, &neg_key));
        assert_eq!(shard.domain_count(), 0);
    }

    #[test]
    fn sweep_across_shards_does_not_require_a_shared_lock() {
        let shard_a = Shard::new(4);
        let shard_b = Shard::new(4);
        shard_a.store_positive("a.example.com", (A_QTYPE, IN_QCLASS), rrset_entry(0));
        shard_b.store_positive("b.example.com", (A_QTYPE, IN_QCLASS), rrset_entry(1));

        // Hold shard A's lock in a background thread for well longer than
        // sweeping shard B alone should ever take, then assert sweeping
        // shard B was not blocked by it.
        let handle = std::thread::spawn(move || {
            shard_a.hold_lock_for_test(Duration::from_millis(200));
        });
        std::thread::sleep(Duration::from_millis(50));

        let start = Instant::now();
        let removed = sweep_stale_namespace(std::slice::from_ref(&shard_b), 1);
        let elapsed = start.elapsed();

        handle.join().unwrap();

        assert_eq!(removed, 0);
        assert!(
            elapsed < Duration::from_millis(150),
            "sweeping shard B should not wait on shard A's held lock, took {elapsed:?}"
        );
    }
}
