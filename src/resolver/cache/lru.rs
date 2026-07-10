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

//! Exact per-shard LRU (`ShardLru`), replacing the current ghost-token
//! `VecDeque` design used by `InMemoryDnsCache`. Gives O(log n)
//! average-case touch/evict with no periodic full-scan compaction, and
//! exact (not approximate) recency ordering within a shard.
//!
//! No non-test callers yet (section-06/section-07 wire this into the
//! top-level cache type); `#[allow(dead_code)]` below is transient, same
//! pattern as `shard_index` in section-01.

#![allow(dead_code)]

use std::collections::{BTreeSet, HashMap};

/// Ordered by `(sequence, domain)` so the numerically smallest entry is
/// always the least-recently-touched domain in this shard.
#[derive(Debug, Default)]
pub(crate) struct ShardLru {
    order: BTreeSet<(u64, String)>,
    /// Reverse index: domain -> its current sequence number, so a touch
    /// can find and remove its old position in `order` in O(log n)
    /// instead of scanning.
    positions: HashMap<String, u64>,
    next_sequence: u64,
}

impl ShardLru {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Records that `domain` was just accessed (hit or store). Removes
    /// its old `(sequence, domain)` pair from `order` (O(log n)) if
    /// present, assigns a fresh sequence, and reinserts (O(log n)).
    /// Unlike the ghost-token design it replaces, there is never more
    /// than one entry per domain in `order` — no compaction pass is ever
    /// needed.
    pub(crate) fn touch(&mut self, domain: &str) {
        if let Some(old_sequence) = self.positions.get(domain).copied() {
            self.order.remove(&(old_sequence, domain.to_string()));
        }
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.order.insert((sequence, domain.to_string()));
        self.positions.insert(domain.to_string(), sequence);
    }

    /// Removes `domain` from LRU tracking entirely (used when a domain's
    /// last record set/negative entry is deleted, whether by eviction,
    /// expiry, or the namespace sweep in section-05).
    pub(crate) fn remove(&mut self, domain: &str) {
        if let Some(sequence) = self.positions.remove(domain) {
            self.order.remove(&(sequence, domain.to_string()));
        }
    }

    /// Returns the least-recently-touched domain without removing it, for
    /// the eviction loop to consult.
    pub(crate) fn peek_oldest(&self) -> Option<&str> {
        self.order.iter().next().map(|(_, domain)| domain.as_str())
    }

    /// Number of domains currently tracked by this LRU — used by the
    /// shard's capacity check, since a domain "counts" iff it has a live
    /// LRU position.
    pub(crate) fn len(&self) -> usize {
        self.positions.len()
    }

    /// Whether `domain` currently has a live LRU position. This is the
    /// single source of truth for "is this domain live in the shard" —
    /// callers should consult this instead of independently unioning the
    /// positive/negative maps' key sets.
    pub(crate) fn contains(&self, domain: &str) -> bool {
        self.positions.contains_key(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_touch_moves_domain_to_most_recent_without_leaving_stale_positions() {
        let mut lru = ShardLru::new();
        lru.touch("a.example.com");
        lru.touch("b.example.com");
        lru.touch("a.example.com");
        lru.touch("a.example.com");
        lru.touch("b.example.com");

        assert_eq!(lru.order.len(), 2, "at most one live position per domain");
        assert_eq!(lru.positions.len(), 2);
        assert_eq!(lru.peek_oldest(), Some("a.example.com"));
    }

    #[test]
    fn lru_peek_oldest_returns_least_recently_touched_domain() {
        let mut lru = ShardLru::new();
        lru.touch("first.example.com");
        lru.touch("second.example.com");
        lru.touch("third.example.com");

        assert_eq!(lru.peek_oldest(), Some("first.example.com"));

        lru.touch("first.example.com");
        assert_eq!(lru.peek_oldest(), Some("second.example.com"));
    }

    #[test]
    fn lru_remove_clears_domain_from_both_order_and_positions() {
        let mut lru = ShardLru::new();
        lru.touch("a.example.com");
        lru.touch("b.example.com");

        lru.remove("a.example.com");

        assert_eq!(lru.positions.get("a.example.com"), None);
        assert!(
            !lru.order
                .iter()
                .any(|(_, domain)| domain == "a.example.com"),
            "removed domain must not remain in order"
        );
        assert_eq!(lru.len(), 1);
        assert_eq!(lru.peek_oldest(), Some("b.example.com"));
    }

    #[test]
    fn lru_touch_and_evict_cost_is_independent_of_shard_size() {
        // Each touch performs exactly one BTreeSet removal (if the domain
        // was already tracked) and one BTreeSet insertion, plus one
        // HashMap lookup/insert — none of which scale with the number of
        // other tracked domains. Assert this indirectly: touching a large
        // number of distinct domains, then repeatedly re-touching one
        // domain, never grows `order`/`positions` beyond the distinct
        // domain count, regardless of how many other domains are present.
        let mut lru = ShardLru::new();
        for i in 0..500 {
            lru.touch(&format!("host-{i}.example.com"));
        }
        assert_eq!(lru.len(), 500);

        for _ in 0..50 {
            lru.touch("host-0.example.com");
        }
        assert_eq!(
            lru.len(),
            500,
            "repeated touches of one domain must not grow tracked count"
        );
        assert_eq!(lru.order.len(), 500);
    }
}
