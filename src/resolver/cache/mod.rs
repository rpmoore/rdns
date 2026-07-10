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

//! Sharded answer-cache implementation. See `docs/plans/cache_rework/` for
//! the design this module is built from.

mod assemble;
mod entry;
mod lru;
mod namespace;
mod shard;
mod singleflight;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Routes a domain name to a shard index in `[0, shard_count)`. Shared by
/// the cache shards (`cache::shard`, section-03) and the single-flight
/// shards (`cache::singleflight`, section-04) — both structures shard
/// purely by domain name, so a single hashing implementation keeps their
/// routing behavior identical and avoids duplicated hashing logic.
///
/// `domain` is expected to already be normalized (lowercased, trailing dot
/// stripped — the same normalization `normalize_question_name` applies in
/// `resolver::mod`) by the caller; this function does not normalize
/// internally, so two differently-cased spellings of the same domain will
/// only route to the same shard if the caller normalizes first. Every call
/// site added in later sections normalizes before calling this.
///
/// `shard_count` is expected to be at least 1 in real use (see
/// `CacheConfig::resolved_shard_count`); `shard_count == 0` is handled
/// defensively (returns 0) rather than panicking, since this is a cheap
/// routing function, not a place to enforce config invariants.
#[allow(dead_code)]
pub(crate) fn shard_index(domain: &str, shard_count: usize) -> usize {
    if shard_count == 0 {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    domain.hash(&mut hasher);
    (hasher.finish() % shard_count as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn shard_index_is_deterministic_for_same_input() {
        let first = shard_index("example.com", 16);
        let second = shard_index("example.com", 16);
        assert_eq!(first, second);
    }

    #[test]
    fn shard_index_stays_within_bounds() {
        let domains = [
            "example.com",
            "a.example.com",
            "www.example.org",
            "sub.domain.example.net",
            "localhost",
        ];
        for shard_count in [1usize, 2, 8, 17] {
            for domain in domains {
                let index = shard_index(domain, shard_count);
                assert!(
                    index < shard_count,
                    "index {index} out of bounds for shard_count {shard_count} (domain {domain})"
                );
            }
        }
    }

    #[test]
    fn shard_index_distributes_distinct_domains_across_shards() {
        let shard_count = 16;
        let mut seen = HashSet::new();
        for i in 0..200 {
            let domain = format!("host-{i}.example.com");
            seen.insert(shard_index(&domain, shard_count));
        }
        assert!(
            seen.len() > 1,
            "expected distinct domains to spread across more than one shard"
        );
    }

    #[test]
    fn shard_index_returns_zero_for_zero_shard_count() {
        assert_eq!(shard_index("example.com", 0), 0);
    }
}
