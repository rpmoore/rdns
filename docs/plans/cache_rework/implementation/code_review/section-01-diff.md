diff --git a/src/config/mod.rs b/src/config/mod.rs
index b2868de..381b448 100644
--- a/src/config/mod.rs
+++ b/src/config/mod.rs
@@ -285,6 +285,65 @@ fn default_metrics_listen_addr() -> SocketAddr {
     SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090)
 }
 
+/// Configuration for the sharded answer cache (`resolver::cache`).
+///
+/// Capacity is counted in domains, not individual cached record sets — a
+/// domain with multiple cached qtypes still occupies one slot.
+#[derive(Debug, Clone, Copy, PartialEq, Eq)]
+pub struct CacheConfig {
+    /// Total domain-count capacity across the whole cache. Replaces the
+    /// `main.rs` `DEFAULT_CACHE_ENTRIES` constant. Default: 10_000,
+    /// preserving today's behavior for anyone not setting this explicitly.
+    pub max_entries: usize,
+    /// Number of shards. `None` means "pick a sensible default" — a power
+    /// of two near `available_parallelism()`, following the
+    /// DashMap/RocksDB convention of roughly 4x parallelism.
+    pub shard_count: Option<usize>,
+}
+
+impl CacheConfig {
+    /// Returns the configured shard count, or a computed default when
+    /// unset: `available_parallelism() * 4`, rounded up to the next power
+    /// of two. Falls back to a parallelism of `1` if the platform can't
+    /// report it.
+    pub fn resolved_shard_count(&self) -> usize {
+        match self.shard_count {
+            Some(count) => count,
+            None => {
+                let parallelism = std::thread::available_parallelism()
+                    .map(|n| n.get())
+                    .unwrap_or(1);
+                (parallelism * 4).next_power_of_two()
+            }
+        }
+    }
+
+    /// Returns the capacity assigned to shard `index` out of `shard_count`
+    /// total shards, given this config's `max_entries`. Per-shard
+    /// capacities sum exactly to `max_entries`: each shard gets
+    /// `max_entries / shard_count`, plus one extra for the first
+    /// `max_entries % shard_count` shards, so the remainder is distributed
+    /// rather than rounded up per-shard (which would overshoot the
+    /// configured total).
+    pub fn shard_capacity(&self, index: usize, shard_count: usize) -> usize {
+        if shard_count == 0 {
+            return 0;
+        }
+        let base = self.max_entries / shard_count;
+        let remainder = self.max_entries % shard_count;
+        if index < remainder { base + 1 } else { base }
+    }
+}
+
+impl Default for CacheConfig {
+    fn default() -> Self {
+        Self {
+            max_entries: 10_000,
+            shard_count: None,
+        }
+    }
+}
+
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct ResolutionConfig {
     pub mode: ResolutionMode,
@@ -3134,4 +3193,63 @@ a.root-servers.net.      3600000      Aaaa  2001:503:ba3e::2:30
             }
         ));
     }
+
+    #[test]
+    fn cache_config_defaults_preserve_current_max_entries() {
+        assert_eq!(CacheConfig::default().max_entries, 10_000);
+    }
+
+    #[test]
+    fn cache_config_shard_capacity_sums_exactly_to_max_entries() {
+        let cases: &[(usize, usize)] = &[(10, 8), (10_000, 16), (1, 4), (0, 8), (7, 1), (100, 3)];
+        for &(max_entries, shard_count) in cases {
+            let config = CacheConfig {
+                max_entries,
+                shard_count: Some(shard_count),
+            };
+            let total: usize = (0..shard_count)
+                .map(|index| config.shard_capacity(index, shard_count))
+                .sum();
+            assert_eq!(
+                total, max_entries,
+                "max_entries={max_entries} shard_count={shard_count}"
+            );
+        }
+    }
+
+    #[test]
+    fn cache_config_zero_max_entries_gives_every_shard_zero_capacity() {
+        let config = CacheConfig {
+            max_entries: 0,
+            shard_count: Some(8),
+        };
+        for index in 0..8 {
+            assert_eq!(config.shard_capacity(index, 8), 0);
+        }
+    }
+
+    #[test]
+    fn cache_config_shard_count_defaults_to_power_of_two_near_parallelism() {
+        let config = CacheConfig {
+            max_entries: 10_000,
+            shard_count: None,
+        };
+        let resolved = config.resolved_shard_count();
+        assert!(
+            resolved.is_power_of_two(),
+            "resolved shard count {resolved} should be a power of two"
+        );
+
+        let parallelism = std::thread::available_parallelism()
+            .map(|n| n.get())
+            .unwrap_or(1);
+        assert!(
+            resolved >= parallelism,
+            "resolved={resolved} parallelism={parallelism}"
+        );
+        assert!(
+            resolved <= parallelism * 8,
+            "resolved={resolved} parallelism={parallelism}"
+        );
+    }
 }
diff --git a/src/resolver/cache/assemble.rs b/src/resolver/cache/assemble.rs
new file mode 100644
index 0000000..dda7963
--- /dev/null
+++ b/src/resolver/cache/assemble.rs
@@ -0,0 +1,16 @@
+// Copyright 2026 Ryan Moore
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! `assemble_response`, `resolve_from_cache`, `ChainLookup` — filled in by
+//! section-06.
diff --git a/src/resolver/cache/entry.rs b/src/resolver/cache/entry.rs
new file mode 100644
index 0000000..b17b9dd
--- /dev/null
+++ b/src/resolver/cache/entry.rs
@@ -0,0 +1,17 @@
+// Copyright 2026 Ryan Moore
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! `RRsetEntry`, `StoredRecord`, `DnssecState`, `NegativeEntry`,
+//! `NegativeKey`, `DomainRecordSets`, `DomainNegativeEntries` — filled in
+//! by section-02.
diff --git a/src/resolver/cache/lru.rs b/src/resolver/cache/lru.rs
new file mode 100644
index 0000000..162ec6c
--- /dev/null
+++ b/src/resolver/cache/lru.rs
@@ -0,0 +1,16 @@
+// Copyright 2026 Ryan Moore
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! `ShardLru` (`BTreeSet` + `HashMap` side-index) — exact O(log n)
+//! touch/evict LRU, filled in by section-03.
diff --git a/src/resolver/cache/mod.rs b/src/resolver/cache/mod.rs
new file mode 100644
index 0000000..73878d1
--- /dev/null
+++ b/src/resolver/cache/mod.rs
@@ -0,0 +1,105 @@
+// Copyright 2026 Ryan Moore
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Sharded answer-cache implementation. See `docs/plans/cache_rework/` for
+//! the design this module is built from.
+
+mod assemble;
+mod entry;
+mod lru;
+mod namespace;
+mod shard;
+mod singleflight;
+
+use std::collections::hash_map::DefaultHasher;
+use std::hash::{Hash, Hasher};
+
+/// Routes a domain name to a shard index in `[0, shard_count)`. Shared by
+/// the cache shards (`cache::shard`, section-03) and the single-flight
+/// shards (`cache::singleflight`, section-04) — both structures shard
+/// purely by domain name, so a single hashing implementation keeps their
+/// routing behavior identical and avoids duplicated hashing logic.
+///
+/// `domain` is expected to already be normalized (lowercased, trailing dot
+/// stripped — the same normalization `normalize_question_name` applies in
+/// `resolver::mod`) by the caller; this function does not normalize
+/// internally, so two differently-cased spellings of the same domain will
+/// only route to the same shard if the caller normalizes first. Every call
+/// site added in later sections normalizes before calling this.
+///
+/// `shard_count` is expected to be at least 1 in real use (see
+/// `CacheConfig::resolved_shard_count`); `shard_count == 0` is handled
+/// defensively (returns 0) rather than panicking, since this is a cheap
+/// routing function, not a place to enforce config invariants.
+#[allow(dead_code)]
+pub(crate) fn shard_index(domain: &str, shard_count: usize) -> usize {
+    if shard_count == 0 {
+        return 0;
+    }
+    let mut hasher = DefaultHasher::new();
+    domain.hash(&mut hasher);
+    (hasher.finish() % shard_count as u64) as usize
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use std::collections::HashSet;
+
+    #[test]
+    fn shard_index_is_deterministic_for_same_input() {
+        let first = shard_index("example.com", 16);
+        let second = shard_index("example.com", 16);
+        assert_eq!(first, second);
+    }
+
+    #[test]
+    fn shard_index_stays_within_bounds() {
+        let domains = [
+            "example.com",
+            "a.example.com",
+            "www.example.org",
+            "sub.domain.example.net",
+            "localhost",
+        ];
+        for shard_count in [1usize, 2, 8, 17] {
+            for domain in domains {
+                let index = shard_index(domain, shard_count);
+                assert!(
+                    index < shard_count,
+                    "index {index} out of bounds for shard_count {shard_count} (domain {domain})"
+                );
+            }
+        }
+    }
+
+    #[test]
+    fn shard_index_distributes_distinct_domains_across_shards() {
+        let shard_count = 16;
+        let mut seen = HashSet::new();
+        for i in 0..200 {
+            let domain = format!("host-{i}.example.com");
+            seen.insert(shard_index(&domain, shard_count));
+        }
+        assert!(
+            seen.len() > 1,
+            "expected distinct domains to spread across more than one shard"
+        );
+    }
+
+    #[test]
+    fn shard_index_returns_zero_for_zero_shard_count() {
+        assert_eq!(shard_index("example.com", 0), 0);
+    }
+}
diff --git a/src/resolver/cache/namespace.rs b/src/resolver/cache/namespace.rs
new file mode 100644
index 0000000..8c5f12b
--- /dev/null
+++ b/src/resolver/cache/namespace.rs
@@ -0,0 +1,15 @@
+// Copyright 2026 Ryan Moore
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! `sweep_stale_namespace` — filled in by section-05.
diff --git a/src/resolver/cache/shard.rs b/src/resolver/cache/shard.rs
new file mode 100644
index 0000000..d0535a4
--- /dev/null
+++ b/src/resolver/cache/shard.rs
@@ -0,0 +1,16 @@
+// Copyright 2026 Ryan Moore
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! `Shard`/`ShardState` (`PositiveShardState`/`NegativeShardState`) and the
+//! per-shard eviction loop — filled in by section-03.
diff --git a/src/resolver/cache/singleflight.rs b/src/resolver/cache/singleflight.rs
new file mode 100644
index 0000000..b4afda4
--- /dev/null
+++ b/src/resolver/cache/singleflight.rs
@@ -0,0 +1,16 @@
+// Copyright 2026 Ryan Moore
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! `ShardedSingleFlight`, `InFlightMiss`, `SingleFlightTicket`,
+//! `SingleFlightLeader` — filled in by section-04.
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 29095ac..6521ab9 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -37,6 +37,8 @@ use crate::protocol::{
     rewrite_response_id, rewrite_response_request_fields,
 };
 
+mod cache;
+
 pub mod policy;
 pub use policy::{
     CidrPrefixError, ClientIdentity, ClientSelector, DomainName, DomainNameError, DomainSelector,
