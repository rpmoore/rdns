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

//! Concurrency benchmark for the sharded answer cache (`docs/plans/cache_rework/`,
//! goal 1: reduce lock scope so concurrent requests for different domains
//! don't serialize behind one global mutex). `#[ignore]`d like
//! `recursive_perf.rs`, run via `just bench` — this measures raw
//! `lookup_chain`/`store_response` throughput under concurrent load
//! directly, not end-to-end DNS resolution through a scripted backend, so
//! it doesn't fit `recursive_perf.rs`'s harness.
//!
//! No before/after comparison against the old, now-deleted
//! single-global-mutex `InMemoryDnsCache` is included here: per the
//! section-08 plan, that comparison is a one-time manual step (run this
//! workload's shape against a temporarily-reinstated old implementation
//! from a pre-section-07 commit, on request) rather than a permanently
//! dual-implemented benchmark kept in the tree — `InMemoryDnsCache` no
//! longer exists in this codebase at all as of section-07.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use rdns::config::CacheConfig;
use rdns::protocol::{RecordData, ResponseCode};
use rdns::resolver::{
    DecomposedResponse, DomainDnsCache, RRsetEntry, ShardedDnsCache, StoredRecord,
};

const A_QTYPE: u16 = 1;
const IN_QCLASS: u16 = 1;
const NAMESPACE: &str = "bench";
const MAX_CHAIN_DEPTH: u8 = 8;

fn seed_entry(now: SystemTime) -> RRsetEntry {
    RRsetEntry {
        records: vec![StoredRecord {
            rtype: A_QTYPE,
            rclass: IN_QCLASS,
            ttl_at_store: 300,
            rdata: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }],
        rrsigs: Vec::new(),
        response_code: ResponseCode::NoError,
        minimum_ttl: Duration::from_secs(300),
        stored_at: now,
        expires_at: now + Duration::from_secs(300),
        dnssec_state: Default::default(),
        // `ShardedDnsCache::store_response` unconditionally overwrites this
        // with its own `namespace` argument at store time — this value is
        // never actually read, but every field must be supplied.
        cache_namespace: NAMESPACE.to_string(),
        dnssec_complete: true,
    }
}

/// One thread's share of the workload: a mix of stores (25%) and lookups
/// (75%, roughly matching a cache that's mostly serving hits/misses rather
/// than constantly re-populating), cycling through `domains` so many
/// threads repeatedly contend for the same small set of shards rather than
/// each staying comfortably within its own.
fn run_workload(cache: &ShardedDnsCache, domains: &[String], operation_count: usize) {
    for i in 0..operation_count {
        let domain = &domains[i % domains.len()];
        if i % 4 == 0 {
            cache.store_response(
                DecomposedResponse {
                    positive: vec![(
                        domain.clone(),
                        A_QTYPE,
                        IN_QCLASS,
                        seed_entry(SystemTime::now()),
                    )],
                    negative: None,
                },
                NAMESPACE,
            );
        } else {
            let _ = cache.lookup_chain(
                domain,
                A_QTYPE,
                IN_QCLASS,
                false,
                NAMESPACE,
                MAX_CHAIN_DEPTH,
                SystemTime::now(),
            );
        }
    }
}

/// Not a pass/fail assertion (absolute throughput is environment-dependent
/// — matches `recursive_perf.rs`'s own convention of printing a table for
/// manual inspection via `--nocapture` rather than asserting a specific
/// number). The property worth eyeballing: `ops_per_sec` at higher thread
/// counts should stay in the same ballpark as at 1 thread, not collapse
/// toward it (which is what a single-global-mutex design would do, since
/// every thread would serialize behind the one lock regardless of which
/// domains it touches).
#[test]
#[ignore = "run via `just bench`; prints a throughput table, no CI assertion"]
fn concurrent_cache_access_across_shards_scales_with_thread_count() {
    // 256 distinct domain names, hashed across whatever shard count
    // `CacheConfig::default()`'s `shard_count: None` resolves to
    // (`available_parallelism() * 4`, rounded to a power of two) — plenty
    // to spread across many shards without needing `shard_index` itself
    // (crate-private, not part of this benchmark's public surface) to
    // engineer the mix by hand.
    let domains: Vec<String> = (0..256).map(|i| format!("host-{i}.example.com")).collect();
    let total_operations = 200_000usize;

    println!("threads,total_ops,wall_ms,ops_per_sec");
    for &thread_count in &[1usize, 2, 4, 8] {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 100_000,
            shard_count: None,
        }));
        let operations_per_thread = total_operations / thread_count;

        // Warm up: pay allocation growth and initial shard-map population
        // cost once, outside the timed window, so it doesn't inconsistently
        // pollute the relative comparison across thread counts (each
        // iteration otherwise builds a fresh, empty cache).
        run_workload(&cache, &domains, domains.len());

        let start = Instant::now();
        thread::scope(|scope| {
            for _ in 0..thread_count {
                let cache = Arc::clone(&cache);
                let domains = &domains;
                scope.spawn(move || run_workload(&cache, domains, operations_per_thread));
            }
        });
        let elapsed = start.elapsed();

        let completed_operations = operations_per_thread * thread_count;
        let ops_per_sec = completed_operations as f64 / elapsed.as_secs_f64();
        println!(
            "{thread_count},{completed_operations},{},{ops_per_sec:.0}",
            elapsed.as_millis()
        );
    }
}
