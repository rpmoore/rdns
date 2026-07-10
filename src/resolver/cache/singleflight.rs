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

//! Sharded replacement for today's single-global-mutex
//! `SingleFlightMisses` (`src/resolver/mod.rs:3826-3931`). Ported
//! unchanged in leader/follower/notify behavior; only the key type
//! (`CacheKey` -> `(String, u16, u16)`, i.e. normalized name + qtype +
//! qclass) and the single-map-becomes-many-per-shard-maps shape change.
//!
//! No non-test callers yet (section-07 rewires `probe_cache`/
//! `resolve_coalesced_*` to use this instead of the old
//! `SingleFlightMisses` in `resolver::mod`); `#[allow(dead_code)]` below
//! is transient, same pattern as `shard_index` in section-01.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use crate::resolver::{ResolutionBackendError, ResolutionResponse};

use super::shard_index;

/// Sharded replacement for today's single-mutex `SingleFlightMisses`.
/// Shard count and routing must match the cache's own sharding so that,
/// in principle, in-flight-miss bookkeeping for a domain and its cached
/// data end up in "parallel" shards — though this structure's lock is
/// intentionally kept separate from the cache shard's lock (`cache::shard`,
/// section-03): merging them would widen the cache-shard critical section
/// to include unrelated single-flight bookkeeping, reintroducing exactly
/// the kind of unrelated-work-under-one-lock problem this rework removes.
pub(crate) struct ShardedSingleFlight {
    shards: Vec<SingleFlightShard>,
}

#[derive(Default)]
struct SingleFlightShard {
    flights: Mutex<HashMap<(String, u16, u16), Arc<InFlightMiss>>>,
}

pub(crate) enum SingleFlightTicket {
    Leader {
        key: (String, u16, u16),
        flight: Arc<InFlightMiss>,
    },
    Follower {
        flight: Arc<InFlightMiss>,
    },
}

pub(crate) struct InFlightMiss {
    result: Mutex<Option<Result<ResolutionResponse, ResolutionBackendError>>>,
    notify: Notify,
}

pub(crate) struct SingleFlightLeader {
    coalescer: Arc<ShardedSingleFlight>,
    key: (String, u16, u16),
    flight: Arc<InFlightMiss>,
    completed: bool,
}

impl ShardedSingleFlight {
    /// `shard_count` must be > 0; construct with the same shard count the
    /// sharded cache itself uses (not enforced here — the caller's
    /// responsibility, per section-07's wiring).
    pub(crate) fn new(shard_count: usize) -> Self {
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(SingleFlightShard::default());
        }
        Self { shards }
    }

    fn shard_for(&self, domain: &str) -> &SingleFlightShard {
        &self.shards[shard_index(domain, self.shards.len())]
    }

    /// Routes to the shard for `key.0` (the normalized domain name) and
    /// delegates to that shard's `begin`.
    pub(crate) fn begin(&self, key: (String, u16, u16)) -> SingleFlightTicket {
        self.shard_for(&key.0).begin(key)
    }

    /// Routes the same way `begin` does; called by `SingleFlightLeader`'s
    /// `complete`/`Drop` path.
    fn finish(
        &self,
        key: &(String, u16, u16),
        flight: &Arc<InFlightMiss>,
        result: Result<ResolutionResponse, ResolutionBackendError>,
    ) {
        self.shard_for(&key.0).finish(key, flight, result);
    }
}

impl SingleFlightShard {
    fn begin(&self, key: (String, u16, u16)) -> SingleFlightTicket {
        let mut flights = self.flights.lock().unwrap();
        if let Some(flight) = flights.get(&key) {
            return SingleFlightTicket::Follower {
                flight: Arc::clone(flight),
            };
        }
        let flight = Arc::new(InFlightMiss {
            result: Mutex::new(None),
            notify: Notify::new(),
        });
        flights.insert(key.clone(), Arc::clone(&flight));
        SingleFlightTicket::Leader { key, flight }
    }

    fn finish(
        &self,
        key: &(String, u16, u16),
        flight: &Arc<InFlightMiss>,
        result: Result<ResolutionResponse, ResolutionBackendError>,
    ) {
        *flight.result.lock().unwrap() = Some(result);
        let mut flights = self.flights.lock().unwrap();
        if flights
            .get(key)
            .map(|current| Arc::ptr_eq(current, flight))
            .unwrap_or(false)
        {
            flights.remove(key);
        }
        drop(flights);
        flight.notify.notify_waiters();
    }
}

impl SingleFlightLeader {
    pub(crate) fn new(
        coalescer: Arc<ShardedSingleFlight>,
        key: (String, u16, u16),
        flight: Arc<InFlightMiss>,
    ) -> Self {
        Self {
            coalescer,
            key,
            flight,
            completed: false,
        }
    }

    pub(crate) fn complete(mut self, result: Result<ResolutionResponse, ResolutionBackendError>) {
        self.coalescer.finish(&self.key, &self.flight, result);
        self.completed = true;
    }
}

impl Drop for SingleFlightLeader {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.coalescer.finish(
            &self.key,
            &self.flight,
            Err(ResolutionBackendError::Transport(
                "single-flight leader cancelled".to_string(),
            )),
        );
    }
}

impl InFlightMiss {
    pub(crate) async fn wait(&self) -> Result<ResolutionResponse, ResolutionBackendError> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            if let Some(result) = self.result.lock().unwrap().clone() {
                return result;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::{BackendProvenance, ResolutionCacheDirective, SourceCredibility};
    use std::time::{Duration, SystemTime};

    fn key(name: &str) -> (String, u16, u16) {
        (name.to_string(), 1, 1) // A, IN
    }

    fn sample_response(marker: &str) -> ResolutionResponse {
        ResolutionResponse {
            bytes: marker.as_bytes().to_vec(),
            received_at: SystemTime::now(),
            response_message: None,
            response_code: None,
            final_question: None,
            canonical_chain: Vec::new(),
            negative_cache: None,
            source_credibility: SourceCredibility::Authoritative,
            backend_provenance: BackendProvenance::forwarding(1, "test-upstream"),
            cache_directive: ResolutionCacheDirective::Cacheable,
        }
    }

    #[tokio::test]
    async fn single_flight_coalesces_concurrent_misses_for_same_name_and_qtype() {
        let coalescer = Arc::new(ShardedSingleFlight::new(4));
        let shared_key = key("example.com");

        // Genuinely spawn N concurrent begin() calls for the same key,
        // rather than calling begin() in a sequential loop, so this
        // exercises real async-scheduler interleaving.
        let mut begin_handles = Vec::new();
        for _ in 0..5 {
            let coalescer = Arc::clone(&coalescer);
            let shared_key = shared_key.clone();
            begin_handles.push(tokio::spawn(async move { coalescer.begin(shared_key) }));
        }

        let mut leader = None;
        let mut follower_flights = Vec::new();
        for handle in begin_handles {
            match handle.await.unwrap() {
                SingleFlightTicket::Leader { key, flight } => {
                    assert!(leader.is_none(), "expected exactly one Leader");
                    leader = Some((key, flight));
                }
                SingleFlightTicket::Follower { flight } => follower_flights.push(flight),
            }
        }
        let (leader_key, leader_flight) = leader.expect("expected exactly one Leader");
        assert_eq!(follower_flights.len(), 4);
        for follower_flight in &follower_flights {
            assert!(Arc::ptr_eq(follower_flight, &leader_flight));
        }

        // Spawn followers' wait() calls *before* completing the leader,
        // so they genuinely park inside `notified().await` instead of
        // hitting wait()'s early-return branch — this is what actually
        // exercises the missed-wakeup-safe register-before-check ordering.
        let mut wait_handles = Vec::new();
        for follower_flight in follower_flights {
            wait_handles.push(tokio::spawn(async move { follower_flight.wait().await }));
        }
        // Give the spawned tasks a chance to actually start polling and
        // park on `notified()` before the leader completes.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let leader = SingleFlightLeader::new(Arc::clone(&coalescer), leader_key, leader_flight);
        leader.complete(Ok(sample_response("resolved")));

        for handle in wait_handles {
            let result = handle.await.unwrap().expect("expected Ok result");
            assert_eq!(result.bytes, b"resolved");
        }
    }

    #[tokio::test]
    async fn single_flight_requests_differing_only_in_bufsize_or_casing_still_coalesce() {
        // This module's key is just (name, qtype, qclass) — there is no
        // bufsize/casing dimension to vary, which is the point: two
        // begin() calls with identical (String, u16, u16) values (as if
        // derived from requests that only differed in EDNS bufsize or
        // original wire casing, fields this module never sees) coalesce
        // into one flight.
        let coalescer = ShardedSingleFlight::new(4);
        let shared_key = key("example.com");

        let first = coalescer.begin(shared_key.clone());
        let second = coalescer.begin(shared_key.clone());

        assert!(matches!(first, SingleFlightTicket::Leader { .. }));
        assert!(matches!(second, SingleFlightTicket::Follower { .. }));
    }

    #[tokio::test]
    async fn single_flight_leader_drop_wakes_followers_and_clears_key() {
        let coalescer = Arc::new(ShardedSingleFlight::new(4));
        let shared_key = key("cancelled.example.com");

        let SingleFlightTicket::Leader {
            key: leader_key,
            flight: leader_flight,
        } = coalescer.begin(shared_key.clone())
        else {
            panic!("expected Leader");
        };
        let follower_flight = match coalescer.begin(shared_key.clone()) {
            SingleFlightTicket::Follower { flight } => flight,
            SingleFlightTicket::Leader { .. } => panic!("expected Follower"),
        };

        let leader = SingleFlightLeader::new(Arc::clone(&coalescer), leader_key, leader_flight);
        drop(leader); // simulate a panicked/cancelled leader task

        let result = follower_flight.wait().await;
        assert!(matches!(result, Err(ResolutionBackendError::Transport(_))));

        // The shard's flights map must no longer contain an entry for
        // this key — a fresh begin() must return Leader again.
        match coalescer.begin(shared_key) {
            SingleFlightTicket::Leader { .. } => {}
            SingleFlightTicket::Follower { .. } => {
                panic!("expected fresh Leader after cancelled leader cleared the key")
            }
        }
    }

    #[tokio::test]
    async fn single_flight_different_shards_do_not_contend() {
        let coalescer = Arc::new(ShardedSingleFlight::new(8));

        // Find two domain names that hash to different shards.
        let domain_a = "domain-a.example.com".to_string();
        let mut domain_b = "domain-b.example.com".to_string();
        let mut counter = 0;
        while shard_index(&domain_a, 8) == shard_index(&domain_b, 8) {
            counter += 1;
            domain_b = format!("domain-b-{counter}.example.com");
        }

        // Force real lock contention on shard A specifically: hold its
        // raw `flights` mutex from a background OS thread across a sleep.
        // A `std::sync::MutexGuard` is `!Send`, so this must be a real OS
        // thread (not a spawned async task that would need the guard to
        // cross an `.await` point).
        let coalescer_for_hold = Arc::clone(&coalescer);
        let domain_a_for_hold = domain_a.clone();
        let hold_thread = std::thread::spawn(move || {
            let shard = coalescer_for_hold.shard_for(&domain_a_for_hold);
            let _guard = shard.flights.lock().unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });

        // Give the background thread time to actually acquire shard A's
        // lock before proceeding.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Domain B's begin() on a different shard must proceed without
        // blocking on shard A's held lock.
        let key_b = (domain_b, 1u16, 1u16);
        let outcome =
            tokio::time::timeout(Duration::from_millis(100), async { coalescer.begin(key_b) })
                .await;

        assert!(
            outcome.is_ok(),
            "begin() on a different shard must not block on shard A's held lock"
        );
        assert!(matches!(
            outcome.unwrap(),
            SingleFlightTicket::Leader { .. }
        ));

        hold_thread.join().unwrap();
    }
}
