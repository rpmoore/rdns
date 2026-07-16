diff --git a/src/config/mod.rs b/src/config/mod.rs
index 4fc7df9..a545fd7 100644
--- a/src/config/mod.rs
+++ b/src/config/mod.rs
@@ -26,7 +26,10 @@ use serde::Deserialize;
 
 use crate::resolver::{DomainName, LocalDnsEntry, LocalDnsEntryValidationError};
 
-#[derive(Debug, Clone, PartialEq, Eq)]
+// Not `Eq`: `refresh: RefreshConfig` embeds `f32` fields (`hot_threshold_fraction`,
+// `lead_ratio`), and `f32`'s `PartialEq` isn't reflexive (NaN), so `f32` never
+// implements `Eq` — that transitively rules out `#[derive(Eq)]` here too.
+#[derive(Debug, Clone, PartialEq)]
 pub struct RuntimeConfig {
     pub dns_listen: Vec<SocketAddr>,
     pub resolution: ResolutionConfig,
@@ -39,6 +42,7 @@ pub struct RuntimeConfig {
     pub metrics: MetricsConfig,
     pub cache: CacheConfig,
     pub chaos: ChaosConfig,
+    pub refresh: RefreshConfig,
 }
 
 /// Default ceiling on concurrent TCP DNS connections per listener. Shared
@@ -81,6 +85,7 @@ impl RuntimeConfig {
             metrics: MetricsConfig::default_enabled(),
             cache: CacheConfig::default(),
             chaos: ChaosConfig::default(),
+            refresh: RefreshConfig::default(),
         };
         config.validate()?;
         Ok(config)
@@ -109,6 +114,7 @@ impl RuntimeConfig {
             metrics: MetricsConfig::default_enabled(),
             cache: CacheConfig::default(),
             chaos: ChaosConfig::default(),
+            refresh: RefreshConfig::default(),
         }
     }
 
@@ -194,6 +200,7 @@ impl RuntimeConfig {
         }
 
         self.cache.validate()?;
+        self.refresh.validate()?;
 
         if self.chaos.enabled {
             if self.chaos.version_bind.is_empty() {
@@ -444,6 +451,91 @@ impl Default for CacheConfig {
     }
 }
 
+/// Popularity-bucket leak rate: `units` drained per `per` elapsed duration.
+/// Deliberately not a float ratio — the popularity bucket's drain-rate
+/// arithmetic (`PopularityBucket::drain_and_increment`, owned by
+/// `resolver::cache::shard`) needs to stay in integer arithmetic to avoid
+/// long-uptime rounding drift. Defined here (not in `resolver::cache::shard`)
+/// since it must be `pub` to appear on `RefreshConfig`'s public field, and
+/// `resolver::cache::shard` reuses this same type rather than defining its
+/// own, to avoid two independent leaky-bucket rate types drifting apart.
+#[derive(Debug, Clone, Copy, PartialEq, Eq)]
+pub struct LeakRate {
+    pub units: u32,
+    pub per: Duration,
+}
+
+/// Configuration for the auto-refresh (proactive TTL-refresh) feature: keeps
+/// genuinely popular domains' cache entries refreshed shortly before they
+/// expire, so a real client query never sees the reactive miss. See
+/// `docs/plans/auto_refresh/` for the full design.
+///
+/// `enabled = false` makes the entire feature a no-op: no `PopularityBucket`
+/// is ever allocated, no worker tasks are spawned, no refresh signal is ever
+/// produced (enforced by the call sites that read this flag — this struct
+/// only carries it).
+// Not `Eq`: `hot_threshold_fraction`/`lead_ratio` are `f32`, and `f32` never
+// implements `Eq` (its `PartialEq` isn't reflexive because of NaN).
+#[derive(Debug, Clone, Copy, PartialEq)]
+pub struct RefreshConfig {
+    pub enabled: bool,
+    pub bucket_capacity: u32,
+    pub leak_rate: LeakRate,
+    pub hit_increment: u32,
+    /// Fraction of `bucket_capacity` a domain's popularity level must reach
+    /// or exceed to be considered "hot." Must be in `0.0..=1.0`.
+    pub hot_threshold_fraction: f32,
+    /// Fraction of a record's original TTL used as the refresh lead window
+    /// (`remaining_ttl <= max(original_ttl * lead_ratio, min_lead)`).
+    pub lead_ratio: f32,
+    pub min_lead: Duration,
+    /// Minimum original TTL for a record to be refresh-eligible at all.
+    pub eligibility_floor: Duration,
+    pub worker_count: usize,
+    pub channel_capacity: usize,
+}
+
+impl RefreshConfig {
+    pub fn validate(&self) -> Result<(), ConfigError> {
+        if !(0.0..=1.0).contains(&self.hot_threshold_fraction) {
+            return Err(ConfigError::InvalidRefreshHotThresholdFraction {
+                value: self.hot_threshold_fraction,
+            });
+        }
+        if self.worker_count == 0 {
+            return Err(ConfigError::InvalidRefreshWorkerCount {
+                value: self.worker_count,
+            });
+        }
+        if self.channel_capacity == 0 {
+            return Err(ConfigError::InvalidRefreshChannelCapacity {
+                value: self.channel_capacity,
+            });
+        }
+        Ok(())
+    }
+}
+
+impl Default for RefreshConfig {
+    fn default() -> Self {
+        Self {
+            enabled: true,
+            bucket_capacity: 10,
+            leak_rate: LeakRate {
+                units: 1,
+                per: Duration::from_secs(60),
+            },
+            hit_increment: 1,
+            hot_threshold_fraction: 0.5,
+            lead_ratio: 0.10,
+            min_lead: Duration::from_secs(5),
+            eligibility_floor: Duration::from_secs(15),
+            worker_count: 4,
+            channel_capacity: 256,
+        }
+    }
+}
+
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct ResolutionConfig {
     pub mode: ResolutionMode,
@@ -1222,7 +1314,9 @@ pub fn parse_local_zone_file(
         .collect())
 }
 
-#[derive(Debug, Clone, PartialEq, Eq)]
+// Not `Eq`: `InvalidRefreshHotThresholdFraction` carries an `f32`, and `f32`
+// never implements `Eq` (its `PartialEq` isn't reflexive because of NaN).
+#[derive(Debug, Clone, PartialEq)]
 pub enum ConfigError {
     NoDnsListenAddress,
     InvalidListenAddress {
@@ -1338,6 +1432,15 @@ pub enum ConfigError {
         len: usize,
         max: usize,
     },
+    InvalidRefreshHotThresholdFraction {
+        value: f32,
+    },
+    InvalidRefreshWorkerCount {
+        value: usize,
+    },
+    InvalidRefreshChannelCapacity {
+        value: usize,
+    },
 }
 
 #[derive(Debug, Deserialize)]
@@ -1362,6 +1465,8 @@ struct RawRuntimeConfig {
     cache: Option<RawCacheConfig>,
     #[serde(default)]
     chaos: Option<RawChaosConfig>,
+    #[serde(default)]
+    refresh: Option<RawRefreshConfig>,
 }
 
 #[derive(Debug, Deserialize)]
@@ -1409,6 +1514,93 @@ impl RawCacheConfig {
     }
 }
 
+#[derive(Debug, Deserialize)]
+#[serde(deny_unknown_fields)]
+struct RawRefreshConfig {
+    #[serde(default = "default_true")]
+    enabled: bool,
+    #[serde(default = "default_refresh_bucket_capacity")]
+    bucket_capacity: u32,
+    #[serde(default = "default_refresh_leak_rate_units")]
+    leak_rate_units: u32,
+    #[serde(default = "default_refresh_leak_rate_per_ms")]
+    leak_rate_per_ms: u64,
+    #[serde(default = "default_refresh_hit_increment")]
+    hit_increment: u32,
+    #[serde(default = "default_refresh_hot_threshold_fraction")]
+    hot_threshold_fraction: f32,
+    #[serde(default = "default_refresh_lead_ratio")]
+    lead_ratio: f32,
+    #[serde(default = "default_refresh_min_lead_ms")]
+    min_lead_ms: u64,
+    #[serde(default = "default_refresh_eligibility_floor_ms")]
+    eligibility_floor_ms: u64,
+    #[serde(default = "default_refresh_worker_count")]
+    worker_count: usize,
+    #[serde(default = "default_refresh_channel_capacity")]
+    channel_capacity: usize,
+}
+
+fn default_refresh_bucket_capacity() -> u32 {
+    RefreshConfig::default().bucket_capacity
+}
+
+fn default_refresh_leak_rate_units() -> u32 {
+    RefreshConfig::default().leak_rate.units
+}
+
+fn default_refresh_leak_rate_per_ms() -> u64 {
+    RefreshConfig::default().leak_rate.per.as_millis() as u64
+}
+
+fn default_refresh_hit_increment() -> u32 {
+    RefreshConfig::default().hit_increment
+}
+
+fn default_refresh_hot_threshold_fraction() -> f32 {
+    RefreshConfig::default().hot_threshold_fraction
+}
+
+fn default_refresh_lead_ratio() -> f32 {
+    RefreshConfig::default().lead_ratio
+}
+
+fn default_refresh_min_lead_ms() -> u64 {
+    RefreshConfig::default().min_lead.as_millis() as u64
+}
+
+fn default_refresh_eligibility_floor_ms() -> u64 {
+    RefreshConfig::default().eligibility_floor.as_millis() as u64
+}
+
+fn default_refresh_worker_count() -> usize {
+    RefreshConfig::default().worker_count
+}
+
+fn default_refresh_channel_capacity() -> usize {
+    RefreshConfig::default().channel_capacity
+}
+
+impl RawRefreshConfig {
+    fn try_into_refresh_config(self) -> Result<RefreshConfig, ConfigError> {
+        Ok(RefreshConfig {
+            enabled: self.enabled,
+            bucket_capacity: self.bucket_capacity,
+            leak_rate: LeakRate {
+                units: self.leak_rate_units,
+                per: Duration::from_millis(self.leak_rate_per_ms),
+            },
+            hit_increment: self.hit_increment,
+            hot_threshold_fraction: self.hot_threshold_fraction,
+            lead_ratio: self.lead_ratio,
+            min_lead: Duration::from_millis(self.min_lead_ms),
+            eligibility_floor: Duration::from_millis(self.eligibility_floor_ms),
+            worker_count: self.worker_count,
+            channel_capacity: self.channel_capacity,
+        })
+    }
+}
+
 impl RawMetricsConfig {
     fn try_into_metrics_config(self) -> Result<MetricsConfig, ConfigError> {
         Ok(MetricsConfig {
@@ -1737,6 +1929,11 @@ impl TryFrom<RawRuntimeConfig> for RuntimeConfig {
             .map(RawChaosConfig::try_into_chaos_config)
             .transpose()?
             .unwrap_or_default();
+        let refresh = raw
+            .refresh
+            .map(RawRefreshConfig::try_into_refresh_config)
+            .transpose()?
+            .unwrap_or_default();
 
         let config = RuntimeConfig {
             dns_listen,
@@ -1750,6 +1947,7 @@ impl TryFrom<RawRuntimeConfig> for RuntimeConfig {
             metrics,
             cache,
             chaos,
+            refresh,
         };
         config.validate()?;
         Ok(config)
@@ -2708,6 +2906,123 @@ a.root-servers.net.      3600000      Aaaa  2001:503:ba3e::2:30
         assert_eq!(CacheConfig::default().validate(), Ok(()));
     }
 
+    #[test]
+    fn refresh_config_defaults_match_spec() {
+        let config = RefreshConfig::default();
+
+        assert!(config.enabled);
+        assert_eq!(config.bucket_capacity, 10);
+        assert_eq!(
+            config.leak_rate,
+            LeakRate {
+                units: 1,
+                per: Duration::from_secs(60),
+            }
+        );
+        assert_eq!(config.hit_increment, 1);
+        assert_eq!(config.hot_threshold_fraction, 0.5);
+        assert_eq!(config.lead_ratio, 0.10);
+        assert_eq!(config.min_lead, Duration::from_secs(5));
+        assert_eq!(config.eligibility_floor, Duration::from_secs(15));
+        assert_eq!(config.worker_count, 4);
+        assert_eq!(config.channel_capacity, 256);
+    }
+
+    #[test]
+    fn refresh_config_defaults_when_absent() {
+        let config = RuntimeConfig::from_toml_str(&valid_toml()).unwrap();
+
+        assert_eq!(config.refresh, RefreshConfig::default());
+    }
+
+    #[test]
+    fn refresh_config_explicit_override() {
+        let mut toml = valid_toml();
+        toml.push_str(
+            r#"
+            [refresh]
+            enabled = false
+            bucket_capacity = 20
+            worker_count = 8
+            "#,
+        );
+
+        let config = RuntimeConfig::from_toml_str(&toml).unwrap();
+
+        assert!(!config.refresh.enabled);
+        assert_eq!(config.refresh.bucket_capacity, 20);
+        assert_eq!(config.refresh.worker_count, 8);
+        // Fields not overridden stay at their defaults.
+        assert_eq!(config.refresh.channel_capacity, 256);
+        assert_eq!(config.refresh.hit_increment, 1);
+    }
+
+    #[test]
+    fn raw_refresh_config_rejects_unknown_fields() {
+        let mut toml = valid_toml();
+        toml.push_str(
+            r#"
+            [refresh]
+            not_a_real_field = 1
+            "#,
+        );
+
+        assert!(RuntimeConfig::from_toml_str(&toml).is_err());
+    }
+
+    #[test]
+    fn refresh_config_validate_rejects_out_of_range_hot_threshold() {
+        let mut toml = valid_toml();
+        toml.push_str(
+            r#"
+            [refresh]
+            hot_threshold_fraction = 1.5
+            "#,
+        );
+
+        let error = RuntimeConfig::from_toml_str(&toml).unwrap_err();
+        assert_eq!(
+            error,
+            ConfigError::InvalidRefreshHotThresholdFraction { value: 1.5 }
+        );
+    }
+
+    #[test]
+    fn refresh_config_validate_rejects_zero_worker_count() {
+        let mut toml = valid_toml();
+        toml.push_str(
+            r#"
+            [refresh]
+            worker_count = 0
+            "#,
+        );
+
+        let error = RuntimeConfig::from_toml_str(&toml).unwrap_err();
+        assert_eq!(error, ConfigError::InvalidRefreshWorkerCount { value: 0 });
+    }
+
+    #[test]
+    fn refresh_config_validate_rejects_zero_channel_capacity() {
+        let mut toml = valid_toml();
+        toml.push_str(
+            r#"
+            [refresh]
+            channel_capacity = 0
+            "#,
+        );
+
+        let error = RuntimeConfig::from_toml_str(&toml).unwrap_err();
+        assert_eq!(
+            error,
+            ConfigError::InvalidRefreshChannelCapacity { value: 0 }
+        );
+    }
+
+    #[test]
+    fn refresh_config_validate_accepts_default() {
+        assert_eq!(RefreshConfig::default().validate(), Ok(()));
+    }
+
     #[test]
     fn metrics_config_allows_zero_max_connections_when_disabled() {
         let mut toml = valid_toml();
diff --git a/src/resolver/cache/shard.rs b/src/resolver/cache/shard.rs
index 652c145..573fe95 100644
--- a/src/resolver/cache/shard.rs
+++ b/src/resolver/cache/shard.rs
@@ -34,6 +34,7 @@ use super::entry::{
     DomainNegativeEntries, DomainRecordSets, NegativeEntry, NegativeKey, RRsetEntry,
 };
 use super::lru::ShardLru;
+use crate::config::LeakRate;
 use crate::protocol::RecordData;
 
 const CNAME_RECORD_TYPE: u16 = 5;
@@ -45,17 +46,6 @@ const DEFAULT_POPULARITY_LEAK_RATE: LeakRate = LeakRate {
 const DEFAULT_POPULARITY_HIT_INCREMENT: u32 = 1;
 const DEFAULT_POPULARITY_BUCKET_CAPACITY: u32 = 10;
 
-/// Leak rate for a `PopularityBucket`: drains `units` worth of level per
-/// `per` elapsed real time. Defined here (cache layer), not in `config`,
-/// because the leaky-bucket concept itself belongs to the cache; a later
-/// section's `RefreshConfig` (`src/config/mod.rs`) references this same
-/// type by name for its `leak_rate` field.
-#[derive(Debug, Clone, Copy, PartialEq, Eq)]
-pub(crate) struct LeakRate {
-    pub(crate) units: u32,
-    pub(crate) per: Duration,
-}
-
 /// Per-domain leaky-bucket popularity tracker. Created the first time a
 /// domain is stored (mirroring `ShardLru`'s own on-first-store creation),
 /// drained-then-incremented on every subsequent lookup hit, and removed
