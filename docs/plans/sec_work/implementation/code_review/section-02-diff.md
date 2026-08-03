diff --git a/.github/workflows/dnssec-anchor-staleness.yml b/.github/workflows/dnssec-anchor-staleness.yml
new file mode 100644
index 0000000..9c0f16f
--- /dev/null
+++ b/.github/workflows/dnssec-anchor-staleness.yml
@@ -0,0 +1,24 @@
+name: DNSSEC trust anchor staleness
+
+# Scheduled, not PR/push-triggered: IANA endpoint flakiness must not block
+# unrelated work. A failing scheduled run notifies via GitHub's own
+# scheduled-workflow-failure emails to repo watchers - see
+# scripts/check-trust-anchor-staleness.sh for what triggers a failure.
+on:
+  schedule:
+    - cron: '0 6 * * 1' # weekly, Monday 06:00 UTC
+  workflow_dispatch:
+
+jobs:
+  trust-anchor-staleness:
+    name: Check bundled trust anchor freshness
+    runs-on: ubuntu-latest
+    permissions:
+      contents: read
+
+    steps:
+      - name: Checkout
+        uses: actions/checkout@v4
+
+      - name: Check trust anchor staleness
+        run: make check-trust-anchor-staleness
diff --git a/Makefile b/Makefile
index 1748cc7..2d37caf 100644
--- a/Makefile
+++ b/Makefile
@@ -1,7 +1,10 @@
 # SPDX-FileCopyrightText: 2026 Ryan Moore
 # SPDX-License-Identifier: Apache-2.0
 
-.PHONY: check-bundled-data-freshness
+.PHONY: check-bundled-data-freshness check-trust-anchor-staleness
 
 check-bundled-data-freshness:
 	./scripts/check-bundled-data-freshness.sh
+
+check-trust-anchor-staleness:
+	./scripts/check-trust-anchor-staleness.sh
diff --git a/scripts/check-trust-anchor-staleness.sh b/scripts/check-trust-anchor-staleness.sh
new file mode 100755
index 0000000..1d574bc
--- /dev/null
+++ b/scripts/check-trust-anchor-staleness.sh
@@ -0,0 +1,131 @@
+#!/usr/bin/env bash
+# Checks the bundled DNSSEC root trust anchors (src/config/root-anchor.txt)
+# against IANA's authoritative root-anchors.xml (RFC 9718), verifying the
+# CMS signature over the XML before trusting its contents. Meant to run on a
+# schedule (see .github/workflows/dnssec-anchor-staleness.yml), not on every
+# PR: IANA endpoint flakiness must not block unrelated work, so a fetch or
+# CMS-verification failure is reported as a distinct "couldn't confirm
+# freshness" finding, separate from an actual staleness finding.
+#
+# RFC 5011 automated rollover is out of scope; this script only detects
+# drift and alerts a human, it never rewrites the bundled file itself.
+set -euo pipefail
+
+repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
+bundled_file="$repo_root/src/config/root-anchor.txt"
+warning_threshold_days=60
+
+tmp_dir="$(mktemp -d)"
+trap 'rm -rf "$tmp_dir"' EXIT
+
+curl_opts=(--fail --silent --show-error --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30)
+
+xml_url="https://data.iana.org/root-anchors/root-anchors.xml"
+p7s_url="https://data.iana.org/root-anchors/root-anchors.p7s"
+pem_url="https://data.iana.org/root-anchors/icannbundle.pem"
+
+xml_file="$tmp_dir/root-anchors.xml"
+p7s_file="$tmp_dir/root-anchors.p7s"
+pem_file="$tmp_dir/icannbundle.pem"
+
+fetch_failed=0
+fetch_urls=("$xml_url" "$p7s_url" "$pem_url")
+fetch_dests=("$xml_file" "$p7s_file" "$pem_file")
+for i in "${!fetch_urls[@]}"; do
+  if ! curl "${curl_opts[@]}" "${fetch_urls[$i]}" -o "${fetch_dests[$i]}"; then
+    echo "::error::Could not confirm trust-anchor freshness: failed to fetch ${fetch_urls[$i]}"
+    fetch_failed=1
+  fi
+done
+if [[ "$fetch_failed" -ne 0 ]]; then
+  exit 1
+fi
+
+# IANA's documented verification recipe for root-anchors.xml (see
+# https://data.iana.org/root-anchors/README): the .p7s is a DER-encoded
+# detached CMS/PKCS7 signature over the XML, signed by the ICANN bundle.
+if ! openssl smime -verify -CAfile "$pem_file" -inform DER -in "$p7s_file" \
+  -content "$xml_file" -noout > "$tmp_dir/verify.log" 2>&1; then
+  echo "::error::Could not confirm trust-anchor freshness: CMS signature verification failed"
+  cat "$tmp_dir/verify.log"
+  exit 1
+fi
+
+echo "CMS signature verified against $pem_url"
+
+status=0
+
+# Extract (key_tag, digest) pairs currently bundled in root-anchor.txt.
+# Zonefile-format DS line: <owner> <ttl> IN DS <key_tag> <algorithm> <digest_type> <digest>
+declare -A bundled_digest_by_tag=()
+while IFS= read -r line; do
+  line="${line%%;*}"
+  line="$(echo "$line" | xargs)"
+  [[ -z "$line" ]] && continue
+  read -r -a fields <<< "$line"
+  [[ "${#fields[@]}" -eq 8 ]] || continue
+  key_tag="${fields[4]}"
+  digest="${fields[7]}"
+  bundled_digest_by_tag["$key_tag"]="$digest"
+done < "$bundled_file"
+
+if [[ "${#bundled_digest_by_tag[@]}" -eq 0 ]]; then
+  echo "::error::No DS entries found in $bundled_file to compare"
+  exit 1
+fi
+
+now_epoch="$(date -u +%s)"
+warning_seconds=$((warning_threshold_days * 86400))
+
+# Each <KeyDigest> element is emitted on its own opening tag line by IANA's
+# XML, with KeyTag/Digest as child elements on subsequent lines - reformat
+# so each KeyDigest's full record (tag line + children up to </KeyDigest>)
+# is on one line, then process record by record.
+while IFS= read -r record; do
+  key_tag="$(echo "$record" | grep -oP '<KeyTag>\K[0-9]+')"
+  digest="$(echo "$record" | grep -oP '<Digest>\K[0-9A-Fa-f]+')"
+  valid_from="$(echo "$record" | grep -oP 'validFrom="\K[^"]+' || true)"
+  valid_until="$(echo "$record" | grep -oP 'validUntil="\K[^"]+' || true)"
+
+  bundled_digest="${bundled_digest_by_tag[$key_tag]:-}"
+
+  currently_valid=1
+  if [[ -n "$valid_until" ]]; then
+    valid_until_epoch="$(date -u -d "$valid_until" +%s)"
+    if [[ "$now_epoch" -ge "$valid_until_epoch" ]]; then
+      currently_valid=0
+    fi
+  fi
+
+  if [[ -z "$bundled_digest" ]]; then
+    if [[ "$currently_valid" -eq 1 ]]; then
+      echo "::error::IANA key tag $key_tag (validFrom=$valid_from) is currently valid but not present in $bundled_file - bundle is missing an anchor"
+      status=1
+    fi
+    continue
+  fi
+
+  if [[ "${bundled_digest^^}" != "${digest^^}" ]]; then
+    echo "::error::Bundled digest for key tag $key_tag does not match IANA's published digest - refresh $bundled_file from $xml_url"
+    status=1
+    continue
+  fi
+
+  if [[ "$currently_valid" -eq 0 ]]; then
+    echo "::error::Bundled key tag $key_tag expired on $valid_until - refresh $bundled_file from $xml_url"
+    status=1
+  elif [[ -n "$valid_until" ]]; then
+    valid_until_epoch="$(date -u -d "$valid_until" +%s)"
+    remaining=$((valid_until_epoch - now_epoch))
+    if [[ "$remaining" -le "$warning_seconds" ]]; then
+      remaining_days=$((remaining / 86400))
+      echo "::warning::Bundled key tag $key_tag expires in $remaining_days day(s) ($valid_until) - plan a refresh of $bundled_file"
+    fi
+  fi
+done < <(grep -Pzo '(?s)<KeyDigest[^>]*>.*?</KeyDigest>' "$xml_file" | tr '\0' '\n' | tr '\n' ' ' | sed 's/<KeyDigest/\n<KeyDigest/g' | tail -n +2; echo)
+
+if [[ "$status" -eq 0 ]]; then
+  echo "Trust anchor staleness check passed: bundled digests match IANA and are within the ${warning_threshold_days}-day warning window"
+fi
+
+exit "$status"
diff --git a/src/config/mod.rs b/src/config/mod.rs
index 3104773..8dbb2b5 100644
--- a/src/config/mod.rs
+++ b/src/config/mod.rs
@@ -20,6 +20,7 @@ use std::time::Duration;
 
 use domain::base::RecordData;
 use domain::base::iana::{Class, Rtype};
+use domain::dnssec::validator::anchor::TrustAnchors;
 use domain::rdata::ZoneRecordData;
 use domain::zonefile::inplace::{Entry, Zonefile};
 use serde::Deserialize;
@@ -726,6 +727,7 @@ pub enum ResolutionMode {
 pub struct RecursiveResolutionConfig {
     pub root_hints_version: String,
     pub root_hints_source: RootHintsSource,
+    pub trust_anchor_source: TrustAnchorSource,
     pub per_authority_timeout: Duration,
     pub max_recursion_depth: u8,
     pub max_cname_restarts: u8,
@@ -743,6 +745,7 @@ impl RecursiveResolutionConfig {
         Self {
             root_hints_version: root_hints_version.into(),
             root_hints_source: RootHintsSource::Static(root_hints),
+            trust_anchor_source: TrustAnchorSource::Bundled,
             per_authority_timeout: Duration::from_millis(750),
             max_recursion_depth: 16,
             max_cname_restarts: 8,
@@ -756,6 +759,7 @@ impl RecursiveResolutionConfig {
         Self {
             root_hints_version: root_hints_version.into(),
             root_hints_source: RootHintsSource::Bundled,
+            trust_anchor_source: TrustAnchorSource::Bundled,
             per_authority_timeout: Duration::from_millis(750),
             max_recursion_depth: 16,
             max_cname_restarts: 8,
@@ -772,6 +776,18 @@ impl RecursiveResolutionConfig {
         }
     }
 
+    /// Returns the configured trust-anchor set as raw zonefile-format
+    /// `DS`/`DNSKEY` lines (one entry per line), deferring the
+    /// `TrustAnchors::from_u8` conversion to callers that actually consume
+    /// `domain`'s validator types, matching how `load_root_hints` keeps
+    /// `RootHintConfig` free of `domain`-crate types.
+    pub fn load_trust_anchors(&self) -> Result<Vec<String>, ConfigError> {
+        match &self.trust_anchor_source {
+            TrustAnchorSource::Bundled => Ok(bundled_trust_anchors()),
+            TrustAnchorSource::Static(entries) => Ok(entries.clone()),
+        }
+    }
+
     pub fn validate(&self) -> Result<(), ConfigError> {
         if self.root_hints_version.trim().is_empty() {
             return Err(ConfigError::InvalidRootHintsVersion);
@@ -783,6 +799,13 @@ impl RecursiveResolutionConfig {
         for root_hint in &root_hints {
             root_hint.validate()?;
         }
+        let trust_anchors = self.load_trust_anchors()?;
+        if trust_anchors.is_empty() {
+            return Err(ConfigError::MissingTrustAnchors);
+        }
+        for entry in &trust_anchors {
+            validate_trust_anchor_entry(entry)?;
+        }
         validate_duration(
             "recursive.per_authority_timeout",
             self.per_authority_timeout,
@@ -876,6 +899,50 @@ impl RootHintsSource {
     }
 }
 
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub enum TrustAnchorSource {
+    Bundled,
+    /// Zonefile-format `DS`/`DNSKEY` lines, one per entry — see
+    /// `TrustAnchors::from_u8` in the `domain` crate for the exact grammar.
+    Static(Vec<String>),
+}
+
+/// IANA's DNS root zone KSK trust anchors, as published at
+/// <https://data.iana.org/root-anchors/root-anchors.xml> (RFC 9718). The
+/// file is embedded at compile time via `include_str!`; `bundled_trust_anchors`
+/// re-derives and validates the bundled entries from it at runtime. Requires
+/// **manual** refresh on future root KSK rollovers (no RFC 5011 automation) —
+/// the scheduled `dnssec-anchor-staleness` workflow flags when a refresh is
+/// needed, it does not perform one.
+const BUNDLED_ROOT_ANCHOR: &str = include_str!("root-anchor.txt");
+
+fn bundled_trust_anchors() -> Vec<String> {
+    TrustAnchors::from_u8(BUNDLED_ROOT_ANCHOR.as_bytes())
+        .unwrap_or_else(|error| panic!("bundled root-anchor.txt asset failed to parse: {error}"));
+    parse_trust_anchor_lines(BUNDLED_ROOT_ANCHOR)
+}
+
+/// Splits a zonefile-format trust-anchor asset into its non-comment,
+/// non-blank data lines. `;` starts a comment, matching `named.root`'s
+/// convention and RFC 1035 zonefile syntax generally.
+fn parse_trust_anchor_lines(source: &str) -> Vec<String> {
+    source
+        .lines()
+        .map(str::trim)
+        .filter(|line| !line.is_empty() && !line.starts_with(';'))
+        .map(str::to_string)
+        .collect()
+}
+
+fn validate_trust_anchor_entry(entry: &str) -> Result<(), ConfigError> {
+    TrustAnchors::from_u8(entry.as_bytes())
+        .map(|_| ())
+        .map_err(|error| ConfigError::InvalidTrustAnchorEntry {
+            entry: entry.to_string(),
+            message: error.to_string(),
+        })
+}
+
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct RootHintConfig {
     pub name: String,
@@ -1493,6 +1560,11 @@ pub enum ConfigError {
     InvalidRootHintEndpoint {
         endpoint: SocketAddr,
     },
+    MissingTrustAnchors,
+    InvalidTrustAnchorEntry {
+        entry: String,
+        message: String,
+    },
     InvalidRecursiveDepth {
         value: u8,
         max: u8,
@@ -1872,6 +1944,10 @@ struct RawRecursiveResolutionConfig {
     root_hints_version: String,
     #[serde(default)]
     root_hints_entries: Vec<RawRootHintConfig>,
+    #[serde(default)]
+    trust_anchor: Option<String>,
+    #[serde(default)]
+    trust_anchor_entries: Vec<String>,
     #[serde(default = "default_per_authority_timeout_ms")]
     per_authority_timeout_ms: u64,
     #[serde(default = "default_max_recursion_depth")]
@@ -1950,8 +2026,18 @@ impl RawRecursiveResolutionConfig {
                 });
             }
         };
+        let trust_anchor_source = match self.trust_anchor.as_deref() {
+            None | Some("bundled") => TrustAnchorSource::Bundled,
+            Some("static") => TrustAnchorSource::Static(self.trust_anchor_entries),
+            Some(other) => {
+                return Err(ConfigError::InvalidTomlConfig {
+                    message: format!("unknown trust_anchor source: {other}"),
+                });
+            }
+        };
         config.dnssec_validation = dnssec_validation;
         config.dname_handling = dname_handling;
+        config.trust_anchor_source = trust_anchor_source;
         config.per_authority_timeout = Duration::from_millis(self.per_authority_timeout_ms);
         config.max_recursion_depth = self.max_recursion_depth;
         config.max_cname_restarts = self.max_cname_restarts;
@@ -2835,6 +2921,107 @@ a.root-servers.net.      3600000      Aaaa  2001:503:ba3e::2:30
         );
     }
 
+    #[test]
+    fn bundled_trust_anchors_parses_without_error() {
+        let entries = bundled_trust_anchors();
+        assert_eq!(entries.len(), 2);
+    }
+
+    #[test]
+    fn bundled_root_anchor_source_text_has_the_expected_key_tags() {
+        // `TrustAnchor` (the parsed record group) is `pub(crate)` inside
+        // `domain`, so key tags can't be read back off a `TrustAnchors`
+        // value — assert against the raw source text's `DS` lines instead.
+        let key_tags: Vec<&str> = BUNDLED_ROOT_ANCHOR
+            .lines()
+            .map(str::trim)
+            .filter(|line| !line.is_empty() && !line.starts_with(';'))
+            .map(|line| {
+                line.split_whitespace()
+                    .nth(4)
+                    .expect("DS line should have a key-tag field")
+            })
+            .collect();
+        assert_eq!(key_tags, vec!["20326", "38696"]);
+
+        // Separately, confirm `domain`'s own parser accepts the same text.
+        assert!(TrustAnchors::from_u8(BUNDLED_ROOT_ANCHOR.as_bytes()).is_ok());
+    }
+
+    #[test]
+    fn recursive_config_toml_honors_static_trust_anchor_override() {
+        let toml = r#"
+            dns_listen = ["127.0.0.1:5300"]
+            per_query_deadline_ms = 2000
+            max_udp_payload_size = 1232
+
+            [resolution]
+            mode = "recursive"
+
+            [resolution.recursive]
+            root_hints = "bundled"
+            root_hints_version = "bundled:v1"
+            trust_anchor = "static"
+            trust_anchor_entries = [
+                ". 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
+            ]
+        "#;
+
+        let config = RuntimeConfig::from_toml_str(toml).unwrap();
+
+        let recursive = config.resolution.recursive.as_ref().unwrap();
+        assert_eq!(
+            recursive.trust_anchor_source,
+            TrustAnchorSource::Static(vec![
+                ". 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
+                    .to_string()
+            ])
+        );
+    }
+
+    #[test]
+    fn recursive_config_toml_rejects_empty_static_trust_anchor_override() {
+        let toml = r#"
+            dns_listen = ["127.0.0.1:5300"]
+            per_query_deadline_ms = 2000
+            max_udp_payload_size = 1232
+
+            [resolution]
+            mode = "recursive"
+
+            [resolution.recursive]
+            root_hints = "bundled"
+            root_hints_version = "bundled:v1"
+            trust_anchor = "static"
+        "#;
+
+        let error = RuntimeConfig::from_toml_str(toml).unwrap_err();
+
+        assert_eq!(error, ConfigError::MissingTrustAnchors);
+    }
+
+    #[test]
+    fn recursive_config_toml_rejects_malformed_static_trust_anchor_entry() {
+        let toml = r#"
+            dns_listen = ["127.0.0.1:5300"]
+            per_query_deadline_ms = 2000
+            max_udp_payload_size = 1232
+
+            [resolution]
+            mode = "recursive"
+
+            [resolution.recursive]
+            root_hints = "bundled"
+            root_hints_version = "bundled:v1"
+            trust_anchor = "static"
+            trust_anchor_entries = ["not a valid zonefile DS line"]
+        "#;
+
+        let error = RuntimeConfig::from_toml_str(toml).unwrap_err();
+
+        assert!(matches!(error, ConfigError::InvalidTrustAnchorEntry { .. }));
+    }
+
     #[test]
     fn config_rejects_unbounded_timing_and_udp_values() {
         let deadline_error = RuntimeConfig::new(
diff --git a/src/config/root-anchor.txt b/src/config/root-anchor.txt
new file mode 100644
index 0000000..39b498d
--- /dev/null
+++ b/src/config/root-anchor.txt
@@ -0,0 +1,12 @@
+; IANA's DNS root zone KSK trust anchors, as published at
+; https://data.iana.org/root-anchors/root-anchors.xml (RFC 9718 format).
+; Digests below were fetched and copied verbatim from that XML on 2026-07-18.
+; Contains both the currently-active KSK-2017 (tag 20326) and the
+; standby/rolled-in KSK-2024 (tag 38696) — RFC 5011 automated rollover is
+; out of scope, so this file requires MANUAL refresh whenever IANA publishes
+; a new root KSK. The scheduled dnssec-anchor-staleness workflow
+; (.github/workflows/dnssec-anchor-staleness.yml) checks this file's digests
+; against IANA on a weekly cadence and alerts (without blocking PRs) when a
+; refresh is needed.
+. 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
+. 172800 IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
