diff --git a/Cargo.lock b/Cargo.lock
index d1c1e7a..764c2e0 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -53,6 +53,26 @@ version = "1.0.4"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801"
 
+[[package]]
+name = "chacha20"
+version = "0.10.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "d524456ba66e72eb8b115ff89e01e497f8e6d11d78b70b1aa13c0fbd97540a81"
+dependencies = [
+ "cfg-if",
+ "cpufeatures",
+ "rand_core",
+]
+
+[[package]]
+name = "cpufeatures"
+version = "0.3.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "8b2a41393f66f16b0823bb79094d54ac5fbd34ab292ddafb9a0456ac9f87d201"
+dependencies = [
+ "libc",
+]
+
 [[package]]
 name = "defmt"
 version = "1.1.1"
@@ -108,6 +128,7 @@ dependencies = [
  "jiff",
  "octseq",
  "serde",
+ "siphasher",
 ]
 
 [[package]]
@@ -206,6 +227,18 @@ dependencies = [
  "slab",
 ]
 
+[[package]]
+name = "getrandom"
+version = "0.4.3"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099"
+dependencies = [
+ "cfg-if",
+ "libc",
+ "r-efi",
+ "rand_core",
+]
+
 [[package]]
 name = "hashbrown"
 version = "0.17.1"
@@ -677,6 +710,29 @@ dependencies = [
  "proc-macro2",
 ]
 
+[[package]]
+name = "r-efi"
+version = "6.0.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf"
+
+[[package]]
+name = "rand"
+version = "0.10.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "c7f5fa3a058cd35567ef9bfa5e75732bee0f9e4c55fa90477bef2dfcdbc4be80"
+dependencies = [
+ "chacha20",
+ "getrandom",
+ "rand_core",
+]
+
+[[package]]
+name = "rand_core"
+version = "0.10.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69"
+
 [[package]]
 name = "rdns"
 version = "0.1.6"
@@ -691,6 +747,7 @@ dependencies = [
  "opentelemetry-prometheus",
  "opentelemetry_sdk",
  "prometheus",
+ "rand",
  "serde",
  "serde_json",
  "socket2",
@@ -809,6 +866,12 @@ dependencies = [
  "libc",
 ]
 
+[[package]]
+name = "siphasher"
+version = "1.0.3"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "8ee5873ec9cce0195efcb7a4e9507a04cd49aec9c83d0389df45b1ef7ba2e649"
+
 [[package]]
 name = "slab"
 version = "0.4.12"
diff --git a/Cargo.toml b/Cargo.toml
index 355e4e7..69ba729 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -9,7 +9,7 @@ license = "Apache-2.0"
 
 [dependencies]
 bytes = "1"
-domain = { version = "0.12.1", default-features = false, features = ["zonefile", "bytes", "std"] }
+domain = { version = "0.12.1", default-features = false, features = ["zonefile", "bytes", "std", "siphasher"] }
 http-body-util = "0.1"
 hyper = { version = "1", features = ["server", "http1"] }
 hyper-util = { version = "0.1", features = ["tokio"] }
@@ -18,6 +18,7 @@ opentelemetry = { version = "0.32.0", default-features = false, features = ["met
 opentelemetry-prometheus = "0.32"
 opentelemetry_sdk = { version = "0.32.1", default-features = false, features = ["metrics"] }
 prometheus = "0.14"
+rand = "0.10"
 serde = { version = "1", features = ["derive"] }
 serde_json = "1.0.150"
 socket2 = "0.6"
