diff --git a/Cargo.lock b/Cargo.lock
index 8557495..c7b28ff 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -11,6 +11,17 @@ dependencies = [
  "memchr",
 ]
 
+[[package]]
+name = "async-lock"
+version = "3.4.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "290f7f2596bd5b78a9fec8088ccd89180d7f9f55b94b0576823bbbdc72ee8311"
+dependencies = [
+ "event-listener",
+ "event-listener-strategy",
+ "pin-project-lite",
+]
+
 [[package]]
 name = "atomic-waker"
 version = "1.1.2"
@@ -41,6 +52,16 @@ version = "1.12.1"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "fc652a48c352aef3ea3aed32080501cf3ef6ed5da78602a020c991775b0aff04"
 
+[[package]]
+name = "cc"
+version = "1.2.67"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "e17dd265a7d0f31ef544e1b20e03add05d3b45b491b633b10d67145d2acc1a38"
+dependencies = [
+ "find-msvc-tools",
+ "shlex",
+]
+
 [[package]]
 name = "cfg-if"
 version = "1.0.4"
@@ -58,6 +79,15 @@ dependencies = [
  "rand_core",
 ]
 
+[[package]]
+name = "concurrent-queue"
+version = "2.5.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "4ca0197aee26d1ae37445ee532fefce43251d24cc7c166799f4d46817f1d3973"
+dependencies = [
+ "crossbeam-utils",
+]
+
 [[package]]
 name = "cpufeatures"
 version = "0.3.0"
@@ -67,6 +97,30 @@ dependencies = [
  "libc",
 ]
 
+[[package]]
+name = "crossbeam-channel"
+version = "0.5.16"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "d85363c37faeca707aef026efa9f3b34d077bce547e48f770770625c6013679e"
+dependencies = [
+ "crossbeam-utils",
+]
+
+[[package]]
+name = "crossbeam-epoch"
+version = "0.9.20"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "2d6914041f254d6e9176c01941b21115dcfb7089e55135a35411081bd106ef3f"
+dependencies = [
+ "crossbeam-utils",
+]
+
+[[package]]
+name = "crossbeam-utils"
+version = "0.8.22"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "61803da095bee82a81bb1a452ecc25d3b2f1416d1897eb86430c6159ef717c17"
+
 [[package]]
 name = "defmt"
 version = "1.1.1"
@@ -118,11 +172,18 @@ dependencies = [
  "bumpalo",
  "bytes",
  "domain-macros",
+ "futures-util",
  "hashbrown",
  "jiff",
+ "log",
+ "moka",
  "octseq",
+ "rand",
+ "ring",
  "serde",
  "siphasher",
+ "tokio",
+ "tracing",
 ]
 
 [[package]]
@@ -149,9 +210,36 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "39cab71617ae0d63f51a36d69f866391735b51691dbda63cf6f96d042b63efeb"
 dependencies = [
  "libc",
- "windows-sys",
+ "windows-sys 0.61.2",
 ]
 
+[[package]]
+name = "event-listener"
+version = "5.4.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "e13b66accf52311f30a0db42147dadea9850cb48cd070028831ae5f5d4b856ab"
+dependencies = [
+ "concurrent-queue",
+ "parking",
+ "pin-project-lite",
+]
+
+[[package]]
+name = "event-listener-strategy"
+version = "0.5.4"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "8be9f3dfaaffdae2972880079a491a1a8bb7cbed0b8dd7a347f668b4150a3b93"
+dependencies = [
+ "event-listener",
+ "pin-project-lite",
+]
+
+[[package]]
+name = "find-msvc-tools"
+version = "0.1.9"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "5baebc0774151f905a1a2cc41989300b1e6fbb29aff0ceffa1064fdd3088d582"
+
 [[package]]
 name = "fnv"
 version = "1.0.7"
@@ -227,6 +315,17 @@ dependencies = [
  "slab",
 ]
 
+[[package]]
+name = "getrandom"
+version = "0.2.17"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "ff2abc00be7fca6ebc474524697ae276ad847ad0a6b3faa4bcb027e9a4614ad0"
+dependencies = [
+ "cfg-if",
+ "libc",
+ "wasi",
+]
+
 [[package]]
 name = "getrandom"
 version = "0.4.3"
@@ -539,7 +638,27 @@ checksum = "50b7e5b27aa02a74bac8c3f23f448f8d87ff11f92d3aac1a6ed369ee08cc56c1"
 dependencies = [
  "libc",
  "wasi",
- "windows-sys",
+ "windows-sys 0.61.2",
+]
+
+[[package]]
+name = "moka"
+version = "0.12.15"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "957228ad12042ee839f93c8f257b62b4c0ab5eaae1d4fa60de53b27c9d7c5046"
+dependencies = [
+ "async-lock",
+ "crossbeam-channel",
+ "crossbeam-epoch",
+ "crossbeam-utils",
+ "equivalent",
+ "event-listener",
+ "futures-util",
+ "parking_lot",
+ "portable-atomic",
+ "smallvec",
+ "tagptr",
+ "uuid",
 ]
 
 [[package]]
@@ -548,7 +667,7 @@ version = "0.50.3"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "7957b9740744892f114936ab4a57b3f487491bbeafaf8083688b16841a4240e5"
 dependencies = [
- "windows-sys",
+ "windows-sys 0.61.2",
 ]
 
 [[package]]
@@ -604,6 +723,12 @@ dependencies = [
  "thiserror 2.0.18",
 ]
 
+[[package]]
+name = "parking"
+version = "2.2.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "f38d5652c16fde515bb1ecef450ab0f6a219d619a7274976324d5e377f7dceba"
+
 [[package]]
 name = "parking_lot"
 version = "0.12.5"
@@ -723,7 +848,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "c7f5fa3a058cd35567ef9bfa5e75732bee0f9e4c55fa90477bef2dfcdbc4be80"
 dependencies = [
  "chacha20",
- "getrandom",
+ "getrandom 0.4.3",
  "rand_core",
 ]
 
@@ -783,6 +908,20 @@ version = "0.8.11"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4"
 
+[[package]]
+name = "ring"
+version = "0.17.14"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7"
+dependencies = [
+ "cc",
+ "cfg-if",
+ "getrandom 0.2.17",
+ "libc",
+ "untrusted",
+ "windows-sys 0.52.0",
+]
+
 [[package]]
 name = "rustversion"
 version = "1.0.22"
@@ -856,6 +995,12 @@ dependencies = [
  "lazy_static",
 ]
 
+[[package]]
+name = "shlex"
+version = "2.0.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba"
+
 [[package]]
 name = "signal-hook-registry"
 version = "1.4.8"
@@ -891,7 +1036,7 @@ source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "c3d1e2c7f27f8d4cb10542a02c49005dbd6e93095799d6f3be745fae9f8fedd4"
 dependencies = [
  "libc",
- "windows-sys",
+ "windows-sys 0.61.2",
 ]
 
 [[package]]
@@ -922,6 +1067,12 @@ dependencies = [
  "syn",
 ]
 
+[[package]]
+name = "tagptr"
+version = "0.2.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "7b2093cf4c8eb1e67749a6762251bc9cd836b6fc171623bd0a9d324d37af2417"
+
 [[package]]
 name = "thiserror"
 version = "1.0.69"
@@ -995,7 +1146,7 @@ dependencies = [
  "signal-hook-registry",
  "socket2",
  "tokio-macros",
- "windows-sys",
+ "windows-sys 0.61.2",
 ]
 
 [[package]]
@@ -1054,6 +1205,7 @@ version = "0.1.44"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "63e71662fa4b2a2c3a26f570f037eb95bb1f85397f3cd8076caed2f026a6d100"
 dependencies = [
+ "log",
  "pin-project-lite",
  "tracing-attributes",
  "tracing-core",
@@ -1128,12 +1280,29 @@ version = "1.0.24"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "e6e4313cd5fcd3dad5cafa179702e2b244f760991f45397d14d4ebf38247da75"
 
+[[package]]
+name = "untrusted"
+version = "0.9.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1"
+
 [[package]]
 name = "utf8_iter"
 version = "1.0.4"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "b6c140620e7ffbb22c2dee59cafe6084a59b5ffc27a8859a5f0d494b5d52b6be"
 
+[[package]]
+name = "uuid"
+version = "1.23.4"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "bf80a72845275afea99e7f2b434723d3bc7e38470fcd1c7ed39a599c73319a53"
+dependencies = [
+ "getrandom 0.4.3",
+ "js-sys",
+ "wasm-bindgen",
+]
+
 [[package]]
 name = "valuable"
 version = "0.1.1"
@@ -1197,6 +1366,15 @@ version = "0.2.1"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5"
 
+[[package]]
+name = "windows-sys"
+version = "0.52.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "282be5f36a8ce781fad8c8ae18fa3f9beff57ec1b52cb3de0789201425d9a33d"
+dependencies = [
+ "windows-targets",
+]
+
 [[package]]
 name = "windows-sys"
 version = "0.61.2"
@@ -1206,6 +1384,70 @@ dependencies = [
  "windows-link",
 ]
 
+[[package]]
+name = "windows-targets"
+version = "0.52.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "9b724f72796e036ab90c1021d4780d4d3d648aca59e491e6b98e725b84e99973"
+dependencies = [
+ "windows_aarch64_gnullvm",
+ "windows_aarch64_msvc",
+ "windows_i686_gnu",
+ "windows_i686_gnullvm",
+ "windows_i686_msvc",
+ "windows_x86_64_gnu",
+ "windows_x86_64_gnullvm",
+ "windows_x86_64_msvc",
+]
+
+[[package]]
+name = "windows_aarch64_gnullvm"
+version = "0.52.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "32a4622180e7a0ec044bb555404c800bc9fd9ec262ec147edd5989ccd0c02cd3"
+
+[[package]]
+name = "windows_aarch64_msvc"
+version = "0.52.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "09ec2a7bb152e2252b53fa7803150007879548bc709c039df7627cabbd05d469"
+
+[[package]]
+name = "windows_i686_gnu"
+version = "0.52.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "8e9b5ad5ab802e97eb8e295ac6720e509ee4c243f69d781394014ebfe8bbfa0b"
+
+[[package]]
+name = "windows_i686_gnullvm"
+version = "0.52.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "0eee52d38c090b3caa76c563b86c3a4bd71ef1a819287c19d586d7334ae8ed66"
+
+[[package]]
+name = "windows_i686_msvc"
+version = "0.52.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "240948bc05c5e7c6dabba28bf89d89ffce3e303022809e73deaefe4f6ec56c66"
+
+[[package]]
+name = "windows_x86_64_gnu"
+version = "0.52.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "147a5c80aabfbf0c7d901cb5895d1de30ef2907eb21fbbab29ca94c5b08b1a78"
+
+[[package]]
+name = "windows_x86_64_gnullvm"
+version = "0.52.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "24d5b23dc417412679681396f2b49f3de8c1473deb516bd34410872eff51ed0d"
+
+[[package]]
+name = "windows_x86_64_msvc"
+version = "0.52.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "589f6da84c646204747d1270a2a5661ea66ed1cced2631d546fdfb155959f9ec"
+
 [[package]]
 name = "winnow"
 version = "1.0.3"
diff --git a/Cargo.toml b/Cargo.toml
index de1c25c..e007ee0 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -9,7 +9,10 @@ license = "Apache-2.0"
 
 [dependencies]
 bytes = "1"
-domain = { version = "0.12.1", default-features = false, features = ["zonefile", "bytes", "std", "siphasher"] }
+# unstable-validator pulls in DNSSEC validation (domain::dnssec::validator); ring is
+# the pure-Rust crypto backend for signature verification. Both transitively add
+# moka and unstable-client-transport as new deps — expected, not a bug.
+domain = { version = "0.12.1", default-features = false, features = ["zonefile", "bytes", "std", "siphasher", "unstable-validator", "ring"] }
 http-body-util = "0.1"
 hyper = { version = "1", features = ["server", "http1"] }
 hyper-util = { version = "0.1", features = ["tokio"] }
