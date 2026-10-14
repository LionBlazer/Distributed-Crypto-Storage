# Private age index, Spiral pages and fresh BFV aggregation

This isolated one-million-row composition implements actual authenticated
PaddedV2 age index -> native Spiral pages -> fresh owner BFV encryption ->
public peer EQ COUNT/SUM -> owner unverified decryption. It passes 64 complete
visible/private reads and a fresh private read after an actual compact
replacement. The [measured report](../../docs/experiment-private-bfv-index.md)
contains per-age/profile/header timings, bytes, native peaks and limitations.

This module owns retrieval/query composition and whole-operation accounting.
Direct module dependencies are compact-store (canonical snapshots, Merkle,
AEAD owner operations), the pinned Spiral SDK (real single-server encrypted
page queries), and compact-bfv-byte-limb-core (fresh packing/encryption,
public-only evaluator and explicitly unverified output). Supporting libraries
are serde/serde_json, getrandom, zeroize and Rayon. It has no TFHE dependency,
plaintext peer index, persistent FHE row cache or precomputed query answers.

## Files and entry points

- src/main.rs: complete posting selection through PageSource, real serialized
  visible/private reads, owner verification, fixed Rows16 BFV composition,
  paired matrix, corruption/freshness rejection and actual owner replacement.
- src/padded_index_codec.rs: byte-identical frozen PaddedV2 callback adapter.
- src/padded_index_codec_tests.rs: copied owning codec contract tests.
- src/resources.rs: Windows current/native-peak working/private counters and
  thread sampling; exits above the decimal 2,000,000,000 B cap.
- run.ps1: verifies the exact SDK revision, prepares ignored source copies,
  builds the unique package with a dedicated target and records source hashes.
- Cargo.toml/Cargo.lock: standalone workspace and locked dependencies.

The BFV API lives in the [separate core](../bfv-byte-limb-core/README.md).
Owner::prepare accepts verified fields and trusted heads/query ID;
PeerEvaluator::evaluate accepts encrypted serialized bytes only; the owner
consumes PendingQuery with decrypt_unverified. No selected address, original
storage ciphertext/nonce or owner secret enters the BFV peer request.
The owner is online and reads selected plaintext. Immutable borrows prevent
concurrent snapshot/head replacement during a query in this harness.

## Query scope and public profiles

Each query obtains the complete rare EQ group from the authenticated index.
It rejects more than 16 rows or groups needing more than one posting page
or one 2048-row data page; no truncation. Each native PIR database has
512 fixed 8192-byte records; PaddedV2 index plaintext pages are 4096 bytes.

Both AddressOnly and Fixed16 perform the same fresh encrypted 16-slot BFV
circuit, including empty results. Inactive slots have encrypted zero value/
COUNT weights; actual active count stays in the owner token. AddressOnly
omits posting/data RPCs for an absent group, exposing empty versus nonempty.
Fixed16 performs real authenticated dummy reads and asserts equal public
request/response lengths and RPC counts across all four cardinalities.
Visible reveals page addresses; Private uses actual fresh Spiral queries.
No leakage policy or active-feedback security is approved by this comparison.

Cached costs 2276 B including duplicated bindings, with another 224 B trusted
heads counted separately; Uncached retrieves the authenticated header per
query. Nonempty Cached uses three sequential exchanges (posting,data,BFV),
Uncached four. Fixed16 preserves these counts for absent results; AddressOnly
absent uses one/two. Fixture oracles and owner logs are outside peer wire.

## Reproduce headlessly

Use the existing Rust 1.99/MSVC toolchain and the Windows resource adapter.
The runner clones only pinned ignored SDK source if absent; -Offline requires
existing source/dependencies. -PrepareOnly performs no compilation or crypto.
The checkout must also contain experiments/bfv-byte-limb-core; an isolated
caller may explicitly supply -BfvCoreDirectory. Set project-local Cargo home
and a dedicated target, avoiding shared same-named stale artifacts.

~~~powershell
$taskCargo = 'E:/Users/white/.cargo/bin/cargo.exe'
$taskCache = 'E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home'
$taskTarget = 'E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target/private-bfv-index'
./experiments/private-bfv-index/run.ps1 -PrepareOnly
$env:CARGO_HOME = $taskCache
$env:CARGO_TARGET_DIR = $taskTarget
& $taskCargo test --release --locked --offline --jobs 2 --manifest-path .local/private-bfv-index/package/Cargo.toml -- --test-threads=1
& $taskCargo clippy --release --locked --offline --jobs 2 --manifest-path .local/private-bfv-index/package/Cargo.toml --all-targets --no-deps -- -D warnings
./experiments/private-bfv-index/run.ps1 -Rows 1000000 -Rounds 8 -Threads 8 -Cargo $taskCargo -CargoHome $taskCache -TargetDirectory $taskTarget -Offline
~~~

Rounds 8 visits each age twice: 64 complete operations across two access
controls, two profiles and two header modes. All fixture data are public
synthetic inputs; fixture maps check returned ordinals/aggregates only after
the complete timer. Ciphertext-only freshness evidence is included in timing.
Generated sources/core copies and JSONL remain in ignored .local/private-bfv-index.
Actual runtime parameters/key bytes and source hashes are recorded. No global
installation, GUI, service, branch mutation or vendor commit is required.

## Validated result and remaining limits

16 focused release tests and authored strict Clippy pass. All 64 measured
whole reads are exact and under 500 ms locally, with only two samples per
case. Actual owner replacement/cache rebuild/header refresh/fresh private
read takes 695.437 ms. Seven malformed/stale retrieval responses and complete
oversized groups abort before fresh BFV preparation.

Canonical data+index are 1.6883827x the same 3,000,000 B logical plaintext.
The single-table known joint key/owner subtotal is 6.738583x; the full 2x
goal remains open. Native combined peak working/private bytes are
690,491,392/697,425,920, including setup. The two retained transient NTT
caches cost 67,108,864 B RAM and persist zero bytes.

The BFV profile retains the release's ABOUT128 label and unresolved independent
security/worst-case-noise validation. Results remain unverified against
malicious arithmetic. EQ only is measured here; core GE/range timings are not
composed evidence. Network/disk/restart, multi-table retention, concurrent
trusted heads, private writes, larger groups, arbitrary SQL and computation/
completeness proofs remain open. This mutation is not BFV UPDATE.
