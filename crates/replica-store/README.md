# Replica store

Ciphertext-only peer records, deterministic placement and verified repair batches
for a bounded, synchronous local composition. Its only project dependency is
[compact-store](../compact-store/README.md): canonical format, limits and complete
`EncryptedSnapshot::decode_for_head` validation. No GUI, SQL, FHE, rewards or network
coordinator policy enters this library. Public synthetic tests keep owner keys only
in fixture construction, never in replica stores.

## Ownership and public contract

`ReplicaStore` owns peer configurations and their actual canonical ciphertext byte
records. `register_peer` declares a `PeerId`, `FailureDomainId` and byte quota.
`seed(peer, object, expected, bytes)` accepts an initial copy only after bounded
manifest equality and full-root validation against the caller's independently
trusted current `Commitment`. It cannot overwrite an existing record. `ciphertext`
borrows the stored bytes; unavailable peers cannot serve. There is no secret-key,
plaintext or decryption API. Neither parsing a head nor matching a root chooses the
network's latest authorized head.

Each quota charges the FULL canonical image (manifest, page revisions, nonces,
ciphertext and tags) plus its eight-byte ObjectId record payload. `usage` separates
canonical, record and charged bytes. Map/Vec/allocator overhead, peer configuration,
receive/root-validation temporaries and any transport buffers are additional RAM.
No canonical hash tree is retained. Image limits, peer count, lifetime admitted
ObjectId count and whole-batch staging payload are explicitly bounded by `Bounds`.
These limits do not establish a whole-process RAM or disk-performance target.

`plan_repair(&[ReplicaTarget])` uses caller-supplied current heads and desired
available copy counts. Existing images are fully revalidated. The deterministic
greedy order is ObjectId then PeerId; quota is reserved across the whole batch and
new copies use distinct declared domains. It does not delete valid extra copies,
and it is not a complete placement search: fragmented quotas can cause failure
even when a different global allocation could succeed.

`RepairPlan` is opaque and consumed once. A checked process-local instance identity,
inventory generation and exact targets bind execution; another store, inventory
change or changed current head/copy policy rejects before fetching. Identity is a
local handle property, not a cryptographic/network identity or durable token.

`repair_local(plan, still_current_targets)` copies actual survivor ciphertext into
bounded destination buffers. `repair_with` accepts an untrusted transport callback
`FnMut(PeerId,ObjectId,&mut [u8])->Result<usize>`: exact output size is fixed before
the call, and its returned framed length and complete destination root are checked.
Short, corrupt, stale and transport-failed sources are skipped in stable order.
The callback owns network authorization, deadlines, trailing-byte detection and its
own allocations. All destination bytes are verified and staged before any copy is
published. A recoverable failed batch/quota/source/head check changes no replica.
This is in-memory atomicity, not an fsync/crash/OOM/panic transaction guarantee.

`set_available` records discovered availability without deleting bytes or freeing
quota. All sources disappearing can therefore leave no recoverable current copy;
repair then reports `NoAvailableSource`, rather than inventing data. `remove_current`
refuses to delete the last AVAILABLE full copy matching the supplied current head.
Changing current versions requires an existing current source; repair may replace
stale records only after receiving and validating current ciphertext. Historical
version preservation/garbage collection is outside this lifecycle.

## Caller responsibilities and requirement scope

The application owns agreed snapshot/head state, authorization, peer discovery and
availability inputs, transport, independent fault-domain labels and durable key
management. Labels do not prove independent operators/machines or Sybil resistance.
This is partial support for requirements 6/7/8/9: actual bounded encrypted records,
quota-aware distinct-domain copying and current-root integrity. It does not establish
mass-outage probabilities, malicious availability/storage claims, consensus, query
proofs, decentralized repair scheduling, rewards, authentication of the caller's
head authority, durable persistence, recovery after process exit or a resource SLA.

## Validation

All 14 runtime tests (12 contract + 2 BFV integration) and one compile-fail doctest
passed, together with strict authored all-target Clippy and package format checks.
The contract suite covers survivor repair, correlated labels, full canonical quota,
whole-batch capacity, all-source loss, wrong heads/tampering/short input, untrusted
source fallback, later-object batch failure, stale/foreign plans, last-copy deletion
and target/staging limits. [BFV integration tests](tests/bfv_recovery.rs) repair
actual encrypted data/index images from surviving peers, restore them under the
original owner and execute genuine COUNT/SUM and locally checked UPDATE. A stale
index response rolls back the entire staged data/index repair batch.

Validation used Rust 1.99, required by the BFV development-test dependency. The
library inherits the workspace nominal MSRV 1.91.1; that older toolchain was
not validated. The only normal dependency is compact-store. No new crypto
dependency or key generation is added to the replica-storage library.

```sh
cargo test --release --locked --offline --jobs 2 -p replica-store -- --test-threads=1
cargo clippy --release --locked --offline --jobs 2 -p replica-store --all-targets --no-deps -- -D warnings
cargo fmt -p replica-store -- --check
```

No performance or scale result is claimed by these behavior tests.
