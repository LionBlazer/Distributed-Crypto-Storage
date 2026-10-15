# BFV query core

Experimental owner-online exact BFV roles, extracted from the frozen
`experiments/bfv-byte-limb-core` baseline. This crate is the ongoing owner of its
cryptographic implementation; product adapters depend on this crate and never on
that historical experiment. No production security or query-proof claim follows.

Owner owns the only secret key; PublicSetup contains only original parameters,
relinearization and rotation keys; PeerEvaluator restores public material only.
Inputs are fresh encrypted selected fields. Public contracts include generic
Equal/AtLeast/ClosedRange COUNT/SUM, explicitly caller-asserted exact-index aggregate,
and indexed amount addition. Pending tokens bind operation/keyset/geometry/query ID
and both opaque112-byte heads. Exact aggregate and UPDATE results remain Unverified;
UPDATE callers must locally check arithmetic/overflow before writeback.

Private modules are kernel, exact_index and indexed_update. This crate depends
only on pinned fhe/fhe-traits0.1.1, rand0.9.2, serde/bincode1.3.3, SHA256 and zeroize;
it has no storage, SQL, PIR, GUI, fixture or deployment dependency. Complete exact
selection, trusted heads/freshness, global transaction policy and resource accounting
belong to its caller. Original public setup must be retained for same-key recovery;
secret serialization is currently exposed as a COUNT only, not a recovery image.

Parameters stay native/unfused/level0 N8192/Q218/t114689, CBD variance10, full unchanged
keyset. Independent security/noise/CCA and malicious arithmetic proof gates remain
open. The inherited37 tests/2 compile-fail doctests move with this implementation;
crate imports change only. Extraction validation passed all 37 runtime tests and
two compile-fail doctests in release/locked/offline mode, plus strict all-target
Clippy. The arithmetic source remains byte-identical to the recorded baseline.
Rust 1.99 is retained from the measured baseline; lower MSRV is not claimed.

The owning storage consumer is [compact-query](../compact-query/README.md), whose
explicit BFV module establishes the owner-built exact-index and compact writeback
contract. Headless GUI uses that module; no owner secret enters a peer evaluator.

Owning validation commands (Rust 1.99):

```sh
cargo test --release --locked --offline -p bfv-query-core -- --test-threads=1
cargo clippy --release --locked --offline -p bfv-query-core --all-targets -- -D warnings
```