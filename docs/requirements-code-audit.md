# Requirements code audit

Source review for the 2026-10-15 prototype changes, against
[REQUIREMENTS.md](../REQUIREMENTS.md) and its synchronized
[AGENTS.md](../AGENTS.md) contract. This is a data-flow and failure-contract review,
not an independent cryptographic security assessment or a claim that all target
requirements are implemented.

## Scope

All seven workspace crates were traced through their owning boundaries:

| Crate | Reviewed behavior |
| --- | --- |
| [fhe-playground](../crates/fhe-playground/README.md) | SQL planning, worker dispatch/commit, actual replica custody, owner view, UI actions and virtual transport |
| [bfv-query-core](../crates/bfv-query-core/README.md) | Owner/public evaluator separation, encrypted predicates/aggregates/projection/insertion/addition, wire and completion bindings |
| [compact-query](../crates/compact-query/README.md) | BFV and retained TFHE paths, authenticated index selection, current heads, compact writeback |
| [compact-store](../crates/compact-store/README.md) | Owner-only AEAD keys, canonical images, bounded decoding, page proofs and replacement/growth |
| [replica-store](../crates/replica-store/README.md) | Actual ciphertext records, quotas, complete data/index bundles, survivor repair and publication |
| [peer-protocol](../crates/peer-protocol/README.md) | Session/request/replay/cancellation lifecycle and its explicit authentication limits |
| [fhe-prototype](../crates/fhe-prototype/README.md) | Original TFHE comparisons, encrypted overflow/update, compressed images and public-fixture measurement harness |

Public fixture oracles in tests/examples compare against completed encrypted
operations; they are not SQL answer sources. Ignored UI previews supply explicit
renderer fixtures and execute no query.

The source/dataflow pass also covers the 21 standalone experiment Cargo manifests,
146 Rust files and 24 PowerShell/Python scripts: BFV SIMD/byte-limb variants and the
frozen core; private BFV index/range/amortization/disk/update; PIR scheduling/cache;
owner-state/recovery/process restart; and bulk disk/scale. Manifest-generating
private-access harnesses, the generated TFHE multibit probe and BFV security
manifest/optional estimator are included. Their public oracle and measured/modelled
timer boundaries were traced; no additional plaintext answer substitution,
cryptographic stub or fabricated elapsed-time path was found. Product manifests
and Rust sources import none of these standalone packages.

Historical benchmarks were not rerun. Ignored generated snapshots, dependency/SDK
implementations and old raw measurements are not comprehensively re-audited here.
This is a first-party source audit, not an independent cryptographic security review.

Seven older standalone runners have a known clean-reproduction defect:
`private-bfv-{index,range,amortization,disk}/run.ps1` and
`private-pir-{batch,expansion,scratch}/run.ps1` copy only the former single-file BFV
core plus kernel. Their current default frozen core also declares child modules,
which those runners omit. Reproducing the recorded result requires the matching
report-recorded earlier source via `-BfvCoreDirectory`, including its hashes/lock,
or the archived measured package. A clean run of those current defaults is not
claimed. The later recursive-copy runners and source-pinned bulk/restart preparers
retain their distinct provenance contracts. No frozen measured source or historical
measurement was rewritten to conceal this limit.

## Findings and changes

1. **Fixture-based topology rebuild was an operational bypass.** The old default
   manager repartition sealed `owner_rows` again after peer addition/removal. That
   could recreate lost data from the inspector fixture. New databases now begin in
   actual ciphertext custody with a minimum of one copy. Adding peers starts them
   empty; removing peers removes their physical copies. Losing every current copy
   produces an unavailable shard, including with a visible owner fixture.
2. **TFHE completion missed an index-only version change.** The retained TFHE
   `PreparedQuery` captured only the data head. It now retains the expected index
   head locally, and both aggregate completion and UPDATE reject a changed index
   before decryption/writeback. The request/output wire is unchanged.
3. **Generic BFV completion lacked a local owner-keyset guard.** `PendingQuery` now
   captures its owner's public-setup digest. A different owner with identical
   parameters cannot complete that pending query. Indexed operation wire domains
   remain separate; this local guard is not authentication of a malicious response.
4. **Virtual response wording overstated the transport.** Local encrypted evaluation
   and simulated response delivery are described separately. Animated packets carry
   operation IDs/session tokens, not complete BFV request/result byte streams.
   The underlying local BFV request and result codecs really process ciphertext.
5. **Peer-ID allocation could overflow.** Updating an existing profile no longer
   allocates an unused next ID. A request needing a new exhausted ID fails before
   topology changes, without wrapping or reusing an identity.

INSERT does not rebuild the database from the owner fixture. Its new encrypted row
is placed in a staging lane; the public-only evaluator rotates that lane into the
next position and adds it to the encrypted target relation. Owner completion decodes
that returned ciphertext and validates old/new rows before compact storage growth.
Only the affected shard is repacked. The existing AEAD format binds row geometry,
so growing that shard requires fresh page encryption; it does not require fresh keys
or replacing unrelated tables. Quota, current-head and all-or-nothing publication
checks apply before the new replica images become live.

## Plaintext and FHE boundaries

The following owner work is intentional, rather than an FHE answer substitute:

- encrypting authorized source/input values;
- authenticating/decrypting index and selected storage pages before fresh FHE input
  preparation in the explicit owner-online exact-index model;
- decrypting the completed encrypted peer response;
- comparing decoded UPDATE/INSERT values against authenticated inputs before
  writeback. This local check does **not** satisfy the succinct proof requirement;
- rendering the owner's editable draft/inspector and checking explicitly public test
  fixtures outside the query implementation.

Peers receive evaluation material and ciphertext, not the owner's secret keys or
plaintext fields. BFV exact-index COUNT/SUM really rotates/adds encrypted weights;
row SELECT really multiplies encrypted originals by an encrypted projection mask.
Generic BFV and TFHE predicate paths really perform encrypted comparisons. Copying
and authenticating already encrypted storage does not require dummy FHE arithmetic.
The planner may fold predicates that are impossible for the public u8 schema
(`age < 0`, `age > 255`, reversed BETWEEN). That decision inspects no stored data
and carries no FHE timing claim. Potentially matching predicates, even when their
actual result is empty, follow authenticated selection and encrypted evaluation.

## Requirements still open

| Requirements | Remaining limit |
| --- | --- |
| 1, 7 | GUI execution, placement and head authority are composed by one local manager. This is not a deployed decentralized scheduler or consensus system. |
| 2, 5 | Exact-index input preparation needs the owner online and exposes selected addresses/cardinality. The final leakage policy and independent BFV security/CCA assessment remain open. |
| 3 | One fixed schema and a bounded SQL subset; no general joins, DELETE, arbitrary schema changes or distributed transactions. |
| 4, 6, 10 | Storage/RAM/latency measurements apply to their recorded configurations. They do not establish a general 2x ratio, a whole-process 2 GB bound, persistent 10–30 GB peers or a 50–100 ms SQL/WAN guarantee. |
| 8 | Repair uses actual ciphertext survivors, but fault-domain labels are supplied facts. No proof of independent domains, malicious availability or durable GUI/key recovery is implemented. |
| 9 | AEAD/root authentication exists. Session IDs and request tokens do not authenticate users, establish write authorization or resist Sybil identities. |
| 11–12 | FHE results remain explicitly unverified. Tests demonstrate that an in-bounds malicious arithmetic forgery can pass metadata/bounds checks; no computation/completeness proof is implemented. |
| 13 | Locally expected data/index heads are checked. Decentralized agreement on the latest authorized heads and durable anti-rollback authority remain external. |
| 14–17 | No reward subsystem is enabled or claimed. |

These are unimplemented requirements, not optional guarantees silently waived by
the prototype. Requirements were not weakened to make the audit pass.

## Verification

Release/locked/offline checks on 2026-10-15, Rust 1.99, two Cargo build jobs,
eight Rayon threads and serial tests:

| Boundary | Result |
| --- | --- |
| BFV core | 53 runtime tests and 3 compile-fail doctests passed |
| Compact store | 27 runtime tests passed |
| Compact query, BFV-only | 25 runtime tests and 1 compile-fail doctest passed |
| Compact query, default TFHE library | 24 runtime tests passed |
| Playground SQL/worker/UI | 165 runtime tests passed; preview exporter opt-in |

```sh
cargo test --release --locked --offline -p bfv-query-core -- --test-threads=1
cargo test --release --locked --offline -p compact-store -- --test-threads=1
cargo test --release --locked --offline -p compact-query --no-default-features --features bfv-experiment -- --test-threads=1
cargo test --release --locked --offline -p compact-query --lib -- --test-threads=1
cargo test --release --locked --offline -p fhe-playground --no-fail-fast -- --test-threads=1
cargo clippy --release --locked --offline -p bfv-query-core -p compact-store -p compact-query --all-features --all-targets -- -D warnings
cargo clippy --release --locked --offline -p fhe-playground --all-targets -- -D warnings
cargo fmt --all -- --check
```

Both owning-library and GUI Clippy checks passed. UI tests use in-memory egui input/meshes;
the opt-in preview renderer also passed, exporting 16 public-fixture CPU images.
Peer storage and preset menus were visually checked at 1500x900 and 1180x720 after
settling menu animation. Storage previews use actual encrypted-engine accounting.
No native GUI or user-desktop input is required. Requirements-mirror consistency and relative
documentation links are checked separately. These tests are correctness/regression
evidence, not new latency, storage-ratio, security or query-proof measurements.
