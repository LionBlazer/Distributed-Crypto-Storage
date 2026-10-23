# Parallel fresh Word and Query verification

Executed 2026-10-23 in the same Windows/MSVC Rust 1.99.0 environment as the
[client proving comparison](../../../../../storage-client/src/word_query/PROVING-VALIDATION.md),
with release opt-level3, native CPU, locked/offline dependencies, Cargo jobs2 and
eight shared Rayon workers. The complete network SQL/FOR UPDATE target is unmet.

## Receiving behavior

`hash::Verifier::fresh_query` joins independent Word and fused Query native
verification. Frame bounds, original product arithmetic and complete DATA binding
remain before dispatch. Each job borrows immutable public setup and the captured
complete expectation, constructing its own fresh native configuration. The Word
checked value is dropped inside its job. Both results finish before return; Word
retains error priority when both fail. An early Word error does not cancel the
other bounded check. No verdict cache, private witness sharing, pool construction,
detached work or proof/profile change is introduced.

The engine's `hash::join` delegates to its existing pinned P3 scheduler. Without
`transcript-audit` it forwards both jobs directly. With that optional feature,
each job temporarily installs the caller's exact capture choice, including no
capture, then restores the worker's previous scope on return or unwind. Only the
original capture closes recording; shared 64-trace/8MiB bounds remain intact.
No new registry normal dependency is needed.

## Alternating complete local intervals

The baseline already joins proving and overlaps public receiving setup with it.
Only fresh Word/Query receiving changes. The unchanged
[local prepared-query interval](../../../../../storage-client/src/word_query/PREPARATION-VALIDATION.md)
includes private Query preparation, the actual SDK FHE product/certificate,
complete read expectation, independent public receiving setup overlapped with
proof production, both fresh native proofs, retained-DATA receiving and protected
owner completion. It excludes prior SQL compilation/current-state witness
synthesis, original query encryption, role-only producer setup, immutable
installation, network, fresh weighted agreement and finalized locks. Overlapping
phase durations are not summed.

No heavy build or other test ran during these six alternating observations.
Every process ran the same five original owning client scenarios and assertions.

| Capture | Fresh verification | Entire local interval ms | Fresh receiving ms | Native proving ms |
| --- | --- | ---: | ---: | ---: |
| r687 | joined | 548.529 | 79.283 | 424.090 |
| r688 | sequential | 525.398 | 102.091 | 379.948 |
| r689 | joined | 444.669 | 77.226 | 330.885 |
| r690 | sequential | 462.298 | 85.871 | 336.118 |
| r691 | joined | 467.424 | 78.669 | 347.489 |
| r692 | sequential | 524.606 | 86.647 | 393.572 |

Receiving min/median/max were 85.871 /86.647 /102.091 ms sequentially and
77.226 /78.669 /79.283 ms joined. The observed median reduction is 7.978 ms
(9.2%). Entire local interval medians were 524.606 and 467.424 ms (10.9% lower
in this short series); ranges were 462.298–525.398 and 444.669–548.529 ms.
The first joined call was slower than its adjacent sequential call. Proving also
varied despite unchanged production code; the whole-interval median is not an
isolated verification speedup or a stable latency distribution.

The largest joined sample exceeds 500 ms. Even the smallest lacks required
network/freshness/finality/lock work. No complete SQL latency bound, composed
cryptographic security or live Predicate admission is established.

## Verification and provenance

The r682 image was built from commit `2845ee18904a46965267d5a789d98dc40557db8f`, passed
the five owning scenarios at r683 and was archived before edits. Its original
source hash map/native receipt remain distinct from current observer workspace
hashes. It is explicitly a historical executable.

| Image | Bytes | SHA256 |
| --- | ---: | --- |
| r682 sequential receiving | 28,657,152 | `4D631CA019F903063AEA9F5BB15B48E90EEB053054665ACDB63CA2DF15F648E7` |
| r686 joined receiving | 28,635,136 | `0AB35895B9817299D7B48087357A81756A9C6405ADFF35E5E71B31E8D04A1B9B` |

Observers pinned the exact image/source provenance and five-case contract, held
the directly launched process handle/image/creation identity, sampled every 20 ms
and retained 120 s/1792 MiB whole-process fuses. All six exited with code 0 without faults or
forced cleanup. Sequential/joined maximum OS working sets were
715,018,240 /716,566,528 bytes; private-byte peaks 731,303,936 /734,351,360 bytes.
These isolated-process observations do not bound a complete production peer.

The scenarios retain actual Source/Role3/DATA/Word/Query proofs, the SDK product,
all 4096 output coefficients, damaged/missing/foreign evidence, mixed suites,
replay, fresh entropy, single-use inputs and prepared-input drop. The owning
registry test additionally checks two simultaneous native OOD failures retain
Word-first errors, then a genuine read succeeds on the same public receiver.

The r693 build and r694 native gate also passed with transcript audit: five
families, 77 challenge groups, 1335 accepted base samples, 78 transcript mutations,
75 typed CAP roots, 3 receiver PP caps, 21 authenticated input commitments and 5
damaged opening cases remained covered. Moving configuration creation onto
workers did not lose verifier traces. This gate took 9.38 s including setup and
hostile cases; that is test duration, not SQL latency or a comparison sample.
Its OS peak was 587,030,528 bytes and private peak 573,276,160, with normal exit 0.
The separate engine gate passed 24 primitive/audit tests, including new worker
enrollment, independent captures, Some/None scope masking, panic restoration and
closed-context reuse. Diagnostic evidence remains separate from a security proof.

Release all-target Clippy passed for the engine with audit, the registry with
owner-read, and the client with word-query. Formatting, local document links and
the canonical requirements mirror/test passed. The live transport and admission
boundary did not change, so no additional multi-process gate was needed here.

Generated binaries, proof frames and receipts remain outside Git. The aggregate
six-capture record `.local/native-verify-comparison-r687/result.json` has SHA256
`DB63091410A67AE7D3D608881C8049C2429088575EE21D4CFF6C52CA8F8AEDFF` and
includes every receipt hash, image and phase line. The r694 receipt has SHA256
`16AEA2CFD69005554A83881B43EBB1A010EBD8BD7E284C354441027D0BD24276`.

Reproduce owning behavior and affected checks:

```powershell
cargo test --release --locked -p storage-client --features word-query --lib word_query:: -- --nocapture --test-threads=1
cargo test --release --locked -p registry200-proof --features owner-read --lib registry_progress::word::read::hash::tests:: -- --nocapture --test-threads=1
cargo test --release --locked -p bfv-hiding-stark --features transcript-audit --lib hash:: -- --test-threads=1
cargo clippy --release --locked -p bfv-hiding-stark --features transcript-audit --all-targets -- -D warnings
cargo clippy --release --locked -p registry200-proof --features owner-read --all-targets -- -D warnings
cargo clippy --release --locked -p storage-client --features word-query --all-targets -- -D warnings
cargo test --release --locked -p repository-contracts --test requirements_sync
```
