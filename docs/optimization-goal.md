# Compact FHE query investigation

Active goal: at most 2x canonical data storage and at most 500 ms per measured
query, while retaining encrypted peer computation. The earlier 100/50 ms indexed
targets remain stretch targets. These are goals, not established capabilities.
Arbitrary SQL remains the direction; each result below must identify its actual
supported query, input size and privacy model.

The prototype branch is `codex/feature/fhe-prototype`. Isolated experiments record
their base commit; only reviewed, validated improvements are promoted to that branch.
See [earlier measurements](fhe-optimization.md) before repeating experiments.

## Acceptance and accounting

- Count exact serialized canonical data, including format/authentication metadata
  and every retained data overlay or persistent FHE cache. Report indexes, keys,
  owner state, replicas, RAM and wire traffic separately and in combined totals.
  A persistent expanded copy cannot be renamed an index to satisfy 2x.
- Exercise varied public records, absent/duplicate matches, exact arithmetic,
  rejected overflow, repeated updates and restart. Fixed-page replacement alone
  does not establish the INSERT/DELETE or durable file lifecycle.
- Time the full supported request: preparation, input restoration/conversion,
  execution, response serialization, verification and owner decryption. Show cold
  and warm measurements, sample counts, CPU threads and transport assumptions.
  Excluded network, consensus or computation proofs must remain explicit.
- Owner secret keys and plaintext stay outside peers. No smaller cryptographic
  security parameters, precomputed answer substitution or noncolluding-server
  assumption is silently accepted. Merkle retrieval proofs are not SQL proofs.
- Compare both visible and concealed index access. Neither leakage policy has
  been selected. See [the privacy comparison](index-privacy.md).

## Experiment ledger

| Experiment | State | What it establishes / next check |
| --- | --- | --- |
| Existing compressed TFHE image | Measured | 50.31x at 1024 three-byte rows; fails storage target |
| Narrow COUNT, multi-input SUM, overflow carry reuse | Reviewed and promoted; 42 owning/dependent tests passed | [Paired measurements](experiment-fast-scan.md): scan 2.68–4.16x faster, UPDATE 1.10–1.30x; storage unchanged |
| Authenticated symmetric pages | Reviewed and promoted; 19 tests passed | [One million rows](experiment-compact-store.md): 1.062549x, 1.145952x including tree hashes; 1000 replacements retain size; no FHE |
| TFHE 1.8.1 compact-to-FHE conversion | Reviewed opt-in [four-mode probe](transciphering-probe.md), actual encrypted COUNT/SUM | AES-radix: 1.033854x page, 1.059896x with owner state before FHE keys; eight-worker 19-warm-sample median/max 117.60/151.78 ms; two-worker max 573.88 ms |
| Native encrypted PRF mask regeneration | Implemented raw and rerandomized controls in the same probe | No persistent FHE masks; 64-row native preparation takes 5.61/5.88 seconds; rerandomized query exceeds 500 ms; storage/security composition still needs review |
| Visible authenticated searchable index + FHE + compact updates | [Reviewed compact-query implementation](experiment-compact-query.md), used by the GUI with eight scoped row initiators | Million-row combined run: 1/4/16-row aggregate max 100.98/477.71/1240.72 ms; 100 point updates p95 264.27 ms; whole-process peak 373.81 MiB; transport/proofs excluded |
| Padded delta-varint age index | [Reviewed V2 format and four-distribution measurement](experiment-index-compression.md) | Data+index 1.743071x; with rebuildable hashes 1.837012x; with all fixed keys and owner state 61.957164x for this 3 MB fixture; no distribution-dependent total length |
| Narrow encrypted request/output and conditional zero | [Reviewed and integrated kernel](experiment-query-wire.md), unchanged cryptographic parameters | One-row encrypted response 527169→148497 bytes; final 1/4/16-row max 91.73/419.42/1334.40 ms; 100 fresh point updates p95 329.03 ms; timing varies between runs and does not establish a universal speedup |
| Actual key amortization across independent tables | [210 retained million-row tables](experiment-key-amortization.md), one owner/evaluator, single replica | 630 MB logical; canonical data+indexes+trusted heads+shared keys/owner state 1.975191x, including hashes 1.996193x. Whole-process peak RSS/commit 1.386/1.401 GB; nine exact supplied-table point queries 56.440–100.138 ms. Global SQL routing, hidden access, transport and proofs excluded |
| Bounded loading of actual encrypted disk images | [1800 independent million-row tables](experiment-disk-tables.md), same live classic owner/evaluator | 5.4 GB logical; actual data/index files plus framing, trusted catalog and all shared keys 1.721920x. Native peak RSS 371 MB; nine exact point queries 61.130–117.962 ms including file read/restore/auth/FHE. OS cache allowed; key/catalog crash recovery and global SQL routing absent |
| Concealed access via single-server PIR and fresh FHE | [Native retrieval probes](experiment-private-access.md) and [composed known-row pipeline](experiment-private-fhe-pipeline.md) | Million-row private >=/COUNT/SUM read 177.79–203.88 ms warm, 279.91 ms first including key restore; visible 47.16–50.68 ms; combined peak 417.86 MiB; hidden SQL index/proofs still absent |
| Concealed complete age-index selection + data PIR + fresh FHE | [Measured bounded composition](experiment-private-index-fhe-pipeline.md); 64 real queries and 19 tests passed | Cached private 1/4/16-row groups: 312.55–337.74 / 534.13–550.91 / 1084.82–1095.49 ms. Fixed16 additionally pads public cardinality and takes >1056 ms. Canonical data+index 1.688383x, joint known material 63.913x; peak 449.90 MiB; neither privacy policy selected |
| Complete age index + visible/Spiral reads + fresh byte-limb BFV | [Actual paired EQ composition](experiment-private-bfv-index.md), 64 exact reads and 16 tests; core separately passes 10 tests | Fixed16 private Cached 330–356 ms, Uncached 452–489 ms across 0/1/4/16-row groups; visible 82–92 ms. Native peak RSS 690 MB. Canonical 1.688383x, known single-table key/state subtotal 6.738583x; ready caches/online owner, no network/proof/UPDATE or full 2x claim |
| Verifiable FHE computation and SQL completeness | [Proof research and actual PBS accounting](experiment-query-proofs.md); no verifier | Instrumented scalar control: 33 PBS for COUNT/SUM, 59/67 for UPDATE at 2/8 workers. Inspected primitive proof systems take seconds, with no TFHE-rs adapter; full 500 ms budget remains unproved |
| Initial 25-bit BFV SIMD over selected rows | [Separate pure-Rust probe](experiment-bfv-simd.md), 35 successful real-FHE checks; not promoted as a backend | That 25-bit N8192 circuit fails exactness. N16384 EQ16/256 warm median 492.21/560.41 ms, max 508.16/573.49 ms; GE/range slower. About 4.49 MB query wire; peak RSS/commit 1.199/1.299 GB; later byte-limb results are separate |
| BFV independent parameter-security inputs | [Exact maps for N16384/plain25 and N8192/byte17](experiment-bfv-security.md), five observable CLI tests passed | Variance10 is CBD(20), not CBD(10); explicit profiles preserve the original default. Generic independent-LWE and ring/KDM exposures are distinguished. No Sage numerical attack estimates executed; security gate remains open |
| Official TFHE multi-bit CPU parameters | [Bounded classic/grouping4 comparison](experiment-tfhe-multibit.md), 89 complete encrypted operations passed | Grouping4 R4/W4: 4-row 572–599 ms, 16-row 2041–2059 ms; larger 558 MB evaluator key, 1.19 GB peak commit, up to 49 sampled process threads. Correct but fails multirow 500 ms; existing backend retained |
| BFV NTT, fused GE and final-output levels | [Separate N16384 variant matrix](experiment-bfv-variants.md), 94 exact encrypted queries | EQ256 max 483.34 ms and output 1.79 MB→197 KB; GE/range remain >500 ms. Fused-only series regresses; optimized NTT raises native peak commit to 1.722 GB. Preserve both controls and regressions |
| Exact 17-bit byte-limb BFV COUNT/SUM | [Separate N8192 probe](experiment-bfv-byte-limbs.md), 52 exact successes and one preserved failed AND-range control | Final additive-range circuit: all 30 EQ/GE/range queries over 16/256 rows take 79.65–220.74 ms, peak RSS 521 MB. Exact maximum SUM passes; public keys 8.93/13.40 MB. No complete index/PIR, UPDATE, independent security validation or arithmetic proofs yet |
| Reusable experimental BFV owner/peer roles | [Separate byte-limb core](../experiments/bfv-byte-limb-core/README.md), ten tests and strict Clippy passed again from the prototype checkout | Fixed16/256 shapes, fresh encrypted inactive weights and two-head/query-ID binding; no storage/PIR/GUI dependency. Explicit malicious-echo test returns an in-bounds wrong answer only as UnverifiedAggregate; no arithmetic verifier or new composed latency claim |
| BFV arithmetic verification after the faster kernel | [Finite primary-source investigation](research-bfv-verification.md), documentation/math checks only | RNS extension/rounding and 31/35 key switches remain part of range proof relation; abstract ring products alone are insufficient. Published BGV maintenance proofs are not a measured BFV adapter. No custom spot-check accepted as a proof; UnverifiedAggregate retained |
| Construct only the pinned BFV profile | [Paired fresh-process measurements](experiment-bfv-profile-setup.md), 11 tests and strict Clippy | Complete Rows16 setup 1492–1504→308–310 ms, peak RSS592→199 MB; Rows256 setup1561–1592→385–417 ms. Complete serialized upstream parameters, keys and arithmetic unchanged; warm queries show no established speedup. No index/PIR/network/proof in this setup probe |
| Exact Spiral owner-state recovery | [Supported secret-seed restoration](experiment-spiral-owner-state.md), seven contract tests plus one genuine private-PIR integration and strict Clippy | 336-byte trusted secret envelope restores against the retained original6029344-byte public setup; first/middle/last records recover exactly. Live secret matrices remain180224 bytes RAM, separately counted. Trusted backup protection, version/architecture portability and malicious-response authentication remain caller boundaries |
| Actual shared BFV/PIR setup across independent retained tables | [Twenty-table composition](experiment-private-bfv-amortization.md), 192 exact paired EQ reads, six before-BFV rejection controls, 18 tests and strict Clippy | 60 MB logical; canonical + shared key/owner known subtotal 1.938696x, with Merkle 1.959699x. All 40 NTT caches stay live: 1.342 GB, known canonical + auxiliary 24.73x, native peak RSS/commit 1.710/1.717 GB. All 192 reads <436 ms locally; no full-state 2x, portable complete owner backup, general SQL or transport/proof claim |
| Complete indexed BFV EQ/GE/ranges up to 256 candidates | [Actual paired range composition](experiment-private-bfv-range.md), 96 exact reads, 11 before-BFV rejection controls, 19 tests and strict Clippy | Private Cached ranges 21/256: 447–470 ms; Private Uncached: 568–591 ms, all eight failures of 500 ms retained. EQ/GE256 maximum SUM16776960 exact; native RSS/commit 352/357 MB. One posting/data page budget, online owner and ready caches; separate one-table setup/ledger, not combined with the twenty-table Rows16 result |
| Parallel native PIR cache preparation | [Exact paired loader comparison](experiment-spiral-cache.md), five owning tests and strict Clippy | Two native caches prepare in 49.7–51.6 ms versus 214.8–228.3 ms using disjoint trial slabs and the same 8-worker pool. Every output word matches the original loader; real PIR reads pass. The 64 MiB pair remains unchanged, peak process RSS 82 MB. Full cold disk/query integration is still required |
| Parallel native PIR trial evaluation | [Paired server scheduling experiment](experiment-private-pir-batch.md), four exact response controls, 32 full range reads, 21 tests and strict Clippy | Same native query responses and crypto profile. Cached private ranges 458–466→414–424 ms; uncached 574–590→508–531 ms, all four candidate misses of 500 ms retained. Query expansion still dominates. Independent request batching is reported as throughput, not individual latency; no header dependency removed |
| Native PIR cache representation and admission | [Independent pinned-source review](research-pir-cache.md), no new runtime measurement | Seven-byte archived words save only 12.5%; the public native evaluator still requires a 64 MiB pair. Bare preprocessed-file APIs lack trusted framing and one ignores short reads. Reviewed slab conversion and capacity-one bounded loading preserve separate pre-NTT root and pre-BFV AEAD gates; source review does not establish cold-query latency |
| Fewer barriers in native PIR query expansion | [Exact combined scheduling experiment](experiment-private-pir-expansion.md), 26 direct-buffer/response controls, 32 full range reads, 23 tests and strict Clippy | Original expansion already parallelizes each half. Safe sibling scheduling plus parallel trials preserves every tested native output. Cached private ranges 379–393 ms; uncached 456–465 ms, all four below 500 ms versus TrialsOnly 506–525 ms. Ready caches and online owner; no cold disk, complete SQL or arithmetic proof claim |
| Indexed BFV UPDATE design and writeback contract | [Implemented experimental boundary](research-bfv-compact-update.md); core and disk owning tests pass, actual measurements appear below | Two fresh encrypted byte planes permit exact per-row addition and whole-operation overflow rejection. Exact owner-built index selection, post-FHE local arithmetic checks, staged data/header rebinding and cache invalidation stay explicit. These local checks provide no computation proof or durable transaction |
| Allocate only the selected PIR gadget scratch | [Frozen negative experiment](experiment-private-pir-scratch.md), 26 exact controls, 25 tests and strict Clippy | All tested expanded buffers and serialized responses match. Across all 22 paired boundary requests, total server time changes 1707.5023→1699.4336 ms (0.47%), failing the predeclared 5% gate. No full-query matrix was run; paired expansion remains the best measured variant |
| Capacity-one disk loading with private BFV queries | [Actual three-table comparison](experiment-private-bfv-disk.md), 293 exact full operations, nine before-BFV rejections, 28 tests and strict Clippy | Best combined scheduler plus memory-only admission reduces complete private range misses to 488–514 ms; two of 288 matrix cells still exceed 500 ms. Native peak RSS/commit 355/361 MB; exactly one 64 MiB NTT pair. Three-table files+peak commit remain 44.01x; larger actual data is required to measure amortization, not project it |
| Actual private disk scale with bounded caches | [1,000 independent million-row tables](experiment-private-bfv-disk-scale.md), same validated executable, 293 exact operations and nine before-BFV rejections | 3 GB logical; actual 2,003 files + whole-process native peak commit = 1.816600352x, with one retained 64 MiB NTT pair and 359/365 MB peak RSS/commit. All cached-header cells ≤456 ms; six uncached private range misses take 506–518 ms. No dropped outliers, general SQL, transport, computation proof or complete owner restart claim |
| Shared BFV exact-index aggregate and amount-addition APIs | [Owning core contracts](../experiments/bfv-byte-limb-core/README.md), 37 runtime tests, two one-use-token doctests and strict Clippy | One original Owner/PublicSetup/PeerEvaluator serves all three wire domains. Exact selection permits eight genuine encrypted rotate/add steps; COUNT must equal active rows. Indexed amount addition checks every limb and rejects global overflow before output allocation. Full encrypted-predicate reads remain; no new composed timing, compact writeback or arithmetic proof claim |
| Same-owner restart and secret checkpoint boundary | [Pinned-source and retained-catalog review](research-owner-recovery.md), baseline missing APIs and proposed lifecycle | The original 1,000-table encrypted files and public catalog cannot recover lost owner secrets. A sealed bounded bundle must retain original compact/BFV/PIR secrets, trusted current heads and original public setup identities; valid-old-backup rollback and durable publication require separate contracts. Secret payload counts alone are not a complete backup or restart measurement |
| Exact-index BFV with actual private disk scale | [Paired 1,000-table experiment](experiment-private-bfv-exact-disk.md), 31 owning tests, strict Clippy, 774 genuine operations and 13 before-BFV rejections | Same 3 GB logical dataset/keyset: actual files plus native peak process commit 1.816302709x. All 384 ExactIndex matrix queries <352 ms, visible maximum 45.008 ms; FullPredicate retains nine failures >500 ms, maximum 562.224 ms. Complete authenticated exact selections/age checks precede eight encrypted rotate/add steps. Both privacy policies remain; 256 rows/one posting+data page, online owner, OS cache allowed; network/proofs/general SQL/restart excluded |
| Genuine indexed BFV UPDATE through compact disk writeback | [Actual 1,000-table lifecycle](experiment-private-bfv-update-disk.md), 42 owning tests, strict Clippy, 359 peer operations plus 126 diagnostic preparations | 100 point cycles, 24 positive multirow/range controls and two carry/endpoint commits preserve canonical/catalog sizes; 16 no-ops, nine global overflows and public echo rejection retain their explicit outcomes. Actual files plus native peak commit = 1.814284747x of 3 GB. Main-cycle commit/invalidation maximum 316.162 ms; compound with readiness/diagnostics/separate SELECT maximum 635.367 ms, all 25 private uncached cycles >500 retained. No private-write, durable recovery, arithmetic proof or general SQL claim |
| Sealed original-owner reconstruction candidate | [Executed owning contracts and composition](proposal-owner-recovery-candidate.md), 66 runtime tests, two doctests and strict Clippy across three isolated packages | After all original owner handles drop, the candidate decrypts original data/index files, retrieves original first/middle/last PIR records and evaluates a fresh BFV predicate using original rotation/product/relinearization keys. Three-table files include a 9,996 B sealed checkpoint; native peak commit 376,266,752 B. External wrapping key stays in RAM. Same-process functionality only; no restart-latency, 1,000-table, anti-rollback or durability claim |
| BFV backend in the actual GUI/SQL engine | [Headless full-operation workload](experiment-bfv-gui-integration.md); 37 BFV-core, 19 BFV-storage, 23 retained TFHE and 80 GUI/SQL runtime checks, three doctests and strict Clippy | All 144 unique matrix cells and three late-shard overflow controls pass on 128 public rows across 1/3/16 peers. Maximum full SQL operation 383.8544 ms, native peak commit 246,702,080 B. The GUI generates no TFHE keys; public BFV material is shared. Exact selection/age authentication, real wire/FHE, checked compact updates and all-shard publication are timed. Visible access, zero virtual delay, no window opened; tiny-table overhead is not a new 2x result |
| Original-owner recovery in a separate process | [Actual writer-exit/reader-restore experiment](experiment-private-bfv-restart-disk.md); 116 runtime test executions, two doctests, strict Clippy and nine before-query rejections | All 768 three-table queries are exact after one committed encrypted update; ExactIndex maximum 317.346 ms, FullPredicate maximum 480.196 ms. Both sealed checkpoints and all 11 files are counted. Files plus parent/serial-child native peak bound total 43.185762x on this tiny fixture; no scaled 2x claim. Live external broker custody, one posting/data page, local transport, unverified arithmetic and nondurable publication remain explicit |

Experiments use separate managed worktrees, including `private-index-research`,
`compact-fhe-query`, `query-proof-research` and `compact-playground`. Generated
reports and ephemeral test data stay in ignored local directories; no keys or
database images are committed. The main GUI is not launched by these experiments.

## New native TFHE direction

The installed TFHE-rs 1.8.1 includes transciphering sessions and encrypted PRF
generation. A candidate keeps only compact masked row bytes at the peer and
regenerates encrypted masks for selected rows when required. An owner-assisted
variant instead supplies a fresh encrypted mask for selected compact input.
Neither approach needs a permanent full FHE table solely for read execution.

The [official PRF contract](https://docs.zama.org/tfhe-rs/fhe-computation/advanced-features/encrypted-prf)
supports server-side encrypted random generation and warns that the stronger
sIND-CPA^D model requires rerandomized variants. The underlying
[LWR-based PRF paper](https://eprint.iacr.org/2024/665) is a security/performance
reference, not an audit of this storage composition. Native API availability
does not prove that reused masks, malformed query inputs, chosen ciphertexts,
cross-machine evaluation or update rollback are safe in our protocol.

An evaluated FHE UPDATE still needs a validated compact writeback. The owner may
verify, decrypt and re-encrypt; this requires that application online for that
operation and must be measured. No current experiment supplies a decentralized
write-authorization or computation-proof protocol.

The AES/OPRF probe remains a separate format. The new compact-query pipeline uses
actual compact-store XChaCha20Poly1305 pages with owner-supplied fresh FHE masks;
its measured read/update lifecycle is not an arithmetic sum of unrelated probes.
The initial GUI adapter passed 13 real SQL workflow tests and 59 headless library/UI/worker
tests, with strict Clippy passing. Its 128-row serial SQL boundary control measured
five point queries at 99.35–120.94 ms, four-row queries at 518.12–551.47 ms, and a
point UPDATE at 233.54 ms. Canonical data/index were 544/2840 bytes for 384 logical
bytes; fixed index metadata dominates tiny tables. The integrated padded-index,
scoped-evaluator version subsequently passed 114 owning/dependent tests and strict
Clippy. Its actual 100 fresh point updates retained 5,229,212 canonical data/index
bytes, reconstructed both images and rejected every stale output. See the report
for complete combined-run timings, CPU budgets and the GUI boundary control.
No GUI window was opened.

The subsequent narrower-wire kernel passed 23 compact-query, 21 compact-store,
59 headless GUI and 13 SQL workflow tests, with strict Clippy. Its independent
100-update integration run retained the same 5,229,212 canonical data/index bytes,
rejected every stale output and peaked at 373.74 MiB. Exact encrypted response
widths reduce traffic without reducing security parameters. One- and four-row
timings varied in paired comparisons; 16-row/range queries and multirow updates
still exceed 500 ms. See the separate report for both comparison pairs and the
final integration control.

Actual larger retained data now demonstrates how the fixed FHE keys can be
amortized below 2x in one configuration, without counting projections or cloned
tables. It does not remove the earlier small-table costs, multirow latency or
the need to account for a real distributed SQL planner and routing structures.

The full goal remains active: measure actual large-scale overhead after the proven
owner-process restart and extend concealed indexed access beyond its measured
one-page budget. Proof, freshness, resource and durable lifecycle requirements
remain unresolved. Transport and malicious-peer computation proofs remain absent
from all local latency measurements.
