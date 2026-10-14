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
| Concealed access via single-server PIR and fresh FHE | [Native retrieval probes](experiment-private-access.md) and [composed known-row pipeline](experiment-private-fhe-pipeline.md) | Million-row private >=/COUNT/SUM read 177.79–203.88 ms warm, 279.91 ms first including key restore; visible 47.16–50.68 ms; combined peak 417.86 MiB; hidden SQL index/proofs still absent |
| Verifiable FHE computation and SQL completeness | [Proof research and actual PBS accounting](experiment-query-proofs.md); no verifier | Instrumented scalar control: 33 PBS for COUNT/SUM, 59/67 for UPDATE at 2/8 workers. Inspected primitive proof systems take seconds, with no TFHE-rs adapter; full 500 ms budget remains unproved |

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

The full goal remains active: reduce index overhead and multi-row latency, compose
concealed indexed access, and retain the unresolved proof, freshness, resource and
durable lifecycle requirements. Transport and malicious-peer computation proofs
remain absent from all local latency measurements.
