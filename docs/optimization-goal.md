# Compact FHE query investigation

Active goal: at most 2x canonical data storage and at most 500 ms per measured
query, while retaining encrypted peer computation. The earlier 100/50 ms indexed
targets remain stretch targets. These are goals, not established capabilities.
Arbitrary SQL remains the direction; each result below must identify its actual
supported query, input size and privacy model.

The prototype branch is `codex/feature/fhe-prototype`. Isolated experiments start
from `95ed312`; only reviewed, validated improvements are promoted to that branch.
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
| TFHE 1.8.1 native one-time-pad transciphering | Implementation in isolated worktree | Measure actual compact-to-FHE COUNT/SUM, fresh/warm input and complete wire costs |
| Native encrypted PRF mask regeneration | Implementation/review in isolated worktree | Avoid persistent FHE masks; audit seed lifecycle, key domain and rerandomization threat model |
| Visible authenticated searchable index | Proposed | Direct row-ordinal lookup is not an index for arbitrary SQL predicates |
| Concealed index via single-server PIR/ORAM | Primary-source comparison | Measure retrieval, index traversal, updates, owner state and subsequent FHE execution together |
| Verifiable FHE computation and SQL completeness | Unimplemented | Include proof generation/checking before claiming requirements 11–13 |

Worktrees: `fhe-fast-scan`, `fhe-compact-store`, `fhe-transciphering`. Generated
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
