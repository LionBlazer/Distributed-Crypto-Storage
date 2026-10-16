# Private source proofs for PostgreSQL row locks

Status: research contract on 2026-10-16; a candidate for review, not a selected or
implemented proof system, lock protocol or accepting API. [Requirements](../REQUIREMENTS.md)
remain unchanged. This addresses the missing private source/control relation in
the [PostgreSQL contract](postgresql-contract.md); [finality](lock-finality-research.md)
is an independent unresolved gate. No latency, whole-process RAM or full-SQL claim
follows from this design.

## Existing boundary

[`bfv-query-proof::ArithmeticAir`](../crates/bfv-query-proof/src/circuit.rs) uses
`TwoAdicFriPcs` and ordinary Merkle commitments for public ciphertext arithmetic.
Its current witnesses are derived from public operands/certificates; that does
not require hiding secret database fields. This configuration must not receive
AEAD/BFV keys, plaintext rows, private identities or lock histories.
[`JobVerifier`](../crates/peer-runtime/src/evidence.rs) verifies real arithmetic
proofs and exact jobs/heads, but does not prove CSTORE-to-FHE conversion, index
completeness or compact output finalization. These remain owner checks today.

[`TableId`/`RowId`](../crates/compact-query/src/identity.rs) live in the encrypted
index. [`SignedIntent`](../crates/transaction-state/src/journal.rs) instead encodes
public commands containing `RowKey`; its metadata witness exposes identities and
access relationships. Reusing that wire for live private locks is not approved.
A bounded private control-state commitment, its availability/recovery policy and
an encrypted/padded representation still need design. Owner signatures establish
permission, never source correctness or discretionary conflict arbitration.

## Proposed relation and public binding

A canonical, bounded statement must bind all of the following together:

- Network/genesis, application/source-proof/FHE profiles and exact ordered data
  and index heads for every participating shard, with no omitted shard.
- Old/new private control roots; authorized controller, transaction generation,
  sequence and request nonce; the eventual finalized parent and freshness barrier.
- A hiding commitment to the client's canonical semantic plan: logical table,
  predicate, projection, ordering, OFFSET/LIMIT, lock strength and wait policy.
- Exact original FHE-request digests, independently derived canonical-input/output
  digests, and every new data/index head in one atomic transition.

The client compiles SQL and pins that semantic plan. The proof must open the same
commitment and constrain the predicate/window actually used. A SQL-text hash plus
an unrelated unproved range is insufficient. A full SQL parser inside AIR is not
required by this client/compiler trust boundary. Public verification checks the
proof and public ciphertext decoding/binding, without repeating plaintext SQL.
Commitment construction, canonical encoding and approved metadata leakage remain
review decisions; a bare hash of a guessable predicate is not hiding.

Private witnesses include source packets/paths, authenticated plaintext/index,
TableId/RowId, plan opening, keys, BFV error/encoding witnesses and old/new control
state. They stay inside the owner prover; peers receive only the reviewed public
bindings and proof, never keys, plaintext or secret witness logs. Public membership
paths, stable row-nullifiers, counts or skip lists must
not silently expose information absent from the current static ReadImage profile.
The owner application may propose/prove with its secrets; peers must validate the
relation and the eventual consensus must serialize decisions.

## Required constraints

1. **Exact source and keys.** Constrain CSTORE's SHA-256 leaf/tree/snapshot rules,
   page address/length/revision, nonce, tag and XChaCha20Poly1305 with the exact
   [`Commitment::aad`](../crates/compact-store/src/format.rs) and
   [`Owner::decrypt`](../crates/compact-store/src/crypto.rs) interpretation.
   `key_domain` is generated independently of the AEAD key. A proposed
   genesis/application-bound key commitment must fix the actual AEAD key; merely
   proving existence of some decrypting key is not the intended relation.
   Non-committing ChaCha/Poly1305 under attacker-controlled keys is documented by
   [Len, Grubbs and Ristenpart](https://www.usenix.org/system/files/sec21summer_len.pdf).
   This is a new-protocol obligation, not a bypass of today's honest fixed-key decrypt.
2. **Complete index invariant.** Either prove table/index consistency per query,
   or establish it at genesis and preserve it through every accepted write. The
   relation must cover exact ordinal coverage, correct age buckets, canonical
   counts/offsets/varints/padding, embedded data head and logical table identity.
   Stable nonzero RowIds must identify the same rows across shards and writes;
   required uniqueness needs an explicit invariant, not an assumed public proof
   from the current allocation-local/CSPRNG checks. Membership alone is insufficient.
3. **Complete lock selection.** Bind candidates to those private IDs and to the
   canonical plan's global order. Prove every conflict/skip against the same whole
   old ownership state, including absence of omitted holders. Own locks cannot
   cause a skip. OFFSET rows acquire locks; LIMIT counts returned non-conflicting
   rows. A valid ordered frontier may establish a bounded prefix only under the
   proven index invariant; fewer results require exhaustion evidence. Resource
   overflow rejects, never produces an unexplained prefix. Rechecking after WAIT,
   isolation and abort/death policy remain separate required semantics.
4. **Real FHE input.** Prove encryption of original fields/presence and exact
   padding/slots, not a prepared plaintext answer. Current
   [`Owner::encrypted`](../crates/bfv-query-core/src/lib.rs) uses secret-key BFV;
   [`PublicUpdateParameters`](../crates/bfv-query-core/src/linear_update.rs) carries
   a setup identifier, not a proof of its secret key. A separately anchored BFV
   secret commitment must bind the actual encryption key and setup identity.
   Constrain the upstream SIMD map/scaling and all five RNS moduli consistently,
   including signed small coefficients. The current secret/error distribution is
   CBD(20), variance 10, not Greco's example Gaussian-noise profile. Range checks
   do not certify honest randomness. Key/seed honesty, noise/security review and
   future evaluation-key correctness remain explicit assumptions or work.
5. **Control and write linkage.** Constrain the state transition, controller and
   replay fences, with [`State::transition`](../crates/transaction-state/src/state.rs)
   as a behavioral reference, not an accepting proof oracle. Every UPDATE/DELETE
   must enforce sufficient ownership for the same private rows/generation. New
   AEAD pages must encode the decoded, genuinely proved peer output; unchanged
   rows, stable IDs and index consistency must be preserved. Whole changed-page
   and shard sets must match the atomic transition. Append/key edits/compaction
   need their own invariant-preserving constraints. An arithmetic proof on other
   inputs or a valid metadata receipt cannot discharge these obligations.

Integer semantics matter inside a finite-field proof: range-check secret limbs,
signs and carries so Goldilocks or RNS wrap cannot satisfy a false integer relation.
Use the actual encoding/NTT/scaling algorithm, not a schematic BFV equation or
unproved spot checks of raw NTT coordinates. A proof of private conversion does
not implement a missing peer-side homomorphic SQL operator.

## Concrete ZK candidate and privacy obligations

Installed Plonky3 crates are `0.8.0`, VCS
`a21e3ed42905040ad49c519e402f018381c12d0c`. Its
[HidingFriPcs](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/fri/src/hiding_pcs.rs)
is a concrete candidate foundation, not the missing source/control AIR. For mask
height N it checks `N >= 2 * (num_queries + extension_degree * opening_points)`.
It requires at least `extension_degree` random codewords. Private prover data
permits one opening, including clones; copying masked LDEs does not refresh this
budget. Both MMCS layers must hide; the PCS type does not enforce that
configuration. The pinned
[hiding Merkle implementation](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/merkle-tree/src/hiding_mmcs.rs)
requires sufficient salt entropy and unpredictable CSPRNG seeding; deterministic
test seeds are not a production configuration.

The [STARK prover](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/uni-stark/src/prover.rs)
also randomizes the trace, quotient and FRI composition. Every auxiliary lookup,
permutation and transcript message still needs a composition review; secrets
cannot be placed in public preprocessing. See
[Haböck and Al Kindi, 2024/1037](https://eprint.iacr.org/2024/1037), revised 2025-02-22.
Pin new proof/application profiles and recompute full soundness bounds; do not
weaken the arithmetic profile. Prover buffers/copies and failure cleanup also
need auditing: masking is not zeroization. No secret trace/LDE/mask cache is implied.
Trace height, chunk count, proof shape and exposed recursion topology must follow
reviewed public bounds/padding rather than newly reveal match/skip counts. No
active-feedback or access-leakage policy is selected by this note.

## Cost evidence and the next gate

The standalone [hiding-FRI SHA-256 gate](../experiments/hiding-fri-sha256-gate/README.md)
now validates the pinned public compression primitive with the fixed hiding backend,
genuine proofs and adversarial tests. Its [validation record](../experiments/hiding-fri-sha256-gate/VALIDATION.md)
pins source/artifact identities, security reports and limited process observations.
Public fixtures do not establish witness secrecy or private-source composition.
SHA chaining/padding, AEAD, authenticated index/control semantics and BFV input
formation remain unimplemented; this gate supplies no SQL acceptance API.

[Greco's pinned artifact](https://github.com/privacy-ethereum/greco/blob/df72c14c02d5d85f189f087feaab109e7fc1b4f1/README.md)
implements BFV input-formation proofs on Halo2. At N8192, four 55-bit moduli,
t65537 and K16, its authors report 9.59165725 s proving / 7.775375 ms verification
on an M2 MacBook Pro, 12 cores and 32 GB installed RAM. This excludes our AEAD,
index and locks; parameters/distributions differ, peak RSS is not established,
and the artifact warns it is unaudited. These are authors' measurements, not a
host prediction, a full-query result or evidence for a 500-ms source proof.

The pinned hiding PCS expands a `T * W` trace to `2T * (W + r)` before LDE.
With 8-byte Goldilocks values and blowup 8, one dense main LDE alone requires
`128 * T * (W + r)` bytes. For illustrative T=2^20, W=10, r=5 this is exactly
2,013,265,920 bytes = 1.875 GiB, before source, keys, quotient or Merkle storage.
This is source-derived accounting for that representation, not a universal lower
bound or measured RSS. Bounded chunks/recursive composition and maintained index
invariants need actual privacy, soundness, whole-process memory and full-operation
measurements; smaller sampling or hidden unbounded caches are not substitutes.

After relation review, the smallest meaningful proposed experiment uses a small
real CSTORE data/index/RowId image, a genuine ZK source/control proof, and actual
independent-peer FHE execution plus its existing arithmetic proof. Fresh original
operands, not owner answers, enter that job. Initially it can test supplied
immutable heads only; it cannot issue a live finalized SQL grant.

| Boundary | Required negative/positive evidence |
| --- | --- |
| Source | Correct real pages; altered tag/path/revision, wrong key/domain/head and row/ID substitution reject |
| Semantics | Changed predicate/projection/order/window/nonce or another plan opening rejects |
| Completeness | Omitted/duplicate candidate, malformed trailing posting, false emptiness and missing shard reject |
| Locks | Real conflict vs false SKIP, own upgrade, OFFSET ownership, exhaustion and limit boundary |
| Composition | Real empty/nonempty FHE results; another request/output/proof cannot bind; unauthorized extra page/write rejects |
| Lifecycle/privacy | Stale parent/sequence/generation, reused masks, insufficient hiding budget and resource overflow reject; public shape and cleanup audited |

Validation must cover the actual constraints, including an adversarial prover,
not only honest witness-generator errors. A fresh finalized parent/barrier and
compliant committee/failure model remain unavailable; two work forks must not be
presented as mutual exclusion. No proof API or production implementation is added
by this document.
