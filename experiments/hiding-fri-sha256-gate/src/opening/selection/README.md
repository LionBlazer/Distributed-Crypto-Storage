# Private bounded selection opening

Validated on2026-10-16: native build, strict Clippy, actual numerical analysis,
one observed genuine composite and all15 Selection cases within the combined85
passed. The [validation report](../../../SELECTION-PACKED-VALIDATION.md) preserves
failures, timer scope and observations. All exercised keys/rows/identities are
explicitly PUBLIC NONSECRET fixtures. This private module
closes a proposed bounded selection link, not BFV formation, a SQL answer or locks.
Its only project dependency remains the parent experiment's compact-store audit.

| File | Owned responsibility |
| --- | --- |
| statement.rs | Public expected context, private canonical plan, fixed commitment encodings |
| air.rs | Same-source opening, full mask membership, LIMIT and stable original-row compaction |
| trace.rs | Non-Clone/nonserializable bounded private witness and one trace allocation |
| mod.rs | Real canonical-source-first composite prover/verifier and local fixture-only CLI |
| tests.rs | Genuine composites and coherent rebuilt malicious selection/commitment cases |

The module reuses the parent's [P2 gadget](../poseidon.rs) and shared backend.
It adds no dependencies, SDK fork, production API, Owner key interface, proof
codec, cache or plaintext peer execution. There is no separately accepting
Selection receipt or marker. The existing 60 tests and profiles remain distinct.

## Exact composition and public values

The composite verifier requires an actual canonical N4 source proof and verifies
it FIRST against independently expected source values. It then requires byte-exact
source public-values equality and verifies the new selection proof. Missing,
foreign or byte-only source proofs reject. Source metadata or a valid selection
proof alone cannot establish source validity. The prover also verifies the
canonical source proof before generating the selection trace.

The new 88 public fields are query-profile8, request8, both heads56, C_key4,
C_open4, C_plan4 and C_sel4. No matching count, identity, mask, presence, private
key, salt, BFV s/e or intermediate stage array is exposed. All public constants
and selectors derive from the same immutable verifier statement and profile.

C_open is EXACTLY the existing canonical-index profile and 680-field encoding:
87-field context/salt prefix, all 587 original plaintext u32 words, six zeros.
It remains request-bound; this does not create a reusable per-version C_state.
The 587 words are streamed through 256 reused Boolean bits; all are u32-bounded.
Data crosses rows10/11, TableId rows14/15 and IDs rows80..84. Private banks are
constant on ALL512 rows and constrained at these exact source-input registers.

## Independently expected semantic plan

The authorized client supplies the independently fixed C_plan for its actual
compiler-final TRUE mask over the nonnullable age domain, expected private TableId,
projection code0/1/2/3 (Age/Amount/AgeAmount/AmountAge), and effective N4 LIMIT.
The module does not compile SQL text or accept an unrelated unproved predicate.
Every 32-byte final TRUE mask is valid; SQL three-valued compilation belongs to the
existing client compiler. None and LIMIT>=4 normalize to4 on this exact N4 source.
No ORDER BY, OFFSET, lock strength, WAIT or SKIP policy is represented.

C_plan uses the exact16-byte domain DCS/PLAN/N4/v1!!, version1, query-profile8,
request8, heads56, C_key4, C_open4, privateTableId8, mask8 packed u32, LIMIT1,
projection1 and independent private salt4:107 fields plus five zeros =112.
The same private TableId is constrained to the source opening, not merely
committed independently. History/authorization of that expected identity remains
the external client's obligation, not a new cross-version identity proof.

For public threshold b=0..255, four d8/c/zero/inverse comparisons establish exact
age equality using age+256-b=d8+256c, both integer sides0..511. All mask positions
are visited. Four accumulators pin the complete matching bits at row256.
Private three-bit differences/carries establish prefixMatch<L for each ordinal;
retained bits equal matching AND that condition. A Boolean4x4 matrix has each
column sum equal retained, binds its row to the retained-prefix rank, and has
Boolean prefix presence. It cannot omit, add, duplicate or reorder candidates.

## Original compacted tuples and commitments

C_sel uses exact16-byte DCS/SELECT/N4/v1, version1, query-profile8, request8,
C_open4, C_plan4, fixedcapacity1 (=4), independent private salt4, then four12-field
tuples (presence, ordinal, ORIGINAL age, ORIGINAL u16 amount, RowId8), plus six
zeros:82+6=88 fields. All inactive tuple fields are zero. Projection remains bound
in C_plan but is not applied as a plaintext answer; later BFV formation must bind
these original fields/presence and exact unused slots to the real encrypted job.
It is not implemented here.

Both commitments use the existing candidate rate8/capacity4/output4 overwrite
P2 construction, explicit zero padding, zero-capacity resets and independently
OS-seeded uniform field salts. This retains experimental assumptions and is not
production cryptography, witness erasure or independently certified privacy.
One shared gadget absorbs C_open at rows0..84, C_plan at85..98 and C_sel at257..267;
inactive rows use zero gadget input and retain the checkpoint. All permutation
equations remain unconditional. No second trace or secret cache is introduced.

## Validation and limits

The source layout is T512/W957/PV88 with both complete row openings and512
verifier-owned periodics. Separate arrays are trace3,919,872B,
masked7,880,704B and main LDE63,045,632B; periodic payload2,097,152B is separate.
These exclude symbolic/quotient/DFT/tree/stack/proof overhead and are not RSS.
Declared bound5 is retained. Individual model estimates of at least128 bits are
per proof; they do not establish composed128-bit security for the two proofs and
the commitment/hash assumptions. Actual analysis found4814 constraints, degree3,
16 quotient chunks and2094 batched functions, with both model estimates128.
The declaration was not lowered. All85 serial genuine/adversarial cases passed,
including the preserved60 old cases and ten separate packed-source cases.
The composite still requires the OLD canonical source profile; these successful
gates add no production acceptance or automatic packed-source composition.

The existing source verification alone was649.3903ms on one observed fixture,
already above500ms. Composition is a feasibility experiment, not an interactive
latency result. Typed/NULL catalogs, independently anchored history, BFV
key/setup/noise/encoding formation, updates, cross-shard completeness, locks,
freshness/finality and live acceptance remain separate unmet requirements.

The child [SelectedEncoding gate](encoding/README.md) opens this exact
request-bound C_sel only after source-first composite verification, then proves the
complete original BFV plaintext encoding. Its [validation record](../../../SELECTED-ENCODING-VALIDATION.md)
records the upstream coefficient tests, genuine composite and all 114 serial tests.
It adds no live SQL acceptance; this module's existing profiles remain unchanged.
