# Private N4 locking selection candidate

This distinct nonaccepting relation passed release build, strict Clippy,
trace-free numerical gates, three genuine composite proofs and all 146 serial
tests. The [validation record](../../../PRIVATE-LOCKING-VALIDATION.md) preserves
exact measurements and their limits.
All fixture keys, rows, IDs and controllers are explicitly PUBLIC NONSECRET.
This is a genuine-proof candidate, not a live SQL lock grant.

| Module | Responsibility |
| --- | --- |
| statement.rs | Independently expected public inputs and exact stable/query encodings |
| air.rs | Complete two-owner conflicts, ordered selection, ownership and atomic rollback |
| trace.rs | Bounded private witness and one fixed trace factory |
| mod.rs | Real canonical-source-first composition and fixture-only CLI |
| tests.rs | Independent metadata oracle, native/AIR cases and genuine/rebuilt proof cases |

The implementation reuses the existing [P2 gadget](../poseidon.rs),
[canonical source statement](../statement.rs) and private shared backend. The
only added direct dependency is dev-only
[transaction-state](../../../../../crates/transaction-state/README.md), used for
actual `State::transition` comparisons. Its authenticated metadata adapter is not
an accepting oracle. There are no production dependencies, SDK changes, Owner key
exports, network messages, proof codecs, caches or public accepting APIs.

## Closed state and expected inputs

The registry contains exactly two existing transactions and holdings for all four
canonical source RowIds for each one. No third holder, other table or other row is
represented. IDs are sorted positive u32; controllers are nonzero 256-bit values;
sequences are positive u32; revision is u32; Failed is Boolean. Every holding is a
five-way Boolean one-hot absent/KeyShare/Share/NoKeyUpdate/Update. Incompatible old
holdings reject. Failed OTHER transactions retain their locks. The actor must be
Active. Events, savepoints, transaction creation/end and MVCC are not implemented.
This is an effective-ownership snapshot, not the transaction-state v2 wire format.

`Expected` is supplied independently with the complete canonical source statement,
genesis, parent, old root and independently supplied client plan C_plan.
Controller authorization is external and unimplemented; pinning Expected does not
authorize the client. Verification checks the real
source proof FIRST, then exact expected context and lock proof. Neither an expected
root nor an expected actor/plan is manufactured from the submitted proof/witness.
The fixture client constructs its root before its request plan; this fixture does
not implement trusted genesis, controller authorization or a registry lifecycle.
Parent is an identity bound into the relation, not a proof of membership/finality.

The 116 public fields are query-profile8/request8/heads56/C_key4/C_open4/genesis8/
parent8/C_old4/C_plan4/C_return4/C_owned4/C_new4. No RowId/controller/mask/count/list
is directly public. Root equality nevertheless leaks an unchanged outcome; this
candidate does not establish an access-leakage policy or hidden outcome guarantee.
No empirical witness secrecy or composed128-bit security is inferred from fixtures.

## Exact fixed commitments

All streams use the existing P2-12 rate8 overwrite construction, zero-capacity
resets, digest4 and explicit zero padding. RegistryProfile is the fixed schema,
bounds, mode codes and P2 identity; it is independent of query profile/request.

- Registry112: domain4/version1/RegistryProfile8/genesis8/DB4/keyDomain4/C_key4/
  privateTable8/all4RowIds32/capacities2/revision1/two15-field transaction records/
  salt4/zero2. Each record is ID/controller8/sequence/Failed/four holding codes.
  Old and new use the SAME domain and encoding. No request, parent, current heads,
  C_open or C_plan enters this stable root. C_key is not a BFV secret-key anchor.
- Plan144: domain4/version1/queryContext96/C_old4/Table8/mask8/actorID1/controller8/
  actorOldSequence1/oldRevision1/mode1/wait1/OFFSET1/LIMIT1/projection1/salt4/zero3.
  Actor fields are selected from the old registry, then fixed by independently
  expected C_plan. OFFSET/LIMIT normalize to0..4 only for this exact N4 source;
  their AIR bits exclude5..7. The256-bit mask is the client compiler's final TRUE
  set, not unrelated SQL text. Global order is fixed source ordinal.
- Each output168: distinct domain4/version1/queryContext96/C_old4/C_plan4/C_new4/
  capacity1/outcome1/salt4/four12-field tuples/zero1. Return tuples contain presence,
  ordinal, ORIGINAL age/amount and RowId8. Owned tuples contain presence, ordinal,
  RowId8 and old/new own modes. Both compact stably with fully zero inactive tuples.
  Owned means rows visited without conflict THIS command, including OFFSET and
  already-owned rows, not every old holding. No projected plaintext SQL answer is
  calculated. Future FHE formation must consume the new exact returned commitment.

The exact old C_open680 encoding is preserved. All587 original u32 words stream
through256 Boolean scratch bits, with source age/amount captures at10/11, TableId
at14/15 and RowIds at80..84. The private registry uses those same identities.
Cross-version preservation and cross-shard uniqueness are separate obligations.

## Walk and atomic outcomes

All256 membership thresholds are checked. For each ordinal, the conflict is the
exact requested-vs-OTHER-held mode table; own holdings never conflict. Search stops
after LIMIT returned rows or the first WAIT/NOWAIT conflict. SKIP conflicts consume
neither OFFSET nor LIMIT. Nonconflicting matches acquire/upgrade even when consumed
by OFFSET. Comparisons use `prefix+8-bound=d3+8*carry`, with operands bounded0..4.

Tentative visit/return/upgrade flags are private intermediate values. WAIT or
NOWAIT late conflict discards ALL their effects: counters/status/controllers/IDs/
holdings are identical, output lists empty, salt identical, and C_new=C_old exactly.
There is no grant. Success increments revision and actor sequence even for LIMIT0.
Fresh successful-root/output salts are OS-seeded producer behavior, not an entropy
proof. Blocked-root equality must not be described as hiding the outcome.

Admission counters are checked BEFORE inspecting conflicts: a32-bit candidate
revision equals old+1 and candidate sequences equal old+actor. Actual new-root
counters equal old+success/old+success*actor. The u32 cap is stricter than the native
u64 domain; it is not native CounterExhausted at2^32. Native parity applies within
bounded admission, with separate cap rejection cases. Counter, range and
comparison equalities are integer bounded well below Goldilocks; no modular wrap
supplies a false comparison. Hash and inverse/zero-test equations use field algebra.

The closed `Blocked` result is an atomic snapshot with no grant. It does not
implement PostgreSQL waiting/wakeup, deadlock handling or MVCC rechecks. The
selected row-conflict and OFFSET/SKIP rules follow the
[row-lock table](https://www.postgresql.org/docs/18/explicit-locking.html#ROW-LOCK-COMPATIBILITY)
and [SELECT rules](https://www.postgresql.org/docs/18/sql-select.html#SQL-FOR-UPDATE-SHARE)
only. Table-level `ROW SHARE`, `OF`/joins, cursor behavior and multiple locking
clauses are outside this candidate.

## Shape and gated validation

Analyzed geometry is T512/W1948/PV116, both full row openings and512 public periodics.
One P2 gadget absorbs source0..84, old85..98, plan99..116, new117..130, owned257..277,
return278..298. Row300 reuses32 scratch bits for sorted transaction-ID difference;
those bits enter no commitment there. Other scratch padding is explicitly zero.
All secret banks stay immutable on all512 rows; only membership accumulation,
source/range scratch and P2/checkpoint vary.

Calculated arrays are trace7,979,008B, masked15,998,976B and mainLDE127,991,808B.
These exclude periodic/symbolic/quotient/DFT/tree/proof/stack overhead and are not
RSS or a memory bound. Old backend parameters and all old relation profiles remain
unchanged. Actual inference found 7,092 constraints, degree 4, 16 quotient
chunks and 4,076 batched functions under the conservative declared bound 5.
Both model floors reached 128 before new trace allocation. These calculations
are not production cryptographic certification.

Offline workspace-only dependency resolution added the dev-only oracle closure to
the standalone Cargo.lock. All 126 existing package records remained exact except
the single new root dev edge; 15 locked records were added using existing root-lock
identities/checksums. The root lockfile is unchanged. Lock/metadata graph inclusion
does not by itself establish which optional code is compiled.

Release build/test-no-run/strict Clippy, all sixteen actual security reports,
three genuine `prove locking-selection` composites and all 146 serial tests passed.
The previous fifteen reports remained field-exact. The validation record separates
proving, verification, complete process intervals and sampled resources.

Remaining gates include registry genesis/lifecycle/authentication, stable row history,
controller custody, same-parent/final freshness, BFV encryption/key/noise formation,
writer fencing and proved output re-encryption, rollback/MVCC and consensus finality.
The live Session/JobVerifier/MetadataVerifier are unchanged and cannot accept this
candidate as FOR UPDATE/SKIP LOCKED. Owner-witness generation is not peer plaintext
execution. No production cryptography, latency or whole-process RAM claim is made.

## SQL compiler adapter

`sql::CompiledLockPlan` is an immutable owner/client value constructed by the real
[sql-plan](../../../../../crates/sql-plan/README.md) parser. Both existing Locking and
VersionLocking CLI gates now compile their public-nonsecret SQL before constructing
Expected/C_plan and following the genuine proof path. There is no peer-supplied AST,
authority flag or plaintext answer. All old AIR equations, profiles, private stream
encodings and fixtures remain separate and unchanged. This new front-end/gate
binding passed six focused new cases and both parsed-query CLI gates. The
[SQL locking-plan validation](../../../SQL-LOCK-PLANS-VALIDATION.md) records
all 195 discovered names separately from the six executed cases, unchanged 19
numerical reports and actual owning rejection checks. Historical reports retain
their original source; no live locking acceptance is inferred.

The request is SHA256(domain || LE64(SQL byte length) || exact SQL bytes || caller
nonce32). CLI samples a fresh nonce from the existing OS-seeded RNG; tests pass
explicit public nonces. It proves no nonce entropy or controller permission.
Canonical C_open is reconstructed for this request; version C_state/version_tag
is immutable and the query request is separate. Genesis/parent/C_old/C_plan and
private actor/TableId still come from independently owned caller context.

Full compiler TRUE-mask256, strength, policy and window feed the existing private
Plan. The N4 adapter admits offset0..4 and finite limit0..4, with None interpreted
as the known four-row source; larger values reject instead of clamping. AmountAge
is explicitly rejected at this adapter, although the parser preserves it: the
current relation returns fixed ORIGINAL tuples and does not attest reversed
projected formatting. Age, Amount and AgeAmount retain their existing masks;
no projected plaintext answer or FHE formation is inferred.

SKIP LOCKED always consumes the complete four canonical source rows. Ordinary
per-shard OFFSET+LIMIT prefixes are not a lock candidate provider. The six tested
examples use the actual transaction-state oracle, genuine canonical source/lock
proofs, a real cold certificate with two parsed warm queries, and a rebuilt wrong
policy trace with independently retained C_plan. Live Session/scripts/typed catalog
remain fail-closed; LockReturn168 is not SelectedEncoding88. Full PostgreSQL,
writer fences, rollback data semantics, key/actor authorization and finality remain
unfinished requirements. No practical latency or RAM result is claimed here.

## Successful returned-original encoding and formation

[LockReturnedEncoding](encoding/README.md) verifies the actual canonical whole
source/lock composite or exact StateLease/lock evidence before child Backend/trace,
then opens Return168 with successful outcome 0. Original age/amount/ordinal/RowId
values feed every coefficient; OFFSET-owned rows do not become RETURNED.
[Returned formation](formation/README.md) binds that exact C_enc to the complete
actual ciphertext and shared Key/five-Basis/local integer relations.

At the returned-formation baseline `c46817d`, compilation/strict Clippy, 23 numeric
calls, three owning oracles, three genuine CLI compositions and all 235 tests passed. The [validation report](../../../LOCK-RETURNED-BFV-VALIDATION.md)
separates the two encoder timers from normal formation's complete composition.
No projected SQL output, column ACL, live grant, writer fence, controller authority
or fresh decentralized agreement is inferred. Existing closed Blocked/selected
PostgreSQL scope remains the published contract.


## Client compiler opening for the experimental public-product job

`sql::CompiledLockPlan::bind_returned` uses the existing 144-field plan commitment
kernel with client-owned selected transaction metadata, TableId and plan salt. It
requires the independently expected `C_plan` and seals the exact typed producer,
request32 and public projection; a supplied root alone cannot claim compiler
provenance. It does not authenticate the controller or agreed head. The
[certified projection job](formation/job/README.md) consumes that capability only
after real prerequisite proofs. Its public projection remains visible; all live
SQL/finality/writer boundaries above remain unchanged. Six new cases, four
existing controls and the independent-process CLI passed; see the
[validation record](../../../CERTIFIED-PROJECTION-JOB-VALIDATION.md) for scope.

## Initialization boundary

The [RegistryBootstrap candidate](../registry_bootstrap/README.md) separately proves
initial empty holdings from canonical source plus independently anchored enrollment.
Its stable Registry112 uses this module's exact shared private field encoder.
Existing LockingSelection/VersionLockingSelection still accept independently
anchored old registries; this candidate does not turn those roots or local fixtures
into historical authority, fresh agreement or a live lock grant.

The [validation record](../../../PRIVATE-REGISTRY-BOOTSTRAP-VALIDATION.md) records
real source/initialization proofs, 12 new tests and 73 affected regression tests.

## Cold proof wire

[wire.rs](wire.rs) owns complete CanonicalIndex Source+Locking encoding and fresh
bounded decoding/verification, including all three returned/owned/new roots.
It has no StateLease or cache-ID transport. The
[wire module](../proof_wire/README.md) and
[validation record](../../../PRIVATE-PROOF-WIRE-VALIDATION.md) describe actual sizes,
foreign/structural/cryptographic rejection and resource observations. The returned
experimental Statement is not a writer capability, durable receipt or live grant.
