# Successful lock-return encoding

This experiment-private bridge opens the **actual successful Return168** commitment
of either canonical LockingSelection or VersionLockingSelection and constrains all
8192 scaled BFV plaintext coefficients. It is a separate `LockReturnedEncoding`
Kind/profile; an old Selection88/SelectedEncoding proof cannot be relabelled.
Release/test compilation, strict Clippy, all 23 numeric calls, three owning
oracles and three genuine CLI compositions passed on frozen R3 source.
All 235 owning tests passed; the [validation record](../../../../LOCK-RETURNED-BFV-VALIDATION.md)
records these actual gates and the remaining acceptance gaps.

The original age, amount, ordinal and RowId are retained even when the compiled SQL
projection requests only Age or Amount. This is an originals-to-encoding relation,
not projected user-visible SQL output, an authority/column-ACL grant or a ciphertext
formation proof. All fields and salts remain private; only public producer inputs
and commitments enter the public statement.

| Module | Responsibility |
| --- | --- |
| `statement.rs` | Sealed Canonical/Certified producer contracts, independent Expected and PV128 |
| `mod.rs` | Actual prerequisite verification, new profile and canonical CLI consumer |
| `air.rs` | Typed reuse of the existing complete coefficient kernel |
| `trace.rs` | The same private witness/trace implementation; no second AIR copy |
| `tests.rs` | Real parent proofs, upstream encoding and rebuilt hostile traces |
| [State consumer](../../state/locking/README.md) | Actual certificate admission and warm typed proof path |

`Expected::canonical` checks the independently supplied full source/control inputs
and exact proposed parent output roots. A real canonical source-plus-lock composite
must verify before the child Backend or trace factory. `Expected::certified` instead
requires the exact VersionLock statement and independent Expected, then an actual
`StateLease::verify_lock` call. The lease only exists after actual StateCertificate
admission. No bool, signature, submitted receipt or direct State/byte proof can stand
in for either prerequisite. Full producer PV116 (including RETURNED, OWNED and NEXT)
and the typed producer profile/domain bind the child context. There is no fresh-head
or controller-authority inference from the cache.

The source sponge opens exactly168 fields: return-domain4, version1, query context96,
C_old4, C_plan4, C_new4, capacity1, **outcome0**, private salt4, four original12-field
tuples and one zero. Gadget C absorbs these21 blocks at rows1..21 and checks the real
parent C_return at row21. A genuine Blocked/NOWAIT parent has outcome1/2; its empty
rows cannot become a successful empty grant. Genuine successful LIMIT0 remains valid.
OFFSET-visited rows can be OWNED without being RETURNED. The bridge opens RETURNED;
it never substitutes C_owned or a predicate/ordinary LIMIT prefix for the actual set.

The unchanged complete coefficient arithmetic is shared with
[SelectedEncoding](../../selection/encoding/README.md). All twelve original sparse
slots, the fixed public inverse-SIMD matrix, canonical M/W ranges and
`W=(78307*M) mod114689` constrain every8192 coefficients. The encoded sponge is
context8 + private salt4 + zeros4 + W8192. Its new SHA256 context includes the new
profile and exact full producer PV116 in canonical u64 little-endian encoding.
Fresh independently sampled input/output salts and existing backend masks remain
required; the AIR proves no salt entropy. Old Selection encoding keeps its exact
88-field source, PV100,11 source blocks,205 periodics and old domain/profile.

Calculated geometry is T512/W3580/PV128/215 public periodic columns, with full
current/next openings. Main trace/masked/main-LDE arrays are
14,663,680/29,368,320/234,946,560 bytes. Public periodic payload is880,640 bytes;
the shared public8192-by12-u32 matrix is393,216 bytes. These are array calculations,
excluding expression DAGs, quotient/DFT/tree/proof/allocator/stack and concurrent
parent/cache allocations. They are not RSS or whole-process memory bounds. The
conservative degree hint remains 5; actual normal/certified reports each have
5243 constraints, degree 4, 16 quotient chunks and full-width batch 7340. Both
per-proof model floors are 128; these were checked before the observed traces. Existing q192/ext5/r5/blowup8/hiding parameters are
unchanged. Per-proof model bounds do not establish composed128-bit security.

The two independently reviewed and actually observed CLI consumers are `security|prove lock-returned-encoding` and
`security|prove version-lock-returned-encoding`. They use the real SQL compiler on
public nonsecret fixtures. Security mode builds bounded native metadata and the
coefficient commitment, but allocates no AIR trace or proof. The canonical proving
timer includes genuine source/lock production and verification plus child setup,
trace and proof. Its verification timer rechecks source/lock/child with fresh
Backends. The certified command reports cold source proof/admission separately;
warm proving includes lock production, real lease verification and child setup,
trace/proof, while warm verification checks both proofs. Fixture preparation,
encoded commitment construction and the preceding security report are outside
these proof timers. The cache retains no Backend or secret witness.

Production BFV key/evaluation-key authority and private peer FHE execution remain
absent. The old LocalFormation contract still accepts old SelectedEncoding only;
the distinct [returned formation](../formation/README.md) accepts this new C_enc
through actual typed-parent and same-key/Basis verification. Source/control genesis and history, authorization, fresh agreed heads,
writer fences, rollback/MVCC and consensus finality remain separate. Live network
SQL and lock acceptance stay unchanged and fail closed. Full PostgreSQL and the
whole-process resource target remain unfinished; no latency SLA is selected.

This candidate is based on published LocalFormation
`4c83c047f5fdaed9ff294d7b3eff1cc1ce411bb2`. Historical reports keep their original
scopes; current gate evidence and unresolved scope are in the linked record.
