# Version-bound private N4 locking selection

This additive nonaccepting relation passed release build, strict Clippy,
seventeen numerical reports, its typed shape gate, one genuine cold/two-warm
CLI chain and all 158 serial tests. The [validation record](../../../../VERSION-LOCKING-VALIDATION.md)
separates actual observations and remaining obligations. Public fixture keys,
plaintext, identities and controllers are NONSECRET.

The prior [canonical locking relation](../../locking/README.md) still requires its
original complete source proof per request. This distinct relation instead uses an
[actually verified StateCertificate](../README.md) and a fresh independently expected
query/control context. It is a reusable proof prerequisite, never a live lock grant.

## Responsibilities and API

| Owner | Responsibility |
| --- | --- |
| `mod.rs` | Typed Expected/Statement, profile/domains, fixed nonsecret CLI fixture |
| `certificate.rs` in the parent | Sealed actual admission and exclusive StateLease |
| Shared locking statement/AIR/trace | Exact closed two-transaction N4 transition |
| `tests.rs` | Cold/warm, independent context, rebuilt source and cache-budget attacks |

`Expected::checked` accepts a typed StateStatement, independently supplied query
request, genesis, parent, old registry root and independently supplied client plan commitment. Controller
authorization is external and unimplemented; Expected pins are not authorization. A private
source-contract enum belongs to Expected: canonical-request and certified-state
contracts select distinct Kinds and encodings. Mutating a generic source relation
cannot turn the old contract into a version certificate. The old constructor is
strictly CanonicalIndex-only; the new constructor requires StateCertificate and its
exact deterministic version tag. Neither constructor verifies a certificate.

`StateLease::prove_lock(expected, statement, witness)` and `verify_lock` compare BOTH
submitted and independently expected full StateStatements against the lease, then
the complete Expected, before public-word conversion, Backend construction or trace
factory invocation. Total field comparisons reject malformed packet lengths without
calling an assert-based word encoder. Equality includes both heads,
complete packets, C_key, C_state, relation and version tag. A cache tag/root alone,
missing proof, old byte/canonical proof or a C_sel alias supplies no authority.
Admission still consumes and actually verifies the completed source proof before
creating the private sealed certificate. Warm callers cannot pass a trusted Boolean,
unchecked prefix, source-proof factory, key callback or arbitrary cached result.

## Exact bindings and unchanged arithmetic

The source stream remains the certificate's exact STATE_DOMAIN/version/profile,
version tag, heads and independently expected C_key, private salt, all587 original
u32 words and six zeros: 87+587+6=680. It is NOT rewritten with the query request.
The source proof covers full AEAD and real canonical N4 index validity, not a byte
opening or incomplete subset. Private TableId/RowIds come from those same words.

The116 public fields are new query profile8/request8/heads56/C_key4/C_state4/genesis8/
parent8/C_old4/C_plan4/C_return4/C_owned4/C_new4. The separate query request and parent
can change without re-proving the unchanged version. A proof for the old context
still fails genuine SDK verification under the new one. Independently expecting
these fields does not prove their authorization or common-parent freshness.

Registry112, its domain DCS/LKREG/N4/v1! and registry-profile digest are BYTE-FOR-BYTE
the old stable encoding: no query request, parent, heads, C_state or plan enters it.
It binds genesis, DB/key domain, exact C_key, private table/all four ordinal IDs,
complete two-transaction holdings/counters/status and salt. Equal AEAD secret keys
with reblinded C_key are different anchors and cannot alias this registry.

New query domains are DCS/VLPLAN/N4/v1 (Plan144), DCS/VLRET/N4/v1! (returned168),
and DCS/VLOWN/N4/v1! (owned168). All bind the new profile and independent query
context. The same six-stream AIR enforces full256 membership, all four conflict
modes, WAIT/NOWAIT atomic rollback, SKIP, OFFSET-acquired versus returned rows,
u32 candidate admission, stable compaction, zero inactive slots and complete new
registry. No constraint is bypassed by the typed source branch.

The closed `Blocked` snapshot and selected PostgreSQL-rule scope are inherited
from the [canonical locking contract](../../locking/README.md#walk-and-atomic-outcomes).
This child adds no wait/wakeup, deadlock or MVCC-recheck protocol, table-level
`ROW SHARE`, `OF`/join/cursor or multiple-locking-clause coverage.

Static shape remains T512/W1948/PV116 with512 periodic columns and two full row
openings. Source/old/plan/new/owned/returned absorb slots remain0..84/85..98/99..116/
117..130/257..277/278..298. Calculated trace/masked/main-LDE arrays remain
7,979,008 /15,998,976 /127,991,808 bytes. Symbolic AIR, periodics, proof/FFT/tree,
witness and cache memory are additional; these arrays do not bound process RSS.
Actual degree, constraint/chunk/batching counts and both per-proof model bounds
must be inspected before trace/proof execution. Old profiles and backend parameters
are unchanged. Individual bounds do not establish composed128-bit security.

## Lifecycle and gates

The existing single-entry64MiB retained-owned cache is unchanged. It charges actual
nested Vec capacities, checked metadata and old PLUS prospective candidate before
replacement. A failed admission retains the old certificate. One exclusive borrowed
lease prevents replacing/clearing the entry in flight; it clones no proof and retains
no Backend/FFT/prover data/key/witness. Restart/miss requires real admission again.
Already allocated candidate construction, allocator overhead and warm proofs/witnesses
are outside that budget; there is no bounded wire decoder or whole-process RAM claim.

`security version-locking-selection` constructs only bounded native fixture metadata
and performs actual symbolic analysis. `prove version-locking-selection` produced
one genuine cold State proof and actual cache admission, then two independent warm
lock proofs with different requests/parents/masks/LIMIT (including LIMIT0). The second
fixture uses the first successful C_new as its independently pinned C_old; fixture
construction is not evidence of real control consensus. Source witness and Backend
are dropped before warm calls. Every warm timer includes fresh Backend setup; no
Backend is cached. All seventeen numerical reports and the observed chain passed
before the complete 158-test suite. The previous sixteen reports remain exact;
this is neither composition-wide security certification nor live lock acceptance.

Remaining requirements include independently anchored control genesis/history and
controller authorization, per-query fresh agreed heads/parent, writer fencing,
rollback/MVCC/finality and cross-version identities. Warm witnesses still contain
2348 private original bytes, registry, plan and salts locally. No BFV formation,
peer plaintext-free query execution, Owner export or production accepting API is
added. The unchanged live hard rejections cannot accept this experiment. Full private PostgreSQL, practical end-to-end latency and the whole-process memory
target remain unestablished; no fixed latency SLA is selected here.
