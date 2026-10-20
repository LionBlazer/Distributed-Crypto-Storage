# Registry200 Joint kernel

This fixed N4/T2/D2 application composes hidden predicate locking with the
original Source and Lifecycle relations and retained real BFV computation.
Its six owning native cases passed; full Acquire and application/runtime
integration remain pending. Construction of a descriptor, request, catalog or manifest supplies
no computation, authorization, finality or SQL permission.

`Descriptor::checked` pins the original SourceSpec, source-object identity,
complete original public setup SHA256 and SHA512, independent public Owner anchor
and **all 33** KeyTransform public values. `Descriptor::decode` parses metadata;
the embedding application must authenticate these independent pins. The old
parameter-only digest inside Key33 keeps its original meaning. Neither that
digest nor this module proves a new public evaluation-key same-secret theorem.

The new descriptor has an exact 896-byte codec and a distinct application ID.
`Application::new` checks the **new** Genesis application commitment and exact
SourceSpec initial shards. It does not invoke the old application's Genesis
checker on a foreign application. Original SourceSpec IDs still label its
unchanged control heads and inner requests. The preproof query remains the
original `intent_query(SourceSpec, new G, parent, nonce, enrollment, operation)`.
Source heads are immutable in this profile; only the single control shard may
change, with sticky enrollment and an exact nonidentical CAS.

## Closed proof lanes

`Request` is exactly 2764 bytes: a new outer lane/application envelope and the
unchanged complete 2716-byte inner request. `Manifest` is exactly 232 bytes and
contains only canonical next/result roots and three fixed-role content references.
Unused references must be zero. All referenced roles have caps checked before I/O.
`Manifest::references()` exposes only those canonical fixed roles, their ordinal,
BlobId and unchanged byte cap. Its exact-size, double-ended, fused iterator
allocates nothing and performs no I/O or proof verification. These references
are public metadata for prefetch, not additional serialized fields or wire tags.

| Lane | Mandatory local evidence |
| --- | --- |
| Bootstrap | Original genuine Source/Bootstrap pair; Pending becomes Active. |
| Control | Original genuine Source/Lifecycle pair plus the genuine private ControlKind Link proving membership in the six non-Acquire operations. An outer lane tag cannot substitute for this proof. |
| Acquire | Retained catalog replay of the Key, Source, both coefficient Encodings, ten Basis, two Formation roles and all 118 output records; exact same Source and full query/context/key; genuine Lifecycle child plus PredicateAcquire Link proving successful Acquire with the same private 256-bit mask and Result144. |

There is no ordinary SELECT/read lane, no missing-proof fallback and no host
callback deciding cryptography. `JointVerifier::check` and its concrete Journal
`TransitionVerifier` implementation perform every mandatory proof check again
on every invocation, including import/reopen. QCs, catalog identities, prior
results and hashes cannot replace those checks. The underlying frontends may
reverify shared premises; "input16/output118" counts roles rather than the total
number of verifier calls. Repeated full replay can be expensive and is a DoS and
scheduling concern for the eventual host. No interactive latency or whole composed
security figure is asserted here.

The real Journal must authenticate the owner signature and validate the supplied
parent before invoking this kernel. Direct calls check mathematical consistency.
This owner-only scope does not establish controller-signature possession or
delegated client rights. A valid historical computation remains distinct from a
fresh linearization barrier and a current finalized lock. The eventual closed
finality adapter must pin the new AppId/Genesis and proof/resource semantics in
its independently selected Rules, replay before voting/import/reopen, and wait
for the required quorum. No quorum means no lock or End permission.

## Depot and setup lifecycle

`JointDepot::open` consumes the existing **typed participant DepotBudget** and
opens one concrete ProductStore. Before moving it into `JointVerifier`, retain
`depot.ingress()`. Cloneable `JointEvidenceIngress` handles use the **same**
`Arc<Mutex<ProductStore>>`, exclusive store gate and shared participant ledger for
bounded public-byte retain/read. They expose no mutable store or lock guard and
never mark a blob as verified. Future candidate uploads therefore remain possible
after verifier construction. Network fetching must finish outside Journal locks;
the verifier performs local reads only and serializes them with ingress.
`JointEvidenceIngress::catalog_claim` uses that same store's bounded local read,
hash/EOF checks and existing canonical catalog parser. The returned unverified
`CatalogClaim::references()` enumerates every retained product premise for
prefetch; neither operation checks those premises or establishes admission.
No network operation may hold the depot mutex. After prefetch, the host must
recheck the current context and run the actual fixed verifier under its one
existing ProofGate; no copied metadata can replace that replay.

`retain_setup` stores the canonical original setup in one or two nonempty chunks,
each at most 32 MiB. `SetupClaim` is a small untrusted 96/136-byte reference record.
Its exact extents, application ID, complete SHA256 and SHA512 are checked before
the restored bytes enter `PublicSetup::from_bytes`. The verifier then rechecks the
original anchor association. The embedding host must durably retain this claim
in authenticated/independently pinned local metadata. A RAM setup alone is not a
restart contract. No secret key, Source key, controller or private opening is
stored in this public depot.
`SetupClaim::{application_id,bytes,parts}` merely borrows or copies its bounded
unverified labels and canonically ordered setup references. These getters perform
no allocation, I/O, hashing or SDK work; the full setup checks remain mandatory.

The existing Body 32 MiB, transport 64 MiB, Journal 256 MiB and old WAL caps are
unchanged. Detached evidence consists of individually bounded blobs in the
explicit participant depot; the signed Body contains the small manifest. The
participant's global local quota accounts the same files, staging and metadata
according to protocol-storage's existing profile. This is not a silent expansion
of legacy ByteBudget. Setup assembly is bounded at 64 MiB; proof buffers are
released by the underlying sequential verifiers. Whole-process 1–2 GiB RAM,
timing and complete Acquire operation sizes require actual measurement.

Immutable full proof history eventually fills a finite quota. Resource exhaustion
must reject new work. Safe history compaction, proof aggregation, client Vault
and staged-transition durability, pending lost-ACK recovery, source replacement,
read freshness, multi-shard SQL and restart promotion remain unresolved. This
kernel alone enables none of those features or a live SQL grant.

## Ownership and direct project dependencies

| Module | Responsibility |
| --- | --- |
| [registry200-journal](../registry200-journal/README.md) | Unchanged inner SourceSpec, control heads, Request and intent query. |
| [registry200-proof](../registry200-proof/README.md) | Actual Source/Lifecycle, private ControlKind and PredicateAcquire proof frontends and original bounded envelopes. |
| [bfv-product-evidence](../bfv-product-evidence/README.md) | Same concrete public depot, canonical catalogs and complete fresh product replay. |
| [bfv-mul-relin-proof](../bfv-mul-relin-proof/README.md) | Full provenance claim decoding and genuine input/output graph verification through retained replay. |
| [bfv-query-core](../bfv-query-core/README.md) | Original public setup/anchor decoding and exact encrypted coefficient request limits. |
| [bfv-key-transform](../bfv-key-transform/README.md) | Exact typed full Key33 metadata and fixed profile. |
| [protocol-storage](../protocol-storage/README.md) | Typed participant depot quota, immutable bounded blob identities and actual file accounting. |
| [version-journal](../version-journal/README.md) | Owner-authorized transition boundary, exact state roots, supplied parent and Genesis. |

`descriptor.rs`, `request.rs` and `manifest.rs` own the new canonical metadata;
`depot.rs` owns local evidence/setup lifecycle; `verifier.rs` owns the closed
composition. `tests.rs` keeps explicitly non-secret fixtures at this boundary.
Six passing owning tests cover canonical pins/caps, unchanged inner query binding,
readonly role/cap enumeration, bounded setup/ingress reopen, rejection of
hash-valid noncatalog bytes by the same parser, and genuine signed Source/Bootstrap/Begin+Kind
admission with fresh replay. They do not substitute for the later full retained
Acquire and independently running peer/finality integration gate. See the
[native validation record](../../docs/joint-admission.md) for exact commands,
the separate closed keyless history cases, negative challenges and measured scope.

## Returning the same fresh Acquire result

`AcquireExpected::new` captures independently selected own outer Request,
Provenance, complete encrypted request and locally recorded CatalogId. It checks
their full application/setup/Key33/Source/heads/query/CT association. This metadata
constructor verifies no proof or quorum and cannot construct `CheckedAcquire`.

`JointVerifier::check_acquire_block` takes the actual Journal/Header/Body and these
pins. One fixed private per-call adapter executes the same complete `check` path
during `Journal::reverify_block`; it captures only this call's actual replay result.
The result is released after input16, all118 records, Source/Lifecycle and
PredicateAcquire have succeeded. Owner signature, canonical Body/state/header
checks are performed by the actual Journal. An Empty or foreign request cannot
produce this result. There is no public verifier callback, acceptance flag,
persisted verification bit or cached backend/result. Ordinary `check`/Journal
consumers keep their previous full checks and discard the owned result.

`CheckedAcquire` exposes the exact public association and actual checked response,
not a lock or a current-head token. The [closed finality owner](../registry200-finality/src/joint/README.md)
must still bind the exact QC, context/slot, semantic decision and original block.
The new full four-validator/FHE owning source case is at the
[client boundary](../storage-client/src/private_predicate/source/locking/joint/tests/full_acquire.rs);
it passed with actual four-OS QCs, fresh keyless replay, one exact client completion
and hostile-evidence checks, as recorded in the
[native process record](../../docs/joint-participant-finality.md). Real prior-lock
contention and general SQL admission remain separate. Individual
input128/output-SDK policies and all existing wire/byte/element budgets are unchanged.
