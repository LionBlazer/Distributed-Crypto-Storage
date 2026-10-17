# Version-bound state certificate and private selection

This validated experiment adds two distinct nonaccepting relations. Release
build, strict Clippy, thirteen actual numerical reports, both genuine CLI proof
gates and all 97 serial tests passed. The previous 86 cases and profiles remain
in that run. The [validation record](../../../VERSION-STATE-VALIDATION.md)
preserves exact timer/resource scopes and the initial compile failure.

StateCertificate proves the complete fixed N4 packed AEAD/canonical-index relation
once. VersionSelection opens the same private plaintext commitment for a fresh
request and independently expected private plan. This is a feasibility gate toward
private source/completeness proofs, not a product SQL accepting path.

Direct dependencies are the parent opening statement/commitment/fixture/trace
modules, sibling Selection statement/trace, private Backend/primitive dispatch,
compact-store's canonical Commitment decoder, pinned P3 proof/field/hash types,
rand and SHA-256. This module has no product or peer-runtime dependency.

## Exact binding

The certificate uses the existing 172-byte data and 2496-byte index images.
Its constructor calls the same complete core canonical/root audits with
independently expected heads and C_key. Its new profile includes the original
packed relation profile; its commitment domain is DCS/STATE/N4/v1! (version 1).

The old request slots now contain a **version tag**: SHA-256 of
DCS/experimental/version-state-tag/N4/v1, the new certificate profile, each
complete public image preceded by its LE u64 length, and canonical C_key.
The tag is deterministic for that exact public version/key/profile. It is not a
query request, agreement certificate or freshness assertion. C_state is excluded
from the tag to avoid circularity.

C_state remains exactly 87 prefix fields +587 private u32 words +6 zeros.
The prefix contains its new domain/version/profile, version tag, both heads,
independently fixed C_key, and four private uniform Goldilocks salt elements.
All packed captures, complete AEAD/index checks and hiding PCS stay unchanged.

Each query has its own request/profile. C_plan uses DCS/VPLAN/N4/v1!; C_sel uses
DCS/VSEL/N4/v1!!. Their fixed encodings remain 112 and 88 fields. They bind the
same heads/key/C_state, independently expected private TableId, final TRUE-age
mask, projection, effective LIMIT and independent salts. Shared SelectionAir opens
every source word, checks the complete age domain and commits four stable
original slots, with unused slots zero. No count, mask, RowId, key, salt or
original field becomes a new public output.

## Ownership and admission

| Entry point | Responsibility |
| --- | --- |
| StateStatement::checked | Independently expected public canonical state/key anchor |
| Candidate::new | Consume an untrusted completed SDK proof and meter owned allocations |
| CertificateCache::admit | Full-statement equality, joint budget, actual source verification |
| CertificateCache::lease | Borrow the exact verified entry exclusively; fail on miss |
| StateLease query prove/verify | New query proof linked to that exact state |

A sealed VerifiedStateCertificate is constructed **only after actual SDK source
verification**. It owns the completed proof and public statement. It has no Clone,
Serialize/Deserialize, mutable accessor, signature/root shortcut or trusted
Boolean. No Backend, FFT buffers, prover data, key or witness enters the cache.
The completed proof is retained; no second PCS opening is requested.

There is one entry and one exclusive borrowed lease. Its Rust lifetime prevents
replacement/clear while in use. The lease owns no proof or additional heap.
No Arc/Rc, global map or reference-counted evicted entry remains elsewhere.
Restart is empty. A miss requires actual proof admission, never metadata credit.

Lookup compares all public fields, including complete packets and C_state,
not a tag alone. Equal tags cannot alias different statements. Changed heads,
packets, key, profile or commitment cannot reuse the entry. Failed admission
preserves the old verified certificate.

## Bounded owned storage

The CLI chooses a **64 MiB retained-owned admission budget**, a local experiment
policy rather than a proof parameter or whole-process RAM bound.

Checked arithmetic charges every nested Vec **capacity**, not length: statement
packets, proof/hiding openings, FRI rows/salts, caps, multiproof siblings, commit
phases and final polynomial. Outer Vec headers and fixed proof/cache/candidate
metadata are included. Pinned SDK0.8 hides cap capacity: the consuming accountant
uses into_roots, measures the actual returned Vec and rewraps the same checked
roots. No serializer, SDK fork or unsafe field access supplies accounting.

Admission charges the old entry **plus** the prospective candidate before
verification/publication. One exclusive lease header is reserved even idle.
Overflow/budget/verification failures publish nothing and retain the old entry.
A genuine replacement case fits each entry alone but rejects their coexistence;
the separate empty-Vec/nonzero-capacity case covers capacity-versus-length.

Native candidate construction has already allocated the proof. Construction,
temporary normalization, allocator overhead, independently owned query
proofs/witnesses, verifier/FFT work and other process memory are outside this
retained-owned budget. No network decoder/preallocation or peak/RSS bound is
provided.

## Geometry and gates

| Relation | Height | Width | Public fields | Periodic columns |
| --- | ---: | ---: | ---: | ---: |
| StateCertificate | 512 | 7161 | 691 | 512 |
| VersionSelection | 512 | 957 | 88 | 512 |

Both reuse complete current/next openings and declared bound 5. Actual SDK
inference reported degree 3 and 16 quotient chunks for each. StateCertificate
has 16133 assertions and 14502 batched functions; VersionSelection has 4814 and
2094. Both decoding bounds reached 128 per proof, without a composition-wide
security claim. Main-array estimates are 29,331,456 /58,703,872 /469,630,976 bytes for
the certificate and 3,919,872 /7,880,704 /63,045,632 bytes for Selection.
Periodic payload, expression DAGs, proof cache and other allocations are separate.

CLI modes are security/prove state-certificate and version-selection.
Security does not generate a trace. The query prove gate genuinely admits one
cold certificate then proves/verifies two different queries over that entry.
Warm query timers include fresh Backend::new setup. Source Backend/witness are
scoped out before warm queries. No Backend is cached, and no speed is predicted.

Cases cover genuine cold/warm empty/nonempty queries, miss/restart/clear,
capacity/overflow/joint replacement, actual proof corruption, old profiles,
independent source/context/collision changes and rebuilt false private bytes.

## Remaining requirements

The certificate proves an exact version, not that it is fresh/agreed/authorized.
Those checks stay independent per query and are not implemented here. Existing
live missing-proof/freshness hard rejections remain unchanged.

Production custody/anchor setup, historical TableId/RowId continuity,
typed/nullable PostgreSQL, BFV formation/linkage, mutations, locks/finality and
product acceptance remain unmet. Known public fixtures exercise private-in-proof
columns, not production secrets or erasure. Per-proof model bounds do not
establish composed 128-bit security or certify commitment/adaptive-proof
assumptions. Observed warm proof plus verification was
592.6200 and 652.7199 ms for two distinct requests, excluding cold source work,
network/FHE/SQL/freshness. Full SQL at 500 ms and whole-process RAM remain
unestablished. The 64 MiB owned cache policy is a separate local limit.

Dependencies are the existing [opening source](../README.md),
[Selection](../selection/README.md), shared P2/backend and pinned SDK.
No dependency, SDK fork, Owner API, codec or production consumer is added.

## Validated version-bound locking extension

The new [VersionLockingSelection child](locking/README.md) adds typed StateLease
locking proof methods. It preserves the existing cache accountant/lifetime and all
old source/selection profiles. Full independently expected State and query/control
context are checked before Backend/trace. Its new Kind/domains reuse shared locking
math and stable Registry112. Seventeen numerical reports, one genuine cold/two-warm
CLI chain and all 158 serial tests passed. The [validation record](../../../VERSION-LOCKING-VALIDATION.md)
preserves exact timings and resource scope; live lock acceptance remains absent.
