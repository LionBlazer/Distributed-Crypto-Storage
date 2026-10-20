# Owner Joint Bootstrap

This module produces the existing N4 Source/Lifecycle Bootstrap relation from a
real fetched, independently pinned encrypted Source. It initializes the private
Registry opening for the distinct Joint application without selecting a predicate
or running FHE. The genesis and EmptyPending owner tests and the complete typed
independent-process lifecycle passed [native validation](../../../../../../../../docs/joint-owner-lifecycle.md).
That record gives the measured scope; it does not establish a general timing or
memory guarantee.

## Ownership and direct dependencies

| Owner | Use |
| --- | --- |
| [SourceOwner and Joint owner composition](../README.md) | Actual AEAD key/Ckey custody, full bundle audit, all four originals, guarded historical openings |
| [Closed Bootstrap association](../../../../../../../registry200-finality/src/joint/bootstrap.rs) | Opaque Pending parent, independent own expectation and exact proof/QC receipt |
| [Lifecycle producers](../../../../../../../registry200-proof/src/lifecycle/README.md) | Unchanged Source-first Bootstrap proof and pure enrollment/Registry opening encodings |
| `registry200-joint`, `registry200-journal` | Existing canonical outer/inner request, manifest, new G and preproof intent |
| `zeroize`, `sha2`, existing OS randomness | Owned private buffers, public pair identity and fresh canonical salts |

`SourceOwner::prepare_joint_bootstrap` requires a `JointBootstrapParent` supplied
only by a live closed `JointHistory`, an independently pinned `JointBinding`, real
`FetchedSource`, guarded nonzero controller labels and a caller-selected fresh
independent nonce. It checks the binding/full descriptor/new G/database/object,
loads and audits the exact original encrypted data and index under both pinned
heads, and matches Source Ckey to the application before proof production.

Enrollment64 is built from the real TableId/controllers and a fresh enrollment
salt. The unchanged Bootstrap intent q binds G, the exact parent, nonce and
enrollment before fresh Copen is formed. Real Source and Lifecycle proofs use
`command=None` and the default Registry. No fixture, secret getter, dummy BFV
operation, ControlKind proof or Result144 is used. The original proof profiles,
pair cap, per-blob cap and transport grammar remain unchanged.

The prepared value exposes the public request and lifecycle evidence; its private
candidate captures the real TableId, all four original IDs, controllers and salts.
After retaining the pair through the existing same-depot ingress, the caller builds
`Manifest::bootstrap`. `candidate.expectation(manifest)` requires its exact
produced pair hash/length and creates only unverified public intent. Hashes do not
replace the mandatory Source/Lifecycle replay.

`JointHistory::apply_bootstrap` checks the complete own expectation before import,
then genuinely checks the owner-signed Body/header, Source/Lifecycle proof, exact
weighted QC and Journal ancestry. `candidate.complete(receipt)` consumes both
values, matches the full association, reopens enrollment and default Registry
roots with the real TableId/all IDs, and returns `CompletedJointBootstrap`.
`into_opening()` moves an **unverified historical candidate** into the existing
typed BEGIN/Acquire path, which must reload real Source and rehash its roots.
Errors consume and clear owned private candidate buffers. Caller copies and native
field/SDK scratch are not promised erased.

## Scope and tests

The Pending factory supports initial genesis and a genuinely applied EmptyPending
lineage. An authentic saved parent can become stale; expectation/application
checks, rather than a raw HeadRef factory or a current-lease assertion, control its
use. The new tests exercise real Source/Lifecycle/Kind proofs and genuine local
weighted QCs for genesis and EmptyPending, then typed BEGIN and fresh keyless
replay. They include malformed prerequisites, foreign intent/binding/object/key,
changed private openings, Active/stale rejection and a physically missing stored
prerequisite. Those local signature tests are distinct from the later executed
four-OS-validator Bootstrap/Begin/recovered-Acquire/End gate.

Owning validation commands:

```sh
cargo test --release --locked -p storage-client --features private-input-proofs private_predicate::source::locking::joint::bootstrap::tests:: -- --test-threads=1
cargo test --release --locked --doc -p storage-client --features private-input-proofs
cargo test --release --locked --doc -p registry200-finality
```

This is not Session SQL admission, an encrypted data COMMIT, network freshness,
current lock ownership, a durable signer installation or an OwnerVault CAS.
[ComputePrepared recovery](../vault/README.md) remains Acquire-only and does not
persist Bootstrap/Control openings, exact signed-byte retries or installation
phases. An old authentic retry is not a fresh invocation barrier. No raw opening
getter, generic verifier, cached success flag or new shared budget is introduced.
