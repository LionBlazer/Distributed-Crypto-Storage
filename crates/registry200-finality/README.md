# Registry200 durable checkpoint finality

This closed library owns the original Registry200 application's actual Journal,
weighted multi-slot signer and certificate floor log. It implements a local
durable protocol boundary. It is not a peer actor, a freshness barrier, an epoch
activation protocol or permission to accept SQL/row-lock results.

| Direct dependency | Responsibility |
| --- | --- |
| `registry200-journal` | Complete canonical application pins and the actual Source-first/Lifecycle transition verifier |
| `version-journal` | Canonical Header/Body, actual work/owner/CAS checks, bounded journal persistence and mechanical ancestry floor |
| `work-finality` | Checked bootstrap weights, actual signatures/QCs, round/lock/POL machine and exclusive multi-slot signer |
| `protocol-storage` | One 256 MiB maximum shared actual-file/transient-reservation quota |
| `sha2`, `ed25519-dalek` | Domain-separated identities and transfer of the caller-owned signing key |

| Public entry point | Contract |
| --- | --- |
| `profile_digest` | Closed algorithm identity selected before bootstrap work |
| `Binding::new` | Independently selected work Genesis, original Registry application, actual Journal Genesis and explicit multi-slot rules |
| `Descriptor::{encode,decode}` | Exact 272-byte **untrusted** candidate metadata, never a verified token |
| `RegistryFinality::{create_new,open_existing}` | Exclusive ownership of actual files and private signer; recovery is existing-only |
| `import_candidate` | Recheck actual full Header/Body/owner/proof and current certified parent, including duplicate imports; retain body before voting |
| `propose`, `receive`, `on_timeout` | Actual local proposal, bounded signed remote input, or local clock control; no generic verifier callback |
| `finalized_head` | Metadata available only after durable decision, floor installation and next-slot signer synchronization |

## Pins and ordering

Construct `Rules::multi_slot(profile_digest(), 272, ...)`, then supply its
`seed_domain(public_network)` to `NetworkSeed` **before** mining tickets. Journal
Genesis uses that same public network tag, not a not-yet-derived finality Genesis
id. `Binding` subsequently pins both complete Genesis identities, the complete
312-byte Registry application descriptor and complete RulesId. The application
id already includes the original Source/Lifecycle proof-wire contract. None of
these bootstrap derivations includes candidates, proofs or certificates.

The new explicit profiles/namespace have no migration or legacy fallback. The
original Registry application preserves its immutable Source head pair and
Pending/Active enrollment/registry control encoding. New predicate/FHE composite
evidence is not admitted by substituting its metadata for the old pair proof.

Every slot has exactly the preceding durable floor as its candidate parent. A
descriptor contains BindingId, slot, previous semantic DecisionId and the complete
192-byte Header. The body must exist in the owned Journal. The closed verifier
always rechecks actual Header work/time/height/body hash and exact current parent,
canonical Body, owner signature, real Source-first proof and child, enrollment and
one-control CAS. Cached candidate status is never a proof shortcut. Empty blocks
are allowed because they preserve all state and need no invented SQL proof.

An agreed-value DecisionId includes ContextId and exact length-delimited value;
it excludes QC bytes, signer subset and commit round. Distinct genuine quorums or
rounds agreeing on one value therefore produce the same successor context. After
the signer decision syncs, this wrapper independently rechecks the candidate/QC,
appends and syncs its floor certificate, installs the mechanical Journal filter,
then calls the signer's no-argument `advance`. No action escapes that wrapper call
before the full order completes. The key stays private-owned throughout.

## Files, quotas and recovery

An existing caller-owned directory contains exactly the adapter's three named
files: `registry-finality-journal-v1`, `registry-finality-floor-v1` and
`registry-finality-signer-v1`. This library does not scan or take ownership of
unrelated files. The caller must include all retained application artifacts in
the same `ByteBudget` before any signer can emit a new action.

The original Journal disk format is unchanged and receives a new Binding-derived
namespace. Its creation's hidden initial write is pre-reserved; successful
`retain_file` transfers that reservation to an actual persistent file charge.
An uncertain creation/transfer error conservatively retains the reservation and
fails installation. Recovery requires an entirely new budget reconstructing all
actual files. Journal/floor/WAL growth is charged before writes; file charges
survive handle Drop. This is a concrete byte quota, not a whole-peer RAM claim.

The floor log has a 168-byte pinned header and records of exactly
`372 + certificate_bytes`, at most `372 + 512 KiB`. Records include sequence,
previous record hash, commit round, exact descriptor, bounded certificate length,
hash and repeated length/trailer. Total floor records cannot exceed the pinned
Journal header bound; floor-file extent cannot exceed 256 MiB. The **one shared**
quota still bounds all these files together. Counts and exact remaining record
length are checked before allocation. No generic deserializer is used.

Reopen first verifies the actual Journal under independent Genesis/application
pins, then verifies each floor's actual QC and historical parent/body/proof before
reinstalling the floor. Signer replay subsequently uses that checked historical
slot-to-parent map, including rechecking losing proposals. A durable signer
decision not yet installed is completed idempotently; a floor whose next-slot WAL
acknowledgment was lost advances the same owned signer. It never accepts a caller
NextContext. Missing, corrupt or torn files are hard errors; no truncation,
automatic recreation, opaque receipt restoration or rollback is provided. Any
uncertain floor/signing I/O poisons the wrapper and suppresses outbound actions.
Host filesystem/directory-entry power-loss guarantees and malicious disk/key
rollback remain operational assumptions.

## Verification status and remaining DCS work

All seven owning cases and three ownership compile-fail examples passed. The
affected work-finality and Journal regressions, strict Clippy and Core default
build check passed too; see the [native validation record](../../docs/registry200-finality.md).
Owning cases use actual public, explicitly non-secret fixtures: Core Source and
Bootstrap/Begin/Acquire/End proofs in owner-signed Journal bodies, real weighted
QCs, private-input destruction followed by fresh reopen, real file faults and
shared quota exhaustion. Empty-only tests are labelled as such. No fake Source
verifier or serialized `valid` flag is used.

The safety premise remains less than one third Byzantine computational weight in
the **activated** roster, with non-rollback durable honest signing. Checked work
does not establish that premise, fair election inclusion, balanced failure groups
or availability if a high-weight participant disappears. The bootstrap roster
remains fixed. Production participant bootstrap, permissionless system-lane work tickets,
safe epoch handoff, freshness barriers and a new joint hidden-predicate/FHE/lock
application are still required. This wrapper's local latest floor cannot certify
globally newest data during an unseen partition and gives no live SQL grant.

The round/lock/POL semantics are pinned separately in
[`work-finality`](../work-finality/src/consensus/README.md), based on
[Tendermint Algorithm 1, arXiv:1807.04938v3](https://arxiv.org/pdf/1807.04938v3).
See the [mechanical Journal boundary](../version-journal/README.md) and the
[original Registry application](../registry200-journal/README.md).

## Export and keyless follower

| Public entry point | Contract |
| --- | --- |
| `candidate_block`, `checkpoint_after` | Bounded original block and persisted QC export; decoding never confers authority |
| `Follower::{new,apply}` | Keyless next-slot verification of the real application and quorum under independent public pins |

The [keyless follower contract](src/follower/README.md) distinguishes checked
in-memory evidence from a durable signer floor and current freshness policy.
Export codecs have a distinct `export_profile_digest`; existing work/vote/QC,
application, binding and disk profiles remain unchanged. The executed
[TLS peer actor](../peer-runtime/src/finality/README.md) is owned by `peer-runtime`.
The genuine Source/Lifecycle history test now also constructs a fresh keyless
follower after private inputs are dropped and rechecks every original Body/QC.
[Network validation](../../docs/network-finality.md) records its exact scope.
Production deployment, system-lane,
reconfiguration and freshness limitations above remain open.
