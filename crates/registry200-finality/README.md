# Registry200 durable checkpoint finality

The distinct [durable Word application](src/word/README.md) connects immutable
SourceVersion and original EMPTY265/Control309 proofs to the actual shared durable
weighted voter, signer WAL and floor. Its bindings, control types and storage/QC
formats remain distinct from the earlier applications. It supplies no network
SQL or current row-lock lease.

`word::History` supplies independent keyless client receiving with one installed
immutable Source verifier, fresh per-operation Word/owner/ancestry/QC checks,
and an original-intent-bound historical receipt. It owns its Journal and Context;
it supplies neither durable signer state nor network freshness.

This closed library owns the original Registry200 application's actual Journal,
weighted multi-slot signer and certificate floor log. It implements a local
durable protocol boundary. It is not a peer actor, a freshness barrier, an epoch
activation protocol or permission to accept SQL/row-lock results.

The separate [closed Joint module](src/joint/README.md) composes the new
FHE/control application with actual weighted checkpoint verification. Its private
parent type can only originate in full application/QC replay. Alongside keyless
history, `DurableJointFinality` owns the actual signer and floor under a distinct
fixed durable Rules profile. Its five owning native cases and two ownership
contracts passed; see the [durable Joint record](../../docs/durable-joint-finality.md).
The original durable adapter below keeps its original application,
proof profiles and byte formats.

| Direct dependency | Responsibility |
| --- | --- |
| [registry200-joint](../registry200-joint/README.md) | Fixed retained FHE plus Source/Lifecycle/Link replay for the separate Joint history and durable owner |
| `registry200-journal` | Complete canonical application pins and the actual Source-first/Lifecycle transition verifier |
| `version-journal` | Canonical Header/Body, actual work/owner/CAS checks, bounded journal persistence and mechanical ancestry floor |
| `work-finality` | Checked bootstrap weights, actual signatures/QCs, round/lock/POL machine and exclusive multi-slot signer |
| `protocol-storage` | Original <=256-MiB shared budget or explicit participant global quota with unchanged control cap and typed depot accounting |
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

Private `pins.rs` selects Original, Joint or Progress installation domains for the
SAME actual FloorLog and participant files. Original choices preserve every
existing magic/hash/profile byte. Joint uses its own fixed Rules/storage profile
and accepts no old-application fallback; see its module README for the executed
tests and complete replay contract.

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
remains fixed. The participant bootstrap below has passed its own native gate;
permissionless system-lane work tickets, safe epoch handoff, freshness barriers
and full network integration of the Joint hidden-predicate/FHE/lock application
are still required. This wrapper's local latest floor cannot certify
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
The participant-host deployment below has a separate four-OS validation record.
System-lane, reconfiguration and freshness limitations above remain open.

## Participant storage

`RegistryFinality::{create_participant,open_participant}` now compose directly with
[`ParticipantQuota`](../protocol-storage/README.md). Three new owning filesystem
cases and a four-independent-OS scenario passed; see the
[participant-host validation](../../docs/participant-finality-host.md). Earlier
validation records retain their legacy-directory and preceding-TLS scope.

The explicit participant storage profile derives one typed file identifier from
the independently pinned binding and local signer public key. Its four control
files are `hex32.journal`, `hex32.floor`, `hex32.wal` and `hex32.meta`. Every actual
creator obtains its own real preflight permit in the same control/global ledger;
every append precharges its complete next extent. Depot and custody handles share
that ledger, with the existing 256-MiB control ceiling unchanged.

NEW first reserves metadata absence, then creates Journal, floor and signer WAL.
It syncs the exact binding/signer/profile metadata last, after the other files.
A quota refusal can therefore leave charged partial files, but cannot publish
completion metadata. Any ambiguous created artifact or owned write/read error
poisons the participant ledger. EXISTING inventories all classes, requires the
exact metadata and all three existing files, then rechecks original application
proofs, QCs and signer replay. Missing files are never recreated; NEW cannot reset
a deleted WAL while an old completion marker survives. No legacy adoption,
migration or automatic partial-install repair is provided.

Metadata uses file sync and, on Unix, a parent-directory sync. Windows directory
entry power-loss durability remains a host-filesystem assumption; this is not a
claim that file sync protects against malicious disk rollback. The separate
[participant daemon source](../peer-runtime/PARTICIPANT-FINALITY.md) keeps the
original Registry application, fixed bootstrap roster and no-SQL boundary.

## Registry208 progress finality

The [Progress finality module](src/progress/README.md) adds distinct typed
binding/value/checkpoint/history/durable ownership for the new closed
Registry208 application. It shares the private durable mechanics with the
legacy Joint owner; old public APIs and protocol domains remain separate.
The owning native gate passed all 26 library cases and 21 compile-fail examples,
including existing durability regressions. Strict consumer Clippy and six
existing TLS actor tests passed too; see the
[Progress validation record](../../docs/progress-finality-validation.md).
The separate [Progress transport gate](../../docs/progress-network-validation.md)
now covers genuine Source/Bootstrap803/Control815 with four independent peer
processes. Full Predicate finality, Result160 owner completion and SQL execution
remain separate gates.
