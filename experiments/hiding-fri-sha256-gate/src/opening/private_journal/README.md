# Owner-authorized private-control Journal

This validated experiment connects genuine private Source + RegistryBootstrap
and Source + LockingSelection proofs to the real version Journal. It is not a live
SQL endpoint or a finalized lock grant. The public request does not expose SQL,
controllers, TableId, RowIds, plan openings, holdings or plaintext.

## Ownership and dependencies

| File | Responsibility |
| --- | --- |
| [mod.rs](mod.rs) | Independently pinned application/genesis verifier, exact parent/update/proof checks, and whole-Body admission. |
| [control.rs](control.rs) | Stable, canonical Pending/Active private-control HeadPairs and application identity. |
| [request.rs](request.rs) | Fixed 2716-byte canonical public request and acyclic Bootstrap intent identity. |
| [fixture.rs](fixture.rs) | Explicit public nonsecret owner/source/controller fixtures and genuine normal CLI composition. |
| [tests.rs](tests.rs) | Real owner signatures, Journal and durable replay, proof rejection and local fork behavior. |

Direct project dependencies are [version-journal](../../../../../crates/version-journal/README.md),
[compact-store](../../../../../crates/compact-store/README.md), the existing
[canonical source](../README.md), [bootstrap relation](../registry_bootstrap/README.md),
[private locking relation](../locking/README.md), [SQL compiler adapter](../locking/sql.rs)
and [actual proof-wire codec](../proof_wire/README.md). The experiment adds direct
local `version-journal` and already-locked Ed25519 2.2.0 edges. Offline resolution preserved all 213
package/version/source/checksum nodes and added only those two direct dependency
edges to the leaf lock. The Root workspace lock is unchanged.

## State and request binding

An independently supplied `Application` fixes network, database, key domain,
`C_key`, immutable initial Source HeadPair, source/control shard IDs and the exact
existing Source/Bootstrap/Lock profiles. It hashes no genesis-dependent registry.
The genesis contains exactly those two sorted shards: the immutable Source and a
Pending control pair. A different application or a preinstalled Active root is
rejected by `PrivateVerifier::new`.

Each control component is exactly 112 bytes:
`magic8 | database16 | component1 | phase1 | zero6 | application32 | root32 | zero16`.
The two components carry registry and enrollment roots respectively. Pending has
phase 0 and zero roots; Active has phase 1 and canonical Gold roots. Parent, query,
nonce, source opening and revision do not enter this stable encoding. An unchanged
registry therefore cannot become a changed HeadPair by rebinding a query.

Only after the actual genesis ID exists does Bootstrap compute enrollment64 and
registry112. Its query identity hashes an adapter domain, application, genesis,
parent, independent nonce and `C_enroll`. It excludes its own query value, `C_open`,
`C_registry`, proof and signature. Enrollment itself uses the unchanged stable
bootstrap stream, which excludes query and `C_open`. This avoids both genesis/root
and request/opening fixed points.

Acquire preserves the exact existing `CompiledLockPlan::compile(sql, fresh_nonce)`
request formula. Owner-local preparation first gets `q32`, rebinds the SAME Source
statement and recomputes `C_open`, then uses the existing typed `PlanOpening` and
144-field plan hash to derive `C_plan`. The complete canonical Journal request
contains q32, C_open, C_plan, enrollment and the original encrypted packets. The
owner's existing Journal signature binds the complete request, parent, updates
and proof. SQL and the private plan opening remain owner-local. Public verification
checks an owner-authorized opaque plan; it does not prove a hidden plan parses to
public SQL, controller signature possession or delegated controller permission.

The request is `DCSPJR01 | operation1 | zero7 | genesis32 | parent32 |
application32 | nonce32 | q32 | C_enroll32 | C_open32 | C_plan32 | packets2444`.
Bootstrap requires C_plan=0. Exact length, tags, reserved fields and canonical Gold
commitments are checked; Source reconstruction uses the independently pinned heads
and C_key, then compact-store's complete public image audit.

## Actual admission path

`Journal::prepare_state` verifies the owner signature before invoking
`TransitionVerifier`. `PrivateVerifier` takes genesis, parent, source membership
and old control root from that real callback and its pinned application, rather
than a submitted Expected. It accepts exactly one control update, preserves the
Source shard, and checks the complete next shard set and state roots. It calls the
original Source-first Bootstrap/Lock wire verifier with both mandatory actual SDK
proofs. Verified output roots must equal the next control heads; enrollment stays
unchanged after bootstrap. A second bootstrap, data update or extra update rejects.

Blocked/NOWAIT preserve C_old and its salt. Both the adapter's explicit
`C_next != C_old` check and Journal's old==new rejection prevent an appendable no-op
or invented grant. Successful LIMIT 0 still consumes real sequence/revision and
can produce a valid changed root without returned rows. The normal fixture encrypts
Source once and reuses its identical packets, heads, key and private opening
witness throughout Bootstrap -> Acquire -> SKIP; it changes only query/opening.

The hard complete Body bound is checked with overflow-safe arithmetic:
`117 + request.len + 456 * updates.len + proof.len <= 32 MiB`, also subject to the
pinned Journal profile. The actual proof-wire's component/frame and nested decoder
budgets remain unchanged. No proof-size estimate is treated as native Journal
integration evidence. The existing per-proof security profiles do not establish a
composed 128-bit security claim.

A direct call to the verifier proves computation/binding only: it performs no
owner signature authentication itself and returns no authorization/grant token.
Only the Journal owns signature admission and publication. No State decode,
plaintext State transition replay, MetadataVerifier, StateLease, receipt or cache
boolean is an accepting path here.

## Source test and CLI contract

All twelve new owning tests passed, alongside fifteen affected old leaf tests,
eighteen Journal contract tests and two repository contract tests. Actual
discovery lists 275 leaf cases; unrelated bodies were not rerun. See the
[validation record](../../../PRIVATE-CONTROL-JOURNAL-VALIDATION.md).
The shared fixture cache contains only canonical public block/body bytes, context
and headers. Every first acceptance and every durable reopen re-verifies the proof pairs; an
exact already accepted duplicate follows the existing idempotent fast path.
Coverage includes initial lineage and actual conflicting SKIP; unchanged encrypted
Source; unauthorized mutation before callback; re-signed foreign query/opening/
plan/enrollment/context/source/output; double bootstrap/unproved Active genesis;
genuine positive-wire Blocked/NOWAIT without append; genuine LIMIT 0; canonical
request/full-Body boundaries; signed data/extra updates; stale CAS; durable reopen
and exact lost-ack resubmission; and a valid detached fork followed by reparenting
rejection and `Freshness::AtLeast` reporting Reorganized.

From the repository root:

```sh
cargo run --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- security private-control-journal
cargo run --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove private-control-journal
cargo test --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::private_journal::tests:: -- --test-threads=1
```

Security mode only creates public fixture/context and analyzes the unchanged
Bootstrap and Lock profiles. It creates no trace, proof or Journal append. Prove
mode produces three genuine pairs, signs and imports their complete Bodies, then
adds an Empty confirmation block under an explicitly easy public work fixture.
Its single JSON observation reports three complete Body sizes and
`outer_lineage_ms`: source/owner fixture setup is outside that timer; proof
production, wire encoding, signatures, mining, actual Journal verification and
confirmation are inside. An external process observer must measure full CLI time
and whole-process resources. The validation record reports one genuine CLI
observation and the affected native test processes. These fixed public fixtures
do not establish an application latency or whole-peer resource guarantee.

## Remaining requirements

Owner authorization of every transition is deliberate stage scope. Controller
permissions/possession/delegation, general registry growth and control lifecycle,
MVCC, encrypted writes and rollback, stable row histories, atomic multi-shard SQL,
writer fencing, partition-safe finality, fresh global barriers and live grants
remain unimplemented. Journal work/confirmations select a locally validated branch
and can reorganize; they do not establish production lock finality. Full encrypted
SQL and peer-only FHE query execution remain required by
[REQUIREMENTS.md](../../../../../REQUIREMENTS.md).
