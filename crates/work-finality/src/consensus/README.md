# Bounded consensus and owned signer

| Direct dependency | Responsibility |
| --- | --- |
| Parent `work-finality` election/vote/QC types | Checked work roster, exact signed vote grammar and actual weighted certificate verification |
| `ed25519-dalek`, `sha2` | Ordinary signing/strict verification and domain-separated identities |
| Rust `std` filesystem/I/O/synchronization | Exclusive WAL ownership, durable publication and shared byte reservations |

| Public entry point | Contract |
| --- | --- |
| `Rules::{new,id,seed_domain}` | Pin complete protocol rules before bootstrap work |
| `Context::new` | Capture independently pinned bootstrap roster, journal, slot and previous decision |
| `DurableVoter::{create_new,open_existing}` | Own key and exclusive WAL; recovery is existing-only |
| `DurableVoter::{handle_bytes,handle}` | Verify remote messages or process owner-local proposal/timer events; sync before publishing |
| `DurableVoter::{outbound,decision,timeout}` | Recover exact durable actions and current local timer |
| `ApplicationVerifier` | Required trusted application-validation boundary; closed application adapter lives in a separate crate |
| `ByteBudget`, `Reservation` | Share finite accounted storage with actual retained application artifacts |


The original `Rules::new` profile of [`consensus`](mod.rs) implements one bounded slot over
the independently pinned bootstrap roster. It follows the round/lock/POL rules of
Algorithm 1 in [arXiv:1807.04938v3, 22 November 2019](https://arxiv.org/pdf/1807.04938v3),
with work-unit weights. It is not a deployed
consensus actor, a journal finality wrapper, or an audited implementation. The [validation record](../../../../docs/work-finality-consensus.md) covers the
executed kernel/filesystem tests. The preceding election/QC layer retains its
separate original validation scope.

This is its own `ConsensusRulesId` version, not wire compatibility with old
Tendermint `master/consensus.html` or an exact CometBFT implementation. In
particular it keeps locks on nil (Algorithm 1, lines 44–46), and follows the
paper's late-valid-value rule (lines 36–43). Differences are explicit: a single
bootstrap slot, finite round/storage bounds, attached signed POL certificates
instead of depending on an unbounded gossip log, one latest future vote per key,
and certificate-plus-application-checked-descriptor commit delivery. The last
form does not require separately retransmitting the proposer's old packet:
the actual precommit quorum attests its voters' protocol participation, while
the application descriptor is still independently validated. It does not bypass
application proofs or replace the assumed honest signing discipline. No safety
or termination theorem for this bounded implementation is claimed from the
paper; its complete runtime integration still needs review and validation.

`Rules::new` requires an application-protocol identity, descriptor bound, maximum
round, three positive timeout durations, positive timeout
increment, and WAL byte bound. There are no production defaults. Its distinct
`ConsensusRulesId` binds all these values, the unchanged mathematical profile,
proposer/lock/POL/nil/commit rules, canonical grammar and storage limits.
`Rules::seed_domain(public_network_tag)` must be passed to `NetworkSeed::new`
**before** work. `Context::new` checks that domain, derives the exact initial set,
and binds the journal Genesis, slot and independently selected previous-decision
anchor. All votes use a separately derived full-instance vote domain
`H(dcs/work-finality/consensus-vote-instance/v1, ContextId)` in the unchanged
mathematical vote envelope; even nil/ANY/future votes cannot cross previous anchors.
The real journal Genesis remains independently available in `ApplicationContext`. Old-domain work cannot silently activate these rules. `Context` cannot
activate a successor `EpochSet`.

The proposer rotates over cumulative checked work units at
`(slot - 1 + round) mod total_work`. `DurableVoter` only prevotes a proposed value
after both its actual proposer signature/POL and the captured application verifier
pass. A conflicting lock permits that prevote only with an actual earlier-round
POL at least as recent as the lock, or the same locked value. Strictly more than
two thirds of current-round prevotes can set the lock and precommit. Nil quorums
and timeouts never clear locks. A late POL can update the valid value after a nil
precommit without producing another precommit. A genuine precommit QC for any
allowed **older round of the same slot** can decide the exact application-checked
value. Slots, sets, steps, values and round weights cannot be mixed.

Nil and ANY evidence is counted from distinct strictly verified signer keys in
each current-round step. Future evidence stores at most one highest authenticated
round per signer, across both steps. A jump needs strictly more than one third of
the roster's work in one exact future round, within the pinned absolute maximum.
There is no relative distance cutoff that could prevent a lagging node catching
up after a partition. Older individual votes are not retained indefinitely: an older commit needs
the complete non-nil certificate and its descriptor. Current maps and the future
map are bounded by the checked roster (at most 4096); retained proposals, valid
values and POLs are also finite. Repeated semantic votes/certificates are no-ops
and do not append WAL records.

### Application and local-control boundary

`ApplicationVerifier::verify(&ApplicationContext, descriptor)` is captured by the
signer and must validate actual proof/source/authorization and parent bindings.
It returns a typed error, not a remote validity boolean or serialized receipt.
Replay invokes it again. The application-protocol identity in `Rules` must pin
the adapter's complete rules. A bounded descriptor may reference separately
retained evidence; this module does not load or authenticate such external files
on the adapter's behalf. Its 1 MiB descriptor cap is not a whole-application-proof
size claim.

**Generic consensus does not provide an application-proof adapter.** The new
closed Registry200 integration is linked in the source increment below. This
module does not turn generic `TransitionVerifier`, a root, a TLS response, or an
application DTO into permission to vote for a database candidate. The original owning tests use an
explicitly separate mathematical application that checks genuine key-bound work
tickets and strict possession signatures. They never simulate Source acceptance.

`handle_bytes` accepts only signed Proposal, Vote and Certificate inputs with
complete independent context, canonical re-encoding and EOF checks. It rejects
the local Propose and Timeout tags. `handle(Input)` is the local owner's entry:
only the local proposer supplies a value, and only the clock owner may fire the
exact returned timeout after its full duration. The library provides no clock,
network scheduler or peer authentication. Timeout increments are not a latency
or liveness measurement.

### Durable protocol and byte accounting

`DurableVoter::{create_new,open_existing}` consume the private `SigningKey`; the
handle has no Clone, Debug, serialization or key accessor. It holds an exclusive
OS file lock. A normal operation first prepares a private machine transition,
then appends the input and exact signed output bytes, calls `sync_all`, and only
then publishes the new lock/valid/signature/decision state. All signatures are
ordinary Ed25519; no new cryptographic primitive is introduced. `outbound` returns
the exact persisted proposal/votes/POL/decision for lost-acknowledgment recovery.

The file has a fixed **144-byte** header:

```text
DCSWFW01 | RulesId32 | ContextId32 | signerPublicKey32 | maxWalBytes8 | hash32
```

Each record is exactly **96 + input_bytes + output_bytes**:

```text
length4 | sequence8 | previousHash32 | inputLength4 | input |
outputLength4 | outputs | recordHash32 | repeatedLength4 | DCSWFR01
```

Integers are little endian; known tags, exact lengths, chained SHA-256 checks,
sequence, pins, EOF and reproduced action bytes are mandatory. Header and record
hashes detect corruption; they do not replace signatures or application proofs.
Recovery bounds the entire file and each remaining frame **before allocation**,
then replays the actual verification/state transitions and compares the exact
locally signed actions. It never trusts a serialized lock or `valid = true`.
The independently selected context, key and verifier are required on reopen.

Input envelopes are at most 2 MiB, descriptor values at most 1 MiB, and an atomic
record at most 8 MiB. The explicit WAL bound is between 8 and 256 MiB. The same
`ByteBudget` is shared with retained application artifacts: external owners hold
`Reservation`s and reserve growth before writes. WAL files register canonical
paths and reserve their next extent before writing; those charges deliberately
survive handle Drop, because the file still occupies disk. Reopen reuses the
exact charge. At most 4096 file paths can be registered. A future runtime adapter
must restore actual existing artifact charges before signing after process
restart; this module does not silently account for an unrelated journal file.
These are concrete library quotas, not a whole-peer RAM/disk measurement.

Any write/seek/sync error poisons the handle and suppresses all outbound signatures
and decisions. A quota rejection occurs before writing and leaves the old state
intact. Neither path truncates or rolls back a signing record. A torn/corrupt tail
is a hard recovery failure. A complete durable record written before a lost reply
is replayed, so its signature cannot be replaced by a conflicting vote. Initial
creation is an explicit installation action; recovery is open-only and never
falls back to creation if a file is missing. Missing or lost directory entries
therefore stop recovery. Malicious disk rollback, copied keys or duplicate signer
installations are outside this crash/corruption contract and require operational
protection. There is no compaction, checkpoint replacement or automatic reset to
free quota; exhaustion safely stops this finite stage.

### Remaining protocol integration

The validated original profile covers one slot and the bootstrap set. The new
validated extension below adds an explicitly separate multi-slot mode.
Reconfiguration with old/new quorum overlap, the system lane and transport remain open.
`Decision` contains the exact descriptor and precommit certificate; it grants no
`FinalizedHead`, SQL result, or database lock. The less-than-one-third bound must
hold on the activated roster; checked puzzle work alone does not establish that
assumption, fair inclusion or availability. Without a quorum the state waits;
it never lowers the threshold or unlocks on timeout.

The new module passes 17 owning tests and three ownership compile-fail examples:
actual work/signature application rejection, nil/ANY/future bounds, late POL,
older-round commit, proposer identity, three owned signer state machines, lost
acknowledgment, exclusive open, real-file torn tails and bounded fault injection,
replay revalidation, cross-previous-anchor genuine votes and shared quota exhaustion. These are local kernel/filesystem
tests, not real network peers or a proof of distributed deployment. Native results
for this slice are recorded in the linked validation record.

See also the official Tendermint
[signing-state contract](https://docs.tendermint.com/master/spec/consensus/signing.html)
and [WAL description](https://docs.tendermint.com/master/spec/consensus/wal.html).

### Explicit multi-slot extension

`Rules::multi_slot` creates a new complete RulesId/seed domain; `Rules::new`, the
single-slot id and the old work/vote/QC profiles are unchanged. Multi-slot initial
installation starts at slot one. `Decision::semantic_id` hashes exact ContextId
and length-delimited descriptor bytes, excluding QC, signer subset and commit
round. Thus distinct genuine commit certificates for one value do not fork the
next slot. `Context::{verify_commit,after_decision}` perform actual mathematical
QC verification/read-only lineage reconstruction and confer no application grant.

Only `DurableVoter::advance()` changes the owned signer's slot. It takes no next
context, requires its own already-durable decision, rechecks application/QC,
checks slot increment, appends/syncs private local command tag 6 with empty action
list, then resets round/lock/valid state in the next domain. Locks never reset on
timeout/nil or an external context. `DCSWFW02` distinguishes this WAL mode, while
the exact existing record framing remains. Reopen begins with the independent
slot-one context and replays every actual decision and Advance. Old slot votes,
including nil/future evidence, cannot cross into the next domain. An advanced
context cannot be used to create a new signer WAL.

The closed [`registry200-finality`](../../../registry200-finality/README.md)
adapter installs a genuine application-checked durable Journal floor before
calling Advance. Generic core Advance by itself is not that installation. The
three new local filesystem/lineage cases passed, together with all 33 preceding
runtime tests and five compile-fail examples. The
[integration record](../../../../docs/registry200-finality.md) covers actual
application proofs, floor recovery and native attribution. No network actor,
epoch activation or SQL grant is
added by this mode.
