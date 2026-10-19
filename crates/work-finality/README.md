# Work election and weighted quorum evidence

Checked fixed-target work tickets, an independently pinned bootstrap
configuration, derived per-key work weights, and bounded weighted quorum
signature certificates. Root integrated and natively validated this prerequisite
on 2026-10-19; the executed scope is recorded below.

This is a reusable mathematical prerequisite for the selected finality contract:
less than one third of confirmed computational weight may be Byzantine, and locks
must wait when the required quorum is unavailable. It does not implement Tendermint
round progression, vote locks, durable anti-double-voting, reconfiguration, fresh
head agreement, candidate proof validation, networking, SQL, or a lock grant. A
`QuorumCertificate` is never a `FinalizedHead` or application admission token.

## Ownership and dependencies

The crate has no direct project-module dependencies. It uses the existing pinned
`sha2` and `ed25519-dalek` versions. Production signs with the ordinary Ed25519 API
and verifies with `verify_strict`; weak public keys are rejected. SHA256d checks
actual key-bound proof of work. No signature, key id, TLS identity, or claimed
hashpower replaces work.

Callers retain signing-key ownership; the library borrows keys for a call and stores
only public evidence. It performs no I/O and makes no secret-erasure guarantee for
caller or library scratch. The dev-only `ed25519-dalek/hazmat` feature constructs two
genuinely valid signatures of the same PoW message using an explicitly PUBLIC,
NON-SECRET fixture key. Both pass production strict verification before duplicate
work is rejected. Hazmat signing is not used by production code.

| Entry point | Contract |
| --- | --- |
| `NetworkSeed::new` | Explicit domain, bootstrap challenge, full big-endian fixed target and lowerable limits; no production default. |
| `NetworkSeed::bootstrap_election` | Work context bound to SeedId, before final Genesis exists. |
| `WorkTicket::{sign,mine,verify}` | Exact election/key/nonce PoW plus possession signature; mining has an explicit attempt budget and checked nonce exhaustion. |
| `Genesis::{from_bootstrap,decode}` | Check work, derive weights, canonicalize tickets and pin the complete configuration independently. |
| `Genesis::{election,derive_epoch_set}` | Check successor work context only; do not certify challenge finality or activate the result. |
| `VoteContext::new` | Derive network/set/epoch from a checked set and bind the caller's independently expected journal Genesis, slot, round, step and optional value. |
| `SignedVote::{sign,decode_and_verify}` | Stateless actual Ed25519 messages; no durable signing policy or candidate validation. |
| `QuorumCertificate::{assemble,verify,decode_and_verify}` | Verify exact context, actual signatures, membership, canonical unique signers and strict weighted quorum. |

All fields which could nominate a weight or a verified result are private. Public
getters expose immutable metadata. There is no serde format, arbitrary-weight
constructor, callback, serialized trusted marker, or signing-key getter.

## Acyclic work and weight contract

The immutable seed excludes tickets, the roster and final Genesis id. A bootstrap
ticket hashes SeedId, epoch zero, the bootstrap challenge, fixed target, validator
public key and nonce. Genesis then hashes the complete seed and checked sorted
tickets. Only after that is its initial `EpochSet` derived and bound to FinalityId.
Genesis does not include that final set id, avoiding a self-hash fixed point.

A future consensus composition must derive the seed domain from an explicit
network tag and its complete consensus-rules identity **before** mining tickets.
The mathematical `profile_digest` fixes tickets, votes and certificates; it does
not fix proposer, round/lock/POL, timeout, system-value or WAL rules. Nodes with
different consensus rules must not reuse one election/vote domain.

Successor tickets bind FinalityId, positive epoch, and an explicit challenge. The
future protocol must prove that challenge is the agreed finalized checkpoint and
that the ticket belongs to the correct election window. Supplying a hash here does
not establish either fact. Old-quorum handoff and monotonic activation are absent.

Every ticket in an election uses the same pinned target. One unique valid PoW is
one fixed-difficulty work unit. A validator's weight is the exact number of its
unique tickets. Splitting keys adds no identity bonus. Deduplication uses the PoW
digest over the fixed context, key and nonce, never signature bytes: a malicious
key holder can choose another valid Ed25519 signature for the same work. Repeated
PoW is an error, not another unit or a silently truncated election.

The target denotes expected puzzle difficulty, not measured CPU time or a proof
of honest hashpower. Work validation cannot prove the Byzantine fraction, honest
bootstrap, fair ticket inclusion, epoch-key security, or independent failure
domains. Those are protocol/fault-model obligations. A single participant may own
most valid work; one-key mathematical fixtures do not demonstrate requirement 1's
availability. A node going offline can remove required online weight, in which
case a later consensus implementation must wait without shrinking its quorum.

## Votes, certificates and limits

Signed context includes the profile, FinalityId, full database-journal Genesis hash,
set id, epoch, slot, round, step and nil/value flag plus all value bytes. Journal
Genesis is an opaque independent pin, not checked application semantics. Slot zero
is rejected. Prevote and Precommit are distinct signed steps. Nil votes can be
verified but cannot construct either non-nil quorum certificate. `Some([0; 32])`
is a value and has a distinct encoding from nil.

Certificates require one exact independently supplied context. Different sets,
networks, epochs, journals, slots, rounds, steps or values cannot be combined.
Signers are unique and sorted. Verification computes `3 * signed > 2 * total` in
checked `u128`; equality at two thirds is insufficient. No API calls the evidence
a commit decision. A public certificate alone supplies no proof of the candidate,
latest state, data availability, full SQL correctness or mutual exclusion.

| Encoding | Fixed length / hard ceiling |
| --- | --- |
| Seed | 144 bytes |
| Work ticket | 217 bytes |
| Genesis | `188 + 217 * tickets`, at most 4,096 tickets and 1 MiB |
| Derived roster | At most 4,096 keys; configured limits may only lower this |
| Signed vote | 290 bytes |
| Quorum certificate | `197 + 96 * signers`, at most 512 KiB |

Decoders check hard byte caps, profile, count limits, checked exact total length
and independent context before allocating a record vector. Fixed messages accept
only their exact length. Canonical order, flags, full EOF and re-encoding are
enforced. Oversized elections are rejected, never cut down to a preferred subset.
These are message/library bounds, not measurements of whole-peer RAM or storage.

Stateless signing deliberately permits the caller to create conflicting votes.
Production must persist signing state and locks before exposing a signature,
reject rollback/double-voting, and verify full application/Source proofs before
voting. Neither this API nor a quorum fixes those missing lifecycle obligations.

## Sources and verification status

Vote-step and weighted-threshold semantics follow the published
[Tendermint algorithm](https://arxiv.org/pdf/1807.04938) and its
[official specification](https://github.com/circlefin/malachite/blob/main/specs/consensus/overview.md).
[Solida](https://drops.dagstuhl.de/storage/00lipics/lipics-vol095-opodis2017/LIPIcs.OPODIS.2017.25/LIPIcs.OPODIS.2017.25.pdf)
is a reference for why PoW admission and reconfiguration require an explicit
bootstrap/network/corruption model; this crate does not implement or inherit its
committee-election theorem. See the project's [requirements](../../REQUIREMENTS.md).
There is no audit, safety, liveness, latency, or full SQL claim for this source.

Owning tests use actual work checks and strict signatures, including alternative
valid signatures for identical PoW, exact quorum boundaries, foreign genuine
quorums, coherently rewritten headers, nil separation, bounded counts and canonical
decoding. Root ran `cargo test --release --offline -p work-finality --
--test-threads=1`: all 16 owning tests and both compile-fail examples passed. The
first command updated only the new local package's lock entry. Subsequent
`cargo clippy --release --offline --locked -p work-finality --all-targets --
-D warnings` and the default core `cargo check --release --offline --locked`
passed. Formatting used the actual Rust 1.99 toolchain.

The frozen donor's eight RAW files had aggregate SHA-256
`AAC992609B5BDC0BC201C84841488810737F219A7891DB920EE9D4B4ACE83E40`;
Root verified each file before importing, formatted it and performed a separate
source review. Native receipts are retained under ignored
`.local/private-peer-native-r1/work-finality-{test,clippy,default}-r1/`.
The test stdout SHA-256 is
`46C1B1762D3AA4156EFB88C635B1E8DCE3E66AD1C985B05F982869658D72FB63`;
stderr is `5F7976A3B65CFD3DBF62E2C9EAE13898C419D71004D27572C0E702A8E35BC726`.
The command took 3.070 seconds including compilation and doctests; this is not a
network finality, worst-case verification or resource measurement. No runtime
consumer, production target, roster activation or SQL admission was added.
