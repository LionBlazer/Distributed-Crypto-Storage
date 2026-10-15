# Storage client

Owner/client composition over independent authenticated peer processes. The owner
retains compact/BFV keys and independently pinned heads; peers retain ciphertext,
public evaluation material and durable version journals. There is no local
evaluator answering SQL and no dependency on the playground or its fixtures.

| Direct project dependency | Responsibility |
| --- | --- |
| [sql-plan](../sql-plan/README.md) | Typed statement plans, without plaintext execution |
| [compact-query](../compact-query/README.md) | Complete authenticated selection, proof-first BFV completion and compact finalization |
| [compact-store](../compact-store/README.md) | Exact trusted heads and bounded canonical formats |
| [peer-runtime](../peer-runtime/README.md) | Remote object transfer, FHE replies, copies and metrics |
| [bfv-query-core](../bfv-query-core/README.md) | Public parameter descriptor |
| [version-journal](../version-journal/README.md) | Work, signatures, confirmed heads and ancestry |

## Verified network path

`Session::create(name, rows, participants, profile)` encrypts owner input, stores it
on real peers, creates an Ed25519 write authority and pins the genesis/profile.
It creates a second physical copy where another participant exists. The caller
supplies the full protocol profile: core provides no cheap-work defaults.
The initial logical shard set is fixed; infrastructure peers can be added as
holders/executors without becoming a voting committee.

`Session::execute(&mut self, sql)` accepts row SELECT/projections, supported age
filters, LIMIT, single-row INSERT and additive amount UPDATE on
`records(age: u8, amount: u16)`. COUNT/SUM and unsupported SQL reject explicitly.

`SqlScript::parse(sql)` validates a bounded script before any network operation.
It supports ordinary comments, the exact non-null unsigned `records` schema,
`CREATE TABLE IF NOT EXISTS`, and the proof-supported Session statements. Multi-row
literal INSERTs lower into individual verified INSERTs. The public `statements()`
view exposes validated plans for import tooling, never stored plaintext or answers.
Scripts are limited to 64 KiB and 256 operations after INSERT expansion.

`script.execute(&mut Option<Session>, create_empty)` owns no process policy: the
caller supplies an actual empty-Session creator with its participants and protocol
profile. A missing table requires CREATE; duplicate unconditional CREATE rejects
before any statement executes. IF NOT EXISTS preserves the existing table, keys
and journal. A valid CREATE followed by SELECT performs a real proved read even
when the table has no rows. Unsupported schema, COUNT/SUM, transactions and
`SELECT FOR UPDATE` reject during planning rather than dropping their semantics.

Execution is sequential, not transactional. `ScriptResult` retains each DDL or
verified query outcome. A later runtime `ScriptError` includes its source statement
number and completed outcomes; those writes remain committed. It never rolls back
or automatically replays earlier statements. Session retains an ambiguous mutation
for the existing `resume_pending` recovery contract. Ordinary syntax and table
lifecycle errors are caught before the creator or any query executes.

Every successful SELECT follows:

1. Synchronize and independently validate work, bodies, authorization and job proofs.
   Resolve the latest locally confirmed descendant of the previous read/write token.
2. Fetch actual ciphertext at exact data/index heads. Authenticate complete private
   index coverage and selected pages before preparing original FHE operands.
3. Ask a peer for the full-residue STARK and encrypted result. Derive the trusted
   canonical input from the pending request and verify before decryption.
4. Recheck confirmed ancestry and state. Apply LIMIT after all logical shards have
   complete verified results; return `VerifiedResult` with the confirmed `HeadRef`.
   A reorganization or conflicting state requires retry.

INSERT/UPDATE complete every proof and overflow check before sealing verified
decrypted outputs into new compact images. Actual holders acknowledge storage.
The owner signs the exact old/new roots and complete encrypted job manifest.
Peers verify authorization/jobs/work, fsync the transition and confirmation blocks,
and synchronize. Publication requires a matching durable block acknowledgement.
Pending publication prevents further acceptance until retry succeeds. Local snapshot
metadata changes atomically after every newly agreed shard authenticates. One
overflowing shard publishes none of an UPDATE.

`Error::PendingMutation` distinguishes an ambiguous durable write from a rejected
statement and includes its stable query identity and submitted head when known.
`resume_pending()` confirms that exact transition and returns its original outcome;
retrying identical SQL does the same. Different SQL is blocked until resolution.
Recovery never runs INSERT/addition again or silently changes the authorized parent.
A reorganized pending write remains explicit rather than being automatically replayed.

`inspect_rows` is an explicit owner editor operation over actual ciphertext, never
a SQL answer source. `copy_shard` transfers from a surviving process; copies cannot
be reconstructed from drafts. Invalid/unavailable holders are skipped, missing
proofs reject, and temporary peer `Busy` responses have bounded retry/failover.
`replace_participant` initializes the new journal before replacing handles.

## Security and lifecycle limits

This is the owner-online exact-index model. The owner authenticates private complete
selection and compact AEAD finalization; public journal validation proves exact FHE
jobs and authorized roots, not an independently public AEAD-to-FHE SQL proof. Access
patterns, sizes, projection, timing and public request metadata remain visible.
TLS credentials are local node administration policy, distinct from free identities
and work-based journal validation. No external chain or identity-count votes exist.

Freshness assumes honest network reachability and sufficient honest work. An eclipse
cannot establish an unconditional globally latest state; confirmation is probabilistic.
Easy playground work is unvalidated and conveys no production attack budget. Mining
runs in bounded requested RPCs, not an autonomous production mining/discovery service.
Owner keys live in memory; owner restart/key recovery, logical resharding, transactions
and production parameter review remain open.

Journal storage stops at its cap; proof-body pruning is unimplemented. Collection
reclaims superseded known compact versions while retaining current and confirmation
states. Unknown failed staging is retained and can fill quota. Copies on one host
share a failure domain. Successful writes do not prove independent availability.
Full-query latency still exceeds the 50–100 ms target.

The earlier `Database::execute` remains an unverified diagnostic path: it rejects
with `MissingComputationProof`, and `AcceptedResult` is uninhabited. The live GUI
uses Session. No unverified diagnostic result can convert to accepted evidence.

## Verification

From the repository root:

```sh
cargo test --release --locked -p storage-client --lib
cargo test --release --locked -p dcs-peer --test proved_sql -- --test-threads=1 --nocapture
cargo test --release --locked -p dcs-peer --test proved_faults -- --test-threads=1
cargo test --release --locked -p dcs-peer --test process_transport -- --test-threads=1
```

The suites exercise all three SQL operations, projection/order/LIMIT, carry,
all-shard overflow rejection, real copies, process loss, exact-head read-after-write,
durable peer restart and damaged/missing replicas. Fixtures are public and secrets
fresh in memory; generated ciphertext and measurements stay outside version control.
