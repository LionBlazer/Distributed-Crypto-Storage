# Storage client

Owner/client composition over independent authenticated peer processes. The owner
retains compact/BFV keys and independently pinned heads; peers retain ciphertext,
public evaluation material and durable version journals. There is no local
evaluator answering SQL and no dependency on the playground or its fixtures.

| Direct project dependency | Responsibility |
| --- | --- |
| [sql-plan](../sql-plan/README.md) | Typed statement plans, without plaintext execution |
| [relational-types](../relational-types/README.md) | Typed schemas, complete dump validation and schema-bound SELECT plans |
| [compact-query](../compact-query/README.md) | Complete authenticated selection, proof-first BFV completion and compact finalization |
| [compact-store](../compact-store/README.md) | Exact trusted heads and bounded canonical formats |
| [peer-runtime](../peer-runtime/README.md) | Remote object transfer, FHE replies, copies and metrics |
| [bfv-query-core](../bfv-query-core/README.md) | Public parameter descriptor |
| [bfv-query-proof](../bfv-query-proof/README.md) | Genuine checked statement capability retained until fresh completion |
| [version-journal](../version-journal/README.md) | Work, signatures, confirmed heads and ancestry |

## Typed imported catalogs

`relational::RelationalSession::import(database, participants, profile)` imports a
validated multi-table `relational_types::ImportedDatabase` as a new encrypted
genesis. Column names, types, NULLs, text, exact decimals, dates and binary fields
are retained. The authenticated encrypted catalog also preserves source views,
procedures and import notices; stored programs are metadata, not executable plans.
Each table is a distinct bounded ciphertext shard, replicated on two peers when
available. All tables share one owner key authority and public BFV setup.

`select(sql)` supports actual table/column names, projections, typed comparisons,
AND/OR/NOT, IN/BETWEEN, NULL predicates, ORDER BY and row windows. Result ordering
uses PostgreSQL's ASC NULLS LAST / DESC NULLS FIRST defaults, accepts explicit
NULLS FIRST/LAST per key and applies OFFSET before LIMIT/FETCH after complete
filtering and ordering. LIMIT ALL/NULL is unbounded, a NULL offset is zero, and
FETCH FIRST/NEXT defaults to one row. FETCH WITH TIES includes the last selected
row's full ORDER BY peer group (including NULL peers and fixed-CHAR comparison),
without restoring skipped rows or using physical ordinals as tie-breaking keys.
Counts are nonnegative bigint literals; arbitrary count expressions and parameters
remain unsupported. TOP remains the existing import-adapter limit spelling. Complete
per-column private postings are authenticated against the agreed index head; equality/range
selection uses binary bounds over sorted postings. This is the existing explicit
owner-online, visible-access index model, not a claim of a secret predicate circuit.
The session retains no imported plaintext row-answer cache.

The client authenticates source pages and encrypts **every original cell of each
selected row** before the peer applies the column mask homomorphically. Unselected
columns are zeroed in BFV; the client never prepares a projected plaintext answer
for a peer to echo. Each block has a genuine full-residue STARK bound to the exact
schema, SQL, initial confirmed head, table, complete ordinals, projection and block
position/count. Empty results still require a proved encrypted operation. A second
work-journal/freshness check precedes acceptance. Returned `Selected.version` is
the exact confirmed head used by the proof binding, even if newer empty blocks
appear while the query executes.

A crate-private `jobs` helper runs at most two independent source-byte blocks at
once and joins every admitted worker before returning an error.
Tasks move into their worker; the private helper preserves input order without
requiring task cloning or shared mutable handoff.
Preferred proof executors rotate only across actual holders of this relation; a query-local
endpoint queue preserves the peer's independent single heavy-work permit. Each
worker retains the exact original chunk, mask, nonce and binding through genuine
proof verification and checked completion. Only zeroizing verified bytes are
collected in block order; no proof replies or expanded traces are retained for
completed blocks. All blocks and the final freshness check precede row decoding.

The private `query_rpc::Requests` scheduler gives typed reads one failure context
across initial/final journal checks, source fetch and all proof blocks. An unreachable exact address/identity is attempted
once per query, including concurrent failover; a later query retries it. A missing
or damaged object excludes only that object at that endpoint. `Interrupted`
returns without fallback or negative caching. Explicit peer `Busy` retains its
existing bounded retry and is never negative-cached. Fixed Session row SELECT
shares the same read-query policy; mutations keep their existing failure policy.
An endpoint recovering during this query is retried on the next query. This changes retry policy, not the version contract: the final
journal synchronization still needs a real response from a remaining reachable
peer, resolves the pinned version floor, checks every expected shard head, and
requires `Freshness::Exact(initial)` plus the same current state root. A cached
failure cannot stand in for reachability or a freshness proof. This remains the
confirmed-known-head model under honest reachability, not proof of an unseen
globally newest state.

The scalar verifier field is the locked Goldilocks transparent `u64` layout
(8 bytes). One 8,192-by-100 public product matrix is 6.25 MiB; its raw blowup-eight
LDE is 50 MiB, or 100 MiB for two concurrent checks before clones, FFT/Merkle,
canonical frames and other SDK allocations. These sizes are not process-peak
measurements or a RAM guarantee. At most two prepared/proof workspaces coexist;
completed zeroizing byte chunks total at most the existing 8-MiB selected original
source budget (at most 1,025 blocks of up to 8,191 bytes). Result-cell, output,
source and index limits remain unchanged.

The 8,191-byte BFV block size is not a row limit: arbitrary-width cells and tables
stream over multiple blocks. Current resource budgets are 8 MiB per encoded table
and per encrypted-index plaintext, the caller's `profile.max_shards` table count,
one million result cells and 32 MiB projected output. Budgets reject explicitly;
no rows are truncated except an explicit SQL row window. WITH TIES can exceed its
nominal count, so all ordinary result/source resource limits still apply to the
expanded selection. The full source/index
snapshot is fetched as ciphertext; only selected data pages are decrypted.

Typed imported catalogs are currently immutable. INSERT/UPDATE/DELETE, joins,
aggregates and transactions require further typed computation/transition circuits
and are rejected before execution. The older two-column writable Session below
remains separate; it cannot silently answer or mutate typed catalog tables.

`schemas`, `shards`, `rows`, `version`, `replace_participant` and `copy_shard`
expose catalog metadata and real custody/restart/repair operations. The core never
starts processes or supplies local consensus parameters. Owner restart/key recovery,
publicly verifiable AEAD-to-FHE conversion, production consensus and a general
500-ms full-operation bound remain open.

## Two-column verified network path

`Session::create(name, rows, participants, profile)` encrypts owner input, stores it
on real peers, creates an Ed25519 write authority and pins the genesis/profile.
It creates a second physical copy where another participant exists. The caller
supplies the full protocol profile: core provides no cheap-work defaults.
The initial logical shard set is fixed; infrastructure peers can be added as
holders/executors without becoming a voting committee.

`Session::execute(&mut self, sql)` accepts row SELECT/projections, supported age
filters, LIMIT, atomic literal INSERT batches and additive amount UPDATE on
`records(age: u8, amount: u16)`, plus COUNT(*), SUM(amount) and their combined
projection. Aggregates authenticate at most 2560 complete matching rows per shard;
over-budget groups reject rather than truncate. Each peer computes encrypted
Q2 ten-band coefficient convolution with the fixed 256-term kernel and supplies
a full-residue product proof. Row SELECT and mutation limits remain 256. Only checked
encrypted partial results are decrypted and combined with checked u64 arithmetic;
empty COUNT is zero and empty SUM is NULL. `VerifiedResult::Aggregated` records
the requested projection and fresh confirmed head. Typed imported catalogs remain
immutable and their aggregate syntax remains unsupported. The [Q2 real-process
record](../../docs/proved-aggregate-bands.md) gives the exact 5119/5120-row fixture,
three full-query samples, artifact hashes and remaining limits.

`SqlScript::parse(sql)` validates a bounded script before any network operation.
It supports ordinary comments, the exact non-null unsigned `records` schema,
`CREATE TABLE IF NOT EXISTS`, and the proof-supported Session statements. Multi-row
literal INSERTs retain one SQL plan, mutation identity, transition and result count
for the entire batch. The public `statements()`
view exposes validated plans for import tooling, never stored plaintext or answers.
Scripts are limited to 64 KiB, 256 source statements and 256 total inserted rows.
Each normalized statement retains the SQL planner's 4096-byte bound.

`script.execute(&mut Option<Session>, create_empty)` owns no process policy: the
caller supplies an actual empty-Session creator with its participants and protocol
profile. A missing table requires CREATE; duplicate unconditional CREATE rejects
before any statement executes. IF NOT EXISTS preserves the existing table, keys
and journal. A valid CREATE followed by SELECT performs a real proved read even
when the table has no rows. Unsupported schema, transactions and
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
2. Fetch the same static encrypted ReadImage for every row SELECT on the same
   public geometry: the entire data image and padded index posting prefix. Pin
   TableId and both agreed heads; authenticate complete private index coverage and
   selected pages before preparing original FHE operands.
3. Ask a peer for the full-residue STARK and encrypted result. Derive the trusted
   canonical input from the pending request and verify every shard, joining all
   admitted workers while retaining encrypted results.
4. Recheck confirmed ancestry and state, then recheck current TableId and both
   heads before decrypting any result. Apply LIMIT after all logical shards have
   complete verified results; return `VerifiedResult` with the confirmed `HeadRef`.
   A reorganization or conflicting state requires retry.

Fixed row SELECT never requests predicate-dependent pages or counts and never
falls back to whole Fetch, FetchPages or selected-ID retrieval. Projection, LIMIT0,
absent buckets and schema-false predicates use identical ReadImage frame lengths
for a given geometry; even empty selections require genuine encrypted proofs.
At one million rows / 256 rows per page this is a 5,461,664-byte whole response,
instead of the 37,604,546-byte full Bundle response. The runtime still audits the
entire physical object once, including the omitted RowId tail, so this does not
claim sparse disk I/O. Its 16-MiB frame cap and 512-prefix-page cap cover the fixed
core geometry. This profile introduces no new selection-dependent address/volume
leak relative to the existing full-fetch path; public layout, operation timing,
failures and the existing owner-online conversion boundary remain observable.
The typed imported-catalog path and aggregate/mutation full-image reads are unchanged.

The query-scoped endpoint queue spans initial/final synchronization, ReadImage and
proof requests. Interrupted returns immediately without an uncancelled replica
fallback; explicit Busy retains bounded retries. Same-query negative availability
changes retry policy only: final Exact(initial), expected shard heads, state root
and actual remaining-peer reachability remain mandatory. A subsequent query retries
recovered endpoints. At most two encrypted read images/preparations coexist; source
images are dropped before proof waits. No persistent field/page answer cache is added.
The real-process `proved_sql` tests assert actual frame counts/lengths across query
variants, complete over-budget rejection, empty-table proofs, interrupted image
retrieval without fallback, and cancelled final freshness after a real proof reply.

INSERT/UPDATE complete every proof and overflow check before sealing verified
decrypted outputs into new compact images. Their client-owned `JobVerifier` derives
the trusted canonical job and verifies each exact output/proof once. Its bounded
byte-exact cache lets the later local journal import reuse that verification;
other peers still verify independently. Compact completion independently rechecks
the authenticated selection's current heads and exact checked input/output binding.
Authorization, complete manifest coverage, old/new head rules, work and freshness
remain outside the arithmetic cache and are always checked. Actual holders
acknowledge storage.
The owner signs the exact old/new roots and complete encrypted job manifest.
Peers verify authorization/jobs/work, fsync the transition and confirmation blocks,
and synchronize. Publication requires a matching durable block acknowledgement.
Pending publication prevents further acceptance until retry succeeds. Local snapshot
metadata changes atomically after every newly agreed shard authenticates. One
overflowing shard publishes none of an UPDATE.

`VerifiedResult::Updated::affected_rows` counts the complete matched selection,
including values unchanged by `amount = amount + 0`, following PostgreSQL's
[UPDATE output](https://www.postgresql.org/docs/18/sql-update.html#SQL-UPDATE-OUTPUTS).
Even an unchanged or empty selection runs genuine per-shard FHE proofs and the
final freshness check. If no compact image changes, it returns the current checked
version without Store, a new transition or a pending write. This does not implement
triggers or SQL row-lock acquisition; locking syntax remains rejected.

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

Fixed-schema SELECT, aggregates and UPDATE authenticate, prove and complete at most two shards
concurrently. The owner shares its immutable keys with scoped workers; no secret
key or plaintext is sent to a peer. All workers finish before an error returns.
For SELECT, all shard proofs and the final confirmed-version check precede result
ordering and LIMIT. Unavailable later shards still reject a query returning only
one row.
UPDATE workers only stage encrypted images in owner memory. Every worker finishes
before an error returns, including overflow; no physical copy is stored and no
transition is signed before every shard completes. The existing freshness check,
all-shard manifest, durable publication and pending-write recovery follow this
preparation unchanged. INSERT preflights the whole incoming batch and protocol
update budget, then packs contiguous input chunks into the largest available shard
capacities, breaking ties by shard ID. This minimizes the number of proof jobs and
changed heads; jobs retain canonical shard order. At most two independent shard jobs run concurrently. Every
target's existing plus incoming relation must fit 256 rows; at most 256 rows enter
one statement. All proofs and complete in-memory stages precede the first Store.
The exact unsigned transition is encoded against all immutable profile budgets
before Store, signature or pending state, so local resource rejection cannot create
a permanently pending write. One signature/manifest publishes every affected shard
atomically and retry retains the original whole-batch identity. Storage RPC failure
may leave unreferenced ciphertext copies; it never publishes a partial shard set.

Both SQL paths use the same private proof-request scheduler for genuine proof
verification and replica failover. A query-local permit serializes RPCs to the
same exact endpoint when multiple workers fail over onto one surviving process;
verification runs after releasing the permit. This queue neither creates database
locks nor changes the peer's independent heavy-operation/resource admission limit.

Typed complete indices use version 2 of their encrypted schema and comparator
format. All predicate searches and result ordering compare text using its declared
column type: variable text preserves trailing spaces; fixed CHAR/NCHAR ignores
trailing U+0020. NULL placement remains independent of sort direction. Original
encoded field bytes are projected unchanged by the genuine proof path. Older
index formats reject; there is no migration or implicit locale collation.

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
The requested 500-ms full-query bound still needs representative workloads and
tail measurements; failure recovery can take seconds.

The earlier `Database::execute` remains an unverified diagnostic path: it rejects
with `MissingComputationProof`, and `AcceptedResult` is uninhabited. The live GUI
uses the corresponding typed or two-column Session. No unverified diagnostic result can convert to accepted evidence.

The [complete-operation record](../../experiments/combined-sql/README.md)
includes three runs per genuine native Windows scenario with one or two independent peers,
eight threads per process and profile-v3 AVX-512 kernels. After atomic INSERT
and private identity integration, single-row INSERT took 277.135–287.988 ms and
three-row/two-shard UPDATE took 414.090–466.094 ms, including authorization,
proof/freshness checks and durable confirmation. The separate 512-row COUNT/SUM
took 197.215–198.752 ms. Its later Q2/page-custody/collection recheck returned
5120-row COUNT/SUM in 194.533–195.016 ms, million-row point SELECT in
452.721–474.222 ms and million-row point UPDATE in 960.821–1083.130 ms.
These small local fixtures do not establish a general latency, RAM or consensus
guarantee. The record preserves full workloads, failed-peer observations, exact
artifacts and reproduction; earlier measurements remain in the linked history.

## Verification

From the repository root:

```sh
cargo test --release --locked -p storage-client --lib
cargo test --release --locked -p storage-client --test relational -- --test-threads=1
cargo test --release --locked -p dcs-peer --test proved_sql -- --test-threads=1 --nocapture
cargo test --release --locked -p dcs-peer --test proved_faults -- --test-threads=1
cargo test --release --locked -p dcs-peer --test process_transport -- --test-threads=1
```

The suites exercise all three SQL operations, projection/order/LIMIT, carry,
all-shard overflow rejection, real copies, process loss, exact-head read-after-write,
durable peer restart and damaged/missing replicas. Fixtures are public and secrets
fresh in memory; generated ciphertext and measurements stay outside version control.

The [typed block measurements](../../experiments/typed-select/README.md) record
matched full 300-row/four-proof observations, exact before/after artifact identity,
separate owned-process memory scope and reproduction. They support that fixed
local workload only.

The writable fixed table now retains one owner-private logical TableId across all
record shards. Initial row identities are allocated once and partitioned in the
same round-robin positions as input rows; INSERT allocates once in VALUES order
and moves disjoint contiguous chunks into its jobs. Fetch and agreed-head restore
require that expected TableId together with both exact heads. The private index
v3 identity map is owned by [compact-query](../compact-query/README.md), including
its sparse owner reference API and exact byte limits. Network fetch still transfers
full encrypted bundles. The public FHE profile, RPC fields and application policy
are unchanged; this does not implement SQL locking or finality.
