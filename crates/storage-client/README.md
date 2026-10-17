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
| [proof-acceleration](../proof-acceleration/README.md) | Pure bounded CPU-worker policy, without the loader feature |
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

Catalog table/column names are exact; live SELECT follows PostgreSQL 18 UTF-8
unquoted folding and quoted exact binding in the single `public` namespace.
Preserved CamelCase source names therefore require double quotes in queries.
Source SQL Server CHECK/FK binding is handled before canonical catalog validation;
checks carry explicit source-language metadata. Overlong live identifiers reject
before key generation, setup installation or object writes. No name fallback or
catalog renaming is performed. The typed private index/domain is v3; old or unknown
formats reject without migration. Neither the fixed private index v3, row encoding,
FHE profile nor proof ABI changes.

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
publicly verifiable AEAD-to-FHE conversion, production consensus and representative
end-to-end performance measurements remain open.

## Two-column verified network path

`Session::create(name, rows, participants, profile)` encrypts owner input, stores it
on real peers, creates an Ed25519 write authority and pins the genesis/profile.
It creates a second physical copy where another participant exists. The caller
supplies the full protocol profile: core provides no cheap-work defaults.
The initial logical shard set is fixed; infrastructure peers can be added as
holders/executors without becoming a voting committee.

`Session::execute(&mut self, sql)` accepts row SELECT/projections, supported age
filters, LIMIT/OFFSET row windows, atomic literal INSERT batches and additive amount UPDATE on
`records(age: u8, amount: u16)`, plus COUNT(*), SUM(amount) and their combined
projection. Aggregates authenticate at most 2560 complete matching rows per shard;
over-budget groups reject rather than truncate. Each peer computes encrypted
Q2 ten-band coefficient convolution with the fixed 256-term kernel and supplies
a full-residue product proof. Row SELECT retains at most 256 rows per shard for FHE;
mutation limits remain 256. Only checked encrypted partial results are decrypted
and combined with checked u64 arithmetic;
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

Every successful fixed-schema row SELECT or COUNT/SUM follows:

1. Synchronize and independently validate work, bodies, authorization and job proofs.
   Resolve the latest locally confirmed descendant of the previous read/write token.
2. Fetch the same static encrypted ReadImage for every such read on the same
   public geometry: the entire data image and padded index posting prefix. Pin
   TableId and both agreed heads; authenticate complete private index coverage and
   selected pages before preparing original FHE operands. With a finite LIMIT,
   validate every matching posting and original candidate, retaining the first
   `min(local matches, offset + limit)` rows in physical ordinal order. The sum is
   checked before execution; LIMIT0 retains zero even for a large offset. Each
   retained prefix must fit 256 slots; it is never silently clamped. LIMIT ALL/NULL
   is unbounded and OFFSET NULL is zero. Without a finite LIMIT, the complete
   matching set must fit the existing budget, including rows later skipped.
   COUNT/SUM authenticate all matches within their separate 2560-row-per-shard
   budget and prepare the original encrypted amount limbs and presence markers. Both read forms share a private
   static-source adapter with no predicate-dependent transport choice.
3. Ask a peer for the full-residue STARK and encrypted result. Derive the trusted
   canonical input from the pending request and verify every shard, joining all
   admitted workers while retaining encrypted results.
4. Recheck confirmed ancestry and state, then recheck current TableId and both
   heads before decrypting any result. Merge proved row prefixes by global
   `ordinal * shard_count + shard_slot`, then skip the global OFFSET and apply LIMIT.
   This stable implementation order does not add SQL ORDER BY support. For aggregates,
   decrypt each checked encrypted partial count/sum only after this gate and add
   them with overflow checks. Return `VerifiedResult` with the confirmed `HeadRef`.
   A reorganization or conflicting state requires retry.

Fixed row SELECT and COUNT/SUM never request predicate-dependent pages or counts and never
falls back to whole Fetch, FetchPages or selected-ID retrieval. Projection, LIMIT0,
absent buckets and schema-false predicates use identical ReadImage frame lengths
for a given geometry; even empty selections require genuine encrypted proofs.
At one million rows / 256 rows per page this is a 5,461,696-byte whole response,
instead of the 37,604,580-byte full RawBundle response. The runtime still audits the
entire physical object once, including the omitted RowId tail, so this does not
claim sparse disk I/O. Its 16-MiB frame cap and 512-prefix-page cap cover the fixed
core geometry. This profile introduces no new selection-dependent address/volume
leak relative to the existing full-fetch path; public layout, operation timing,
failures and the existing owner-online conversion boundary remain observable.
Typed imported-catalog reads and final mutation custody checks retain complete
images. Initial UPDATE source eligibility is described below.
The fixed pagination path still validates O(matches) source rows, including skipped
and discarded candidates and LIMIT0, plus O(table rows / 64) bitmap traversal. It
uses a zeroizing bitmap of at most 125,000 bytes per shard and one decrypted
data-page scratch buffer. It does not stop source validation at the window or
change ReadImage traffic. Pagination integer literals fit nonnegative i64 and
usize; duplicate clauses, FETCH and aggregate pagination reject during parsing.
The historical unverified Database adapter rejects a nonzero OFFSET before I/O;
the historical LabEngine applies the window after its encrypted projection.

RowWindow is an owner-side nonserialized plan. OFFSET0 retains the existing LIMIT
prefix preparation; no wire, operation, proof profile or journal version changes.
The owner still selects plaintext originals and freshly encrypts the BFV inputs.
The genuine peer proof covers the existing arithmetic statement; it does not
independently prove source-to-selection/formation or their complete composition.
Pagination adds neither production SQL acceptance nor a substitute fixture answer;
Database::execute retains its separate missing-proof rejection. Fresh agreed
heads remain mandatory. No latency, memory or complete PostgreSQL claim follows.

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
Aggregate tests cover the same cases, a sparse 2560-match million-row source and
identical source frame lengths across COUNT, SUM, empty predicates and row SELECT.
These transfer bounds do not establish a latency improvement; end-to-end timings
must be measured separately with matching process and proof profiles.

INSERT/UPDATE complete every proof and overflow check before sealing verified
decrypted outputs into new compact images. Their client-owned `JobVerifier` derives
the trusted canonical job and verifies each exact output/proof once. Its bounded
byte-exact cache lets the later local journal import reuse that verification;
other peers still verify independently. Compact completion independently rechecks
the authenticated selection's current heads and exact checked input/output binding.
An interrupted proof RPC ends proof preparation for a new mutation immediately,
without trying an uncancelled holder. This boundary applies independently of the
read scheduler's optional memory of unavailable executors. All workers still join
and no newly staged mutation is stored or authorized after that preparation error.
An already authorized pending mutation retains its exact publication/recovery
contract below; cancellation never rolls back a durable remote write.
Authorization, complete manifest coverage, old/new head rules, work and freshness
remain outside the arithmetic cache and are always checked. Actual holders
acknowledge storage.
The private `session::writeback` freezes recipient roles from the current
`Shard.peers` placement before proof jobs. Same-geometry UPDATE uses a fixed,
public-geometry padded Delta for known holders only when it is smaller than Full
Store. Other participants are preplanned new replicas and receive Full Store.
A failed known-holder Delta never changes that recipient's mode. Different participant IDs sharing a TLS identity or socket
address, and conflicting endpoint bindings for one ID, reject before proof work;
routing aliases cannot become new replicas or count as separate copies. INSERT stays
Full Store. Every actual full frame, delta geometry/page budget and immutable
transition budget passes locally after all proofs and before any write/signature.
The runtime still audits the entire physical base and reconstructed target and
charges full-object quota. Existing final `FetchVersion` and holder `Fetch`
custody checks, freshness and exact pending-transition recovery remain in place.
See [padded UPDATE writeback](../../docs/padded-update-delta.md) for resource and
privacy boundaries; this transport change alone establishes no latency bound.

The owner signs the exact old/new roots and complete encrypted job manifest.
Peers verify authorization/jobs/work, fsync the transition and confirmation blocks,
and synchronize. Publication requires a matching durable block acknowledgement.
Pending publication prevents further acceptance until retry succeeds. Local snapshot
metadata changes atomically after every newly agreed shard authenticates. One
overflowing shard publishes none of an UPDATE.

Changed-head final imports use `RemotePeer::fetch_version` and borrow both complete
images from its single immutable `ReceivedVersionBytes` frame. The endpoint queue
is released before owner validation. The existing target binding, exact agreed
data/index heads, full canonical audits, index-header AEAD, TableId and owner-key
checks still run; no partial image or server claim replaces them. The frame drops
before trying another holder or retaining staged shard metadata. A nonce-valid
different object at the same agreed heads is not compared with an older object ID.
Known unexpected successful RPC variants remain successes for Trace and endpoint
failure memory, but cannot become imported versions. Store/Delta/Copy, holder
credit, pending transition identity and proof/freshness acceptance are unchanged.

The read scheduler retains its bounded Busy retry. Mutation synchronization still
calls FetchVersion directly without Busy retry. Both paths return Interrupted
immediately from journal synchronization and changed-head imports, before marking
an endpoint unavailable, trying another holder or publishing staged shard metadata.
Mining and pending publication also stop at an interrupted response without trying
another miner or publisher. A prior durable publication acknowledgement does not
clear the retained block when a later reply is interrupted: retry publishes that
same block. A lost Mined reply has not been validated by the owner and may require
bounded mining again for the same signed transition, not necessarily the same
header. These changes establish no latency or RAM improvement.

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
Before acceptance, cancellation retains the original pending identity and any known
submitted head. Its error remains `Error::PendingMutation`, with the transport
cancellation in its reason. The acceptance boundary follows confirmation, final
synchronization and the required full-image owner checks, when the pending record
is taken. Subsequent holder refresh and journal collection remain best effort;
this boundary does not promise universal late cancellation or remote rollback.
Actual two-peer tests cancel after journal, full-version, mined and publication
replies, assert no later request is sent in that cancelled attempt, then recover
the original write without new SQL preparation, FHE proof or Store.

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

Typed complete indices use version 3 of their encrypted schema/catalog format.
Version 2 is rejected because CHECK interpretation now has an explicit per-check
language; the row codec and comparator ordering are unchanged. All predicate
searches and result ordering compare text using its declared column type: variable text preserves trailing spaces; fixed CHAR/NCHAR ignores
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
Practical full-query latency still needs representative workloads and tail
measurements; failure recovery can take seconds. The current goal has no fixed
latency cutoff.

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
its sparse owner reference API and exact byte limits. Fixed SELECT, aggregates
and eligible initial UPDATE reads use the static ReadImage footprint. Final
mutation custody checks, Full-source UPDATE and typed-table fetches retain
complete objects. Identity-map changes do not change the public FHE profile. The current
custody RPC/application namespace is specified below; SQL locking and finality
remain unimplemented.

## Custody object profile

The client uses [randomized object profile 2](../../docs/salted-custody-objects.md).
Creation/import stage all new object nonces before their first Store. Mutation
PreparedWrite retains one immutable TargetVersion for all preplanned Delta/Full
recipients and a complete raw object whenever a frozen Full recipient requires it. Publication retries preserve recorded IDs;
Copy preserves the envelope. Both recovered-holder paths call the same complete
custody validator before crediting a replica. TargetVersion by itself proves no
payload integrity, SQL completeness, authorization or agreed freshness.

After an agreed mutation, FetchVersion still transfers the complete object and
both image roots are independently rebuilt. The owner validates its exact heads,
logical TableId and encrypted header through the shared full-image validator,
without constructing a temporary Table that this metadata-refresh path discards.
Other full fetch and holder-credit paths keep their complete custody checks.
Database creation explicitly configures its BFV owner with the existing bounded
worker policy, resolved once from available CPUs and `RAYON_NUM_THREADS`.
A budget of one keeps full-image owner audits serial; larger budgets permit at
most one scoped helper shared with all other compact-store audits in the linked
image. Invalid/zero requests retain the existing bounded-default semantics.
Each image keeps its independently expected head; data still authenticates before
the complete index, followed by unchanged schema, geometry and owner AEAD header,
embedded data head, TableId and count checks. No images or shards are newly audited
concurrently, no executor is added, and `Limits` keeps the same hard decode caps.
There is no reuse of a server audit or cross-RPC validation cache; wire/profile,
proof, admission and freshness rules are unchanged. No timing gain is claimed.

## Static initial UPDATE source

Before proof preparation, private `session/writeback` freezes each shard's
recipient transports from public geometry and committed known holders. UPDATE
uses the shared fixed `ReadImage` source only when every frozen candidate is
Delta. Any Full candidate, including a new replica, requires a complete source
before that shard's proof; fetch or Store errors never change this class.

Private `StagedImages` carries either a complete Table with proved replacement
addresses or the core's immutable `UpdatePatch`. The static path uses the same
complete posting/candidate authentication, 256-row budget, genuine BFV Addition
proof and whole-ReadHeads binding. No partial index is represented as a Table or
snapshot. All shards finish proof/decode/overflow staging and all candidate wire
and journal budgets pass before the first Store or owner signature.

Each `PreparedWrite` owns one fresh salted `TargetVersion`, shared by every full
and padded-delta recipient. Static patches supply full new data and the genuine
index-header replacement proof, preserving encrypted row identities through
unchanged Merkle subtrees. A known holder's failed Delta never becomes Full.
INSERT continues to stage and send complete images.

Final agreement synchronization still receives and audits both complete images.
Pending holder restoration also retains its complete Fetch/CheckedObject audit;
a prefix, nonce binding or earlier Store acknowledgement never establishes
complete custody. Existing signed-pending recovery keeps the same authorized
transition and object instead of rerunning FHE or allocating another nonce.
Interrupted static-source reads terminate immediately; mutation proof
cancellation follows the query RPC contract. This does not establish global
cancellation across legacy Full-source or journal phases, public source
completeness, SQL locks or a new latency guarantee.

## Boolean conditions on the writable fixed table

Live `Session` row SELECT, COUNT/SUM and additive UPDATE accept bounded age-only
boolean WHERE expressions, including AND/OR/NOT, parentheses, comparisons,
[NOT] BETWEEN, [NOT] IN, IS [NOT] NULL and boolean TRUE/FALSE/NULL. SQL UNKNOWN is
preserved through compilation; only TRUE ages enter the complete authenticated
selection. Signed i64 comparison bounds can extend beyond the u8 storage domain;
unsupported numeric types and expressions reject rather than being coerced.

The owner's compiled 32-byte age mask is handed to compact-query and never sent as
new peer metadata. All selected original operands still require genuine encrypted
peer computation and exact proof checks. Fixed ReadImage footprints, frozen Full/
Delta UPDATE placement, statement-wide staging, pending retry identity, final
full-image custody audits and agreed-version checks remain unchanged. A union's
whole per-shard cardinality shares the existing budget; OR overlap never applies
an additive update twice. NULL comparisons cannot become TRUE merely through NOT.

`SqlScript` plans every statement before any creator callback or execution and
runs only live Session operations. Its signed-literal/operator token boundaries
are preserved. The historical `Database::execute` and local laboratory range
adapters reject discontinuous age sets before fetching/evaluating; they are not
live fallbacks. Typed imported catalogs keep their separate nullable Expr/index
semantics and immutable mutation contract. This fixed-domain feature implements
neither general typed expressions nor SQL locks/transactions or a new public
source/completeness proof.

## Recognized locking plans remain non-executable

The fixed `sql-plan` front end recognizes a distinct locking SELECT contract for
all four row strengths and default Wait/NOWAIT/SKIP LOCKED. Session, historical
Database and whole-script preparation explicitly reject that variant before
synchronization, source fetch, proof requests or Store. Typed RelationalSession
keeps its existing separate unsupported-locking rejection before network I/O.
The private N4 proof experiment consumes compiled SQL; it is no live executor.
Ordinary owner-assisted Session arithmetic/source preparation is unchanged. Full
source/selection/formation composition, authorized control-root history, writer
fencing, MVCC and independently fresh agreed heads remain required before live
locking acceptance. The [SQL locking-plan validation](../../experiments/hiding-fri-sha256-gate/SQL-LOCK-PLANS-VALIDATION.md)
records 14 script PASS cases and both actual TLS rejection cases. Typed peers run
in server threads; the fixed Session case uses an independent OS peer process.
Both reject before locking-query I/O and retain the source version; fixture setup
is separate. Historical GUI row tests and strict four-package checks also passed.
