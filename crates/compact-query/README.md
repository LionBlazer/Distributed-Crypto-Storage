# Compact query

Two explicit experimental storage/FHE contracts share the same canonical Table and
owner-built encrypted index. `tfhe-backend` is the legacy default and retains its
FullScan/coarse-candidate encrypted predicate and conditional UPDATE semantics.
`bfv-experiment` selects the explicit `compact_query::bfv` module; callers cannot
pass FullScan or coarse candidates into its exact-index API. The GUI uses BFV only.
Historical completion methods return unverified results. The separate proved BFV
completion path below verifies genuine arithmetic evidence and complete authenticated
index selection; global agreement and freshness belong to the network client.

## Generic byte projection proof composition

With `bfv-experiment`, `byte_select::check` verifies the serialized genuine
BFV ciphertext-by-public-polynomial proof against the trusted original byte
request. `byte_select::complete_checked` rebinds its unforgeable checked marker
to the exact request/output before reconstructing and decrypting the actual peer
ciphertext. The returned `VerifiedByteSelection` exposes only decrypted bytes
and the checked arithmetic evidence. It cannot be constructed from owner fixtures
or an unverified network response.

This path accepts [bfv-query-core](../bfv-query-core/README.md)'s schema-neutral
8,191-byte chunk contract rather than `records(age,amount)` fields. Its caller
authenticates complete typed indexes and original compact rows, binds all chunks
to schema/table/query/version, and checks fresh agreed state separately. The
kernel's public mask encodes column projection, while exact matching rows come
from the authenticated index. Neither the wrapper nor arithmetic proof silently
claims arbitrary homomorphic SQL predicate evaluation or hidden access patterns.
The direct dependencies are the existing `bfv-query-core` representation adapter
and `bfv-query-proof` STARK verifier; no GUI, SQL parser or network policy enters
this reusable completion boundary.

## Explicit BFV composition

[bfv-query-core](../bfv-query-core/README.md) owns unchanged BFV arithmetic/wire/key
roles. This module owns storage schema, complete authenticated index selection,
every selected age check, current data+index heads and owner-local checked UPDATE/INSERT
writeback. Live selected field slots and page buffers are zeroized when owner query
state drops. Fields reserve their complete bounded capacity before plaintext is
pushed; this is not a guarantee about every compiler, stack or allocator copy. No
persistent plaintext/FHE cache is introduced.

`bfv::Owner::generate` returns one secret owner and an Evaluator whose clones share
public material through Arc. It generates no TFHE keys. Owner::seal/restore and Table
reuse the canonical storage lifecycle. `prepare_exact_aggregate_for_experiment`
accepts one exact AgeRange, not separate predicate/candidate ranges; peer evaluation
rotates/adds fresh byte/COUNT weights and completion returns UnverifiedAggregate.
`prepare_exact_update_for_experiment` freshly encrypts original amounts and deltas;
peer addition precedes owner unverified decode and local checked-add validation of
ALL selected rows. Only then can apply_exact_update_checked_for_experiment stage
all affected compact pages and the index binding before publishing both images.
A global u16 overflow changes neither image. Slot/order/limb mismatches reject.

`bfv::Owner::prepare_exact_select_for_experiment` reuses exact authenticated index
selection to freshly encrypt ORIGINAL age/amount fields plus a projection/active
mask. `Evaluator::evaluate_indexed_select` performs BFV ciphertext multiplication
and relinearization to suppress unrequested columns and inactive slots, returning
encrypted values and presence markers. `complete_exact_select_unverified_for_experiment`
rechecks both heads and consumes that encrypted output before returning rows with
their authenticated local ordinals. Bounds/bindings are checked, without an arithmetic
proof. Plaintext fields retained for preparation are never substituted as query
answers. The caller owns returned plaintext, global freshness, cross-shard ordering
and any SQL output limit; the same owner-online input-preparation/leakage boundary
as exact-index aggregates remains.

Selection is bounded to min(caller budget,256) before input encryption; every posting
and data page is Merkle/AEAD authenticated, duplicates and every age mismatch reject
without filtering. Multiple posting/data pages remain supported. Exact aggregate
uses fixed Rows256 and encrypted zero weights even for absent matches; no owner
COUNT/SUM answer is substituted. Input authentication does not prove output
arithmetic; core outputs remain ProofStatus::Unavailable.

`prepare_insert_for_experiment` authenticates the complete bounded target table
and independently encrypts original rows and the nonempty authorized incoming batch.
`Evaluator::evaluate_indexed_insert` adds the independently encrypted incoming batch,
already placed at its public append slots, to the encrypted original relation. `apply_insert_checked_for_experiment` consumes that BFV
output, checks every decoded old/new field against the authenticated inputs, then
stages larger compact data and a rebuilt exact index. It preserves the storage/key
identity and advances each revision once for the whole batch; every target data page receives fresh encryption
because its AEAD binds row count. Other tables remain unchanged. A failed head,
output, bound or storage check publishes neither image. No fixture supplies the
append result; local validation still does not constitute a succinct proof.
The combined relation must fit the caller budget and the 256-row FHE boundary.
`stage_proved_insert`/`stage_checked_insert` require the exact full-residue Addition
evidence, decrypt the complete peer result and stage one whole grown data/index pair.
Prepared incoming fields are zeroized when their single-use state is dropped.

The low-level crate carries Rust 1.99 and the exact N8192/Q218/t114689/full-keyset
profile. Independent security/noise/CCA gates remain unresolved. Retained public
setup bytes, expanded public keys, owner secret and temporary fields/wire must be
counted; public evaluator cloning does not imply free key material. This composition
is visible access: no Spiral, hidden-address, disk durability or owner-key recovery
is added. GUI transport/cancellation and all-shard atomic publication stay outside.

Release/locked/offline validation passed 22 BFV-only runtime tests (11 storage
composition tests, including encrypted projections/current-head rejection, and
11 canonical-index tests) and one compile-fail doctest. The
legacy default TFHE backend retained all 23 passing tests, including full-scan/coarse
selection. Strict all-target Clippy passed with both backends and with BFV only.
Use --no-default-features --features bfv-experiment when validating BFV-only storage
and GUI consumers. The existing default backend's broader semantics/tests remain.
Encrypted INSERT extends the BFV-only suite to 25 runtime tests and one compile-fail
doctest, including checked growth, actual decoded-output writeback, altered output,
wrong owner and independently changed data/index heads.
The default TFHE library suite passes 24 tests after adding index-only-head freshness
rejection for both aggregate completion and UPDATE.

## Proved BFV completion

`prepare_provable_aggregate` reuses the private complete authenticated selection
boundary and encrypts original amount limbs and per-row presence markers for the
coefficient-convolution kernel. `check_aggregate_proof` verifies the genuine
full-residue product against the retained request and source heads;
`complete_checked_aggregate` rechecks exact evidence before decrypting the actual
peer ciphertext. `VerifiedAggregate` exposes its decrypted count, nullable sum
and checked evidence. Empty selection still requires a real proof. The private
aggregate materialization budget admits at most 2560 matching rows per shard,
while row SELECT, UPDATE, INSERT, legacy TFHE and RowReferences retain their
separate 256-row bounds. The authenticated total count is preflighted before
posting traversal or FHE; excess rejects without a result prefix. Arbitrary owner
vectors cannot construct this storage-bound preparation. Original fields, pages
and ordinals are dropped/zeroized after encryption; only the encrypted request,
exact heads and cardinality/keyset/context pending capability remain. No aggregate
answer comes from retained source fields. The owner-online AEAD-to-FHE boundary
and existing full snapshot network retrieval remain unchanged.

The new path composes [bfv-query-proof](../bfv-query-proof/README.md) with the private
exact-selection constructor. `prepare_provable_select` and `prepare_provable_update`
authenticate the complete selected posting lists and data pages before encrypting
original values. A missing posting, duplicate ordinal, incorrect stored age, changed
head or over-budget group is rejected; matching groups are never truncated. An
optional absent range represents only the SQL planner's schema-proven constant-false
predicate. SELECT's public polynomial expresses column projection across every slot,
without plaintext match bits or selected count; private presence stays encrypted.

`complete_proved_select` independently reconstructs the canonical arithmetic request
from the retained one-use preparation, verifies the serialized STARK, restores its
proved ciphertext and decrypts only that result. `VerifiedSelection` exposes decoded
rows and the private-field checked evidence. Input authentication and full-coefficient
arithmetic checking together protect the prepared exact selection; the caller must
still pin the agreed data/index heads and authorize the SQL plan.

The borrowed `check_select_proof`, `check_update_proof` and `check_insert_proof`
methods retain their one-use pending preparation when a candidate response is bad,
allowing the transport caller to try another real replica. The consuming
`complete_checked_select`, `stage_checked_update` and `stage_checked_insert` methods
recheck current heads, independently derive the canonical input and compare both
identities with the private checked marker before restoring/decrypting anything.
A marker for another request or a changed output rejects; UPDATE evidence cannot
finish an INSERT even though both use the same addition primitive. The original
`*_proved_*` methods delegate to these two phases and perform one full verification.
No peer response is accepted because failover is enabled.

`stage_proved_update` follows the same proof-first sequence and writes decoded FHE
amounts into new authenticated compact pages, without recomputing expected sums.
An encrypted global overflow yields no staged table. `stage_proved_insert` verifies
the addition of both independently encrypted operands before staging the larger data
image and rebuilt index. Both methods preserve the original Table; publication and
all-shard atomicity belong to the network client after every shard has passed all
checks. Historical `*_checked_for_experiment` methods remain explicitly separate.

The `proved_operations` integration suite crosses a real public-setup wire boundary,
proves every canonical BFV coefficient and exercises the owning storage API. It
covers 242 selected rows whose postings and data cross pages, omitted projection
columns, absent/constant-false selections with the same public projection, actual
INSERT followed by proved SELECT, UPDATE byte carry and global overflow, unchanged
source images, changed heads, replayed requests and corrupted arithmetic results.
It uses fresh in-memory keys and explicitly public fixtures, with the full proof
security profile in every case:

```sh
cargo test --release --locked --offline -p compact-query --no-default-features --features bfv-experiment --test proved_operations -- --test-threads=1
```

These methods establish the bounded owner-online exact-index contract. They do not
supply concealed access, permissionless agreement, a crash-atomic network commit or
a 100-ms query guarantee by themselves. The proof crate reports complete measured
proving/verification costs separately from its final cryptographic verifier call.

## Legacy TFHE backend

An owner-assisted selective FHE experiment over compact authenticated pages. The
peer's canonical table is a [compact-store](../compact-store/README.md)
EncryptedSnapshot, with age:u8 and amount:u16 packed into three bytes per row.
Only rows selected for the current query become temporary TFHE ciphertexts. There
is no persistent FHE row cache, plaintext row cache, pad cache or update overlay.

## Ownership and public contracts

| Entry point | Responsibility |
| --- | --- |
| Owner::generate | Keep the XChaCha20Poly1305 key and TFHE ClientKey; create one shared public Evaluator |
| Owner::seal | Seal a table and build its encrypted complete age posting index |
| Table | Hold independently trusted data/index heads and canonical encrypted images |
| Table::fork_for_experiment | Copy encrypted table/index state for local transactional staging, without copying keys |
| Owner::prepare | Authenticate index/data pages, select complete candidates, encrypt temporary stream masks and the age predicate/delta |
| PreparedQuery::encode_request | Serialize only addresses, exact head, encrypted masks and encrypted predicate/delta |
| Evaluator::with_row_workers_for_experiment | Select 1..8 scoped initiating threads with shared public evaluation material |
| Evaluator::evaluate | Verify exact pages, XOR public compact bytes with FHE masks, evaluate encrypted COUNT/SUM or atomic overflow-safe AddAmount |
| UnverifiedOutput | Return encrypted results explicitly lacking a computation proof |
| Owner::*_for_experiment | Decrypt unverified outputs; compare updates with owner-local plaintext expectations and compactly write them back |

One Owner/Evaluator pair supports many independent Table handles. Evaluator::clone
shares public evaluation material. Owner has no Clone, printing, serialization or
secret-key export API. The compact-store temporary plaintext and stream-mask
buffers are zeroized on drop. TFHE owns its key/ciphertext allocations; this crate
does not add a key-erasure guarantee beyond the underlying library. Caller source
rows and returned experiment plaintext remain the caller's responsibility.

Selection::IndexedAgeRange uses an owner-built encrypted equality/range index.
Selection::FullScan explicitly converts every row. A candidate range must contain
the complete predicate range; genuine FHE equality/range comparisons are still
performed on all selected rows. No answer is precomputed at the owner.

The default evaluator initiates rows serially. The optional
with_row_workers_for_experiment(1..=8) policy creates bounded scoped OS threads
outside the shared Rayon pool, with a server-key context per initiating thread.
It preserves row ordering, encrypted predicates and global overflow rejection.
Eight configured row workers add at most eight initiating threads to the selected
Rayon budget; one-row and empty phases create none. The policy does not raise the
256-row materialization limit. See measured gains and limits in the report.

COUNT and SUM return exact u32 values, including (0,0) for no matches. AddAmount
adds an encrypted u16 delta. If any matching row would overflow, an encrypted
global rejection condition preserves all original amounts. The owner-local update
experiment decrypts and compares every selected output, stages fresh encrypted data
pages and the index binding page, and only then publishes both images in the Table.
This is atomic in memory; durable crash-atomic persistence is a separate boundary.

## Index consistency and limits

The V3 encrypted private index contains the exact 112-byte data commitment, a
32-byte logical TableId, 256
little-endian u32 counts, 257 u32 byte offsets and per-age delta-LEB128 postings.
The 2,196-byte header fits in page zero. Fixed-per-N encrypted zero padding makes
the total index size independent of age distribution. Each bucket starts with an
absolute row
ordinal and then strictly positive gaps. Canonical unsigned encodings, count/byte
boundaries, address bounds and selected duplicates are checked. Selected varints
can straddle authenticated pages; unrelated posting pages are not read.

Header and posting pages use the same compact-store AEAD/Merkle contracts. An
owner-authenticated current index head and its exact encrypted table-head binding
establish which complete posting list was built. AddAmount never changes age, so
only page zero needs replacement, including its unchanged posting suffix.
There is no public arbitrary-age mutation or peer-built untrusted index API.

The table limit is 1,000,000 rows. MAX_ROWS is a distinct hard limit of 256 selected
rows for row operations and the legacy TFHE paths below (proved Q2 aggregates have
the separate 2560-row budget described above), checked from authenticated counts or the full-scan count
before any FHE pad encryption. A lower caller budget is honored. SelectionBudget
returns the full selected count and effective budget; it never truncates a group.
Private outputs use an encrypted bit and u16 sum for exactly one selected row,
and ten-bit COUNT plus 24-bit SUM otherwise. Owner-facing values remain u32;
the largest SUM is 256 * 65535 = 16,776,960. Conditional zero selection uses
TFHE's CPU IfThenZero API. The extended-types feature exports FheUint24 without
changing the configured cryptographic parameters. Wire encodings are bounded at 128 MiB. This bounds honest
materialization, not every malicious TFHE parameter/allocation path.

The compressed index avoids a permanent four-byte ordinal per three-byte row.
Report canonical data, encrypted index, rebuildable hash payload, keys, replicas
and transient query traffic separately. A favorable combined data/index size does
not imply that the same table plus its complete FHE key set fits below 2x. The
[index-size report](../../docs/experiment-index-compression.md) records the format,
bounded decoder and historical V2 million-row sizes: 1.743071x for data plus
padded index, but 61.957164x including shared FHE keys and owner state. Those
measurements predate the V3 private identity tail and do not describe current
index expansion. Key amortization is a separate system-level question.

## Private logical row identities

`TableId::generate` allocates one random logical table identity. Standalone
`Owner::seal` creates a new logical table, including for empty input. A caller
partitioning one table allocates one TableId and one consuming `RowIds` allocation,
partitions that allocation in the same original order as its rows, and calls
`Owner::seal_partition` for each shard. Shard, physical ordinal, row values and
snapshot revision never contribute to either identity. TableId and RowId are
nonzero 32-byte CSPRNG values; uniqueness is checked within each allocation and
against the authenticated old target prefix on append. Across independent
allocations uniqueness is probabilistic, with 256-bit collision resistance;
there is no global identity registry. Entropy/collision failures reject without
silently assigning a replacement identity. Copying or knowing an ID establishes
neither row existence nor authorization.

The encrypted v3 index appends an ordinal-to-RowId map after the padded postings.
Its start is aligned to 32 bytes, so one ID never crosses a 4,096-byte page.
`Owner::row_references` accepts at most 256 distinct in-bounds ordinals, verifies
page zero against the exact data head and expected logical TableId, then
verifies/decrypts only needed ID pages, cached within that call. Its immutable
`RowReferences` carries TableId, both exact heads and ordered ordinal/RowId pairs.
These are owner-private authenticated metadata, not public FHE/completeness
proofs, freshness certificates or SQL lock grants. Existing network fetch still
transfers the complete encrypted bundle; sparse private-page decryption does
not introduce sparse network retrieval. Ordinary restore authenticates the
header and full encrypted image roots without scanning/decrypting all row IDs.

Amount-only genuine updates retain every ID. An INSERT preparation owns its
new-ID allocation before FHE input encryption; checked staging preserves the old
prefix and appends those exact IDs. One whole SQL allocation is divided across
parallel target jobs. Retained pending retry reuses the exact encrypted images
and heads. Restore requires independently supplied logical TableId and both
heads. Future checked movement, rekeying or compaction must carry these IDs with
their rows; those operations are not implemented here. No plaintext IDs were
added to peer RPCs. Private index schema v3 rejects older formats without a
migration. This is an owner-library format contract; the public arithmetic
profile, kernel ABI and peer application policy are unchanged.

For 1,000,000 rows the fixed geometry is 2,196 header bytes, 2,015,624 padded
posting bytes, an aligned ID offset of 2,017,824 and 32,000,000 ID bytes:
34,017,824 plaintext bytes across 8,306 pages, or 34,416,624 encrypted image bytes
including all page overhead and its manifest. `decode_index_head` applies that
exact versioned byte geometry rather than the data-row limit. With 256 data rows
per page, the 3,187,648-byte data image and two public heads bring bundle parts
to 37,604,496 bytes, below the unchanged 64 MiB transport/custody bounds. The old
8 MiB index cap has been replaced by this exact maximum; participant quotas
remain independently enforced. ID generation uses at most 8 KiB entropy scratch
and a temporary sorted 32-byte-per-row uniqueness copy, released before index
construction. The allocation payload peaks near 64 MB at one million rows;
rows, encrypted/plaintext images, Merkle structures and allocator overhead are
additional. This calculation and owning geometry tests are not whole-process
RAM or latency measurements.

## Experiment boundary

The historical index preparation is private owner policy, with visible candidate
cardinality and physical addresses at the storage peer. The owner reads/decrypts encrypted index pages. This is not
a peer-executed concealed SQL index, ORAM/PIR, arbitrary SQL, distributed consensus,
durable key recovery or authorization. The proved completion path above adds exact
arithmetic verification while retaining the explicit owner-built index contract.
Public canonical age-operator shape (Equal, AtLeast, AtMost, Range), including the
implicit 255/0 endpoints of one-sided shapes, sizes,
revisions, access repetition and
timing are also visible. The required leakage model remains open.

The owner must independently obtain trusted current data/index heads. An old Table
is intentionally usable as an old version; global freshness remains external.
Both BFV and TFHE completion check the prepared data and index heads against the
supplied current Table, including an index-only revision change.
restore_table_for_experiment reconstructs encrypted images with the same live key
authority and independently supplied TableId and both heads. It does not persist or restore keys.

The bincode round trips accept trusted experiment objects and enforce total wire
limits; they are not hardened hostile FHE decoders. Metadata/domain/version checks
are not cryptographic evaluation proofs. Aggregate decryption does not verify
computation. Update checking repeats selected plaintext work at the owner and is
explicitly unsuitable as the project's succinct single-peer proof protocol.

## Reproduction

From the workspace root, run CPU-intensive commands serially:

~~~sh
cargo test --release --locked --offline -p compact-query -p compact-store
cargo clippy --release --locked --offline -p compact-query -p compact-store --all-targets -- -D warnings
cargo run --release --locked --offline -p core-workloads --example compact_query -- 1000000 5 100 8
cargo run --release --locked --offline -p core-workloads --example compact_query -- 1000000 5 30 8 8
~~~

The example emits JSON lines and saves no keys/data. It includes full encrypted
request/output serialization, index lookup/proofs, exact page verification,
compact-to-FHE conversion, genuine encrypted predicate/COUNT/SUM, owner decryption,
and owner-verified compact writeback. Every repeated UPDATE encodes and freshly
decodes both complete canonical images, rebuilds their hashes, checks constant live
size and rejects its old output against the new head. It also performs actual 4-row, 16-row and empty UPDATEs with fresh full-image
decode, and a 21-row range aggregate. Setup and cold in-memory key/image
round trips are separate. Transport, disk IO, consensus and computation proofs
are unmeasured. See the [experiment report](../../docs/experiment-compact-query.md).

The `index_storage` example measures padded data/index sizes across four public
age distributions and exact encrypted-image restart. See the
[index format and measured accounting](../../docs/experiment-index-compression.md).

The [narrower query wire experiment](../../docs/experiment-query-wire.md) records
exact encrypted widths, operator-shape leakage, unchanged TFHE parameters, traffic
savings and mixed CPU results. Its 16-row aggregates and multirow updates still
exceed 500 ms; the data/index compactness result does not establish that query target.

The key_amortization example retains independent encrypted Tables under one
Owner/Evaluator and counts actual data, indexes, trusted heads, shared keys and
hashes. The [actual amortization report](../../docs/experiment-key-amortization.md)
measures 210 million-row tables at 1.975191x canonical material or 1.996193x with
hashes, with 1.386 GB whole-process peak RSS. Queries use supplied table IDs;
this does not establish global SQL routing or a bound for every database size.
Its Windows measurement wrapper constrains only its own headless child process.

The `disk_tables` example writes independent canonical images to an explicitly
supplied ignored directory and loads one table at a time using the same live
owner keys and independently retained heads. Actual file corruption, truncation,
bounded frame lengths, wrong heads and own-file cleanup are checked. The
[disk experiment](../../docs/experiment-disk-tables.md) measured 5.4 GB logical
data at 1.721920x counted material, 371 MB process peak RSS and nine supplied-table
point queries at 61–118 ms including image reads/authentication. It does not
persist keys/catalogs or implement crash recovery, hidden access or global SQL
routing. Use a dedicated Cargo target to keep experiment artifacts separate.
