# Compact query

Two explicit experimental storage/FHE contracts share the same canonical Table and
owner-built encrypted index. `tfhe-backend` is the legacy default and retains its
FullScan/coarse-candidate encrypted predicate and conditional UPDATE semantics.
`bfv-experiment` selects the explicit `compact_query::bfv` module; callers cannot
pass FullScan or coarse candidates into its exact-index API. The GUI uses BFV only.
Neither backend provides a cryptographic computation/completeness proof.

## Explicit BFV composition

[bfv-query-core](../bfv-query-core/README.md) owns unchanged BFV arithmetic/wire/key
roles. This module owns storage schema, complete authenticated index selection,
every selected age check, current data+index heads and owner-local checked UPDATE
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

Selection is bounded to min(caller budget,256) before input encryption; every posting
and data page is Merkle/AEAD authenticated, duplicates and every age mismatch reject
without filtering. Multiple posting/data pages remain supported. Exact aggregate
uses fixed Rows256 and encrypted zero weights even for absent matches; no owner
COUNT/SUM answer is substituted. Input authentication does not prove output
arithmetic; core outputs remain ProofStatus::Unavailable.

The low-level crate carries Rust 1.99 and the exact N8192/Q218/t114689/full-keyset
profile. Independent security/noise/CCA gates remain unresolved. Retained public
setup bytes, expanded public keys, owner secret and temporary fields/wire must be
counted; public evaluator cloning does not imply free key material. This composition
is visible access: no Spiral, hidden-address, disk durability or owner-key recovery
is added. GUI transport/cancellation and all-shard atomic publication stay outside.

Release/locked/offline validation passed 19 BFV-only runtime tests (8 storage
composition tests and 11 canonical-index tests) and one compile-fail doctest. The
legacy default TFHE backend retained all 23 passing tests, including full-scan/coarse
selection. Strict all-target Clippy passed with both backends and with BFV only.
Use --no-default-features --features bfv-experiment when validating BFV-only storage
and GUI consumers. The existing default backend's broader semantics/tests remain.

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

The V2 encrypted age index contains the exact 112-byte data commitment, 256
little-endian u32 counts, 257 u32 byte offsets and per-age delta-LEB128 postings.
The 2164-byte header fits in page zero. Fixed-per-N encrypted zero padding makes
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
rows per request, checked from authenticated counts or the full-scan count
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
bounded decoder and actual million-row sizes: 1.743071x for data plus padded
index, but 61.957164x for one table including the full shared FHE key set and owner
state. Key amortization is a separate system-level question.

## Experiment boundary

The index is private owner policy, with visible candidate cardinality and physical
addresses at the peer. The owner reads/decrypts encrypted index pages. This is not
a peer-executed concealed SQL index, ORAM/PIR, arbitrary SQL, distributed consensus,
a proof of query correctness/completeness, durable key recovery or authorization.
Public canonical age-operator shape (Equal, AtLeast, AtMost, Range), including the
implicit 255/0 endpoints of one-sided shapes, sizes,
revisions, access repetition and
timing are also visible. The required leakage model remains open.

The owner must independently obtain trusted current data/index heads. An old Table
is intentionally usable as an old version; global freshness remains external.
restore_table_for_experiment reconstructs encrypted images with the same live key
authority and independently supplied heads. It does not persist or restore keys.

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
cargo run --release --locked --offline -p compact-query --example compact_query -- 1000000 5 100 8
cargo run --release --locked --offline -p compact-query --example compact_query -- 1000000 5 30 8 8
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
