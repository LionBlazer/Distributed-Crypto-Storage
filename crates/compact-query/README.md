# Compact query

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

COUNT and SUM return exact u32 values, including (0,0) for no matches. AddAmount
adds an encrypted u16 delta. If any matching row would overflow, an encrypted
global rejection condition preserves all original amounts. The owner-local update
experiment decrypts and compares every selected output, stages fresh encrypted data
pages and the index binding page, and only then publishes both images in the Table.
This is atomic in memory; durable crash-atomic persistence is a separate boundary.

## Index consistency and limits

The encrypted index contains the exact 112-byte data commitment, 257 little-endian
u64 posting boundaries and one u32 logical row ordinal per table row, grouped by
age and sorted within each group. Boundary/header and posting pages use the same
compact-store AEAD/Merkle contracts. An owner-authenticated current index head and
its encrypted exact table-head binding establish which complete posting list was
built. AddAmount never changes age, so only the binding page needs replacement.
There is no public arbitrary-age mutation or peer-built untrusted index API.

The table limit is 1,000,000 rows. MAX_ROWS is a distinct hard limit of 256 selected
rows per request, checked from authenticated boundaries or the full-scan count
before any FHE pad encryption. A lower caller budget is honored. SelectionBudget
returns the full selected count and effective budget; it never truncates a group.
Private COUNT uses ten bits, then widens to u32; the largest SUM is
256 * 65535 = 16,776,960. Wire encodings are bounded at 128 MiB. This bounds honest
materialization, not every malicious TFHE parameter/allocation path.

The encrypted posting payload alone uses four bytes per three-byte table row.
Report canonical data, encrypted index, rebuildable hash payload, keys, replicas
and transient query traffic separately. The data-only compactness target does not
imply a combined data/index/key expansion below 2x.

## Experiment boundary

The index is private owner policy, with visible candidate cardinality and physical
addresses at the peer. The owner reads/decrypts encrypted index pages. This is not
a peer-executed concealed SQL index, ORAM/PIR, arbitrary SQL, distributed consensus,
a proof of query correctness/completeness, durable key recovery or authorization.
Public age-operator shape (equality/range), sizes, revisions, access repetition and
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
~~~

The example emits JSON lines and saves no keys/data. It includes full encrypted
request/output serialization, index lookup/proofs, exact page verification,
compact-to-FHE conversion, genuine encrypted predicate/COUNT/SUM, owner decryption,
and owner-verified compact writeback. Every repeated UPDATE encodes and freshly
decodes both complete canonical images, rebuilds their hashes, checks constant live
size and rejects its old output against the new head. It also performs an actual
four-row UPDATE and a 21-row range aggregate. Setup and cold in-memory key/image
round trips are separate. Transport, disk IO, consensus and computation proofs
are unmeasured. See the [experiment report](../../docs/experiment-compact-query.md).
