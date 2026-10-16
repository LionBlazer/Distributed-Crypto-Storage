# Compact store

A small storage experiment for fixed-width byte rows. The owner encrypts pages
with RustCrypto XChaCha20Poly1305 and retains the secret key. Peers hold opaque
pages and a rebuildable SHA-256 Merkle tree. This module has no project-module or
GUI dependencies. It is a foundation for compact input storage and authenticated
address-based retrieval, not an FHE evaluator or SQL query proof.

## Ownership and API

- Owner owns a random 256-bit key and random key-domain ID. It has no printing,
  cloning, serialization or key-export API. The key is zeroized on drop.
- Layout declares a schema ID, row width, rows per page and row count. Rows use
  exactly their supplied bytes, including the final partial page. Layout::address_of
  maps a known logical row ordinal to its page and byte offset.
- Owner::seal creates an EncryptedSnapshot and its Commitment at revision zero.
  The application obtains this head directly from its owner or another independently
  authenticated source. A commitment parsed from the responding peer has no such trust.
- EncryptedSnapshot clones share private, immutable ciphertext allocations. Each
  clone owns an independent page-slot vector and Merkle levels; replacing a slot
  cannot modify another snapshot. Imports copy packet slices directly into combined
  reference-count/payload allocations without temporary Vec buffers. Converting an
  owner-created or replacement Vec into a shared slice allocates and copies its
  payload. Public lookups still return separate owned packet buffers, and imports
  still audit every packet and the complete root.
  There is no mutable packet accessor, shared plaintext/key cache or serialized Arc.
- EncryptedSnapshot::lookup returns a LookupResponse for one exact public page
  address, with a Merkle proof. LookupResponse::verify takes the requested address
  and independently known head, returning VerifiedPage only after validation.
- EncryptedSnapshot::decode_for_head imports a complete image against an
  independently trusted head. It rejects a mismatched manifest before allocating
  pages, then verifies the full root. Plain `decode` checks internal consistency
  only; a peer-supplied embedded root does not establish authorization or freshness.
- VerifiedSnapshotBytes::decode_for_head fully validates canonical immutable input
  bytes against the independently expected head, checking every packet revision
  and the complete root. Its private, non-cloneable/non-deserializable lineage
  borrows the input and owns checked Merkle levels without allocating packet copies.
  lookup returns the same ordinary owned membership response and rechecks current
  resource limits. Consuming into_snapshot copies packets and moves the checked
  tree without another root pass. Both owned decode entry points use this same
  parser and root reducer. No byte can be omitted, changed through this API or
  accepted from metadata alone. This is local validation, not an across-RPC cache,
  AEAD/source proof or freshness guarantee. Wire bytes and all limits are unchanged;
  full-operation speed and process memory still require measurement.
- OwnedVerifiedSnapshotBytes::decode_for_head consumes a canonical Vec through
  that same complete parser, retaining its exact allocation and checked Merkle
  levels. The sealed capability has no Clone, Deserialize or mutable-byte API.
  lookup produces ordinary owned responses under current resource caps without
  materializing the image. Consuming into_bytes returns the original Vec;
  into_snapshot allocates packet payloads only when required and moves the checked
  tree without another root pass. This still audits every byte and retains the
  bounded tree. Materialization temporarily holds canonical bytes and copied
  packets; no process-memory or full-operation latency improvement is established.
- EncryptedSnapshot::apply_verified_replacements consumes an authenticated base
  and verified target pages, preserves database/domain/layout, requires the next
  global revision, and returns only an image whose complete reconstructed root
  equals the exact target. Omitted or duplicate replacements reject. An unchanged
  image accepts only the same exact head and no replacements. This ciphertext-only
  primitive grants no head authorization, SQL proof or freshness; the caller owns
  durable staging and provenance. It does not copy every base page again.
- LookupResponse::verify_for_reissue uses the same ordinary membership verifier
  and returns a non-cloneable, non-serializable VerifiedPagePath. It retains the
  exact old head, address, packet and private siblings. Immutable commitment/address
  accessors expose only its authenticated binding metadata. Owner::reissue_page consumes
  it with an independently supplied matching head and same-length new plaintext.
  It rechecks owner, geometry, resource/response bounds and revision exhaustion,
  authenticates the old AEAD, then uses the existing fresh-nonce page encryption
  and Merkle domains to return a new head plus ordinary LookupResponse. Odd missing
  siblings duplicate the new node when deriving the new root/path. The source stays
  unchanged; no partial EncryptedSnapshot or Table is constructed. This is a local
  page proposal, not SQL execution/proof, durable publication or head finality.
  It does not audit unseen pages or replace complete-image custody admission.
  An old path rejects against a newer expected head; explicitly trusting the old
  head again may create another proposal. There is no spent-capability registry.
- Owner::decrypt accepts VerifiedPage and returns PlainPage; the decrypted buffer
  is zeroized on drop. The application remains responsible for its source plaintext
  and any copies. Public nonce, ciphertext and tag accessors on VerifiedPage permit
  a future separately validated transciphering adapter without exposing the key.
- Owner::derive_keystream_range authenticates/decrypts a page only at the owner,
  then derives a requested temporary pad range by XOR with public ciphertext. Its
  SecretMask erases the pad on drop; the owner must never send this plaintext pad.
- Owner::replace_pages stages all fresh encrypted packets before mutating the
  snapshot, rejects duplicate addresses, and advances a single global revision.
  This supplies in-memory atomic batches, not durable crash-atomic transactions.
- Owner::replace_page requires the previously known head, encrypts one replacement
  page with a fresh nonce and a new page revision, updates its Merkle path, and
  returns the new head. It retains no historical ciphertext. This replacement API
  preserves geometry.
- Owner::grow_from_checked_plaintext stages a larger row count under the same owner,
  schema, row width and page width, with the next global revision. The caller must
  validate the original prefix and authorized new rows first. Every page is freshly
  encrypted because row count is bound in its AEAD associated data. The source stays
  unchanged on failure. SQL semantics, shrinking, durable writes and disk compaction
  belong to callers.
- Limits caps rows, pages, page plaintext, image bytes and response bytes before
  parsing allocates payload/proof buffers. The page-count cap also bounds index
  construction. A peer may configure lower quotas.

The caller owns head publication, authorization, durable key management, consensus,
independent confirmation of freshness, networking and replication. A read requiring
the current head must pass that current head; an old snapshot remains readable when
its old head is intentionally selected. This is not a proof that a supplied head
is the network's latest confirmed version.

## Format and authentication

All integers are little-endian. The exact canonical image has:

| Component | Bytes |
| --- | ---: |
| Magic/version | 8 |
| Database ID, key-domain ID, schema ID | 48 |
| Snapshot revision | 8 |
| Row width and rows per page | 8 |
| Total row count | 8 |
| Version root | 32 |
| Each page revision | 8 per page |
| Each XChaCha20 nonce | 24 per page |
| Each authentication tag | 16 per page |
| Encrypted row payload | Exactly row_width * row_count |

Thus live canonical bytes are 112 + logical_bytes + 48 * page_count. No plaintext
compression or row padding improves this denominator. Tiny tables exceed 2x because
of fixed metadata. With 3-byte rows and 256 rows/page, asymptotic page overhead is
6.25%; the exact result must include the 112-byte manifest and final short page.

Page AEAD associated data binds its format domain, database, key domain, schema,
complete row geometry, exact page index and page revision. Unchanged pages keep
their original page revision; the global snapshot revision is instead bound by
the version root. Each Merkle leaf hashes the exact index, packet length and packet.
Nodes use a separate hash domain. Odd final nodes duplicate themselves, with exact
height and duplicate-sibling checks in verification. The outer version root hashes
the complete manifest prefix and tree root, committing to count, shape and revision.

The rebuildable index stores approximately 2 * page_count 32-byte hashes; report
index_hash_bytes separately. It is held in memory, not silently embedded in canonical
storage. If persisted, these bytes must be added to disk accounting. Allocator and
vector overhead, owner keys, plaintext fixtures, image/response copies and process
memory are additional costs, not represented by that hash-payload counter. Shared
ciphertext adds reference-count/allocation metadata per admitted page; page count
bounds that metadata for each snapshot. Clones still copy slots and Merkle levels,
and old packets remain alive while any snapshot retains them. This is request/value
ownership, not a persistent cache or a measured whole-process memory/speed claim.

Lookup response encoding is index:u64, packet_length:u32, sibling_count:u32, followed
by the complete packet and 32-byte siblings. Packet encoding is page_revision:u64,
nonce:[u8;24], ciphertext, tag:[u8;16]. VerifiedPage::ciphertext excludes its tag.

RustCrypto references: [XChaCha20Poly1305 0.10.1](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/),
[SHA-2 0.10.9](https://docs.rs/sha2/0.10.9/sha2/),
[zeroize](https://docs.rs/zeroize/latest/zeroize/).
The cipher and hash dependencies are pinned; keys and 192-bit nonces use OS entropy.
Production message limits and cryptographic review remain necessary.

## Guarantees and open boundaries

A valid proof demonstrates that all bytes of the requested fixed page belong to
the exact supplied commitment. Omitting or altering bytes/nodes, swapping addresses,
or replaying a proof against a changed current root fails. AEAD separately checks
integrity and its associated-data binding during owner decryption.

The index directly addresses a known row ordinal. It does not find an encrypted
predicate, establish a complete duplicate-key posting list, prove absence of an
arbitrary SQL key, or prove COUNT/SUM/UPDATE computation. XChaCha20 encryption is
not FHE-compatible merely because payload bytes can be read. Compact-to-FHE
conversion must be implemented, validated and measured separately.

Privacy remains undecided in the project. This experiment reveals database/schema
identifiers, row/page counts and sizes, page revisions, requested page positions,
repetition, timing and response sizes. It does not expose the owner key or plaintext.
Concealed access with ORAM/PIR remains a separate comparison requiring a collusion
model, protocol, bandwidth/rebuild budget and measurement. These observable accesses
are an experimental case, not approval to relax the privacy requirement.

Measured values and exact conditions are recorded in the [experiment report](../../docs/experiment-compact-store.md).

## Reproduction

From the workspace root, with public synthetic age:u8 + amount:u16 rows and
ephemeral in-memory keys only:

~~~sh
cargo test --release --locked -p compact-store
cargo clippy --release --locked -p compact-store --all-targets -- -D warnings
cargo run --release --locked -p core-workloads --example compact_lookup -- 1000000 1000 1000
~~~

The example prints JSON lines without writing data or keys. The three arguments
select row count, warm lookup samples and page replacements. Its storage sweep
includes zero, tiny and large datasets with varied row bytes. Lookup timing includes
direct address calculation, proof construction, response encoding/decoding,
verification and owner decryption. It reports warm p50/p95/p99 plus one cold
in-memory image reconstruction, index rebuild and lookup. This is not cold disk IO.

Every replacement is checked against the previous head, the resulting plaintext
is checked, live encoded/index sizes are checked to remain constant, and the final
image is decoded against its exact current head. Stale proofs are tested separately.
Replacing fixed pages is not a full insert/delete lifecycle or disk crash-recovery
experiment. Timings exclude transport, consensus, FHE conversion/evaluation and
computation proofs. Measure whole-process peak memory externally; the example's
index payload count is not a process-memory measurement.
