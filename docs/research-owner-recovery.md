# Same-owner restart: missing recovery boundary

Source-only assessment; no backup implementation, keys, benchmark or recovery claim.
The retained 1,000-table files cannot restart the same owner after its live secrets
are lost. Recreating fixtures/keys would create another database, not recover it.

## Existing state and APIs

| Required state | Authoritative size / current contract |
| --- | --- |
| Per-table compact owner | 32-byte secret plus database 16/domain 16 identity. Identity already exists in each trusted head; semantic owner payload 64 is not a serialized image. `Owner` has generation only, no export/import. |
| Trusted data+index heads | 112 bytes each, 224/table; includes database/domain/schema/layout/revision/root. Parsing a peer head does not establish freshness. |
| BFV owner | Generated N8192 secret serialization count 8195 in the measured run. `secret_key_serialized_bytes()` immediately drops a zeroizing buffer; it exports no image and there is no Owner restore API. |
| Original BFV public setup | Measured 13,395,426 bytes, retained file; exact parameters, geometry, relinearization and rotation keys. Preserve original bytes, not regenerated keys. |
| Spiral owner | Existing opaque 336-byte secret envelope; supported restore requires the original 6,029,344-byte public setup and expected 32-byte domain. |
| Catalog/cache | Current public JSON catalog 700,670 bytes for 1,000 tables contains filenames/lengths/heads, not secrets or cached counts/offsets. Authenticated cached-header payload 2276/table is optional: reconstruct it from authenticated index page 0 after restoration. |

Sources: [compact owner](../crates/compact-store/src/crypto.rs),
[head format](../crates/compact-store/src/format.rs),
[current BFV core](../experiments/bfv-byte-limb-core/src/lib.rs),
[Spiral wrapper](../experiments/spiral-owner-state/src/lib.rs),
[catalog/loader](../experiments/private-bfv-disk/src/disk.rs),
[actual scale ledger](experiment-private-bfv-disk-scale.md).

The disk probe keeps per-table compact Owners, BFV Owner and Spiral OwnerState
only in memory. It writes both public setups and encrypted snapshots; its transient
Spiral image is dropped after same-process restoration. `build_catalog` generates
new owners; no catalog-to-restored-owner loader exists. The retained catalog was read-only checked: 1,000 unique IDs 0..999, 700,670 bytes,
SHA256 197E6976B6D5A1F9B541E9F398AF4D37250482494634E28D2BB3892570477E4B.
Its 2,003 directory files contain snapshots/catalog/two public setups, no owner image.
The preserved dataset cannot acquire missing secrets from that public catalog.

For 1,000 tables, existing operational secret payload is 32,000+8195+336=40,531 bytes; trusted head
payload adds 224,000. These are semantic/count subtotals, not a backup format or
complete storage/RAM ledger. Cache payloads, metadata, AEAD framing, public material
and every retained backup copy must be counted explicitly. Merkle/NTT caches can be
rebuilt from original authenticated files; no plaintext database or answer cache
is needed.

The pinned local `fhe` 0.1.1 release has `SecretKey::{to_bytes,from_bytes}` through
fhe-traits; its roundtrip test compares keys. Source `src/bfv/keys/secret_key.rs`
SHA256 337E85E2DC4A7540039B800517EC32389DC3152516C9FDAD18CC58DC55ACEC70
shows the decoder checking coefficient count against degree only. Serialized
coefficients do not include parameters, geometry or public-key provenance. A new
bounded owner wrapper is needed; merely exposing upstream decoding is insufficient.
The 8195-byte count is not a portable authenticated envelope or general decoder cap;
a bounded secret-image decoder contract is currently missing.

## Proposed owner-only sealed boundary

Use the existing standard XChaCha20-Poly1305 implementation with a separately
protected random 256-bit owner recovery key, fresh 24-byte OS-random nonce per seal,
and explicit authenticated format/version/algorithm and bundle identity. Do not
store that recovery key beside the backup, or send plaintext secrets to peers,
logs, reports or Git. Count this additional 32-byte key too; its custody/availability remains external.

The authenticated confidential payload should contain a consistent checkpoint:
per-table keys and identities; exact current data/index heads; bounded table-ID,
filename and exact-length map; generation/checkpoint identity; BFV secret image,
complete serialized profile/geometry, pinned implementation/serialization versions
and SHA256 of ORIGINAL public setup; Spiral 336
image and original public-setup identity/domain/SDK-RNG-platform contract. Public
setup files may be separate but must match authenticated lengths/digests before
public decoders. Either seal cached headers with their two heads or reconstruct
them; never trust unauthenticated cached metadata.

A digest binds public-wire identity; it does NOT prove an arbitrary BFV secret
matches its evaluation keys. Trusted export from the actual live Owner supplies
that provenance. Upstream secret decoding and self-encrypt/self-decrypt under a
new key cannot establish the match. Original-key evaluation tests below are
diagnostics, not mathematical proofs of arbitrary keyset consistency. Preserve
the same setup for every read,
exact aggregate and indexed update sharing that Owner.

Restore validates bounded framing/authentication before secret/protobuf/SDK decode,
then profile, geometry, identities and checkpoint consistency, and only publishes
handles after all checks succeed. Use Zeroizing for exported/decrypted images and
temporaries. Compact Owner and BFV SecretKey erase owned secrets on drop; upstream
protobuf copies and Spiral private allocations are not comprehensively zeroized.
That remaining audit is explicit, not solved by wrapping one outer buffer.

AEAD cannot prevent rollback to a valid old backup. A separately trusted latest
checkpoint or monotonic/consensus authority is required. Snapshot/index/catalog
and secret checkpoint need a durable transactional publication contract; current
separate writes have no fsync/atomic multi-file crash guarantee. Do not infer newest
heads from whichever peer answers. Drop in-flight pending tokens on restart and
start a fresh session/query-ID domain; persistent replay/update authorization is
still external. This adds neither consensus nor backup availability.

## Owning acceptance gates before implementation claims

1. Restore a dropped original owner against unchanged disk bytes/heads; verify and
   decrypt actual pages from both original data and index. No reseal/regeneration.
2. Restore BFV secret with ORIGINAL public keys, then actually evaluate rotations
   AND a ciphertext product/relinearization and decrypt known non-secret fixtures.
   Reject wrong key/profile/setup/geometry; self-roundtrip alone is inadequate.
3. Restore Spiral against ORIGINAL public wire and perform actual authenticated
   PIR page reads; reject wrong seed/domain/profile/public wire and corruption.
4. Reject malformed/oversized/truncated/tag-changed images before publication;
   enforce loader 3..2000 tables, 8 MiB/image, 64 MiB BFV-wire cap and exact profile limits.
5. Exercise torn checkpoint writes, mixed generations, stale trusted heads, replay,
   interrupted update and backup rollback against the external freshness policy.
6. Reopen the same 1,000 catalog/files, count every backup/public/secret byte and
   cold reconstruction/native peak; benchmark complete operations after restart.