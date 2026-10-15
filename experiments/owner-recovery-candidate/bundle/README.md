# Sealed owner checkpoint composition

This candidate library owns a bounded XChaCha20Poly1305 backup envelope and
same-owner handle reconstruction. It uses the standard existing RustCrypto
AEAD, with a separately held 32-byte WrappingKey. It implements no new primitive.

Direct project dependencies:

| Dependency | Role |
|---|---|
| Generated [compact-store](../../../crates/compact-store/README.md) candidate | Original key export/import and authenticated original snapshots |
| Generated [BFV owner core](../../bfv-byte-limb-core/README.md) candidate | Original BFV secret/public identity and real owner evaluation APIs |
| [Spiral owner-state](../../spiral-owner-state/README.md) | Existing 336-byte seed envelope; original public setup/profile |

Third-party dependencies are pinned Spiral, RustCrypto XChaCha20Poly1305,
getrandom, SHA-256 and zeroize. BFV and compact-store have no reverse dependency.

Public entry points are WrappingKey::{generate,from_protected_memory},
seal_checkpoint, restore_checkpoint, catalog_digest, and read-only getters on
RestoredCheckpoint/RestoredTable. RestoredTable::read_original_snapshots performs
held-file exact reads, complete Merkle reconstruction and trusted-head equality
before snapshots can reach page authentication/decryption or native caches.

CheckpointAnchor is PUBLIC but must come from an independent authenticated
latest-checkpoint authority, not the backup peer. It binds bundle/checkpoint ID,
generation, full public-key digests, geometry and all table names/lengths/heads.
AEAD authenticity alone does not prevent rollback to a valid old anchor/bundle.

Restore order is fixed: bounded outer framing; AEAD into Zeroizing plaintext;
bounded manual catalog parse; current anchor and original-public digest gates;
physical file head/length checks; public decoders; provisional secret owners;
publish only when every owner restored. A physical head check is not validation
of the full ciphertext body; read_original_snapshots supplies that later gate.

The hard caps are 1 MiB plaintext bundle, 3..2000 tables, 64 ASCII bytes per
leaf filename, 8 MiB canonical image, 64 MiB BFV public wire and the existing
exact PIR public/image/profile sizes. No secret image has Debug/serialization
traits. Opaque owner images and the opened bundle use Zeroizing. Existing
upstream protobuf/SDK temporary and private-allocation zeroization limitations
remain explicit.

The acceptance test is opt-in because it uses real BFV keys and real private
PIR. It drops original Owner/client handles within one process, preserves the
same public peers/cache and encrypted files, then checks original data/index
plaintext and a real encrypted predicate with rotations/products/relinearization.
It is not a cross-process, fsync/atomic-publication, anti-rollback, full SQL,
malicious-evaluator proof or latency benchmark.
