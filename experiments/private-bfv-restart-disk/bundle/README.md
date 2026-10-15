# Sealed process-restart owner bundle candidate

This new compositor copy wraps owner recovery images with standard
XChaCha20Poly1305 using an external separately held wrapping key. It does not own
key custody, rollback authority or durable multi-file publication.

Direct dependencies are [compact store](../../../crates/compact-store/README.md)
and [BFV core](../../bfv-byte-limb-core/README.md), with their validated recovery
adapters copied by the parent experiment's source preparer, plus
[Spiral owner state](../../spiral-owner-state/README.md). Those owning libraries
do not depend on this storage/demo compositor.

seal_checkpoint returns ciphertext and a public CheckpointAnchor. restore_checkpoint
authenticates bounded ciphertext before secret decoding, validates exact original
public identity and all trusted physical head/length pairs, then constructs owner
handles provisionally. read_original_snapshots performs full Merkle reconstruction
before use. The caller supplies an independently trusted current anchor.

RestoredCheckpoint::into_parts and RestoredTable::into_parts MOVE the original
restored handles into a reader's runtime; no owner-key cloning or self-reference is
needed. Secret images and AEAD plaintext buffers use Zeroizing. The existing SDK
and upstream protobuf temporary-allocation zeroization limits still apply.

The current candidate admits3..2000 unique tables, bounded leaf filenames,
8MiB individual images,64MiB original BFV public input, exactly6,029,344B Spiral
public input, at most1MiB secret plaintext, and at most1,048,704B sealed wire.
These are pinned experiment constraints, not a general backup format.
