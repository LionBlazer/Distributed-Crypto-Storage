# Owner-private encrypted state

This module provides bounded authenticated backup/restore of an actual BFV
Owner, its salted key anchor and a Ready proof epoch. It is an owner application
capability, enabled by `key-proofs` (`formation-proofs` for the epoch). It is
not a peer import path, public same-secret evaluation-key proof or SQL grant.
The caller independently retains the complete original PublicSetup, scope,
record identity, authentic public anchor and full Key33 when applicable.

| Direct module/dependency | Responsibility |
| --- | --- |
| [Owner/PublicSetup](../lib.rs) | Actual SDK secret, fixed parameters and complete original setup identity |
| [anchor custody](../key_anchor/owner_state.rs) | Private input salt and exact coefficient commitment reopening |
| [epoch custody](../key_anchor/proof_epoch/owner_state.rs) | Private output salt, recomputed Shat and unchanged actual Key proof |
| [KeyMaterial](../key_anchor/key_material.rs) | Single shared private transform and commitment computation |
| [bfv-key-transform](../../../bfv-key-transform/README.md) | Existing bounded genuine Key verifier and verified owned public evidence |
| chacha20poly1305 / prost | Existing XChaCha20Poly1305 AEAD and the official SDK SecretKey protobuf encoder |

`OwnerStateAuthority::new(Zeroizing<[u8;32]>)` consumes a caller-custodied
high-entropy wrapping key. It exposes no key getter, Clone, Debug or serde.
`OwnerStateIdentity` is ordinary independently supplied public scope/record
metadata. `EncryptedOwnerState::from_bytes` checks bounded canonical grammar;
it does not authenticate a record. `as_bytes` returns ciphertext only.

## Lexical restore

1. `Owner::backup_private_state` requires the actual Owner's full setup identity
   before copying its secret. `Owner::restore_private_state` authenticates the
   supplied setup and identity, then validates a fixed 8208-byte private encoding:
   exact degree 8192, zero reserved fields and all coefficient bytes in 0..40.
   These become signed CBD coefficients in [-20,20]. Only then does it encode
   the official protobuf and call the SDK deserializer. No received protobuf or
   attacker-selected allocation length crosses that boundary.
2. `OwnerKeyAnchor::backup_private_state` reopens its actual input root before
   encryption. `owner.restore_key_anchor` borrows that Owner, requires the
   authentic expected public anchor, authenticates and restores its canonical
   salt, and rehashes the actual restored secret to the same Cs.
3. `epoch.backup_ready_state` accepts only Ready with its genuine matching Key
   proof. `anchor.restore_ready_epoch` borrows that anchor, restores the original
   output salt, recomputes Shat from the actual SK and both commitments, compares
   all Key33, verifies the exact stored proof and only then constructs Ready.
   A public Key frame alone cannot reconstruct either private opening. Active
   jobs exclusively borrow the epoch; they cannot overlap a backup call.

Old generation/proving entry points remain. Recreating an anchor or epoch with
the old factory still chooses fresh salts. Backup never exposes plaintext SK,
salts or Shat, and no self-referential owner aggregate is constructed.

## Record grammar and limits

`BFVOPS01` version 1 uses a fixed 624-byte public AEAD associated-data header:
magic8/version2/role1/reserved5, database16/key-domain16/epoch4, record-id32,
geometry4, original setup SHA25632/SHA51264, anchor claim140, full canonical
Key33 as 33 little-endian u64 (264 bytes), random XNonce24, ciphertext length4,
reserved8. Owner omits anchor/Key fields as zeros; Anchor omits Key fields.
Every restore reconstructs this header from independent pins before decryption.
The setup hashes cover its unchanged complete encoder, including rotation keys.

Private payloads are Owner8208, Anchor48, and Epoch48 plus the original complete
Key frame (208-byte header plus the existing at-most20MiB proof). AEAD adds a
16-byte tag. `MAX_OWNER_STATE_BYTES` is the checked maximum 20,972,416 bytes;
Owner records are 8848 bytes and Anchor records 688 bytes. Exact lengths,
canonical Gold words, role-specific zero fields and EOF are mandatory. Existing
proof envelopes, AIRs, profiles, proof caps and security assessments are unchanged.

This authenticates an owner-held backup of the actual generated pair. It does
not establish a new public theorem that arbitrary PK/RK bytes use the secret.
The wrapping authority and the independent pins must come from the legitimate
owner; a malicious peer must never supply their replacements.

Explicit owned plaintext, wide/narrow SK buffers, official protobuf coefficients,
encoded secret protobuf, input/output salts and retained Shat use guarded
zeroization. The SDK's restored SecretKey zeros its coefficient storage on Drop.
Native field vectors, hash/FFT/trace/PCS workspaces, allocator copies, SDK parser
scratch and the caller's own copies are not promised erased. Neither allocation
failure nor whole-process RAM/latency is certified by this source change.

No file writer, atomic publication, monotonic rollback protection, OS keystore,
password KDF or adjacent wrapping-key file is selected. A correctly authenticated
old snapshot remains cryptographically valid: an OwnerVault must durably reconcile
it with current network decisions. Source Ckey salt, locking controller/Registry
state, staged transitions, pending SQL completions and exact lost-ACK retry bytes
are separate storage-client obligations. This is not total restart recovery.

Owning tests cover genuine old-ciphertext decryption after Owner destruction,
fixed malformed secret preflight, wrong authority/setup/scope/role/record/anchor,
tampering/truncation/trailing/resource bounds, and restored full Key33 plus fresh
Basis5/Formation after the original Owner/epoch ends. The Key primitive also tests
owned genuine evidence, foreign pins and a canonically repaired false commitment.
All six new runtime cases passed natively, along with the existing Core and Key
regressions and ownership compile-fail contracts. The
[validation record](../../../../docs/owner-key-recovery.md) gives the exact scope,
source pins and whole-suite resource observations. It does not claim that an
owner application can yet recover an interrupted SQL transaction.
