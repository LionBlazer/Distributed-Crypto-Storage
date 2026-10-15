# Same-owner recovery candidate

Source candidate for restoring the ORIGINAL compact/BFV/Spiral owner handles.
It does not modify the owning main packages or frozen probes. At preparation
time no Cargo, key generation or dataset operation is performed. Validation
status and the bounded execution contract are recorded in the
[proposal](../../docs/proposal-owner-recovery-candidate.md).

## Ownership

| Module | Owned boundary |
|---|---|
| adapters/compact_owner_recovery.rs | Additive compact-store Owner image export/import; original key and DB/domain identity |
| adapters/bfv_owner_recovery.rs | Additive BFV Owner image export/import; original profile, geometry, version and public-keyset binding |
| [bundle](bundle/README.md) | AEAD checkpoint envelope, bounded catalog, independent current anchor, original public/file gates and all-or-failure composition |

The adapters become modules inside source COPIES of
[compact-store](../../crates/compact-store/README.md) and
[BFV core](../bfv-byte-limb-core/README.md). Neither owning library depends on
the bundle, storage adapters or the demo. Existing
[Spiral owner-state](../spiral-owner-state/README.md) is reused unchanged and
requires the ORIGINAL public wire.

Exported compact/BFV images are opaque OwnerRecoveryImage handles containing
Zeroizing storage, with explicit AsRef<[u8]> access; they implement no Debug,
Display, Serialize, Clone or Deref. The standard returned buffer must never be
logged or sent to peers. The bundle immediately seals these borrowed secret
bytes; plaintext secret images and the external wrapping key have no file,
CLI or environment-variable path.

## Source preparation

~~~powershell
.\experiments\owner-recovery-candidate\prepare.ps1 -SourceRepository $mainCheckout
~~~

This creates a NEW ignored .local/owner-recovery-candidate/source-T directory.
It verifies the reviewed BFV/compact source hashes, copies project source only,
adds the owning modules, and emits source-provenance.json. Generated owning
packages have unique IDs and preserved library names; bundle dependency aliases
point at those copies. No vendor source is committed/copied. Validated locks are copied; no Cargo
command runs at preparation time. The future build uses a dedicated
target/owner-recovery-candidate to isolate artifacts.

Original files from old probes cannot be recovered after their unsaved AEAD
keys were lost. The acceptance test creates one fresh tiny three-table checkpoint
before dropping owners, then uses the SAME encrypted files, ORIGINAL public
BFV evaluation keys and ORIGINAL PIR server setup/cache after reconstruction.
There is no fixture reseal, replacement keyset or newly generated answer.

Full process restart, external wrapping-key custody, durable publication,
anti-rollback authority, query arithmetic proof and resource/performance scale
remain separate work. The minimum three tables and unique DB IDs are this
compositor's explicit probe constraints, not universal cryptographic rules.

## Validated bounded result

39 BFV runtime cases (including explicit ignored original-key restore) plus two
doctests, 23 compact-store runtime cases and three bundle unit cases plus the
explicit ignored checkpoint/PIR integration passed. Strict authored Clippy passed
for all three packages. Final three-table test native peak RSS/private commit was
363,659,264 /376,266,752 B. This is functional same-process reconstruction evidence,
not a recovery-latency or scale-storage benchmark. The actual original-key/PIR
fixture, logs, first Clippy failure and final correction are retained ignored.
Wrapping keys are intentionally dropped when tests finish; no persistent custody
or restart path is established by retained sealed files alone.