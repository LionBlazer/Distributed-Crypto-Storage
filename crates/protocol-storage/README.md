# Retained protocol storage

This module owns actual shared file-byte accounting and bounded immutable public
evidence files. Journal, finality signer and proof consumers use the same budget;
none of their verification or deployment policy belongs here.

| Direct dependency | Responsibility |
| --- | --- |
| Rust `std` | Files, exclusive ownership, bounded streaming and accounting |
| Existing `sha2` | SHA-256 identity of complete original public blob bytes |

The module depends on no consensus, Journal, cryptographic proof, SQL or peer
runtime crate. A `BlobId` is caller-constructible content identity, never a valid
proof, cached verification result, availability promise or application grant.

## Shared quota and error ownership

`ByteBudget::new(limit)` requires an explicit positive limit no larger than
**256 MiB**. The same instance accounts for actual Journal, signer WAL, finality
floor and proof files. The participant's separate disk quota is an additional
owning-runtime check. Neither this library limit nor a message cap establishes a
whole-peer RAM or disk guarantee.

`register_file(path)` reads the actual canonical regular-file length after the
caller acquires its exclusive file lifecycle. `FileCharge::grow(next_bytes)`
precharges an absolute new extent before a write. Charges survive handle Drop;
exact reopen reuses an existing charge. No public file-charge release exists.
At most 4096 canonical file paths are tracked. A whole-process restart must build
a new budget and register **all** retained protocol files before signing or
admission; opening an evidence directory alone cannot discover an external WAL.

`Reservation` covers transient or not-yet-created artifacts. `resize` reserves
growth before writing and shrinks only after actual removal. `retain_file(&mut
self, path)` atomically transfers an exact already-charged lease to an actual
file; failure leaves the lease intact. An owner must not use `?` across file
creation/transfer if that would drop the only charge while a file may survive.
Explicit error/poison branches can consume `retain_conservatively()`: those
bytes stay charged until a new accounting owner reconstructs actual disk at a
full restart. There is no reset or release operation for this ambiguous charge.

## Public evidence lifecycle

`EvidenceStore::open(existing_directory, budget, limits)` acquires an exclusive
lock, bounded-scans recognized files, registers actual retained bytes and hashes
every complete blob. Unknown files, symlinks and corrupt identities are errors.
All names, regular-file types and extents are checked before any cleanup.
Recognizable abandoned staging files are removed under this ownership **before**
registering retained blobs: a crash may leave `.part` and `.blob` hard links to
one physical payload, which must not be double-charged at an exact quota.
Successful removal releases only an already tracked stage charge. Failed removal
keeps an existing conservative charge, attempts registration of an uncharged
survivor and fails opening. A failed open is not a reconstructed complete
inventory; admission must not resume from that partially populated budget.

`StoreLimits` explicitly lowers the hard **32 MiB per blob** and finite file
count. Existing Source, child, sequence, decoded-element, Journal Body and
transport limits remain separately enforced by their original consumers. This
store neither changes those caps nor defines an aggregate query-message format.

`stage(BlobId)` borrows the store exclusively, charges the entire expected extent
and creates a new staging file. `write_chunk` accepts at most the remaining exact
length. `finish` requires complete original bytes and SHA-256 identity, syncs file
contents, and uses a no-clobber hard link to the committed name before removing
the stage. There is no overwrite/copy fallback on an unsupported filesystem.
An existing committed name is reused only after its actual full contents match.
Explicit `cancel` reports cleanup errors; Drop is best effort and never releases
bytes for a failed removal. No committed eviction/garbage collection exists.

On Unix, publication/removal also syncs the directory. Windows `std` file sync
and hard-link success do **not** establish power-failure durability of directory
entries. Reading a missing referenced identity fails; recovery does not recreate
proofs or trust an earlier receipt. Directory enumeration cannot know whether an
independent application manifest references an absent file. The application must
resolve every required identity again on reopen. This is an explicit durability
limit, not a claim of complete failure tolerance.

`reader(id)` supplies bounded sequential public bytes. The caller consumes all
bytes and calls `finish` to check exact length, EOF and actual SHA-256. This is
still only identity checking: application consumers must decode and verify every
required cryptographic proof under independent expected Source/query/parent pins,
then separately check freshness before voting, admission and offline restoration.
No verification flag is persisted or returned by this module.

## Verification scope

The owning source tests use public non-secret bytes and actual temporary files:
pre-write shared quota, exact persistent reopen, partial-creation error ownership,
immutable duplicate/corruption handling, bounded upload/read, explicit cancellation,
abandoned-stage recovery, actual two-hardlink crash survivors at exact quota,
corrupt-stage preservation, missing evidence and exclusive directory ownership.
Bounded cleanup/sync/lost-response fault injection operates on real files and
retains their actual accounting; it is not a filesystem power-loss test. All
twelve tests passed on Windows, along with the existing 33 work-finality tests
and five ownership compile-fail examples. Strict Clippy and the Core default
build check passed. The [validation record](../../docs/protocol-storage.md)
preserves exact scope, source pins and the limits of the resource observation.
