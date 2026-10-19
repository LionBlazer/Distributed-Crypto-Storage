# Retained protocol storage

This module owns actual shared file-byte accounting and bounded immutable public
evidence files. Journal, finality signer and proof consumers use the same budget;
none of their verification or deployment policy belongs here.

| Direct dependency | Responsibility |
| --- | --- |
| Rust `std` | Files, exclusive ownership, bounded streaming and accounting |
| Existing `sha2` | SHA-256 of complete original public blob bytes and the explicit storage profile/header |

The module depends on no consensus, Journal, cryptographic proof, SQL or peer
runtime crate. A `BlobId` is caller-constructible content identity, never a valid
proof, cached verification result, availability promise or application grant.

## Shared quota and error ownership

`ByteBudget::new(limit)` requires an explicit positive limit no larger than
**256 MiB**. The same instance accounts for actual Journal, signer WAL, finality
floor and proof files. With this legacy constructor, the participant's separate
disk quota remains an additional owning-runtime check. Neither this library limit nor a message cap establishes a
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

## Published legacy verification scope

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

## Explicit participant namespace and quota

`ParticipantQuota` adds a **new** local logical-file accounting profile. It does
not import or migrate legacy Journal/finality workspaces or `custody-v2` trees.
`ByteBudget::new` and `EvidenceStore::open` retain their legacy bounds; a scoped
CONTROL budget cannot be passed to the legacy evidence opener. The new entry
points are `ParticipantQuota::{create_new, open_existing}`, `control_budget`,
`depot_budget`, `custody_budget`, `control_file`, `custody_file`, `depot_directory`,
`usage`, and `EvidenceStore::open_depot`.

Both participant constructors take an independently supplied namespace `[u8; 32]`
and exact decimal capacity. Capacity is positive and at most **30,000,000,000
bytes**; 10, 20 and 30 decimal GB are policy choices, and smaller limits are
accepted. This local capacity is not a consensus RulesId. The fixed profile
digest binds the namespace grammar and accounting rules, not a chosen local
capacity. The exact 136-byte `participant-v1.profile` header pins the profile,
namespace, capacity, CONTROL limit, file limit and blob limit, with a checksum.
This checksum is metadata identity, not authorization or proof.

The root contains exactly:

| Entry | Contents and accounting class |
| --- | --- |
| `participant-v1.profile` | Exact immutable header, charged to CONTROL |
| `participant.lock` | Empty exclusive root lock, a charged CONTROL file slot |
| `control/` | Flat lowercase 64-hex stem plus `.wal`, `.journal`, `.floor` or `.meta` |
| `depot/` | Existing exact CAS `.blob`, `.part` and `.evidence-lock` grammar |
| `custody/` | Flat lowercase 64-hex stem plus `.object2` or `.meta` |

Class directories contain no subdirectories or symlinks. `control_file` and
`custody_file` derive canonical paths from the caller's independent 32-byte file
identifier and a closed typed suffix. They do not verify the file's application
semantics. The caller must still validate each Journal, WAL, metadata and custody
object under its own exact expected context and existing wire/resource bounds.

ONE private ledger counts global charged extents/reservations and each class.
All CONTROL files, root header and root lock share **one total 256 MiB cap**.
Depot and custody share the remaining global capacity; obtaining more handles or
cloning any budget creates no new allowance. `DepotBudget` and `CustodyBudget`
are distinct public types constructed only by `ParticipantQuota`. All descendant
budgets, reservations, file charges, file permits and stores retain the exclusive
root lock, even after the `ParticipantQuota` handle is dropped.

The accounting unit is logical file bytes, including serialized metadata and
lock-file lengths, plus pending/reserved extents. Directory entries, filesystem
allocation rounding, filesystem journals and other physical overhead are
excluded. This is not a measured physical-disk quota or whole-peer RAM guarantee.
Callers must honor the exclusive namespace lifecycle and use permits before
filesystem writes; the ledger is not an operating-system filesystem sandbox.
`usage` observes charged totals and tracked retained/pending paths, so in-flight
reservations can exceed current file lengths without exceeding the quota.

`open_existing` checks independent header pins and the complete bounded inventory
of **all three classes before returning any budget**. Unknown entries, wrong
types, symlinks, wrong extents and corrupt complete CAS identities fail opening.
All names/types/extents pass preflight before any recognized abandoned stage is
removed under exclusive ownership. At most 4096 retained/pending paths and 4096
active reservations are tracked. Recovery permits one additional temporary
publication hard-link name, then removes the stage before retained accounting:
this represents the same charged CAS payload, not a second retained-file slot.
Incomplete inventory never yields an admission-capable handle.

### Create and reopen ownership

`preflight_file(path, initial_extent)` on a scoped budget checks the closed class
path and physical absence before reserving one pending slot and its full initial
extent. An existing path is refused before any pending entry is installed; that
ordinary refusal does not poison the namespace. The returned `FilePermit` owns
the exact path and quota until `register_file(&mut self)` observes the regular
file and promotes the same charge. The initial extent may cover an unwritten
header; no second charge is added on promotion. `FileCharge::grow` precharges
later absolute growth. The signer WAL performs this preflight before its actual
create and uses the unchanged header bytes and write/sync order.

Dropping an unpromoted scoped permit releases its slot/extent only when the path
is proven absent. A surviving or unknown artifact keeps the charge and poisons
the namespace. `check_existing_file` validates a tracked scoped path before an
existing-file open. Public scoped `register_file` reuses exact tracked charges;
it never adopts an unpermitted fresh path after startup. An actual untracked
survivor or changed/lost retained file poisons the shared inventory; a malformed
out-of-scope path is refused without an I/O ownership change. Private startup
inventory is the only bulk registration path. Legacy unscoped preflight performs
no early accounting or path restriction and preserves late registration.

For a separate lease, `preflight_file(path, 0)` followed by exact
`Reservation::retain_file(&mut self, path)` transfers the already charged lease
to that pending path atomically. Successful transfer empties the lease and the
permit then drops without poisoning or releasing the retained file. On any
creation/transfer error the owner must explicitly keep a possibly surviving
artifact charged, using `retain_conservatively` where its actual removal is
unknown. Do not use an unguarded `?` that drops the only payload lease. A
post-promotion uncertain write/sync similarly calls the borrowing
`FileCharge::mark_io_failed`; the charge already survives handle Drop. These
error branches poison the new shared
namespace and keep persistent charges; other actors cannot continue writing
through a cloned budget. Successful actual stage removal may release its extent
without clearing poison. Resumption requires dropping **all** owners and a new
strict full-disk reconstruction. There is no reset API.

`EvidenceStore::open_depot` derives the fixed directory from its typed budget and
uses the same CAS parser, streaming writer/reader, no-clobber publication and
recovery implementation as the legacy store. Publication validates its scoped
target before linking and retargets the actual same stage charge. A single blob
is still at most **32 MiB**; the hard **32 MiB Journal Body**, **64 MiB transport
message** and legacy **256 MiB whole Journal** limits remain independent and
unchanged. A larger participant depot is not permission to aggregate proofs into
an oversized message or Body. No proof verification flag, SQL/lock grant,
same-secret key assertion, consensus decision or freshness receipt is stored.
Every required proof and agreed-head pin must still be checked by its owning
consumer on admission and reopen. The Unix/Windows directory durability
qualification above applies unchanged.

### New-profile validation

The new owning tests cover concurrent shared reservations, the independent
CONTROL cap and decimal capacities using scalar leases (no gigabyte payload
allocation), path checks before creation/open, persistent file growth and exact
lease transfer, partial-creation/sync poison, root-lock lifetime through every
descendant type, whole-namespace restart inventory, malformed/foreign headers,
unknown files, actual two-hardlink recovery, immutable lost-ACK retry, quota
failure and full file-slot recovery. The extra symlink case is Unix-only and was
not executed on Windows. All **27 Windows storage tests** passed, including the
twelve unchanged legacy cases. All **39 work-finality tests** and five existing
ownership compile-fail examples passed. Three new signer cases use the actual
participant namespace: header quota refusal before creation, six write/advance
failure/reopen paths, and an actual changed file extent. Both record and Advance
write errors, and position-check errors, poison the shared participant budget.
The strict replay and original multi-slot wire formats are preserved.

Strict Clippy for storage, work-finality and registry200-finality, Core default
member compilation, workspace format and requirements mirror checks passed.
[Participant quota validation](../../docs/participant-quota.md) records commands,
source pins, the Windows lock-test correction and resource-observation limits.
