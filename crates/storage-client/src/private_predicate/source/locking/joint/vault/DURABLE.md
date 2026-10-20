# Historical owner Control Vault

`OwnerVault` is a bounded owner-private BEGIN/End phase log. Its five genuine
proof/QC/file runtime tests and two new ownership examples passed on the native
release build; the [validation record](../../../../../../../../docs/joint-owner-control-vault.md)
pins the source, full commands and failure scope. It does
not enable SQL, install a current lease, commit encrypted data, or establish
anti-rollback/power-loss protection. The already validated in-memory Acquire
capsule remains a separate API and format.

The application supplies an independent `JointBinding`, `OwnerVaultIdentity`,
external `OwnerVaultAuthority(Zeroizing<[u8;32]>)`, real `SourceOwner` and fetched
Source, and bounded original checkpoint/Body replay inputs. Initial setup and
every proof premise must be available in the same public depot. The initial
public prefix remains a mandatory caller recovery input; the Vault does not
replace it with a saved parent DTO or proof-success flag. Source and BFV private
backup authorities remain separate, and no key is written beside the WAL.

`create_new` and `open_existing` take the caller's ONE `ParticipantQuota`. They
internally open `JointDepot` and the concrete keyless `JointHistory` from that
quota's actual depot budget. No unrelated History, generic verifier, second store
or independent ledger can be supplied. The canonical WAL path is
`control/<sha256(VaultProfile,binding,recordID)>.wal`; its own exclusive file lock
is held through replay and the complete handle lifetime. This also excludes a
second opener using the same already-open quota. Ingress clones retain the same
depot/root ownership; drop every descendant before independently reopening the
namespace. A dedicated client-private quota root is local custody, not a claim
that a peer participant owns those secrets or that separate roots share one
physical-disk limit.

The old participant profile, control filename grammar, 256 MiB CONTROL ceiling
and independent total capacity stay unchanged. The NEW Vault profile additionally
limits a Control Body to 64 KiB, a record to 1 MiB, the file to 16 MiB and the log
to 128 records. Public replay accepts at most 128 entries and a checked 16 MiB
aggregate of original Body/QC/header metadata. Reaching a cap refuses new work;
there is no truncation, reset, repair, migration or compaction fallback. These
local bounds do not revise existing 32 MiB Journal Body/proof or transport caps.

`create_new` replays actual signed Bodies and weighted QCs, obtains a sealed
historical Active predecessor, checks the supplied bank's complete original
stamp, then reloads the real Source/Table/all four RowIDs and reopens Cenroll and
Creg before writing Idle. `open_existing` authenticates every complete record and
repeats these checks. It reconstructs parents only from actual History replay;
an AEAD-authenticated head cannot construct a `VerifiedJointParent`. The host
holds its existing native ProofGate around construction/replay, preparation,
candidate preflight and completion. This owner creates no second gate and makes
no RPC under History/depot locks.

The observable sequence is:

1. `cursor()` observes generation, pendingID and the exact last ciphertext-record
   digest. Every phase-changing operation requires that complete CAS value.
2. `prepare_control` restores the private Idle bank against real Source, runs the
   existing genuine Source/Life/Kind producer, retains its public premises in the
   same depot, and returns public request/manifest data for owner signing. The
   private draft has no submission API and is not persisted yet.
3. `seal_body` checks the original owner-signed canonical Header/Body with the
   fixed `JointHistory::check_control_candidate`. That method rechecks own
   context/manifest and the actual Source/Life/Kind proofs; it returns only `()`
   and neither imports nor issues a receipt. The Vault precharges the exact
   append **and** a complete 1 MiB terminal allowance before writing BodyPrepared.
   Only after complete file sync can `submission` expose that exact candidate.
4. `submission` returns the saved Header/Body without signing, proving, stepping,
   encrypting again or choosing a fresh nonce. BodyPrepared always becomes
   SubmittedUnknown on reopen. No persisted marker claims whether a send happened.
5. `complete_control` restores the exact private candidate and calls real
   `apply_control` plus consuming private completion. It atomically transfers
   reserved bytes into the existing file charge, writes/syncs the next bank and
   outcome, then returns Completed. `acknowledge` appends Idle with the same bank;
   the prior completed record remains intact. A failure after History advanced
   poisons the owner, so no unstored outcome can escape.

The hash-chained, versioned XChaCha20Poly1305 log binds the distinct role/profile,
full binding ID and record identity in associated data, and each record includes
sequence, prior digest, random nonce and bounded exact lengths. The pending
snapshot retains the preceding private Idle and generation under that same
chain, so the candidate cannot be relabelled to another old bank. All explicit
private Registry/controllers/salts/command buffers and AEAD plaintext use guarded
storage. Caller copies, stack moves, reallocations, primitive-field traces and
cryptographic/SDK scratch are outside the clearing claim.

Quota reservations are not persisted. Pending reopen must acquire the complete
terminal allowance again before returning a usable handle. Other already-held
quota capabilities can consume capacity first; that is an availability refusal,
not evidence of a durable reservation. `grow_reserved` transfers only the delta
under one ledger lock without a release/recharge window. The append position is
checked after precharge. `ByteBudget::require_live` observes shared poison without
allocating a slot: an existing terminal lease remains usable when all other
reservation slots are occupied. A partial write, failed sync or lost sync
acknowledgement retains all uncertain charges, poisons the shared ledger and
requires strict fresh namespace replay. No same-handle retry or shrink follows
uncertain I/O.

An exact already-finalized pending target is allowed only through full latest
`apply_control`/private-opening replay against the original saved predecessor.
A genuinely newer or different head without a matching saved private bank yields
`RecoveryRequired`, not the old bank. Knowing no later checkpoint is not a
freshness proof. File fsync is performed before publication; directory sync is
performed only on Unix, matching the existing storage qualification. On Windows
it is a no-op, so directory-entry survival across power loss is not claimed.
Missing files and corrupt/torn tails reject existing-only open.

The five owning tests use real Source/Life/Kind and local genuine weighted QCs,
not fake verifier results. They cover BEGIN→End, fresh reopen/exact retry and
already-finalized retry, CAS/double opens, full reservation slots, valid-AEAD false
bank, unauthorized Body/damaged Kind, lost Body/Completion sync ACKs, before-write
and partial-write faults, quota refusal on terminal-lease recreation, and a real
unsaved successor. They are not OS-network tests or evidence of current-lock/SQL
admission.

The executed owning validation command is:

```powershell
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::vault::durable::tests:: -- --nocapture --test-threads=1
```
