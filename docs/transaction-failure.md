# Failed transaction frames in public control state

`transaction-state` now models an unfinished frame as Active or Failed. The
authenticated `FailCurrent` action releases only its own lock events after the
current savepoint cut (all its events when no savepoint exists), preserving older
lock strengths and other owners. Failure of a parent also releases acquisitions
from children already joined by RELEASE. No failure history or tombstone grows.

Failed frames reject acquisition, SAVEPOINT, RELEASE and repeated failure intent.
ROLLBACK TO restores Active at the selected cut; END releases ownership and a
Commit intent in a failed frame produces the actual Abort outcome. Duplicate
savepoint names continue to shadow older ones. Rejected commands, invalid
authentication/revision/sequence and WAIT/NOWAIT conflicts leave the complete
original state unchanged; they do not implicitly classify a SQL statement error.

The state, intent, profile, authorization, metadata head and application domains
advance together to v2. Status is a canonical byte, and Failed states cannot
retain post-cut events. Unknown tags and v1 formats reject without migration.
`MetadataVerifier` still cannot authorize any encrypted data update.

This is bounded, branch-local public control metadata, not a live SQL transaction
or final lock grant. It neither proves SQL failure nor rolls back encrypted data.
MVCC, read-your-writes, complete private candidate proofs, data/control composition,
privacy policy, durable owner recovery and an agreed-state finality/failure model
remain required. Live SQL locking syntax still rejects. See the
[PostgreSQL contract](postgresql-contract.md) and the
[module contract](../crates/transaction-state/README.md).

## Verification

On Windows MSVC Rust/Cargo 1.99.0, release, locked/offline, with two Cargo
jobs and Rayon workers and `-C target-cpu=native`, all 37 owning tests passed:
14 control, 12 journal and 11 lifecycle tests. There were no failures, ignored
tests or filtered tests. Strict all-target Clippy for transaction-state and
version-journal passed with warnings denied. Formatting, requirement mirror
and local documentation links also passed.

The integrated seven source files and 21 owning controls were checked before
and after execution. Their canonical source matches the independently reviewed
donor; integration changed only line endings. All previous 23 tests were
retained and the 14 new cases executed. The existing pagination target was
reused; its previous binary evidence remains preserved. Subsequent publication
edits change only documentation. No FHE query or performance run was added.

The tests include immediate frame release, upgrade restoration, nested RELEASE,
duplicate names, failed command atomicity, capacity exhaustion, canonical status
and v1 rejection, real controller signatures, tampered status/request/data heads,
replay and actual durable journal reopen with savepoint recovery. An old-head
mutation rejects during candidate construction; independently signed status,
request and extra data mutations reach import and reject there. These are control
tests, not FHE query-performance or SQL-completeness measurements.

The reviewed source-only donor had one narrow test correction before native
validation: the old-head negative must assert the earlier InvalidTransition
instead of unwrapping candidate construction. Production code was unchanged by
that correction. Both donor snapshots remain preserved locally.

Local immutable evidence (generated logs and outputs remain ignored):

| Record | SHA-256 |
| --- | --- |
| Reviewed donor manifest | `AD57654DA1AB6A274F68BC718D5ABB961927F441C30FB69F8E78DA0C82D6AEE2` |
| Reviewed donor patch | `A95413087A4B194C9BB5C738BC096F95478A825A7683481657620C963ABD8FF0` |
| Integrated source manifest | `BCF1C0BF4B36E21ADE99A0D96C3FB0E488071877E345A66F46C008FC7FCB076A` |
| Native validation receipt | `6700BAB3B1FF6CEB235BFB5A28C5693464CE64ABAD46FB074E4A26C2E5DDE1EC` |

## Reproduction

```powershell
cargo test --release --locked --offline -p transaction-state --all-targets -- --test-threads=1
cargo clippy --release --locked --offline -p transaction-state -p version-journal --all-targets -- -D warnings
```

The lockfile and cryptographic dependencies are unchanged. These correctness
runs establish neither a 500 ms query bound nor a whole-process RAM bound.
