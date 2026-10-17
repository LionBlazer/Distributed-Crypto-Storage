# Owner-authorized Registry200 Journal validation

Validated on Windows x86_64 MSVC with Rust 1.99.0 against parent
`84d380d36a6b103cf95197af9e30238fba2eab99`. The [experimental adapter](src/opening/registry_lifecycle/journal/README.md)
connects actual Registry200 proof bytes to the unchanged owner-authorized
[version-journal](../../crates/version-journal/README.md). It does not grant live SQL locks.

## Admission and ownership

Application binds the database/key domain, exact source/control shards, complete
immutable encrypted source heads, C_key and a fingerprint derived from actual wire
roles, profiles and byte/slot limits. It excludes genesis and per-command roots,
so Pending genesis has no commitment fixed point. New Pending/Active domains and
the exact canonical 2716-byte Request200 remain distinct from Registry112.

The real Journal checks the owner's strict Ed25519 signature over complete request,
update and proof bytes before calling PrivateVerifier. That verifier reconstructs
Expected from actual previous/next shard state and parent, exact request domain,
sticky enrollment and external C_old. The original Source-first SDK verifier
checks both mandatory proofs. The control CAS must exactly equal the verified
next root, preserve source heads and change the control state. There is no
plaintext state-machine execution in the acceptance path.

Owner preparation first matches the externally retained private opening and salt
to independently validated C_old, before building C_cmd or proving. The public
nonsecret fixture encrypts once and retains identical packets/source heads for all
commands. Host state-machine output supplies prover input and fixture assertions;
it does not authorize acceptance. Producer proof objects are dropped before the
Journal freshly decodes and verifies the emitted pair.

ValidatedParent means an exact known validated protocol parent. Client freshness
and confirmation are checked separately. Valid siblings can remain evidence under
their original parent; a proof cannot be reparented. A verified unchanged-root
WAIT/NOWAIT result cannot append. Failed Commit resolving to EndAbort3 does mutate
and append. Delegated controller signatures are not implemented.

## Executed gates

Release rustfmt checks, Clippy all targets with `-D warnings`, test and CLI builds
passed. Actual discovery listed **318** tests: all 304 previous declarations plus
14 new. Executed **70 leaf tests** (all 14 new and 56 prior controls), plus the
actual `requirements_sync` and `architecture` contract tests: **72 passed**.
The other **248 leaf bodies were not rerun**. Contract sources were compiled with
release rustc and the actual built serde_json/Cargo metadata, without a GUI build.

Owning tests exercise canonical request/control and complete Body bounds; private
opening mismatch; signature-before-callback; resigned request/proof/source/enrollment
and CAS tampering; every lifecycle operation; preserved upgrades and savepoint
recovery; genuine inter-owner sparse SKIP/OFFSET; genuine WAIT/NOWAIT proof
verification and durable rejection; failed Commit→Abort; transaction slot
compaction and ID non-reuse; original-parent siblings and reparent rejection;
durable reopen/duplicate retry; and atomic quota exhaustion.

All **32** security invocations passed the existing individual unique/list target
checks. The complete ordered JSON lists from all 31 old commands were exactly
equal to the prior wire validation. The new command's three full geometry
dictionaries match actual canonical Source/Bootstrap/Transition after excluding
only statement_case. Source W11521/PV691, Bootstrap W1082/PV104 and Transition
W6741/PV116 retain Q16. Individual targets do not establish composed 128-bit soundness.
No Cargo manifest, lockfile, dependency graph, requirement or production consumer changed.

The initial sandbox attempt passed rustc version discovery but rustfmt received
AccessDenied before Clippy or compilation. Its eleven evidence files are retained.
The successful attempt used the required access and a fresh build target with
byte-identical source; no source repair or relaxed validation was involved.
A subsequent sandboxed prove attempt returned generic Verification after 107.4808 ms
without a success report; its one observed-process CSV row and failure logs remain
retained. Its exact internal failure was not exposed. The successful runtime retry
used the identical compiled artifact with required access and a separate output
folder; the 45 successful observations below exclude that additional failed attempt.

## Actual durable lineage and replay

One normal prove command generated and owner-signed Bootstrap plus seven transitions,
appended every actual Body, checked EndAbort and final private state, appended an
empty confirmation block and resolved the locally confirmed mutation. It dropped
the durable journal before reopening and re-verifying all eight proof pairs.

| Index | Operation | Actual complete Body bytes |
| ---: | --- | ---: |
| 0 | Bootstrap | 21737887 |
| 1 | Begin | 30884399 |
| 2 | Savepoint | 30880655 |
| 3 | Acquire | 30884815 |
| 4 | RollbackTo | 30880015 |
| 5 | Release | 30881871 |
| 6 | FailCurrent | 30879983 |
| 7 | End (Commit intent → Abort) | 30883119 |

Genesis encoded bytes: **716**; empty Body: **9**.
Actual durable file length after reopen: **237915597 bytes**, independently
checked as `76 + genesis_bytes + sum(eight_body_bytes) + empty_bytes + 9*(192+36)`.
Each actual Body fits the unchanged 32 MiB cap. Durable bytes fit the unchanged
256 MiB quota. The existing DCSLFPW1 frame/profile/decoder policies remain unchanged.

Full owned-process elapsed was **75925.8489 ms**. The narrower timer,
after public fixture setup, covered proof generation, signed Body encoding,
durable append, local confirmation and complete reopen/replay:
**75828.0598 ms**. This is a local experimental lifecycle
and journal measurement, not encrypted peer SQL latency. No fixed latency threshold
is part of the goal; reasonable performance remains desired.

The quota test uses the same genuine transition Body, original parent and
quota-bearing genesis with distinct valid sibling headers, and verifies each
first accepted sibling through the real verifier. The serialized fixed-main
lower bound is 28,065,792 bytes per transition and 19,373,568 for Bootstrap:
Bootstrap plus nine transitions already exceeds 256 MiB before overhead.
It observes actual ResourceLimit within that bound and unchanged validated head,
accounting and disk after failure. It does not lower a postproof quota or assume
that empirical frontier sizes are fixed. Exact known block retry follows the
core idempotent path without re-verification or an additional record.

## Resource observations and reproduction

CPU: AMD Ryzen 9 9950X3D2 16-Core Processor, 16 cores/32 logical processors.
Build jobs and Rayon threads were two; `RUSTFLAGS=-C target-cpu=native`.
Cargo used `--release --locked --offline`, the standalone leaf, pinned offline cache
and fresh `.local/target-private-lifecycle-journal-r2`. The 213-package graph,
1236 old EXE/DLL artifacts, SDK and tool bytes were protected and unchanged.

The owned-PID observer covered 32 numerical, one full lineage/reopen and 12 filtered
test processes: **45 observations/8958 CSV rows**.
Largest observed OS peak/working set: **1264300032/
1264300032 bytes**; largest sampled private usage:
**1265991680 bytes**. Nominal sampling was 100 ms, with maximum
actual interval **111.1376 ms**. No sampled 1792 MiB soft
fuse or 1200-second per-process fuse fired. Compiler and contract processes were
outside this observer. These observations do not establish a whole-peer RAM bound,
hostile OOM recovery, distributed availability or an SQL latency guarantee.

The fixture streams proofs and drops temporary Bodies; test caching is restricted
to two public Bootstrap/Begin Bodies. It retains no long private proof history as
verification authority. Payload accounting, decoder slots, durable disk and process
RAM are different measurements.

From the standalone leaf:

```powershell
cargo run --release --locked --offline -- security private-lifecycle-journal
cargo run --release --locked --offline -- prove private-lifecycle-journal
```

Security mode emits three analytical reports and creates no trace, proof or append.
Focused tests use the compiled test executable with `--test-threads=1`: all new
journal tests, former wire/lifecycle/private-journal and prerequisite controls.
Local raw logs, artifact discovery, snapshots and memory CSVs remain under
`.local/private-lifecycle-journal-validation-r2`. Generated proofs, binaries,
operational owner keys and participant data are not committed. The fixed fixture
key seed is explicitly public and nonsecret.

Frozen source manifest SHA256: `B17F014F8B806B6E8854F2A21BE4961ECC280FD0AAD323FF482A787C01ABC4BA`.
Root executed-source SHA256: `95AB1ECF08E39DBA0CBA9C4A21FC04C99980B43C5B01008D22905377765052BB`.
Closed gate receipt SHA256: `94CE4AB6DBDC2834C6046E2C957C7587F341D7CC2E280C7E3AE5C6E3F63E4A0A`.

## Remaining requirements

The journal retains full historical Bodies under a 256 MiB quota. Unbounded useful
history needs a safe checkpoint/compaction protocol; raising quotas or discarding
proof history silently is not a solution. Durable reopen restores public heads and
proofs, not private owner openings/salts. Secure private-state persistence/recovery
remains open.

The adapter authorizes opaque private command commitments. It does not prove parsing
of arbitrary PostgreSQL text, controller possession/ACLs, BFV projected rows or
encrypted data commit/rollback. It adds no peer I/O, fresh agreed heads, live SQL
lock admission, MVCC/writer fences, complete SQL computation/completeness proofs,
decentralized finality or compact encrypted storage. The full PostgreSQL goal
remains active, including FOR UPDATE and SKIP LOCKED end to end.
