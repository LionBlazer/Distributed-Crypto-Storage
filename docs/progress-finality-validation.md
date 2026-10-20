# Registry208 finality validation

The new `registry200_finality::progress` boundary passed its owning native gate
on 2026-10-20. It binds the actual closed Registry208 application to weighted
decisions and strict durable replay. It supplies historical operation finality;
it does not install a private owner bank, establish the newest network head or
grant a live SQL lock.

## Application and own-operation binding

The independent Binding includes the complete new application Descriptor and
SetupClaim, Work/Journal Genesis and Rules selected before mining tickets. New
candidate, checkpoint, storage and seed domains reject legacy values. Existing
Original and Joint public APIs, formats and algorithm identities are preserved.

`OperationExpectation` retains independently supplied Context, parent, slot,
previous DecisionId, request, manifest and exact owner-signed Body. A fresh
`History::apply_operation` compares these before QC verification, application
proof work or import. A move-only `VerifiedOperation` is produced only after
actual application/QC verification and ancestry-floor publication. Generic
Empty blocks cannot produce this receipt. A latest retry rechecks its actual
historical before-context and proofs; no saved checked flag grants authority.

The private durable engine pairs each Joint or Progress Binding with its fixed
actual verifier. Both typed public owners share this implementation. It keeps
one actual storage/depot ledger and the host-owned ProofGate. The ordering is
Journal validation and append sync, signer decision sync, exact floor sync and
installation, then next-slot signer advance. Uncertain owned I/O poisons the
owner and shared ledger while retaining charges. Cold reopen fully verifies
proofs, QCs and WAL output; malformed or missing files are not repaired.

## Checks and observed time

| Gate | Result | Test body | Complete command |
| --- | --- | ---: | ---: |
| Finality library, original/Joint/Progress | 26 passed, none ignored | 240.36 s | 391.040 s |
| Ownership/privacy compile-fail examples | 21 passed | 2.49 s | 5.696 s |
| Existing TLS actor cases | 6 passed | 19.39 s | 41.034 s |
| Finality/runtime/daemon/client all-target Clippy | passed, warnings denied | n/a | 8.390 s |

The library command includes a 2m29s rebuild; the actor command includes a
21.46s rebuild. These are complete observations of different gates, not a
before/after query benchmark. The 26 cases include ten Original adapter cases,
five Joint history/mining cases, eight shared-engine cases and three new
Progress cases. They share bounded public setup and one actual Key proof;
no private live SDK Owner is retained globally.

The cryptographic positives use real Source, legacy Lifecycle/Link, new
Bootstrap803/Control815 proofs and genuine three-key local QCs under a real
four-key Work roster. Rejections cover independent Body/request/context/parent
association, corrupt signatures with the same otherwise canonical checkpoint,
missing or corrupt premises, and a genuine Control child paired with a
hash-valid non-proof Source. Failed own-operation attempts preserve Journal
count, charges, head, floor and candidate presence before an honest retry.
EmptyPending bootstrapping follows a genuinely finalized successor.

Recovery cases cover lost floor acknowledgment, partial floor writes, refusal
after floor publication, missing/corrupt records, quota refusal, strict reopen
and one-use same-drive handoff destruction on error, Drop and unwind. Torn files
remain byte-for-byte unchanged. Original assertions remain in the shared-engine
tests. Recovery intentionally repeats full verification across its trust boundary.

An early Clippy run rejected two different-sized installed verifier variants;
both now own their concrete verifier through `Box`. Test-only Manifest copies
use the existing canonical codec. After the 26-case pass, consumer Clippy found
the same size issue in the private runtime owner enum. Both existing owner
variants are boxed at construction. Dispatch, commands, limits and deadlines
are unchanged; strict consumer Clippy and the affected actor tests then passed.
Failed attempts are retained as failures. Already-passed finality cases were
not repeated for this mechanical runtime allocation change.

The six TLS cases exercise actual socket I/O between existing Original Empty
actors in the test process: canonical terminal framing, bounded queue/body
ownership, independent pins, two partitions, healing, offline catch-up and
concurrent relays. They do not establish Progress transport or four independent
peer-process execution. No full FHE evaluator/input16/output118 runs in this
26-case finality group. The separately executed
[Progress application gate](progress-application-validation.md) covers local
genuine full FHE composition without a QC.

## Reproducibility and limits

```sh
cargo test --release --offline --locked -p registry200-finality --lib -- --test-threads=1
cargo test --release --offline --locked -p registry200-finality --doc -- --test-threads=1
cargo clippy --release --offline --locked -p registry200-finality -p peer-runtime -p dcs-peer -p storage-client --all-targets -- -D warnings
cargo test --release --offline --locked -p peer-runtime --lib finality::tests:: -- --test-threads=1
```

The gates used release/offline/locked Rust 1.99 MSVC, host-native code generation,
two Cargo jobs and two requested Rayon threads. The unchanged 1792 MiB per-PID
soft fuse and 1800-second whole-command budget did not fire. The maximum sampled
and OS-peak working set in the 26-case group was 1056133120 bytes; maximum private
bytes were 1077350400, with a largest sample gap of 715.793 ms. These are fixture
observations, not a proof of the complete peer's resource bound.

Both native receipts cover 1661 unchanged files during their own command batch.
The r3 to r4 source delta contains only the two runtime boxing files. Subsequent
edits update module documentation and two module comments. Full result,
stdout/stderr, CPU and memory hashes are in the local validation profile:
`.local/progress-finality-validation-r1/profile.json`, SHA-256
`F1D14921C1C178DAFDE78C8CB66086B750E1D52F6677D03B236B364532B35CEE`.

| Receipt | SHA-256 |
| --- | --- |
| r3 source | `779B87CA336ED77C9F8C426A8B6B965FC29C294DC0946A3F35648C72B4571038` |
| r3 unchanged after | `48FCE1626745BBB7F15BA150DE49B3FEBE9819A49F53A80DACD8203A51C55BF6` |
| r4 source | `0E1952BE67EFD3A3EBC77503E751A513D1CC1E75170E3708A22FFEFB79727DDE` |
| r4 unchanged after | `AEECFFB3291873D58F1EA57AD9C57E3EDF96F6D09F75DE13790BE0C812CC6563` |

The safety premise remains less than one third malicious activated compute
weight and non-rollback honest durable signing. Proof of work does not establish
that premise or permissionless admission. New-G full Predicate finality, actual
Progress peer transport/process consensus, durable State208/Result160 owner
completion, parked WAIT continuation, freshness policy, mutable EPQ, Session
integration and complete PostgreSQL behavior remain separate unfinished work.
