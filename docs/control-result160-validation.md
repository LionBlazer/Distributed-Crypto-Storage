# Private Control Result160 validation

The new owner-private Control opener passed its owning native gate on
2026-10-20. It checks a genuine transition's private mathematical result before
a future owner completion step. It does not accept a QC, install a bank, grant
a current lock or return SQL rows.

## Exact association and private ownership

`ControlOpeningContext` borrows independently retained Expected, exact Command,
revision, controllers, command salt and optional actor Progress. Construction
checks the actual Cmd160 builder and rejects the Predicate/Acquire/FailCurrent
lanes. The context itself remains unverified metadata.

`ControlResultOpening::open` consumes a zeroized private 160-field preimage and
requires the actual sealed `VerifiedStep`. It checks the complete independent
Expected, canonical field range before conversion, domain, context, old/next and
Result roots, operation, transaction, exact old/next actor Progress, fixed zero
fields and padding. Control status is Applied or End-only Aborted. A parked
actor's supported EndAbort binds its actual previous Progress commitment.
There is no unchecked constructor, raw array getter, Clone, Debug or serializer.

Control has no separate invocation/call cell; those fields are fixed zero.
Current intent is associated through complete Expected and Cmd160. A parked
original invocation is inside the exact previous Progress commitment. Complete
next State208 opening, independent signed Body/request/manifest/QC association,
freshness and atomic owner WAL completion remain separate mandatory boundaries.

The application adds one immutable `transition_step()` accessor. It borrows
the already verified actual Control or Predicate Step and returns None for
Bootstrap. It introduces no verifier selection, cached success bit or new
authority. No AIR, result builder, profile, wire format, cap, dependency or old
public API changed.

## Owning checks and observed time

| Gate | Result | Test body | Complete command |
| --- | --- | ---: | ---: |
| Core cryptographic progress cases | 9 passed, none ignored | 144.63 s | 196.505 s |
| Core privacy compile-fail examples | 7 passed | 2.72 s | 49.555 s |
| Ordinary Progress application cases | 4 passed, 1 explicitly ignored | 30.52 s | 37.747 s |
| Application privacy compile-fail examples | 2 passed | 0.33 s | 1.998 s |
| Both packages, all-target Clippy | passed, warnings denied | n/a | 5.097 s |

The command times total 290.902 seconds, including builds. The Core test and
Core doc-test commands rebuilt for 51.59 and 45.87 seconds respectively. These
are observations of this gate, not a before/after query-speed comparison.

Existing genuine Begin and normal End proofs now open their actual private
Result160. One additional actual Control proof reuses the same existing Source
to check parked EndAbort/status3 and the previous Progress. The original normal
End/compaction/fresh-blind-resume chain is retained. All 160 mutations and 160
noncanonical aliases reuse an actual proof. Wrong command, transaction,
controller, revision, salt, independently repaired foreign Expected and
altered/absent previous Progress reject. Actual Predicate proofs reject the
Control opener; actual Control proofs reject the Predicate opener. Application
cases check genuine Bootstrap None and Control Some through the new accessor.

The full FHE case remains explicitly ignored in this focused gate. Its new
typed-opening assertions were compiled, not executed. Its computation,
input16/output118 replay and fixed verifier are unchanged; only the existing
sealed Step accessor and already tested Predicate opener are used. The earlier
[full application validation](progress-application-validation.md) remains the
executed evidence for that composition. No new FHE, Source, Encoding, Key,
Basis, Formation or Bootstrap proof was added for this change.

```sh
cargo clippy --release --offline --locked -p registry200-proof -p registry200-joint --all-targets -- -D warnings
cargo test --release --offline --locked -p registry200-proof --lib registry_progress:: -- --test-threads=1 --skip registry_progress::model_tests::
cargo test --release --offline --locked -p registry200-proof --doc registry_progress:: -- --test-threads=1
cargo test --release --offline --locked -p registry200-joint --lib progress::tests:: -- --test-threads=1
cargo test --release --offline --locked -p registry200-joint --doc progress:: -- --test-threads=1
```

## Reproducibility and remaining integration

The gate used release/offline/locked Rust 1.99 MSVC, host-native code generation,
two Cargo jobs and two requested Rayon threads. The unchanged 1792 MiB per-PID
soft fuse and 1800-second whole-command budget did not fire. Maximum sampled
and OS-peak working set was 1036861440 bytes; maximum private bytes were
1083375616. The largest sample gap across commands was 869.381 ms. These are
bounded fixture observations, not a complete-peer resource guarantee.

All 1663 source files were unchanged through the native batch. Only module
documentation and this record changed afterwards. The source receipt SHA-256 is
`8C28E903441F903BBD496E945DAF898EFE280B818E596937ED64F19193B34362`;
the unchanged after receipt is
`77CC8CE7CC9750B7E249FB78CC80D72B6162070DE25602A7C5FF0E10728E4AD1`.
The complete local result/log/CPU/memory profile is
`.local/control-opening-validation-r1/profile.json`, SHA-256
`0173747DDCAF76216A606B1515D0C2D8E4975B955059C00DC53DBB1E9A97BF3B`.

The separate [Progress finality gate](progress-finality-validation.md) verifies
the local QC/durability boundary. Real Progress peer transport, State208 owner
completion, durable parked calls, network WAIT/resume, freshness policy,
cancellation/rollback/deadlock handling, mutable EPQ and complete PostgreSQL
execution remain unfinished integration. Neither opener can enable them.
