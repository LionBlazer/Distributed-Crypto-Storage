# Fixed-source statement progress validation

The new `registry200-proof::registry_progress` module implements and verifies
separate Bootstrap803, Control815 and Predicate896 hiding proof relations. On
2026-10-20 its five model tests, nine cryptographic tests and three ownership
compile-fail examples passed. This record does not establish SQL/network
admission, a finalized lock, a current lease or a complete PostgreSQL engine.

## Behavior proved at this boundary

The fixed relation uses four authenticated Source rows, two transaction slots,
Registry208, Statement96, Progress48 and Result160. Source and full PrivateMask
Encoding prerequisites are genuinely verified on each call. Individual backend
security assessment, bounded proof encoding, self-verification and independent
verification run through the actual frontends. The public mathematical Key33
labels in these Core fixtures do not substitute for a Key/Formation proof or an
FHE evaluation; those remain application prerequisites.

- `SKIP LOCKED` skips conflicts before OFFSET and acquires unlocked matching rows
  consumed by OFFSET. LIMIT ends the walk without an extra lock; LIMIT zero
  performs no search.
- WAIT keeps the acquired/upgraded prefix, original Statement and cursor in a
  committed Progress opening. Another transaction's proved End preserves that
  progress through slot compaction by stable transaction ID.
- Resume keeps the original mask, options, call and statement association while
  accepting a fresh query context, Source opening and blinded Encoding identity.
  A genuine foreign mask and changed original options are rejected. Cursor zero
  is explicitly covered.
- NOWAIT requires a real conflict and proves the failed/savepoint state. An
  invented failure, changed prefix, missing progress, unrelated parked control,
  substituted Start identity and repaired roots/checkpoints do not become valid
  proofs.

No legacy Source/Lifecycle/Encoding profile or wire is reinterpreted. A separate
regression confirmed the original three profile bytes and geometry. Parked
RollbackTo/cancellation, deadlock handling, mutable-source EvalPlanQual and
general SQL remain unfinished.

## Executed commands and observations

Checks used release/offline/locked Rust 1.99 MSVC, host-native codegen, two Cargo
jobs and two requested Rayon threads. The existing 1792 MiB per-process soft
fuse and 1800-second whole-command budget were preserved; neither fired.

| Owning gate | Result | Test body | Whole command |
| --- | --- | ---: | ---: |
| New model cases | Five passed | Under 0.1 s | 0.492 s |
| Initial genuine SKIP cases | Two passed | 28.81 s | 29.341 s |
| All new cryptographic cases after iterator cleanup | Nine passed | 135.03 s | 174.753 s |
| Guarded witness ownership | Three compile-fail examples passed | 0.46 s | 36.826 s |
| Legacy profile/geometry regression | One passed | Under 0.1 s | 0.528 s |
| Strict Clippy, both affected packages/all targets | Passed | N/A | 0.743 s |

The final cryptographic process's maximum sampled working set and OS peak were
1032368128 bytes; maximum private bytes were 1077559296. The largest observer
sampling gap was 545.934 ms. These observations cover these Core fixtures, not a
complete production peer or a formal maximum-memory bound.

```sh
cargo test --release --offline --locked -p registry200-proof --lib registry_progress::model_tests:: -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib registry_progress:: -- --test-threads=1 --skip registry_progress::model_tests::
cargo test --release --offline --locked -p registry200-proof --doc registry_progress:: -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib tests::original_three_profile_bytes_and_geometry_are_preserved -- --exact --test-threads=1
cargo clippy --release --offline --locked -p registry200-proof -p registry200-joint --all-targets -- -D warnings
```

Initial compilation found a guarded-array/slice coercion and test calls treating
infallible `Journal::PendingImport::commit` as a Result. The corrected compile
passed in 73.013 seconds. Strict Clippy then identified indexed loops, constant
chunk iteration and discarded validated arrays. The fixes preserve iteration
order, cells, constraints and salt validation. Both affected SKIP proofs were
repeated within the complete nine-case gate; failed attempts remain recorded as
failures. No native proof or security check was replaced with a simulated result.

## Reproducibility pins

The initial reviewed Core17 source packet is
`AA407A9379352363A9C925FFC805239588104B763A9590DDFD27B54918178421`;
its native compile/style fixes and formatting are included in the final source
receipt. The five-model/two-initial-SKIP gate's unchanged after receipt is
`BC1A60D5B6CA5A4A29A2DF408484DB97D2B093FC4CDDF5F8AE159CCD1F5E0EEA`.
The complete final batch covers 1642 unchanged source files, source receipt
`0F6B3912B6A56488DF3B67C6BD59ACA9A33037E9BBB70EE20ACF7C250FFCC705`,
after receipt
`2482DFEA0A76669698B11D99A062AA79104FA41E5300D94145D4D08DE2E29567`.
The subsequent unchanged-source legacy regression receipt is
`C3E6ABDF343267BAC66FDE806D88B18AD490104FC6B5A8ACC3A0413689C1ACA2`.

The final cryptographic stdout, stderr and CPU CSV SHA-256 values are:

```text
DB281011432819CE013D978AE23DEBBE3E3E19FEF3B991A6644EFDFFF46EB5FF
B0275A9250A0C7D273EF7E10AE8B1E04B272DF283F77A9A88BB28B18A792A88D
341366184C3EF9E98B4AC9B25FD2018192CCC1025D0143E84EA89C91AB2B0621
```

Local generated observations remain uncommitted under
`.local/private-peer-native-r1/joint-progress-crypto-r6/` and
`.local/joint-progress-native-r6/`. Documentation was updated after the tested
source freeze. The same batch also passed four preliminary new application
Bootstrap/Control/descriptor/store cases and two application privacy examples;
it did not run a positive new-application FHE input16/output118 Predicate case
or any new network/finality gate. The later positive FHE/application gate passed
as recorded in [its validation](progress-application-validation.md); new network
and finality integration remain unfinished.
