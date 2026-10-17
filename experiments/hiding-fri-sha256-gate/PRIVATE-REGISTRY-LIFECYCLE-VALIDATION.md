# Private Registry200 lifecycle validation

This is a validated experimental owner-witness relation for four canonical rows,
two live transactions and two savepoints per transaction. It proves an empty
bootstrap and seven private control operations: Begin, Acquire, FailCurrent,
Savepoint, RollbackTo, Release and End. It adds no live SQL acceptance or peer-only
FHE query execution. The [module contract](src/opening/registry_lifecycle/README.md)
defines the exact boundary. Existing Registry112, proof wire and Journal profiles
retain their earlier meanings.

## Source and build

The integration input was `5c7a4c834d5ddc8760fc3f149b31bcbdfd60adc7` on
`codex/feature/sql-latency`. Frozen SOURCE manifest `F7B4A85F68A551D0578341BA99C1C15D40177FAE9EF61836A52AE7DC2AFBB7BA`
and full patch `5DEB74CBE2336A0BC3FF53751515D83CBCB99776C975CC9BFCD29F1FC1BDBB98`
received two independent SOURCE reviews. The bundle has 21 task paths: seven
additive existing dispatch/profile/rejection seams and fourteen new module files.
Both requirements copies matched before implementation and after validation.

Root R1 stopped at sandboxed rustfmt with OS error 5 before Cargo. R2 reached the
compiler and found the generic `Val - AB::Var` type error. R3 fixed it with the
explicit constant-to-expression conversion, then retained twelve strict Clippy
findings. R4 uses ordered slice/enumerate loops, equivalent integer predicates,
a let-chain and an explicit seven-operation selector list, without lint suppression.
Independent SOURCE review confirmed the same equations, profiles and test bodies.
Failed logs, inputs and produced executables were retained in separate targets.

Executed native source receipt:
`F44022A231C5D65BD1A9648CD79558E7B47962DC60D77F250B3C815C892B73C3`.
All sixteen other task files, 969 tracked controls, 1,090 prior PE artifacts,
904 SDK anchors and five tools remained exact. Leaf/root Cargo manifests and locks
were unchanged; all 213 locked leaf package nodes were preserved. The build used
the pinned 1.99 toolchain, release CPU-native flags, Cargo jobs 2, Rayon threads 2,
and locked offline dependencies.

Rustfmt, release Clippy for all targets with `-D warnings`, test compilation and
CLI compilation passed. Actual test discovery listed 296 unignored tests: the
275 earlier cases plus 21 new cases. Discovery is distinct from execution below.

## Actual numerical gates

All 27 earlier CLI calls preserved their complete ordered JSON outputs. Both new
security aliases emitted canonical Source followed by the child without creating
a trace or proof. Source retained W11521, 28,949 constraints, degree 4 and quotient 16.
The new actual reports are:

| Primitive | Width | Public values | Constraints | Degree | Quotient chunks | Unique/list bits |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| registry-lifecycle-bootstrap | 1082 | 104 | 4996 | 3 | 16 | 128/128 |
| registry-lifecycle | 6741 | 116 | 26562 | 5 | 16 | 128/128 |

Each relation has height 512, 512 periodic columns, proof degree bits 10, 192 queries
and five random codewords. These are per-proof analytical bounds, without a composed
128-bit theorem. Transition raw trace, masked main trace and main LDE arrays are
27,611,136, 55,263,232 and 442,105,856 bytes; these arrays are not process RAM.

The six complete streams have 680+64+200+160+200+144 = 1,448 fields and 181 absorbs.
Source680 preserves its original fields and padding. Controller enrollment has a
distinct stable v2 profile; each u64 counter/ID uses independently ranged u32 limbs.

## Genuine proofs and observed process resources

Both normal CLI proof paths created and verified real Source+child proofs. The
lifecycle path first established a genuine empty Registry200 root, then proved
Begin with that exact old root. Actual Postcard component sizes and single-run
timings were:

| CLI primitive | Source bytes | Child bytes | Proving ms | Final pair verification ms | Observed whole CLI ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Bootstrap | 19298879 | 2428815 | 4171.0126 | 1061.2934 | 5630.9098 |
| Lifecycle Begin | 19296575 | 11580415 | 11153.973 | 1248.3752 | 12877.4132 |

The lifecycle proving timer includes its separate genuine bootstrap prerequisite;
final verification covers only the reported Source+Begin pair. Whole CLI observation
also includes fixture/setup and component serialization. These are owner-local
public nonsecret fixtures and single observations, without an application latency SLA.

There were 41 owned-process observations across numeric gates, proof
CLIs and serial test filters, totaling 3969 memory samples. Sampling was nominally
100ms; the largest recorded interval was 215.1105ms. The largest observed OS-peak
working-set value was 1095331840 bytes (1044.59 MiB). No sampled 1792 MiB or
1200s-per-child soft fuse fired. This does not establish a hard memory bound or
whole GUI/peer/FHE workload resource compliance.

## Executed behavior and failure boundaries

All 48 selected leaf tests passed: all 21 new cases and 27 existing controls.
The remaining 248 discovered bodies were not rerun in this stage.

| Serial test filter/control | Passed |
| --- | ---: |
| `private-lifecycle-owning` | 21 |
| `private-journal-control` | 12 |
| `wire-frame-boundary` | 2 |
| `bootstrap-wire-boundary` | 4 |
| `locking-wire-boundary` | 4 |
| `owning-control-0` | 1 |
| `owning-control-1` | 1 |
| `owning-control-2` | 1 |
| `owning-control-3` | 1 |
| `owning-control-4` | 1 |

The new owning tests compare nineteen commands with the independent public native
State, including all seven operations, actual selected/skipped candidate mapping,
sparse masks, OFFSET and real conflicting WAIT/NOWAIT. Genuine Source, bootstrap
and a ten-transition chain pass through the public composite verifier. A genuine
Bytes proof verifies under its own contract and fails the canonical prerequisite;
a genuine foreign enrollment child verifies under its own Expected and fails the
independently expected context. Missing Source is rejected.

Coherently rehashed attacks reach the original SDK proving/verification path for
false SKIP, stale command counters/controller words, incorrect principal, forbidden
Failed commands, newest duplicate targets, the eighth name word, Gold counter aliases,
foreign-state erasure, compacted snapshots, absent garbage, last Source RowId words
and padding mutations. Repaired positive controls isolate the intended constraints.
The native oracle is test-only; public verification never calls the owner model.

The actual `requirements_sync.rs` and `architecture.rs` test files also passed,
compiled with rustc against the pinned serde_json artifact where required. Architecture
used the actual locked offline workspace metadata. This was not a GUI test build.

## Reproduction and remaining obligations

From the standalone experiment, with the recorded CPU/Rayon/Cargo settings:

```powershell
cargo clippy --release --locked --offline --all-targets -- -D warnings
cargo test --release --locked --offline --no-run
cargo test --release --locked --offline opening::registry_lifecycle::tests:: -- --test-threads=1
cargo run --release --locked --offline -- security registry-lifecycle-bootstrap
cargo run --release --locked --offline -- security registry-lifecycle
cargo run --release --locked --offline -- prove registry-lifecycle-bootstrap
cargo run --release --locked --offline -- prove registry-lifecycle
```

Source receipt, compiler/numeric/CLI/test/contract logs and memory CSVs are retained
locally. The combined validation receipt is `A87697A602AACFA9E6FA9F9D6C95004C0F8B0AB0CE6999F9DE7501FA926B3A90`. Generated proofs,
logs, executable outputs and fixture state are not committed.

Registry200 has no old-wire or private-Journal admission path. The lifecycle transition
child and Source+transition pair exceed the old 5 MiB and 26 MiB caps; those contracts were preserved. A new typed wire
must measure actual complete signed Body encoding under the existing 32 MiB bound,
validate bounded canonical SDK decoding and preserve Source-first independent Expected.
Summing these two serialized components is not that emitter/Body validation.

Every command still needs independent owner authorization; enrollment does not
prove controller signature possession, delegation or ACL permission. Snapshot means
the control parent, without MVCC or encrypted data rollback/commit. Result144 is not
legacy Return168 and provides no original-value SQL tuples. Stable-state lineage,
fresh decentralized agreement, writer fencing, peer-only encrypted computation,
resource compliance and complete PostgreSQL remain separate unfinished obligations.
