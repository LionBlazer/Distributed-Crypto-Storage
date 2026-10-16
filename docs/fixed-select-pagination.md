# Fixed-record PostgreSQL row windows

The fixed-record prototype now represents row pagination explicitly as
`sql_plan::RowWindow { offset, limit }`. It supports integer/NULL OFFSET and
integer/ALL/NULL LIMIT, once each, in either order. NULL OFFSET means zero;
ALL/NULL LIMIT means unbounded. Signed literals must be nonnegative and fit
both PostgreSQL bigint and the platform usize. Unsupported expressions, FETCH,
aggregate pagination and duplicate clauses reject during complete parsing.
These are the relevant [PostgreSQL LIMIT/OFFSET semantics](https://www.postgresql.org/docs/18/queries-limit.html).

## Computation boundary

For a finite limit, each shard retains and proves its first K matches, where
K=OFFSET+LIMIT uses checked addition. A later local row cannot precede the first
K global rows because K earlier rows from the same shard already precede it.
The client joins the checked shard results by the existing global ordinal,
then applies OFFSET and LIMIT exactly once. Per-shard OFFSET would be incorrect.
Without ORDER BY this is the prototype's stable implementation order, not an
ordering guarantee added to PostgreSQL.

For every shard, the owner still authenticates the complete matching source,
verifies the peer's genuine BFV arithmetic proof and performs the existing final
freshness/exact-head checks before result completion. LIMIT0 uses a zero retained
prefix without evaluating OFFSET+LIMIT; it does not skip source authentication,
proof or freshness. An
unbounded window retains the complete matching set. Each retained local prefix
must fit the existing 256-row FHE geometry. Larger prefixes reject rather than
clamp, even when the final window would contain only one row.

The value is an owner-side plan, without a new serialized representation.
The BFV arithmetic relation, RPC/application/journal/profile formats, static
ReadImage shape and source validators remain unchanged. Offset zero follows the
previous prefix preparation. Historical Lab tests apply the window after their
complete encrypted projection. The historical unverified `Database::execute`
rejects nonzero OFFSET before I/O and continues to reject unproved results.
The live GUI gains no in-process fallback.

This remains an owner-assisted prototype: the owner selects plaintext originals
and prepares fresh encrypted operands. Its arithmetic proof does not independently
prove source-selection-formation or the complete composition. This change does
not establish peer-only SQL computation, production acceptance, private locks,
MVCC, agreed-state finality, whole-process resource bounds or the 500 ms target.
Full PostgreSQL remains the objective; the fixed-record grammar is still partial.

## Verification

Windows MSVC Rust/Cargo1.99.0, release, native CPU flags, two Cargo jobs and two
owner/peer Rayon threads. Dependencies remained locked/offline. The selected
packages use the BFV experiment with default TFHE features disabled. A new target
preserved previous measured outputs. No external proof-kernel DLL was deployed;
the observed linked native CPU engine reports avx512. This is not a portable
baseline comparison. These are correctness runs, not performance comparisons.

Release dcs-peer build, compilation of SQL/client/peer and GUI tests, and strict
all-target Clippy for the four affected packages passed. The source was frozen
before compilation: 19 task paths, 285 owning controls and 44 provenance inputs.
The only integration delta from the reviewed donor was the parser's supported
grammar error text. Executable parser behavior and all other donor Rust remained
unchanged. Existing modified-file test names were preserved.

Actual functional results: 60 parser/client tests; 52 actual-process peer
tests; seven historical SQL-row tests and one requirements-sync test; three
exact compact-query source/proof regressions. All 123 executed tests passed.
The one ignored test is the existing sparse-million-row aggregate measurement,
which requires a separate quiet performance run. No new test was ignored.

The peer test process itself exited successfully with 52 passed and one
ignored in 137.52 seconds. The first evidence parser incorrectly required
the test name and terminal `ok` on the same line; inherited child diagnostics
separated them. A corrected serial parser ties every start to exactly one
terminal status and reconciles the complete libtest counts. An evidence-only
recovery rechecked the original output, exit status, all three new named
tests, frozen sources and binary snapshots. No native test or proof was
rerun for this correction. The original failed observer receipt is retained.

The actual-process cases use public nonsecret fixtures and independent OS peers.
Uneven interleaved shards with more than 256 local matches prove the global
windows (1,3), (100,100), (128,128) and (1000,0). A required 257-row local prefix
rejects before a proof despite a one-row final result. ALL/NULL/end/empty windows
require both shard replies; cancellation after a real proof refuses completion
and permits the same query after recovery. The existing static-shape test also
checks OFFSET2/LIMIT1 and OFFSET1000000/LIMIT0.

Separate source-boundary regressions check a corrupt later posting under
LIMIT0, wrong-prefix evidence, forged results and old heads/replayed proofs.
GUI row-window cases belong to the historical Lab boundary; they are not counted
as independent process tests. The repository requirements-sync test compares the
canonical requirements and AGENTS mirror after line-ending normalization.

Each command records actual argv, output, exit status and per-suite result counts.
Required new tests must appear as actual PASS lines; a zero-test filter cannot
satisfy a gate. Sources/provenance are checked before and after each command.
Owned EXEs are retained before later Cargo invocations, so feature-unification
rebuilds are disclosed without replacing earlier binary evidence. Logs, PE
snapshots, ephemeral peer state and generated keys remain ignored, not committed.
No query latency or RAM measurement was made in this change.

The local immutable evidence is identified below. Generated evidence and
binary snapshots remain ignored; these digests identify this run rather
than replace independent reproduction.

| Record | SHA-256 |
| --- | --- |
| Frozen source manifest | `6D823B176DBF423DE8736EFDE26915208F06F994F66C4E724068715ABB2B5492` |
| compile-success.json | `B2427DA04CE435FE7F2BA8D181E269F8D39EA456F86BBA4D8C5D63B4B85274A3` |
| functional/20261016-221217-346-parserClient/success.json | `F8D281290733330B5762D58956F0FD76CBA18C51B579924B5956488209CD3953` |
| functional/20261016-222130-200-peers-evidence-recovery/success.json | `6432CC0B927DB372C6FEFE50599CFBE70531026997E34325E9578206C6D210FA` |
| functional/20261016-222136-456-playground/success.json | `A9EF55FE796AC671DFCF96541CCF3A25DDA6C75A1EE64E3FC02520693F18B717` |
| functional/20261016-222145-016-sourceGuards/success.json | `8A6DFD4A36619DE30B3DC3EE53382855DF44EEF3E7035A5838E0DD91A4ECC136` |

## Reproduction

From the repository root with the pinned environment above:

```powershell
cargo build --release --locked --offline -p dcs-peer --no-default-features --features compact-query/bfv-experiment
cargo test --release --locked --offline -p sql-plan -p storage-client --no-default-features --features compact-query/bfv-experiment -- --test-threads=1
cargo test --release --locked --offline -p dcs-peer --test proved_sql --no-default-features --features compact-query/bfv-experiment -- --test-threads=1
cargo test --release --locked --offline -p fhe-playground --test sql_rows --test requirements_sync --no-default-features --features compact-query/bfv-experiment -- --test-threads=1
```

The three exact compact-query regressions use `--no-default-features --features
compact-query/bfv-experiment`: the library's
`index::tests::discontinuous_later_bucket_corruption_is_not_hidden_by_union_or_zero_limit`
and the `proved_operations` tests
`limited_select_proves_the_ordered_prefix_and_empty_result_without_reusing_other_evidence`
and `old_heads_replayed_proofs_and_forged_results_cannot_complete_or_stage_changes`.
Run each with `--exact --test-threads=1`. The same four package selections also
passed `cargo clippy --release --locked --offline --all-targets` with the BFV
feature flags and `-- -D warnings`.
