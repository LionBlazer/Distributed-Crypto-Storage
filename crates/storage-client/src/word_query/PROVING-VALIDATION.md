# Joined native Word and Query proving

The later [verification comparison](../../../registry200-proof/src/registry_progress/word/read/VERIFICATION-VALIDATION.md)
keeps this joined production as its control and measures independent Word/Query
verification in the same local prepared-query interval.

## Change and owning checks

`PreparedPublicQuery::prove` moves its two independent protected inputs into
`p3_maybe_rayon::prelude::join`. Word and fused Query use the same native Rayon
pool already used by their backends; no second worker pool is created. The
original encrypted input stays outside both closures. Both branches finish
before either Result is handled, with the previous Word-first error priority.
Each backend still obtains independent fresh OS randomness for its native proof.
No witness clone, retry, proof reuse, equation, sampler, verification decision,
wire format or SQL admission changed.

The optional word-query feature directly names the already pinned P3 0.8.0
scheduler with parallel support. Default storage-client compilation does not
enable this optional dependency. The scheduler may execute serially in a
one-worker pool; simultaneous execution is not part of the API contract.

Every measured process ran the same five owning word_query scenarios. They
include actual Source/Role3/DATA/Word/fused Query arguments, the SDK FHE product
and certificate, independent native verification, the complete 4096-coefficient
oracle, corrupted frames, mixed suites, foreign endpoints, replay, fresh entropy,
single-use inputs and prepared-input drop. Their assertions were unchanged.
All six alternating captures passed without faults or forced cleanup.
The ten client compile-fail examples, release all-target Clippy with word-query,
default client all-target compilation, formatting and requirements mirror checks
also passed. No distributed transport boundary changed in this scheduling step.

## Alternating local measurements, 2026-10-23

The measured interval is the same local prepared-query interval defined in
[PREPARATION-VALIDATION.md](PREPARATION-VALIDATION.md): private Query preparation,
actual SDK product/certificate, complete receiving expectation construction,
public receiving setup overlapped with proving, both fresh native proofs,
retained-DATA receiving and owner completion/decryption. It excludes prior SQL
compilation/current-state witness synthesis, original query encryption, role-only
producer setup and immutable Source/Role3/DATA installation. It contains no
network, fresh weighted agreement or final lock grant.

The baseline already overlaps public receiving setup with proving, but produces
Word and Query sequentially. Only the new image joins these two proof jobs.
Runs alternated new/old/new/old/new/old, with RAYON_NUM_THREADS=8, one test at a
time, and no simultaneous heavy build or test.

| Capture | Word/Query scheduling | Local interval ms | Native proving ms |
| --- | --- | ---: | ---: |
| r650 | joined | 450.698 | 327.588 |
| r651 | sequential | 557.148 | 422.984 |
| r652 | joined | 492.432 | 349.567 |
| r653 | sequential | 542.664 | 402.615 |
| r654 | joined | 508.345 | 363.523 |
| r655 | sequential | 506.926 | 374.095 |

Sequential min/median/max were 506.926 / 542.664 / 557.148 ms; joined values were
450.698 / 492.432 / 508.345 ms. The observed median reduction is 50.232 ms (9.3%)
in this short series. Native proving medians were 402.615 and 349.567 ms. This is
not an isolated cryptographic speedup: public setup competes for the same workers
and its duration also changes. The last joined run was slower than its adjacent
sequential run. Neither a stable acceleration nor a 500 ms bound is established.

The full SQL/FOR UPDATE target remains unmet. In particular, a sub-500 ms local
sample cannot supply the missing network, freshness, finality, locking or composed
cryptographic security guarantees. Predicate admission remains closed.

## Resource and source provenance

Windows/MSVC Rust 1.99.0, release opt-level3, native CPU, locked/offline dependencies
and Cargo jobs2 were retained. The reported CPU is AMD Ryzen 9 9950X3D2 with 16
physical cores/32 logical processors; no affinity was imposed.

The sequential r645 image was validated at r646 and frozen before rebuilding.
It was built from baseline c378826f878aefbd2f501b508d668a092fe4a320 and is explicitly
historical, not a build of the joined source. Its original source hash map and
native receipt are archived separately from current observer workspace hashes.

| Image | Bytes | SHA256 |
| --- | ---: | --- |
| r645 sequential | 28,635,648 | `4389A78E753EDED47821CEC51097F158AE32F85C4A51D20B1DD3629E787F8662` |
| r649 joined | 28,657,664 | `D649105E0A77DD7F579392A47F058EFD0E33D656E9CE40435F5AA99256D3A898` |

Each observer pinned the exact image, five-case contract and source provenance,
held the directly launched process handle/image/creation identity, and retained
120 s /1792 MiB whole-process fuses with 20 ms sampling. Sequential/joined maximum
OS working sets were 713,023,488 /714,706,944 bytes; sampled private-byte peaks
were 730,017,792 /732,688,384 bytes. Each process exited0 normally.

These observations bound only the measured isolated process. Separate per-proof
allocation checks do not establish a composed bound for overlapping proof jobs,
receiving setup and a production peer. Callers must budget the complete process.

Generated receipts, proof packets and executable archives remain outside Git.
The six receipts under
`.local/word-cmd-native-rNNN-storage-client-observe-tests/result.json` have hashes:

| Capture | Receipt SHA256 |
| --- | --- |
| r650 | `2EDA0B232DD6274FE3DE36157DB26965A4B3525437F1E72CB2A24CB17BB5BBBD` |
| r651 | `F7B3A722F45F7E3087270EEC07DACD42AE695E5FA21EF35789C05D53C570BD72` |
| r652 | `E8B2490DE54B77E6720949EB8458A4F0079CCA4781842495278B28BCFA229174` |
| r653 | `4EC4A7BF408D8037985BAF4E60E462A2F1CA1310391396271A5E5C7789D4A444` |
| r654 | `83C5197282C09F88CDCB37F4013DDFEB2FE2DFAF78B3843B57422CF1FA7FAD78` |
| r655 | `77F521FF52776859EA14F6BABA23CCB48A511CB70DA796807BB6DFA6DB7E0288` |

Reproduce the owning behavior and relevant checks using the stated environment:

```powershell
cargo test --release --locked -p storage-client --features word-query --lib word_query:: -- --nocapture --test-threads=1
cargo test --release --locked -p storage-client --features word-query --doc word_query -- --test-threads=1
cargo clippy --release --locked -p storage-client --features word-query --all-targets -- -D warnings
cargo check --release --locked -p storage-client --all-targets
cargo test --release --locked -p repository-contracts --test requirements_sync
```
