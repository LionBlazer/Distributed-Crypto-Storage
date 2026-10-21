# Full Formation AIR inspection, 2026-10-21 UTC

These checks execute the actual fixed AIR's public inventory and native symbolic,
lookup and numerical analysis. They do not build a private MAIN, commit PP, prove
Formation, verify a Formation proof or accept a DCS query. No full-query latency
improvement or 500 ms success follows. Application/GUI/peer/WAL/QC paths and old
cryptographic profiles remain unchanged.

## Executed gates

Rust 1.99.0/MSVC, release, `-C target-cpu=native`, two Cargo jobs and two Rayon
threads. Root alone ran Cargo; source reviewers ran no native work.

```sh
cargo clippy --release --offline --locked -p bfv-unrelinearized-certificate --all-targets -- -D warnings
cargo test --release --offline --locked -p bfv-unrelinearized-certificate -- --nocapture --test-threads=1
cargo build --release --offline --locked -p bfv-unrelinearized-certificate
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

After the build, Root directly ran the produced binary with
`--unverified-formation-air-plan` and `--show-profile`. The original public PIT
profile remained exactly `9d97f6eede741c9a179fc359d8b33f299720ab54576fbfe955f6192af65a5724fecbfad31bf8b4f7ba1d88c2d9aebcdcd2a2c925b0f9b838b71be1806b343bed`.
Root manifest/default members and Core sources are unchanged. Offline resolution
adds only pinned p3-batch-stark 0.8.0 and this experiment's consuming edges; no
existing package version changed.

All 25 owning tests passed in 0.57 s. Twenty existing SDK/arithmetic/hostile-graph
cases remain the separate owner-local oracle. The two new descriptor tests cover
all 4096 range/hash boundaries, 512 Cs words, exact first-stage bit reversal and
twist, four-consumer fanout, padding, changed literal nonce/request and actual
native symbolics. Geometry descriptors have no claims and fail the pair fence.
Three production-helper tests exercise exclusion of future banks from an earlier
peak, a later quotient peak and checked overflow. None is a proof-success test.

Final test compilation took 5.55 s; binary compilation took 5.71 s. The final
direct CLI helper took 0.062 s including genuine SDK fixture preparation, native
analysis, process startup and source guards. Those are development feedback
costs, not query/proving/verification latency. Strict Clippy, formatting, the
original profile and requirements mirror passed. No long network/recovery or
old cryptographic scenario was repeated for this isolated experimental boundary.

## Actual native shape

| Quantity | Derived value |
| --- | ---: |
| H / MAIN / PP / PV | 8192 / 512 / 272 / 36 |
| BASE / EXT constraints | 1588 / 46 |
| Domain-aware degree | 4 |
| Sizing / committed ZK quotient chunks | 4 / 8 |
| Original tuples / width / maximum count | 128 / 2 / 4 |
| Default packed lookups / AUX base width | 43 / 220 |
| Batched openings / weighted height | 1846 / 4194304 |
| Hiding budget / LogUp report | 404 / 296 bits |
| Conditional native UDR / LDR reports | 128 / 128 bits |

MAIN declares 13 next columns, but this SDK opens the full width at both points;
AUX also opens at both points. Counting only 13 would understate the proof.
Packing comes from actual original Lookups and native domain helpers. All original
messages enter the LogUp error term. Full aggregate and individual finite security
floors, committed chunk/rate consistency, multiplicity height, fresh private
configuration and hiding requirements are preserved. These reports are not a
lattice, composed security or whole-application theorem.

## Checked memory policy

The initial conservative calculation returned Resource at 2107375616 bytes above
the unchanged 1879048192-byte gate, before any PP or private MAIN allocation.
The final calculation uses the pinned SDK's actual sequential ownership phases.
It changes accounting, not real allocations or the memory limit.

Let P/M/A/Q/R denote PP, MAIN, AUX, quotient and random-codeword LDE banks. The
LDE envelope is max(2P, P+2M, P+M+2A, P+M+A+2Q, P+M+A+Q+2R, P+M+A+Q+R).
Two copies are conservatively reserved for the current bank; an owned dense
conversion may move storage while a borrowed conversion may copy it. Future banks
do not exist during earlier commits. Charging ALL banks plus an extra largest
MAIN combined incompatible phases. The full quotient bank is still doubled even
though native chunks can be transformed separately.

| Phase | LDE bytes charged |
| --- | ---: |
| PP | 570425344 |
| MAIN | 1369440256 |
| AUX | 1299185664 |
| Quotient | 1231028224 |
| Randomization | 1168113664 |
| Opening | 1157627904 |

Every original raw MAIN/PP/AUX, masked-bank, matrix salt, conservative tree and
FRI reserve remains. Their sum is 407633920 bytes. An additional 41943040-byte
opening reserve charges eight full EF5 vectors alongside FRI, covering denominator
and inverse inputs/results, adjusted weights, compression/reduction and small
opening/query containers. The final checked estimate is 1819017216 bytes, with
60030976 bytes below the original gate. It is a preallocation policy, not an RSS
measurement, process bound or permission to bypass a real cap failure.

The source evidence is p3-batch-stark 0.8.0 common.rs PP setup and prover.rs
MAIN/permutation/quotient/randomization ordering; p3-fri hiding_pcs.rs and
two_adic_pcs.rs borrowed quotient/opening views; p3-dft's in-place LDE; p3-matrix's
owned/borrowed dense conversions; and MMCS/FRI ownership of leaf and folded banks.
Changing domains, batch geometry, concurrency, storage types or SDK requires
renewed accounting. Real allocator fragmentation, thread stacks, caller-retained
proofs/witnesses and baseline process state remain to be measured with the
unchanged held-process 1792 MiB fuse before any actual Formation result exists.

## Remaining boundary

Root removed four temporary heap allocations per AIR evaluation using fixed
arrays and copying each public value before assertion. Constraint/interactions
ordering and counts stayed unchanged. Compiler fixes were a missing AirBuilder
trait import, equivalent PP iterator/range idioms and placing tests after helpers.
The fixed Source9 and resource-only packets were independently source-reviewed;
local raw logs and snapshots remain uncommitted.

The actual consuming private builder/prover/codec and receiving verifier are still
absent. They must use the SAME already-scaled W and salts as genuine encoding,
the SAME bounded S and Cs salt, all coefficients and repaired internal-wire
negatives. This experiment's exact-request q cannot use SourceVersion's version
tag. Immutable-data amortization requires an explicit new typed contract plus
per-call hidden-mask/Formation/product/fresh-head/lock durability checks, never
cached old success or relabeled checkpoints. The complete DCS <=500 ms target
is not achieved by this inspection.
