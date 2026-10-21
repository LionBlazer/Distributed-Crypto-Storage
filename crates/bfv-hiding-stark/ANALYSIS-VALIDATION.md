# Single-collection symbolic assessment

Root validated this change on 2026-10-21 with Rust 1.99/MSVC, locked offline
dependencies and the original CPU policy (Cargo jobs=2, Rayon=2, no DCS
feasibility switches). It changes preparation of an assessment, not the proof
system, accepted statements, suite parameters or proof serialization.

## Change and security boundary

The pinned Plonky3 0.8.0 `StarkSecurityParams::from_air` constructs symbolic
constraints to count them, then constructs them again to compute the degree
with periodic columns. The private `CollectedAir` borrows the same immutable
AIR and collects its actual BASE and EXT vectors once. Both SDK passes receive
all those expressions unchanged. Every BaseAir method is forwarded, including
periodic data, both rotation lists, degree/count hints, Boolean reliance and
public boundary declarations. Existing metadata/hiding guards run before the
first collection. The SDK still owns the degree, quotient sizing, batching and
security calculations; their formulas are not reimplemented.

The view implements only symbolic evaluation for this assessment. Grouping
BASE then EXT preserves the SDK's separate vector counts and maximum degree;
using that grouping in a proof's alpha fold would change its equations. Actual
proving and native verification continue to use the original AIR, preserving
the original fold order. The vectors are dropped when `analyze` returns. There
is no public view constructor, new verification token, cross-claim cache or
caller-selected assessment shortcut. Deterministic equations/metadata for the
same immutable AIR remain the existing trusted-caller contract.

## Executed gates

From the repository root, under the policy above:

```sh
cargo clippy --release --offline --locked -p bfv-hiding-stark -p registry200-proof --all-targets -- -D warnings
cargo test --release --offline --locked -p bfv-hiding-stark --lib -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib two_lane_encoding::tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib two_lane_encoding::tests::actual_source_and_both_encoding_assessments_match_direct_sdk_parameters -- --exact --nocapture --test-threads=1
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

Strict all-target Clippy passed. The four engine tests passed in 0.06 s. They
include a genuine hiding proof and changed-public-value rejection, original
suite/shape checks, unsupported metadata rejection before symbolic allocation,
and differential assessment against the unchanged SDK. Six analytical cases
cover empty, BASE-only, EXT-only and interleaved equations; genuine nonbase
extension constants; periods 1/2/16/512; no degree hint, an undersized hint and
an overestimate. All 13 numeric SDK parameters, every grinding site, both
proof-derived bounds and reported shape agree. The original AIR is evaluated
exactly once per optimized assessment.

The nine existing two-lane Source/encoding proof and framing cases passed in
23.94 s under the held-process observer. They include one real original Source
proof, two honest child proofs, both genuine independent and joint byte
verification, repaired-context attacks and two malicious child proving attempts.
No tests were ignored. Nine old Source/admission/profile/wire cases then passed
in 0.42 s, and requirements synchronization passed. No production network or
recovery boundary changed, so those expensive gates were not repeated.

After that nine-case gate, one additional analytical test was added to the same
owning module. Its exact filter above passed separately in 0.70 s. It compares
the complete SDK parameters for the actual Source and both encoding AIRs and
records same-process timings. The only dependency change is the test-only
existing `p3-fri=0.8.0` edge for that independent SDK oracle; package versions
and production dependencies are unchanged. The final unfiltered command would
run ten owning cases; the nine proof cases and the analytical case were
executed separately, without regenerating the expensive honest proof setup.

## Observations and limits

The analytical test builds each AIR outside the timers. Both routes inspect
that same immutable object. The collected interval includes `analyze` guards
and the report-bound calculation; the direct interval includes only SDK
parameter derivation. Neither interval includes proving or native proof
verification. Complete parameters agree before timing is reported; these are
ordered single observations, without an isolated DAG-cost or latency guarantee.

| Actual AIR | Collected analysis | Direct unchanged SDK | Constraints |
| --- | ---: | ---: | ---: |
| Original Source691 |202.954 ms|264.958 ms|28,949|
| SourceAllOriginal encoding |89.067 ms|101.459 ms|6,916|
| PrivateMask encoding |16.444 ms|16.266 ms|2,592|

All three infer degree 4, retain the original hint 5/chunks 16 and meet both
individual 128-bit floors. The mask observation shows no speedup. The direct
SDK route is a diagnostic comparison, never an alternative verifier.

In the earlier nine-case proof run, joint Source/two-child verification took
1060.086 ms versus 1760.166 ms for two independent calls on the same proof bytes.
These include framing, fresh actual Source verification and both child checks.
The original Source prove interval was 3557.203 ms; source/mask child prove
intervals were 1908.705 ms/1283.205 ms. Comparing those values with a different run
does not isolate this change from machine load or proof randomness.

That held process exited 0 after 23,959.7225 ms OS lifetime, with 27.03125 CPU seconds.
Across 1175 nominal 20 ms samples, peak private bytes were 856,133,632 and OS peak
working set was 844,238,848. The 120 s/1792 MiB fuses did not fire; no observer fault,
cleanup kill, unexpected terminal child or source/image drift occurred. Source
payload was 19,304,607 B and the children were 3,357,959 B/2,366,279 B, within their
unchanged caps. This is one process observation, not a whole-peer memory bound.

Joint verification still exceeds the 500 ms target before Formation, full FHE
evaluation, fresh-head/consensus, transport and client completion. No complete
SQL query was measured or admitted here. Individual proof floors do not imply
composed protocol or lattice security.

## Evidence identities

Generated outputs remain ignored; exact local records are:

- `.local/collected-air-native-r1-observe/result.json`, SHA256
  `93C164FC5AEA735D2D6AB72BA1D782FA8BEB6F424F5920EC7036A11E9385A096`.
- `.local/observe-collected-air-r1.py`, SHA256
  `CD991D2FE76A5401AC4087A109BC75771E7012F2514979E2ACC1EB99C9273B43`.
- Observed release image `registry200_proof-5076f82234ff8d30.exe`, 6,333,952 B,
  SHA256 `DD2B96625437CE644E56A8E754384EEAD59C4F101E217FD06075F3F371540941`.
- Separate analytical test `.local/collected-air-native-r2-assessment/result.json`,
  SHA256 `5174D4E87463092BC9B2475BF4A2F051AC1B02D7B5B49D80F5648EB370C125C9`.
- Independent core source review `.local/collected-air-independent-review-r1/review.md`,
  SHA256 `C04F40C21963BE6FD841AF7AB7AC20AE9EE122419027FB59964CBC49F2EC7C7F`.
