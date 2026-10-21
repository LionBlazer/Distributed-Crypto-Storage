# Complete private graph validation, 2026-10-21 UTC

The owner-side graph contains all 139264 gates: 24576 forward-secret butterflies,
16384 public-A pointwise products and 98304 inverse butterflies. Its lazy fixed
metadata supplies 4352 rows of 32 slots, 266240 nodes, exact predecessor IDs,
fanout and coefficients. This is real pre-proving arithmetic for all four N4096
Formation equations. It does not implement the cryptographic Formation AIR or
its argument, authenticate Source/Cw/Cs, verify freshness or accept SQL. The
complete-query limit of 500ms remains unmet.

## Executed gates and reproduction

The standalone owner diagnostic and owning package ran with Rust1.99.0/MSVC,
release, `-C target-cpu=native`, two Cargo jobs and two Rayon threads:

```sh
cargo clippy --release --offline --locked -p bfv-unrelinearized-certificate --all-targets -- -D warnings
cargo test --release --offline --locked -p bfv-unrelinearized-certificate -- --nocapture --test-threads=1
cargo run --release --offline --locked -p bfv-unrelinearized-certificate -- --private-formation-graph-fixture
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

All 20 release tests passed in 0.54s; test compilation took 3.81s. The existing
single genuine random SDK fixture additionally compared all four complete graph
products with both the independent SDK Poly oracle and the existing fast Gold
arithmetic. It did not add another SDK setup or proof. Clippy with warnings denied,
formatting, normal release build and the requirements-mirror gate passed.

The graph test changes an internal butterfly's received values and repairs its
two outputs. Every local gate equation still holds, and all four final products
are unchanged. The actual predecessor audit rejects the false wire. It also
rejects a missing fourth consumer, wrong complete request identity, missing/extra
gates, a short secret and coefficient4095 outside [-20,20]. A noncanonical Gold
encoding of zero preserves the modular local equation but fails the audit.
These cases reuse the same bounded graph and public setup.

The previous public certificate profile, CLI protocol and old private-witness
check remain unchanged. No root manifest/lock, dependency, production proof,
network actor, timeout, SQL admission or memory limit changed. The package's
public-certificate and SDK tests passed as part of the same 20-test run.

## One complete local diagnostic observation

| Phase | Observed time |
| --- | ---: |
| Real SDK input preparation |6.2362ms|
| Real SDK encrypted multiplication |1.7391ms|
| Guarded private witness construction |1.8896ms|
| Existing private arithmetic precheck |1.5016ms|
| Full public graph plan and inventory |2.7662ms|
| Full private trace construction and predecessor audit |8.6619ms|
| All 4*4096 graph-derived Formation equations |0.1804ms|
| Whole local diagnostic including cleanup and unlisted lifecycle work |24.9815ms|

This is one observation, not a comparable whole-query speedup. The measured
process lifetime was 37.5322ms and summed CPU time was 31.25ms. Its executable
was 1146368 bytes, SHA256
`C466A10E68A263715A5A041AD572A80A6578C21D126A3E3342730C890AF4CFC3`.
The test executable was 1790464 bytes, SHA256
`0154E7D79AB4322EDDDE756DCFF40C26FE21243AABBA6915D8EB3325A6ADD6A1`.

The held-Windows-process observer checked exact image identity, creation time,
source hashes and terminal state. Both processes exited0, with no cleanup kill or
fuse. The unchanged observation limits were 120s and 1792MiB per process, sampled
every20ms. This is distinct from production resource enforcement.

| Process | Sampled peak private bytes | OS peak working-set bytes | Samples |
| --- | ---: | ---: | ---: |
| Explicit graph fixture |7745536|17494016|2|
| Owning test suite |22593536|22654976|27|

The short fixture's two private-byte samples can miss a peak; its OS peak working
set is a separate counter. Neither quantity extrapolates to a future large native
proof. The 4456448-byte private trace, 2129920-byte wire bank, public tables,
inventory and four products have a conservative logical sum of 8310768 bytes,
below the 8388608-byte graph vector prescreen. That prescreen excludes the
original witness/SDK/Statement/allocator/stack and is not a whole-PID bound.

## Source review and remaining composition

The independently reviewed five-file packet had aggregate SHA256
`E973EF6F18C31B9847D29039E7F6669CCD9B1C0088B2C36D7479EAB5B4558C8C`.
The executed six Rust files (main, fixture, and four gold_formation modules) total
59222 bytes, sorted POSIX-path/NUL/raw-bytes SHA256
`10682C702A9127771794D0D38842FD54BB88FF6A78A67001B2CB578B26791D90`.
Root added the separate CLI/lifecycle hook, formatting and the cheap boundary
negatives; it changed no existing proof profile. Raw receipts, snapshots and
observations remain local and are not committed.

The future single-AIR argument must constrain these actual gates and all private
wire/range/hash associations. It must open both full Cw vectors and the same
bounded secret's correctly scoped Cs, with independent Source and key context.
The current two-lane encoding returns already scaled W; feeding it to this
diagnostic's raw-m API would scale twice. Its private salts also require an actual
consuming Formation builder. Those integration gaps remain unresolved. A validated
graph, successful decryption or owner-local replay grants no proof or SQL
authority. Full security/resource assessment and complete DCS measurement are
still required before claiming the 500ms target.
