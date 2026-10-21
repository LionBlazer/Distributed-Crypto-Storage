# Native validation, 2026-10-21 UTC

Scope: one fixed private arithmetic AIR with two actual internal LogUp edges,
H512, MAIN19 and public PP3. This is neither the N4096 Formation relation nor FHE,
Source authentication, a fresh agreed head, distributed finality or SQL. The
complete-query target of at most500ms remains unachieved. There is no comparable
whole-query before/after measurement or claimed query speedup in this result.

## Reproduction and source boundary

From the repository root, using Rust1.99.0/MSVC, release, `-C target-cpu=native`,
two Cargo jobs and `RAYON_NUM_THREADS=2`:

```sh
cargo clippy --release --locked --manifest-path experiments/hiding-logup-wire/Cargo.toml --all-targets -- -D warnings
cargo test --release --locked --manifest-path experiments/hiding-logup-wire/Cargo.toml -- --nocapture --test-threads=1
cargo run --release --locked --manifest-path experiments/hiding-logup-wire/Cargo.toml -- --public-fixture
cargo test --release --locked -p repository-contracts --test requirements_sync
```

The successful local commands additionally used `--offline` and the existing
bounded local target/cache. Only the standalone workspace and its lock are new;
the root workspace, root lock, existing proof profiles and production paths are
unchanged. The actual published `p3-batch-stark`0.8.0 crate archive matched its
locked checksum, and its13 Rust files matched the reviewed official source at
`a21e3ed42905040ad49c519e402f018381c12d0c`. No SDK source was patched or vendored.

The six Rust files plus standalone Cargo.toml/Cargo.lock total72238 bytes, with
sorted POSIX-path/NUL/raw-bytes SHA256
`599152F7EB5AF896A820233F403B38496E50087D2CA4C2B91227D0525D481EDF`.
An independent source review acknowledged this exact source set before the
successful native tests. Documentation is excluded from that aggregate.
The profile is
`1006a39293d3063778a860342fc68c451574b4a73b46446e13c4b44bb8f5337e`.

## Observed native gates

All three owning release tests passed in0.28s. A separate false-wire proving
attempt retained the same public output and valid ordinary arithmetic equations.
The actual native verifier rejected it with
`Lookup(TerminalSumNonZero)` after the PCS and ordinary AIR checks. The honest
proof passed independent reconstruction and verification, including a fresh
verification after repaired hostile frames. Wrong context/output/public PP,
damaged MAIN/AUX, terminal/instance/degree/random-presence changes and canonical,
EOF, sequence, aggregate-budget and frontier negatives passed their assertions.
No additional proving call was needed for those hostile-frame cases.

Clippy with warnings denied, formatting, normal release build, metadata-only CLI
and the repository requirements-mirror test passed. The initial honest test
failed only at the unpublished decoder budget262144; [accounting](DECODER-BOUND.md)
explains the corrected1048576 budget and stricter frontier bounds. The successful
test executable had SHA256
`CF615E036EE8865677DA32798904B331A42C52301E4659C162171980C9B8FFF5`.

## One complete local fixture observation

| Operation | Observed time |
| --- | ---: |
| Public setup, assessment, private proving and canonical framing |49.5164ms|
| Independently rebuilt setup, bounded decoding and actual verification |23.0876ms|
| Whole local fixture interval |72.6042ms|
| OS-observed process lifetime |83.0658ms|
| Summed process CPU time |140.625ms|

The explicit public fixture returned503 in a636776-byte frame. Its executable
was2165760 bytes, SHA256
`44CCE67F4789BFC36A136F9BA76ABA3639AAEFBF018496F71631631C1B661390`.
The observer retained the Windows process handle and checked image identity,
creation time, exit code and source hashes. Both observed processes exited0
without a fuse or cleanup kill. Sampling interval was20ms, timeout120s and the
process resource fuse1792MiB; neither production timeouts nor production limits
were altered.

| Process | Sampled peak private bytes | OS peak working-set bytes |
| --- | ---: | ---: |
| Public fixture |18018304|25919488|
| Three-test suite |26619904|32112640|

Private-byte sampling can miss short peaks; working set is a different OS
quantity. These are measurements of this small primitive only, not an extrapolated
full Formation or peer-process resource guarantee. Raw command, source guards,
logs and held-process observations remain local and are not committed.

## Conditional assessment and remaining boundary

The actual batch symbolic assessment found69 constraints, degree4, eight
committed quotient chunks, two packed lookups from four original width-two
tuples, AUX base width15 and157 batched openings. The charged multiplicity-height
was2048. Including the native LogUp error term gave305 lookup bits; both SDK UDR
and LDR reports reached their128-bit commitment cap. The independent baseline
also passed. The logical workspace prescreen was81174528 bytes, distinct from
the observed OS counters.

These are conditional individual SDK assessments, not a composed/statistical-ZK
or lattice-security theorem. A complete Formation graph, authenticated input and
query relation, fresh-head verification and integration into real DCS remain
necessary before any SQL answer can be accepted. This executable grants none
of those capabilities and keeps its FHE/SQL/freshness flags false.
