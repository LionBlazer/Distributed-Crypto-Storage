# Fixed public compression validation

On 2026-10-16 the standalone candidate built and passed its ten release tests.
This validates a real SHA-256 compression relation and the selected backend's
configuration/behavioral gates. It does not implement SHA chaining/padding,
XChaCha20Poly1305, CSTORE opening, BFV input formation, SQL completeness, private
lock control or finality. All primitive inputs are public fixtures; successful
proofs do not empirically establish witness secrecy or ZK composition. No owner
keys, rows or other private witnesses were used.

## Reproduction and identity

The host was Windows x86_64 MSVC, Rust `1.99.0 (b940084d7 2026-09-28)`, release,
`RUSTFLAGS=-C target-cpu=native`, Cargo jobs 2 and Rayon threads 2.
`CARGO_BUILD_TARGET` and `CARGO_ENCODED_RUSTFLAGS` were absent. The standalone
lock contains 68 packages including this experiment, with all 19 P3 packages
pinned to 0.8.0. The newly fetched `p3-sha256-air` archive's VCS commit is
`a21e3ed42905040ad49c519e402f018381c12d0c`; other dependency versions/checksums
match the parent workspace. No production manifest or proof profile changed.

These are the exact commands issued by the local phase driver, with `$manifest`
set to the absolute path of this directory's `Cargo.toml`. They describe the
completed stages; they are not a recommendation to run another coordinated job.

```powershell
cargo generate-lockfile --manifest-path $manifest
cargo fetch --locked --manifest-path $manifest
cargo tree --locked --offline --manifest-path $manifest
cargo build --release --locked --offline --manifest-path $manifest
cargo test --release --locked --offline --no-run --manifest-path $manifest
cargo clippy --release --locked --offline --all-targets --manifest-path $manifest -- -D warnings
```

After independent lock/source review, the phase driver started the built release
binary with argument `security`. After numerical review, the observer started
that binary with `prove` in one fresh process. A separate observed invocation
started the built test executable with `--test-threads=1 --nocapture`; it did not
rebuild it.

The experiment was uncommitted during validation. Final compilation recorded
parent `6e38660393f9bfb16482043643f26898eba3f045`; security and both observed
runs recorded its docs-only child `defd48ad5a90404144f1aa80a9599a2e74e7e1c4`.
All frozen experimental sources and the lock were identical across that update.
The hashes below, not either parent commit alone, identify the experiment.
Only README status and this report were changed after the runs; the executable source,
manifest, source-relation contract and lock remain byte-identical.

| Artifact | SHA-256 |
| --- | --- |
| `Cargo.lock` | `DDE5656BF9172DE1916A5FD17F38238033C53B028474E84B400DC4173874024B` |
| `Cargo.toml` | `447BD517EE69445E2D01825DDC0F1B52860E80F8696F2EA54F4F7E627E755006` |
| Run-time `README.md` | `7E680A464BDBEECBFE64A3585871D9866CCA96F642EF81FEB6403578BE2BF6AE` |
| `SOURCE-RELATION.md` | `9FF704B837FF4CB5B4D1D4F18D32E6FA0E6CD9AD442EB4F3C4AC4177EECCBBF2` |
| `src/air.rs` | `0990F8A1F51B05ED38506A8105A5ADD2CA7F30099F4E24B35EB7BA29FA8DFA9A` |
| `src/backend.rs` | `FD5CDCDFE71616AF030BF8096B32A455569420D336A9840CD285563423808DF9` |
| `src/main.rs` | `DDC790EE228B37DECE9459AFEAABDD77DB76101301AFFCC4DEA1C9238C5BB902` |
| `src/statement.rs` | `2FD99A57EAE574970F08396527E308BC9E51D6A0902D02F54EF124FAA6E48E91` |
| `src/tests.rs` | `071D6EFB1438C1ABE831063D9AD38F0D9331B0922E038AFB694C6D514EEC6A5B` |
| Release CLI | `611D05ABC57A9213188352B0F6521589FEC8441E1E4C1AE2FE37CD2FC37B0F1D` |
| Release test executable | `6E9A2DA6F7DCC377CDF538585B7E6C45C0C4A7926FA171560C7427D8E0A03E98` |

## Numerical and process observations

Both SDK decoding reports were 128 bits for the final wrapper: 8,136 constraints,
degree 3, eight quotient chunks and 7,823 batched functions. The original trace
was `512 * 7728`, post-ZK proof degree bits 10, blowup 8, 192 queries and five
random codewords. The hiding budget is `512 >= 2 * (192 + 5) = 394`.
These bounds use the pinned calculator with a 319-bit extension-field floor and
stated 128-bit Poseidon2/hash assumption. They are not independent cryptographic
certification or approval to place private data in this experiment.

Source-derived array sizes are 31,653,888 bytes for the original trace,
63,348,736 bytes for its masked matrix and 506,789,888 bytes for the dense main
LDE. These are separate array sizes, not a sum, peak prediction or RAM limit.

| Separate observed process | Result | Maximum sampled OS peak working-set counter | Maximum sampled private bytes |
| --- | --- | ---: | ---: |
| One CLI `prove` | Exit 0; genuine proof verified | 539,148,288 B (514.171875 MiB) | 523,051,008 B (498.8203125 MiB) |
| Ten serial release tests | 10 passed; 0 failed/ignored; exit 0 | 541,011,968 B (515.94921875 MiB) | 526,401,536 B (502.015625 MiB) |

The single public-fixture proof printed 1,363.2911 ms proving and 259.3232 ms
verification. The observer's process interval was 2,022.8059 ms. The tests printed
10.51 s, with a 10,763.2214 ms observer interval. These are one-shot observations,
not a latency distribution, full SQL timings, a 500-ms claim or extrapolation to
private source proofs or other hardware/geometry.

The external observer checked exact source, lock and binary identities, then
sampled only its own spawned process. Its 1,792 MiB threshold and ten-minute
timeout were abort guards; neither run triggered them. It used `WaitForExit(100)`
between observations. That is a 100-ms wait, not a guaranteed 100-ms sample
interval: process property access, CSV flush and scheduling add overhead. Valid
sample gaps in the first proof run were 193.304–230.031 ms. The maximum of live
sampled OS peak counters is not a guaranteed final lifetime peak;
private-memory samples can miss transients. The guard can overshoot and is not a
hard OS memory limit. No complete SQL-process RAM compliance follows.

The first observer (`FA50DA315C82998305B674DBD50D58E64D3E3AB7A515607144550D8368E4B665`)
recorded nine CSV rows; its final exit-race row has empty counters. Maxima above
were independently recomputed over the eight valid rows. Original files were
preserved, with an explicit `counter-observation-note.json`; no rerun replaced
this sample. The updated test observer
(`A1F144C55AB5E61A894807A59C1FFFE8B144C71DC5E1CD8FFD12DCABEE62F59D`)
rejects unavailable live counters or skips an exited observation; all 50 test
rows contain counters. Its stderr contains the expected caught "already opened"
panic from the single-opening negative test, not a failed test.

## Checks and retained evidence

The first release build passed, but test compilation failed with `E0284` because
three direct PCS calls lacked an explicit challenger type. The test-only fix used
fully qualified `Pcs<Challenge, Challenger>` calls. The next test compilation
passed, but strict Clippy rejected fixed `chunks_exact` calls. Equivalent borrowed
`as_chunks`/`as_chunks_mut` projections fixed those warnings. Independent source
review checked both fixes; no AIR, statement meaning, parameters, acceptance
checks or test cases were removed. The final release build, test compilation and
strict all-target Clippy all passed. Failed logs were retained.

The ten tests cover independent RustCrypto compression oracles; actual security
shape and allocation accounting; a genuine proof with request/input/output and
proof-shape negatives; raw rebuilt wrong-output, internally valid alternate-last-
row and internal-schedule forgeries; insufficient hiding/codeword budgets;
one-opening enforcement across cloned prover data; and independently forked
configuration RNGs. The alternate rows first satisfy the unwrapped upstream AIR.
This reaches the actual wrapper constraints rather than only replaying a proof.

Local raw evidence is retained outside Git under
`E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/hiding-fri-sha256-gate-runs/`:

| Directory | Evidence |
| --- | --- |
| `20261016-104327-617-lock` | Generated/reviewed lock, fetch and dependency tree |
| `20261016-104549-582-compile` | First successful build and failed test compilation |
| `20261016-105116-997-compile` | Successful test compilation and failed strict Clippy |
| `20261016-105448-738-compile` | All three final compile/Clippy stages; exact source metadata |
| `20261016-105548-021-security` | Numerical JSON, binary hash and source metadata |
| `20261016-105621-024-observed-prove` | Archived first observer, manifest, stdout/stderr, CSV, result and correction note |
| `20261016-105941-020-observed-tests` | Updated observer, ten-test logs, all 50 samples and result |

The next relation remains [unimplemented](SOURCE-RELATION.md). Production
acceptance, existing arithmetic proofs and the root workspace remain unchanged.
