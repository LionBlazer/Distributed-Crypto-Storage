# Fixed public source-primitive validation

On 2026-10-16 the standalone SHA-256/HChaCha20/ChaCha20 candidate built, passed
strict all-target Clippy and all nineteen serial release tests. Three separate
processes generated and verified genuine public-primitive proofs. This validates
the stated primitive relations and backend gates under the pinned SDK/model; it
does not establish witness secrecy/ZK composition, AEAD authentication, CSTORE
opening, BFV formation, SQL completeness, locks, finality, a hard RAM limit or a
500-ms SQL result. Every fixture, including its test key, is PUBLIC NONSECRET.

The earlier [VALIDATION.md](VALIDATION.md) remains unchanged and describes a
different SHA-only revision. SHA numbers below belong to the current shared
backend, not that historical binary. No benchmark or proof was rerun for this note.

## Reproduction and immutable identity

Compilation, security and all observed executions recorded parent
`01162cff4ad0489647aec3388fb0d2d84b6baab7`. After validation, the task branch
fast-forwarded to `b6107a712f011cbff678754138225a81f60b7279`, preserving all
standalone code/lock bytes; only this report and three discovery/module documents
were then changed. The incoming root Cargo.lock update is outside this isolated
workspace, which has no project path dependencies. There was no rebuild after
that fast-forward or documentation editing.

Host/toolchain: Windows x86_64 MSVC, Rust `1.99.0 (b940084d7 2026-09-28)`,
`RUSTFLAGS=-C target-cpu=native`, Cargo jobs 2, Rayon threads 2. Build target,
encoded Rust flags and compiler wrappers were unset. The separate target was
`MAIN/.local/target-hiding-chacha-primitives`; `MAIN` denotes the repository's
original `E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage` checkout.

| Frozen artifact | SHA-256 |
| --- | --- |
| Reviewed R2 source manifest, 13 task files + 7 controls | `752AECE46D29BAC84F8F8826C71E52EB6AD2CF90A540BB726EEBCC7319BBD927` |
| Standalone Cargo.lock | `34AF9D761D4D8BD52D7FEFE47303AE7E4EDD4D8542876D492E13424021689CBC` |
| CLI `release/hiding-fri-source-primitives.exe` | `ABE49A7C595951D02EE7797A51F6884525694505E63D53EA2811996C88DC5663` |
| Tests `release/deps/hiding_fri_source_primitives-2623599eefa6bbec.exe` | `F070300FCA3EA66BC25C3EBB7FB218D32D2CBE256FDC9A5C1FE62F460A1E353B` |
| R2 phase driver | `BBB3ED9DEAE1D277EFD13AE64A9D62C7A3DC64D4E516B04BE7549FD10DC8BC31` |
| External observer | `2FBBE341644746F3576A423F0A5C8A684CD1D30767ACBBF3834C3769732512FD` |

The lock contains 72 packages, including 19 P3 crates all at 0.8.0, VCS
`a21e3ed42905040ad49c519e402f018381c12d0c`. All 67 prior registry versions and
checksums were retained. The four additions exactly match root-pinned checksums:
ChaCha20 0.9.1, cipher 0.4.4, inout 0.1.4, zeroize 1.9.1. Rand's existing ChaCha20
0.10.2 remains separate. The oracle source pin is
`b5d39c45c45df97335f4b6effb853cde97810de1`.

Executable source bytes below are the compiled revision, unchanged by publication
preparation. Paths are relative to this experiment. The original manifest also
records the three pre-validation document versions; subsequent document edits
are not changes to these executable inputs.

| Source | SHA-256 |
| --- | --- |
| Cargo.toml | `28EFB37B502B5E9DB8B91DE2A041860DE2E881239C1C2308985C2EB7DFB32A9B` |
| src/air.rs | `0990F8A1F51B05ED38506A8105A5ADD2CA7F30099F4E24B35EB7BA29FA8DFA9A` |
| src/backend.rs | `1BEA80937972712301CEA804E8215C599C85E6D344CB696E0EE6AE35DA017328` |
| src/main.rs | `A61D48B7C81D6813FDD24064AB422D48C874D4DF063F31BFD2A6C35DE0602660` |
| src/statement.rs | `CF343EA95109DF4F69EB1FD1CC14528D3E6114E180DB073EE4AB7F125B11CA87` |
| src/tests.rs | `5780D6672A1708B34EFD12FEA2790617F61DE2D19715D6D2C820F11DB2310279` |
| src/primitive.rs | `95D902D2E6741B918A047A0F81E8B2870E439EAE122D5BCEE0E0807A614648D4` |
| src/chacha/mod.rs | `830EF18E9F923D8BD09B35BD73ECC689A63DCAFC422EFA886EE895F64D2D0166` |
| src/chacha/air.rs | `AAC53DDE6EB4839FC5A039D3C994CEEF29C2143292DC6A046EC4283846042FC5` |
| src/chacha/statement.rs | `81795986CC8CD74A2E180C9267B364D4AB4CD12879FBC061847C19CA54BED4A4` |
| src/chacha/tests.rs | `D77664A008814A00C6D0BDBC132B8197201A9D9EA755287BE2BEACD02CD7B818` |

## Actual phases and retained failures

The local phase commands used absolute `$manifest` for this workspace:

```powershell
cargo generate-lockfile --offline --manifest-path $manifest
cargo build --release --locked --offline --manifest-path $manifest
cargo test --release --locked --offline --no-run --manifest-path $manifest
cargo clippy --release --locked --offline --all-targets --manifest-path $manifest -- -D warnings
& $binary security sha256
& $binary security hchacha20
& $binary security chacha20
```

`$binary` is the exact compiled CLI above. After independent numerical review,
the observer sequentially started it with `prove hchacha20`, `prove chacha20`,
`prove sha256`; the exact test executable then ran
`--test-threads=1 --nocapture`. These invocations did not call Cargo or rebuild.

All paths below are local retained evidence, not generated outputs committed here:

| Stage | Location under `MAIN/.local/` |
| --- | --- |
| Frozen reviewed source | `hiding-chacha-source-r2-20261016-122131-381.json` |
| Offline lock, archives and package diff | `hiding-chacha-runs/20261016-121606-834-lock` |
| First build/no-run passed, Clippy exited 101 | `hiding-chacha-runs/20261016-121818-928-compile` |
| Successful R2 build/no-run/Clippy, all exit 0 | `hiding-chacha-runs/20261016-122325-012-compile` |
| Security startup failure, **zero CLI executions** | `hiding-chacha-runs/20261016-122508-642-security` |
| First actual three security CLI executions, all exit 0 | `hiding-chacha-runs/20261016-122558-832-security` |
| Observed HChaCha proof/verify | `hiding-chacha-observations/20261016-123429-256-prove-hchacha20` |
| Observed ChaCha proof/verify | `hiding-chacha-observations/20261016-123516-686-prove-chacha20` |
| Observed SHA proof/verify | `hiding-chacha-observations/20261016-123517-074-prove-sha256` |
| Observed nineteen serial tests | `hiding-chacha-observations/20261016-123555-823-tests-serial` |

The first Clippy run found only constant-size `chunks_exact(4)` and an indexed
test-helper loop. The independently reviewed fixes changed these to
`as_chunks::<4>().0`/typed four-byte copies and `state.iter().enumerate()`.
Reversing those exact fragments reproduces the earlier source hashes; no AIR,
profile, constraints or test cases changed. First compiled binaries were archived
before reusing the owned target. The subsequent Security startup attempt failed
on sandbox-denied Git metadata access before any CLI ran. Its incomplete folder
and explanatory note remain; the same frozen driver with the required worktree
access performed the first actual three security executions. Neither failure is
silently discarded or counted as successful validation.

Successful compile/security metadata SHA-256 values are respectively
`DCE7620B9C37C3572F19E60DF0BF5FE1B6F3046EE67D568E29767D0B1833B6DF`
and `14F551C2F9B0324E8A93D6C06B232C00549FDE85DAF2864D21199E55A86B61B8`.
Each observed folder archives both executables, the exact observer, source/lock,
all phase exit records and numerical evidence. Independent reads checked all 26
evidence copies and both artifact copies per run against their recorded hashes.

## Numerical and behavioral gates

All modes use 512 rows, post-ZK degree bits 10, blowup 8, 192 queries, five random
codewords, degree-five Goldilocks extension and two independently hiding MMCS.
OS-seeded masks/salts, clone stream forking and single-opening checks remain.
Both unique/list-decoding reports are 128 under the pinned calculator, experimental
128-bit hash-collision model and random-oracle assumptions, not a production
security certificate or an empirical proof of private-witness secrecy.

| Mode | Width | Opening points | Periodic columns | Constraints | Degree | Quotient chunks | Batched functions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SHA-256 | 7728 | 1 | 0 | 8136 | 3 | 8 | 7823 |
| HChaCha20 | 788 | 2 | 8 | 1492 | 3 | 8 | 1676 |
| ChaCha20 | 788 | 2 | 8 | 1492 | 3 | 8 | 1676 |

ChaCha accounting includes both complete 788-column openings:
`2*(788+5)+8*10+10=1676`; reading only 512 next-state columns does not reduce
the SDK's full-width next opening. Masking budgets are 394 for SHA and 404 for
ChaCha, both below 512. Counted ChaCha trace/masked/LDE payloads are
3,227,648 / 6,496,256 / 51,970,048 bytes; SHA's are
31,653,888 / 63,348,736 / 506,789,888. These are separate arrays, not a peak sum.

All nineteen tests passed, zero ignored, stdout interval 11.31 s. They cover
independent RFC/draft/RustCrypto oracles and genuine proofs; rebuilt malicious
internal/XOR/carry/nonboolean/wrong-output traces; skipped final quarter-round with
a matching false claim; HChaCha/ChaCha feedforward distinction; valid alternate
input traces; and shared shape/masking/RNG/single-opening contracts. The expected
SDK panic about an already opened private commitment is caught by the named
single-opening test, which passed; it is the only test stderr diagnostic.

## One observed invocation per mode

The following CLI intervals are shown to four decimal places. They are individual
primitive samples, not a latency distribution, clean benchmark or SQL operation.

| Mode | Prove ms | Verify ms | Observer elapsed ms | Valid memory rows |
| --- | ---: | ---: | ---: | ---: |
| HChaCha20 | 156.1794 | 40.1273 | 455.2734 | 1 |
| ChaCha20 | 157.9532 | 39.4603 | 260.6359 | 1 |
| SHA-256 | 1233.9433 | 236.6581 | 1759.5571 | 9 |
| Nineteen serial tests | — | — | 11359.1645 | 65 |

| Mode | Max sampled working set bytes | Max sampled OS-peak counter bytes | Max sampled private bytes |
| --- | ---: | ---: | ---: |
| HChaCha20 | 57,802,752 | 57,802,752 | 53,985,280 |
| ChaCha20 | 58,011,648 | 58,011,648 | 54,636,544 |
| SHA-256 | 526,512,128 | 539,250,688 | 523,517,952 |
| Nineteen serial tests | 532,508,672 | 541,782,016 | 574,775,296 |

All four processes exited zero without an observer abort; all CSV rows have valid
counters. Each ChaCha process has **one sample only**, giving no sample-gap or
final/lifetime-peak conclusion. SHA's eight observed gaps were 162.708–193.680 ms;
the tests' 64 gaps were 149.271–199.820 ms. The configured 100 ms `WaitForExit`
is a wait between observations, not a 100 ms sampling interval.

The observer checked working set, private bytes and the live OS-peak counter
independently against a 1,792 MiB abort guard, with a ten-minute timeout. It
controlled only its owned child. This is sampling and an abort policy, not a hard
OS memory limit: short transients can be missed, stopping can overshoot, and the
maximum sampled OS-peak counter is not certified final lifetime peak. Observer
elapsed time also includes process/observer overhead; CLI prove/verify intervals
cannot replace full-operation measurements. No inference about private-source
proof cost, production memory compliance or 500-ms SQL follows.
