# Complete relinearization: executed validation

This is an executed local mathematical composition on parent `92eaee50ceac5e43ec2d001e796342eacd3ba9f7`.
The prepared source manifest SHA-256 is `A260C7128460CD0745F80E0EB74B821D216F74524EA1150F11A1B2A1607E5CC9`. Fixtures are public and
nonsecret. An actual Core Owner generates the original setup and ciphertexts;
actual SDK ciphertext multiplication supplies three native NTT components.
The separate SDK relinearization oracle never supplies a proof or verifier input.
Private Owner and SDK evaluation key drop before composition proof production.

The genuine 32-component stream was written one public component at a time,
then verified with a fresh independently pinned public-key preparation after
dropping the producer and its prepared key. Both complete output components,
all five moduli and all 8192 coefficients per row, match the independent SDK oracle.
Normal checked spool cleanup succeeded before the CLI reported success.

## Reproduction and checks

Windows x86-64, Rust 1.99.0 MSVC, release, locked/offline dependencies,
`RUSTFLAGS="-C target-cpu=native"`, two Cargo jobs and two Rayon threads.
The new standalone lockfile resolves 145 packages and introduces no external
package coordinate absent from the existing tracked lockfiles. Existing root
and primitive manifests, lockfiles, profiles, proof caps, AIRs and tests are unchanged.

```powershell
$env:RUSTUP_TOOLCHAIN = '1.99.0-x86_64-pc-windows-msvc'
$env:RUSTFLAGS = '-C target-cpu=native'
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
$env:CARGO_TARGET_DIR = Join-Path (Get-Location).Path '.local/target-complete-relinearization-reproduction'
cargo check --release --offline --locked
cargo clippy --release --offline --locked --manifest-path experiments/bfv-complete-relinearization/Cargo.toml --all-targets -- -D warnings
cargo run --release --offline --locked --manifest-path experiments/bfv-complete-relinearization/Cargo.toml -- security
cargo run --release --offline --locked --manifest-path experiments/bfv-complete-relinearization/Cargo.toml -- prove
cargo test --release --offline --locked --manifest-path experiments/bfv-complete-relinearization/Cargo.toml -- --test-threads=1
```

Default core check, owned-source rustfmt and strict new all-target Clippy passed.
The compiled inventory contained exactly seven runtime tests; all seven ran and
passed, without ignored tests. The new leaf doctest command passed with **zero**
doctests; this does not rerun historical dependency doctests. Both existing
`requirements_sync` and `architecture` contract tests were compiled directly from
their unchanged owning Rust sources and passed, one test each, with the original
playground manifest context. No GUI application test suite is claimed.

- `spool::tests::public_spool_checked_finish_removes_the_exclusive_canonical_child`
- `spool::tests::public_spool_write_error_is_terminal_and_checked_cleanup_still_removes_owned_files`
- `tests::all_thirty_two_genuine_components_reverify_after_producer_drop_and_match_actual_owner_sdk_product`
- `tests::incomplete_cancelled_and_exhausted_streams_never_yield_a_checked_result_or_advance_after_rejection`
- `tests::malformed_or_unsupported_original_key_is_rejected_by_bounded_source_before_public_ntt_preparation`
- `tests::native_ntt_input_checks_every_component_modulus_and_last_word_without_sdk_pb_relabeling`
- `tests::original_owner_public_key_preprocessing_matches_all_fifty_sdk_rows_and_rejects_setup_substitution`

The genuine-stream test also rejects out-of-order/truncated/reserved frames,
noncanonical last residues, changed last outputs, and a genuine foreign-query
proof payload with repaired honest headers through actual primitive verification.
It tests inverse/Embed/forward/MAC endpoints without claiming exhaustive replay of
every omitted component. Separate tests exercise terminal cancellation, incomplete
finish, lifetime attempts and failed-candidate byte charging, original-key rejection,
all fifty key rows against SDK probes, and terminal spool write/checked cleanup.

## Observed complete CLI operation

| Included work | Milliseconds |
| --- | ---: |
| Owner/input and independent SDK oracle | 264.217 |
| Public key preprocessing | 132.114 |
| Proving and public spool writes | 99,770.359 |
| Fresh key setup, spool reads and verification | 7,706.115 |
| Complete operation including checked cleanup | 107,885.529 |

The setup was 8,930,306 bytes. The actual 32 public component frames
totaled 67,671,532 bytes; the largest was 3,998,843
bytes. Existing primitive proof caps remain 16 MiB. New per-component cap is
20 MiB; the exact lifetime stream byte budget is 541,140,544 bytes and 64 attempts,
including failures. No aggregate proof frame or network transport is implemented.

| Ordinal | Frame bytes |
| ---: | ---: |
| 0 | 2,034,267 |
| 1 | 2,035,382 |
| 2 | 2,034,115 |
| 3 | 2,034,981 |
| 4 | 2,031,297 |
| 5 | 2,840,035 |
| 6 | 2,026,487 |
| 7 | 2,024,017 |
| 8 | 2,029,403 |
| 9 | 2,024,921 |
| 10 | 2,034,545 |
| 11 | 2,023,563 |
| 12 | 2,030,836 |
| 13 | 2,030,593 |
| 14 | 2,025,114 |
| 15 | 2,017,199 |
| 16 | 2,028,439 |
| 17 | 2,027,008 |
| 18 | 2,027,463 |
| 19 | 2,025,003 |
| 20 | 2,023,885 |
| 21 | 2,032,293 |
| 22 | 2,025,769 |
| 23 | 2,031,885 |
| 24 | 2,028,148 |
| 25 | 2,020,932 |
| 26 | 2,024,192 |
| 27 | 2,027,356 |
| 28 | 2,027,706 |
| 29 | 2,021,904 |
| 30 | 2,023,951 |
| 31 | 3,998,843 |

Target-owned root and descendant processes were observed at nominal 100 ms
intervals, with a sampled per-PID 1792 MiB soft fuse. Across numeric, genuine CLI
and runtime test commands: 3 observed process instances,
921 memory rows; maximum sampled working set
959,918,080 bytes, private bytes 961,056,768,
OS-reported peak working set 984,375,296 bytes,
and maximum aligned concurrent working set 959,918,080
bytes. The largest actual interval was 522.182 ms.
These are observations of this local operation, not a hard whole-process RAM
guarantee, an admission policy, a distributed benchmark or SQL response latency.

## Security assessment and boundaries

All twelve actual primitive analytical reports have finite assessed terms and
empty unassessed lists. Each uses its unchanged 144-bit acceptance floor. Five
inverse reports occur once each; each of five forward reports occurs five times;
Embed and MAC occur once. The weighted conditional proof-only union estimate is
152.441319559146 bits. The enforced floors alone yield 139 bits for 32 components.
These calculations assume appropriate composition and do not establish adaptive
Fiat-Shamir composition, setup authority, stronger primitive binding identities,
same-secret evaluation-key validity or whole-system 128-bit security.

Input is a pinned public mathematical nativeNTT3 Q5 statement. This experiment
does not certify SDK protobuf conversion (the SDK serializes PowerBasis despite
its NTT tag), storage/source formation, encrypted predicate, selection completeness,
full multiplication/modulus extension/downscale, SQL, writer permission, agreed
freshness or decentralized finality. `composed_128_claim` and all production
authority flags remain false. Production query acceptance is not changed.

An initial strict Clippy gate failed solely on an unnecessary decoder lifetime.
The correction elided that lifetime without behavior/profile/test changes; the
failed R1 logs and source remain separate. All successful gates below use R2.
No cached prior result is represented as current execution.

## Local evidence

Receipts and proof/memory outputs stay ignored under `.local/`.
No credentials, private keys, participant data or generated binary outputs are committed.

| Gate | SHA-256 of successful receipt |
| --- | --- |
| compile | `F8F21400E8390C5B18DC2E35D10ED02E3711C0F9A9CC6FEC70A98C78B8CF8118` |
| numeric | `080CE95667108EDAF074F6CE33D88D5408936EC63B6548C6F20E384C1F9C2D19` |
| prove | `9907E734E50227477AEAFE736E6D0CF27D38C6778E488F106F10BB3D0F29BE43` |
| tests | `0486C1325D8BC675D25E85F104BDFCD21C2320AA7B9227B9043695FF5E5C4BCC` |
| docs | `8A5787AC169DAE65D5F33BC1A136D2B9D9A7BC9B1907EAE9140288F0F0936A83` |
| contracts | `A19B68726A71CBC180ABD9800585ADB5D5CCD385333D5A0DFB35F438522E08BD` |
