# One fresh Key verification per Ready restore

Status: **PASSED native release validation**, 2026-10-20. Authenticated Ready
restore now adopts the exact original Key frame and compares all Key33 using the
checked transform returned by that same fresh verification. It no longer invokes
the native Key verifier a second time inside the same restore. The public
standalone verifier and every separate restore still verify freshly.

The additive
[`Evidence::verify_owned_with_transform`](../crates/bfv-key-transform/README.md)
returns the existing checked type alongside the exact owned evidence. The
original `verify_owned` signature delegates to it and discards only the checked
transform. No cache, persisted verified bit, caller-supplied receipt, unchecked
constructor, changed proof profile or larger cap is introduced. The
[owner-state contract](../crates/bfv-query-core/src/owner_state/README.md)
retains independent complete setup, parameter, authentic anchor, AEAD, private
opening and full Key33 checks.

## Source and environment

The frozen batch started from `47f10358c364229ec47f2025501480963c4cce2f` on
`codex/feature/sql-latency`, with seven task paths changed. All 1,589 source files
remained unchanged through the native batch:

- Source receipt SHA-256:
  `D65D361366E32D8124BC13F3B3B958560BDB33925D7017F2802245507C01C101`.
- Verified after receipt SHA-256:
  `42E02621CAB19314976E5BDB56D561CAC14D61C2889092154D5BDA27E1528A5A`.

Publication changes after the batch are documentation only. Local immutable
receipts and raw logs remain outside Git. These are library-level tests, with no
network-peer or owner-process recovery claim. Windows/MSVC Rust 1.99.0 used
release/offline/locked builds, `RUSTFLAGS=-C target-cpu=native`, two Cargo jobs and
two Rayon threads. The proof backend reported AVX-512. No 1,800-second command or
1,792-MiB individual process memory fuse fired. Inherited chunk/packed experiment
flags are not read by these tests.

## Executed validation

| Gate | Result | Whole command seconds | Largest individual OS process peak bytes |
| --- | --- | ---: | ---: |
| Key primitive suite | 7 passed | 35.286 | 796,434,432 |
| Core owner-state restoration | 6 passed | 101.770 | 1,374,449,664 |
| Standalone Key verifier regressions | 3 passed | 21.733 | 976,056,320 |
| Ownership documentation contracts | 35 passed | 4.556 | 73,703,424 |
| Strict eight-package Clippy, all targets | passed | 6.743 | 11,087,872 |
| Default core check | passed | 4.106 | 81,391,616 |

The featureful owner-state suite ran for 60.53 seconds inside the test; its whole
command includes compilation. Its largest private bytes were 1,433,284,608 and
maximum memory sampling gap was 463.418 ms. These are whole-suite observations,
not a before/after benchmark, SQL latency or a general allocator/resource bound.
One initial owner-state invocation omitted `formation-proofs` and selected zero
tests in 5.350 seconds. It is retained in the after receipt and contributes no
runtime test coverage. The corrected command below ran all six cases.

The new primitive case verifies exact byte ownership and the same checked
transform, rejects a foreign full setup and expected anchor, and repairs a
canonical changed commitment before requiring native verification failure. The
new Core attack uses two genuine, independently verified proofs under the same
anchor with different output commitments. An authenticated original-epoch backup
containing the other proof is rejected, while the original restores to Ready
with its exact frame; rotation-only changes to the original setup are rejected.

Existing cases also restore old ciphertext after Owner destruction, reject wrong
authority/scope/role/record and malformed/tampered input, restore the original
private opening, and produce freshly verified Basis5/Formation after the original
Owner/epoch ends. Standalone tests preserve genuine verification, full setup and
canonical bounded-decoder rejection. No public fixture or decryption substitutes
for a Key proof.

## Reproduction

Run sequentially with the environment above and locked dependencies available:

```powershell
cargo test --release --offline --locked -p bfv-key-transform --lib -- --nocapture --test-threads=1
cargo test --release --offline --locked -p bfv-query-core --features formation-proofs --lib owner_state::tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p bfv-query-core --features formation-proofs --lib key_anchor::tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p bfv-key-transform -p bfv-query-core --features bfv-query-core/formation-proofs --doc
cargo clippy --release --offline --locked -p bfv-key-transform -p bfv-query-core -p bfv-product-evidence -p registry200-joint -p registry200-finality -p storage-client -p peer-runtime -p dcs-peer --features private-input-proofs --all-targets -- -D warnings
cargo check --release --offline --locked
```

This removes a duplicate computation at the existing proof boundary; it does not
authenticate caller-provided setup/anchor authority, prove arbitrary evaluation
keys use the same secret, establish freshness/finality or enable generic SQL.
Owner-state durability, rollback resistance and native SDK scratch-erasure
qualifications remain unchanged. Full DCS performance still needs end-to-end
measurements on the eventual admitted operation.
