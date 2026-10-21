# Word EMPTY208 validation

Validated 2026-10-21 on Windows x64 using the repository's pinned release/offline/
locked toolchain and native CPU target, Rayon2, one test thread. This is an
immutable initial-state component; it does not measure complete SQL or grant
currentness, enrollment authority, finality or assessed BFV/product security.

The final r131 actual release binary was 12043776 bytes, SHA256
`7B6363293B27662270CECBDFAC5107E3F27E1C1F1E01EA1ECC84AC1025E23207`.
The bounded observer checked the same executable/source identities before and
after, native process creation/exit identity, exit0, no direct children, no forced
cleanup, 120s ceiling and 1792MiB whole-process ceiling with 20ms sampling.

| Native owning gate | Cases | Test duration | OS peak working set | Peak sampled private bytes |
| --- | ---: | ---: | ---: | ---: |
| New Word bootstrap, including original Word Begin continuation and attacks, r131 | 4 |16.22s |554872832 |549625856 |
| Existing CanonicalSource/Bootstrap803 after private AIR/writer sharing, r128 | 3 |14.29s |843747328 |855973888 |
| Existing public Word metadata/openings and six original transition examples, r132 | 3 |2.01s |183693312 |176553984 |

The old bootstrap gate ran before the final two equivalent fixed-slice iterator
lint fixes in the new opening helper/test fixture. Its r127 binary was 12049408
bytes, SHA256
`EB7DD89A4226EF8AADD3B89376EE15415D30320A935B113D8169B9E93F7EBF8D`.
The shared AIR/writer did not change afterwards. The affected new bootstrap and
public Word gates were repeated on the final binary; the table records those runs.

The new gate independently proves and receives a genuine StateCertificate and
original Word EMPTY208 root, then genuinely proves/verifies an original Begin
transition whose OldRoot is exactly that verified empty root. Cross-family frames
are rejected. Repaired native arguments/headers under changed genesis, enrollment
or root fail actual native verification; Source absence or canonical/native
damage is rejected before child acceptance. A foreign C_state with identical
version_id remains a distinct full expectation and cannot reuse the certificate.
The bounded canonical frame rejects wrong namespaces/reserved fields/lengths,
trailing bytes, repaired trailing payload and over-budget advertised length.

Owner diagnostics reject altered final source byte, substituted/zero controllers,
noncanonical salt and changed registry blinding. The actual native attack test
recomputes every Poseidon witness and checkpoint after inserting revision,
allocator, a transaction/lock slot, both progress banks, roots or padding and
repairs the claimed root; all fail. A separately altered final row ID in the
constant private bank, with a fully repaired root, also fails its link to Source.
These checks use the real proof backend, not owner diagnostics or fixture answers.

In the standalone r131 honest scenario, mandatory receiving of Source and EMPTY
child took 667.637ms. Owner fixture preparation, genuine Source/child proving and
that receiving took 3545.966ms, measured before the subsequent Word Begin proof.
The Source certificate was 12255583 bytes; framed EMPTY child was 2429415 bytes.
These are single component observations, not a latency distribution or an SQL
result. No own builds/tests overlapped that measurement. An earlier r126 run had
all four native cases pass but its observer rejected stdout instrumentation;
the accepted runs move instrumentation to stderr and pass exact test-name checking.

Strict release Clippy on both normal/test targets passed at r131 with no lint
suppression. Six Word/EMPTY compile-fail ownership/constructor examples passed at
r130. The dependency-free requirements mirror test passed at r130. Those contracts
did not change in the two iterator lint fixes. Final changes to this record are
documentation only; no executable source changed after final native validation.

Reproduce the actual owning boundaries with the pinned repository environment:

```powershell
$env:RAYON_NUM_THREADS = '2'
cargo test --release --offline --locked -p registry200-proof --lib registry_progress::word::bootstrap::tests:: -- --test-threads=1 --nocapture
cargo test --release --offline --locked -p registry200-proof --lib registry_progress::bootstrap::tests:: -- --test-threads=1 --nocapture
cargo test --release --offline --locked -p registry200-proof --lib registry_progress::word_inventory::api_tests:: -- --test-threads=1 --nocapture
cargo test --release --offline --locked -p registry200-proof --doc registry_progress::word -- --test-threads=1
cargo clippy --release --offline --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

The old Bootstrap803 Source/profile/framing/statement policy is preserved. The
shared helper is private; no caller supplies its const generic size, AIR, topology,
setup, randomness or a verified flag. The normal public API produces only
unverified bytes, while the private move-only result requires both real native
verifications. Network SQL, current-head and lock acceptance guards stay closed.
