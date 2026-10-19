# Source-first Registry200 lifecycle producer

The original Bootstrap/Transition prover-input model, trace writer and private
commitment builders now belong to `registry200-proof::lifecycle`. The experiment
imports the same implementation. Its normal CLI, wire, Journal owner and legacy
encoding fixture use the Core typed producer. This change removes the experiment
dependency needed by a future client producer; it does not enable network SQL.

## Boundary and preserved contracts

`PreparedWitness::new` consumes an explicit bounded mathematical witness,
reaudits the complete independently supplied Expected and reconstructs the
Source/enrollment/old/command openings. It captures the full statement and private
witness banks without Clone, Debug, serialization or private-data getters.
`prove` matches the captured Expected, genuinely verifies the canonical Source
proof and drops its backend before assessing, allocating and proving the child.
The resulting evidence retains the original DCSLFPW1 byte grammar. Persisted
bytes still require genuine Source-first verification on every admission/reopen.

Owned plaintext/controller bytes, integer salts and native registry/command
banks are zeroized on drop. Caller copies, transient Gold fields, field traces
and SDK scratch are outside that erasure claim. The public mutable mathematical
DTO deliberately remains available for genuine well-shaped hostile traces; it
does not establish authorization or correctness. Verifiers never execute the
native registry model to compute an answer.

The old AIR equations, domains, profiles, security settings, operations,
Source/child limits and 32 MiB signed-Body reservation are unchanged. Source
verification is shared internally with coefficient-encoding producers/verifiers;
no success Boolean, caller callback or decoded proof escapes that helper.

## Executed validation

Commands ran on Windows/MSVC Rust 1.99.0, in release mode with offline locked
dependencies, native CPU flags, Cargo jobs 2 and Rayon threads 2. The ignored
runner preserves separate CreateNew logs and uses a nominal 100 ms Windows
process observer with a sampled 1792 MiB per-process soft fuse. All successful
runs below completed without a fuse or runner-budget abort.

The first new-test run failed in all four cases before proof creation: a test
helper sent an enrollment64 preimage to the lifecycle digest helper, whose fixed
supported sizes are 144/160/200. Only that fixture call was corrected to the
existing Source commitment digest. No production digest, AIR or verifier guard
changed; the failed receipt remains preserved locally.

| Native boundary | Result | Test runtime | Whole command, including compilation | Maximum observed WS / private bytes |
| --- | --- | --- | --- | --- |
| Four new Core producer tests | 4 passed | 14.02 s | 45.070 s | 843,739,136 / 839,581,696 |
| Existing lifecycle owning tests | 21 passed | 92.61 s | 201.320 s | 905,150,464 / 901,287,936 |
| Other Core tests and ownership doctests | 13 + 2 passed | 2.35 + 0.32 s | 28.942 s | Not separately monitored |
| Signed Journal history, eight genuine Source/lifecycle pairs, durable reopen | 1 passed | 86.87 s | 99.592 s | 1,220,435,968 / 1,241,034,752 |

The new tests verify actual Source/Bootstrap/Begin bytes after dropping private
prepared inputs; reject complete-Expected cross-use before Source construction;
reject genuinely damaged canonical Source proofs and resource bombs; and preserve
bounded raw geometry for real AIR attacks. The existing tests cover all seven
operations and coherent cryptographic attacks. The Journal regression covers
failed End resolving to Abort, actual signed append and durable proof rechecking.

These are producer/test process observations, not end-to-end SQL latency or a
whole-peer RAM guarantee. The new-test observer recorded 219 samples with a
616.881 ms maximum gap; the lifecycle run recorded 1122 samples, maximum gap
565.804 ms; the Journal run recorded 714 samples, maximum gap 921.928 ms. Its
whole-command timer includes waiting for a Cargo build lock.

The rebuilt actual CLI emitted exactly the same seven JSON security objects as
the preserved earlier binary: two for `registry-lifecycle-bootstrap`, two for
`registry-lifecycle`, three for `private-coefficient-encoding`. Analytical reports
are not computation proofs. Strict Core and experiment Clippy and format checks
also pass. The requirements mirror remains synchronized.

## Reproduction and receipt pins

Use the repository's locked toolchain and actual environment. The corresponding
Cargo commands are:

```text
cargo test --release --offline --locked -p registry200-proof lifecycle::prover_tests:: -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof -- --test-threads=1 --skip lifecycle::prover_tests::
cargo test --release --offline --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::registry_lifecycle::tests:: -- --test-threads=1
cargo test --release --offline --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::registry_lifecycle::journal::tests::lifecycle_tests::seven_operations_failed_end_abort_and_durable_reopen_use_eight_real_proof_pairs -- --test-threads=1
```

The final proof-test source manifest is `.local/lifecycle-producer-full-r2/source.json`,
SHA256 `D43781648F9DA66720F8D7DEE22A7550E758D16203DF0D7E2FE2B1C1758AE56B`.
All 1417 listed raw files still matched after the Journal regression and CLI
rebuild, before these documentation updates. No runtime source changed afterward.

Ignored receipts under `.local/private-peer-native-r1/` retain these stdout / stderr
SHA256 pins:

| Receipt | stdout | stderr |
| --- | --- | --- |
| `lifecycle-producer-full-r2` | `3D8E0622AD35233879FB271B4AE387BCC6027DCA03C9FD5973DD77726D0849BA` | `F9F3F6E0EF45624D313E359C971369D5E440B0EF685C4CE79C632A953F29B346` |
| `lifecycle-producer-old-lifecycle-r1` | `5AAB410EBF85818ACC1B2297C093443A8C80C306A111CA743685530EF79D2624` | `82A6E3DF1B126FEAB587C772A21BC3ADC225021BE688839F1C6F97C5EDB15CF9` |
| `lifecycle-producer-core-regressions-r1` | `078D998ADF6A2CA8355D7E67F372B9A3A25AAEF823EC15CE9A860AE743E6F25C` | `86FF66052F99F8932763BF10E8FEB2E42F94643341FEA151C5CB4B42519F677F` |
| `lifecycle-producer-journal-r1` | `754C83F76EA999417782895DC0D3C7469E0141B36EA2FDA151C65FA956C21FFA` | `F27CE5B625B297223A617C252CE34B52D5E7951812B99E74A09E5DA61B561201` |

Rebuilt CLI SHA256 is
`92144FC30A571858984067D1E24495EBB02807F287BEF0D7A01946BD7664D24F`.
The three unchanged stdout hashes are respectively
`DC87B9261F8DD6D6B3FE0807FDBA0B08BEFDEC60DC5F8A4F7E5E7B8210808347`,
`CC2B2BAE37B6735C6B4D0C8D254012E3EC4BA02379A4A27A5EE4D665E0267392`
and `1535E189F3C00AC62F432C4F4BF35304562D6F20DEA91AB9AF2B4DFBF317AAA2`.
Generated logs, binaries, witnesses and private material are not committed.

## Remaining system work

Individual proof security targets do not establish composed 128-bit security.
Enrollment labels do not prove controller signatures or delegated rights. This
producer neither observes a finalized head nor grants row ownership, SQL results,
MVCC or writer fencing. Joint hidden LockingSelect compilation, same-Source
input16/Lifecycle/link orchestration, actual encrypted-output completion, durable
composite evidence and fresh weighted agreement remain separate work. The
[detached linkage byte-cap blocker](private-predicate-acquire.md) and the
[actual private peer execution boundary](private-where-peer.md) still apply.
