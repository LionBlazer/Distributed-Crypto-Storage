# Private proof wire validation

The [private wire module](src/opening/proof_wire/README.md) transports complete
actual SDK Source+Bootstrap and cold Source+Locking proof pairs. Both pairs pass
fresh bounded canonical decoding and the original Source-first verifier. No
proof field is replaced by a hash, cache identifier, StateLease or receipt.
All fixture keys, records, controllers and owner inputs are PUBLIC NONSECRET.

The experiment adds no Journal adapter, live SQL grant, controller authority,
agreed freshness, finality, writer fence or peer-only FHE query acceptance.
It returns only an experimental Statement. The independently expected source,
genesis, parent, enrollment/old registry/plan remain caller-owned authority inputs.

## Format and resource policy

Header DCSLKPW1 is exactly 88 bytes: magic8, role1, zero7, CanonicalIndex
profile32, child profile32 and two u32LE proof lengths. It precedes one Bootstrap
output root or three Locking returned/owned/new roots, then the two original
Postcard proofs. Reserved bytes, fixed profiles, lengths, canonical Gold roots
and exact EOF are checked. Encoder/decoder byte equality retains every SDK field.

New wire-only limits are 20 MiB Source, 5 MiB child and 26 MiB complete frame;
sequence length 16384 and independent Source 24 Mi / child 8 Mi aggregate Serde slots, summed
32 Mi slots. Nested lengths are checked before Vec reservation. Slots are not bytes or
a hard RAM bound. Current Source is W11521/PV691, Bootstrap1082/104 and
Locking1948/116; the source opened row has 11526 elements. Actual SDK analysis
selects quotient chunks; both real profiles use 16. Three random/trace/quotient
batches, all 192 queries, complete local/next/hidden openings, separate salts,
ten binary FRI rounds, pruned authentication frontiers and all PoW witnesses are
preserved. Shape checks precede the SDK, which checks the exact frontier and proof.
Unexpected verifier panics reject; allocation abort is not caught by catch_unwind.

No old AIR/profile/hiding parameters or production verifier changed. Offline
resolution preserves all 213 package/version/source/checksum entries; only the
leaf package gains direct bounded-postcard and postcard dependency edges.
Root Cargo files and every unrelated lock/control path remain unchanged.

## Actual validation

Rust 1.99.0 MSVC, offline/locked/release, `RUSTFLAGS=-C target-cpu=native`, two
Cargo jobs/two Rayon workers and a fresh isolated target. Rustfmt, strict
Clippy `--all-targets -- -D warnings`, test/CLI builds and actual 263-case discovery
passed. All 24 previous full ordered numeric JSON lists remain exact; two wire
alias modes add 26 calls total and retain the old bounds/shapes. Both unique/list
estimates are 128 per proof (Bootstrap 4996 constraints / degree 3; Locking 7092 / degree 4;
both 16 quotient chunks). This does not establish a composed 128-bit bound.

Both CLI gates generate/serialize the genuine pair, drop it, then fresh-decode
and verify the bytes. The inner timer includes reconstruction, shape/security
analysis, fresh backends and both cryptographic verifications. The outer owned
process timer also includes fixture/setup/proving/serialization. Lengths vary
with transcript-derived pruned authentication paths; these are actual observations,
not general maximums, SQL latency or a performance-improvement claim.

| Pair | Source B | Child B | Frame B | Fresh decode+verify ms | Outer ms | Observed OS peak working set B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| bootstrap | 19304223 | 2429903 | 21734246 | 1629.2231 | 6991.1397 | 844492800 |
| locking | 19300927 | 3831151 | 23132262 | 1522.2484 | 6544.2594 | 843710464 |

Both measured frames satisfy the new component and complete-frame limits. A
future Journal must still encode/check its complete Body:
`117 + request_bytes + 456*update_count + proof_bytes`, or
`573 + request_bytes + proof_bytes` for one update, against the unchanged 32 MiB
maximum. No signed Body, durable append or reopen was tested by this stage.

The 15 affected leaf cases all passed, zero ignored: ten new wire cases and five old
owner prerequisite/composition controls. The earlier full source/locking checks
retain their [published Bootstrap scope](PRIVATE-REGISTRY-BOOTSTRAP-VALIDATION.md);
the other 248 leaf cases were discovered/compiled, not rerun here.

| Leaf process group | Passed | Outer ms | Observed OS peak working set B |
| --- | ---: | ---: | ---: |
| `wire-frame-boundary` | 2 | 107.1603 | 2056192 |
| `bootstrap-wire-boundary` | 4 | 80759.1587 | 1078550528 |
| `locking-wire-boundary` | 4 | 80474.1825 | 1058697216 |
| `owning-control-0` | 1 | 15074.9790 | 844992512 |
| `owning-control-1` | 1 | 14173.1410 | 844062720 |
| `owning-control-2` | 1 | 5230.5028 | 820523008 |
| `owning-control-3` | 1 | 11162.6086 | 845283328 |
| `owning-control-4` | 1 | 9146.9189 | 844963840 |

Real pair roundtrips preserve every byte. Genuine foreign pairs first pass their
own Expected; foreign pair/child splices then reject. Wrong Expected contexts,
all output roots, missing Source, hash-only receipts, malformed/canonical-field/
varint/EOF/advertised-length inputs, 31 structural families and 15 same-shape child
corruptions plus Source corruption reject through the owning APIs. Same-shape
attacks pass structural decoding before requiring actual SDK rejection.
All eight unchanged bounded-postcard owning tests passed, including rejection
before consumer reservation, shared nested budgets and scalar/error distinctions.
The actual requirements-mirror and architecture owning tests each passed too.

Owned-PID GetProcessMemoryInfo observations used nominal 100 ms sampling, sampled
1792 MiB soft fuse and 1200 seconds per child. All final observed children exited zero
without either fuse. Actual CLI sample intervals and private allocations were:

- bootstrap: 68 samples, 67 intervals 100.1510–254.6984 ms (mean 102.7314 ms); sampled working set 844492800 B, private bytes 840544256 B.
- locking: 65 samples, 64 intervals 100.1687–110.2113 ms (mean 100.5767 ms); sampled working set 843710464 B, private bytes 839557120 B.

These observations do not bound the whole peer process or malicious-input RSS;
the nested budget/canonical/shape checks establish rejection behavior separately.
No query-latency cutoff or whole SQL performance claim is made.

## Reproduction

Use the pinned Rust/flags/Rayon configuration above and an isolated target.

```sh
cargo clippy --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --all-targets -- -D warnings
cargo test --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml wire:: -- --test-threads=1
cargo test --release --locked --offline -p bounded-postcard --lib -- --test-threads=1
cargo run --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove registry-bootstrap-wire
cargo run --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove locking-selection-wire
```

Initial compile checks exposed a base-field value in a hostile EF5 test cell and
a runtime assertion over constants. The test now uses Challenge::ZERO and an
explicit const assertion. All failed evidence was retained; no runtime equation,
profile, structural rejection, budget or test assertion was weakened.
