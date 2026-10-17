# Private registry bootstrap validation

The distinct [initialization relation](src/opening/registry_bootstrap/README.md)
has genuine canonical-source and bootstrap proofs. It proves initial empty
holdings for the closed four-row/two-transaction registry from independently
anchored enrollment and the exact original source. It does not establish a live
SQL grant, owner/controller authorization, agreed freshness, writer fences,
durability or peer-only encrypted query execution. All fixture keys, rows,
controllers and identifiers are explicitly PUBLIC NONSECRET.

## Checked contract

Source680, enrollment64 and the unchanged Registry112 each use a complete
Poseidon stream. All TableId and ordinal RowId words come from the same canonical
source; both shared 256-bit controllers are Boolean and nonzero. Initial IDs1/2,
revision2, Active/sequence1, Failed=false and every held mode zero are AIR
constants. The positive oracle matches two native Begin steps; native State is
never an acceptance verifier. Source proof verification precedes the child factory
and verification. An independently supplied Expected binds source, genesis,
parent and enrollment. A valid foreign enrollment does not satisfy that Expected.

Registry112 uses the original locking profile/domain/order. RegistryScope only
extracts the shared encoder scope; no old relation, profile, dependency, lock,
production verifier or network acceptance rule changed. The root is a proposed
post-genesis output, not Genesis.initial_shards: owner-signed registration remains
unimplemented and no genesis-hash fixed point is introduced.

## Actual checks

Pinned Rust 1.99.0 MSVC, Cargo offline/locked/release, `RUSTFLAGS=-C target-cpu=native`,
two Cargo jobs and two Rayon workers; fresh isolated target. Strict Clippy with
`--all-targets -- -D warnings`, rustfmt and release/test compilation passed.
Actual test discovery contains exactly 253 cases. The 85 affected cases below
all passed, with zero failures or ignored cases; unrelated formation/job and peer
process cases were not rerun. The actual requirements-mirror and architecture
tests passed separately. All existing tracked control paths, SDK/tool anchors and
old protected executables/DLLs stayed byte-identical.

All 23 old numerical modes preserve their complete ordered JSON outputs,
including extra composite records and both empty Poly1305 cases. The new 24th
mode reports:

| Item | Actual value |
| --- | ---: |
| Trace height / width / public values | 512 / 1082 / 104 |
| Periodic columns / opening points | 512 / 2 |
| Proof degree bits / queries / random codewords | 10 / 192 / 5 |
| Constraints / actual degree / quotient chunks | 4996 / 3 / 16 |
| Batched functions | 2344 |
| Unique / list decoding estimate, bits | 128 / 128 |
| Trace / masked trace / main LDE arrays, bytes | 4431872 / 8904704 / 71237632 |

Every backend checks its actual analytical and proof-specific estimates before
acceptance. These are per-proof estimates under the existing SDK assumptions;
two individual 128-bit gates do not establish a 128-bit composite. Array-size
estimates are not process RAM measurements or bounds.

The real `prove registry-bootstrap` CLI creates both proofs, verifies the source
before the child, and verifies the complete pair again. Observed prover time
(including source proof and its verification) was 4461.2006 ms;
complete-pair verifier time 1090.8494 ms. The outer process,
including public fixture/setup work, took 5658.2172 ms. No SQL latency
or performance improvement is inferred.

| Executed group | Passed | Outer process ms | Observed OS peak working set, bytes |
| --- | ---: | ---: | ---: |
| `new-bootstrap-suite` | 12 | 55319.2868 | 923922432 |
| `affected-old-locking-suite` | 24 | 32132.7854 | 869314560 |
| `affected-source-suite` | 14 | 271164.2767 | 987541504 |
| `affected-canonical-source-suite` | 13 | 180265.0744 | 1000669184 |
| `affected-chacha-suite` | 9 | 2951.3297 | 79204352 |
| `stable-registry-cross-profile` | 1 | 107.9566 | 2056192 |
| `backend-241` | 1 | 1713.8441 | 541081600 |
| `backend-242` | 1 | 108.1023 | 2056192 |
| `backend-243` | 1 | 409.5412 | 75423744 |
| `backend-244` | 1 | 308.6238 | 72024064 |
| `backend-245` | 1 | 107.9521 | 2056192 |
| `backend-246` | 1 | 107.4337 | 2056192 |
| `backend-247` | 1 | 106.3949 | 2056192 |
| `backend-248` | 1 | 2023.4974 | 540999680 |
| `backend-249` | 1 | 106.5790 | 2056192 |
| `backend-250` | 1 | 106.6415 | 2056192 |
| `backend-251` | 1 | 1622.6149 | 540884992 |
| `backend-252` | 1 | 3347.8938 | 541425664 |

The 12 new cases cover actual genuine source/bootstrap proofs; independently valid
foreign enrollment; missing/wrong canonical prerequisite before a child factory;
exact native initialization; coherent invented initial holdings/status/counters;
controller mismatch, zero/nonboolean bits; complete TableId/final RowId capture;
last source word, domain/version/genesis/key scope; salts/checkpoints/padding and
stable query-independent roots. Rebuilt hostile traces use the raw SDK prover;
every proof it emits must fail actual verification. An SDK proving error also
rejects that malformed trace. Repair controls isolate the affected relation.
The other 73 cases cover the original locking/source/canonical/ChaCha/backend
boundaries and stable-registry identity across source profiles. Twelve top-level
backend cases use exact names, rather than a broad nested `tests::` filter.

For the standalone CLI, 56 owned-PID samples observed peak working
set 844808192 B, sampled working set
844804096 B and private bytes
841191424 B. Its 55 actual
intervals were 100.1448–130.2462 ms
(mean 100.9452 ms). Observation used
GetProcessMemoryInfo at nominal 100 ms, a sampled 1792 MiB soft fuse and a
1200-second per-child runtime fuse. All final observed children exited zero without
either fuse firing. This is not a hard memory bound, the complete peer process,
network SQL execution or a latency cutoff. Proof serialization/Journal body fit
has not yet been measured.

## Reproduction

Set the Rust/Rayon configuration above and use an isolated Cargo target. These
commands reproduce the owning gate and new suite; numerical regression modes
are the existing SHA256, ChaCha, Poly1305, source, selection, state, locking,
formation and returned-encoding gates documented in the parent experiment.

```sh
cargo clippy --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --all-targets -- -D warnings
cargo test --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --no-run
cargo run --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- security registry-bootstrap
cargo run --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove registry-bootstrap
cargo test --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::registry_bootstrap::tests:: -- --test-threads=1
```

Two initial compile attempts exposed a missing Expected import and seven unused
must-use return values in tests. A third native run passed 11 new tests but exposed
an incorrect diagnostic assertion: four C_open limbs can fail on one row. The
test now scans the complete trace and checks nonempty failures confined to row84,
retaining raw SDK rejection and the root-only repaired positive. No AIR equation
was changed. All failed logs/artifacts were preserved; the final fresh build and
all checks above use the corrected source. Source-only donor metadata describing
old README prefixes as RAW is imprecise: preservation is canonical-LF; no such
wording is used as native evidence.
