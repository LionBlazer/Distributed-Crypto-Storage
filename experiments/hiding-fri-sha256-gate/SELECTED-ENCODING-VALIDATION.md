# Private Selection to complete BFV plaintext encoding

This experimental relation links the existing request-bound private Selection
commitment to every coefficient of the original bounded N4 BFV plaintext. It
does not enable network acceptance. Secret-key/error sampling, common RNS
ciphertext formation, a BFV key anchor, agreed freshness and private row locks
remain separate requirements. PostgreSQL compatibility and a complete 500 ms
operation are not established by this gate.

## Computation and ownership

The independently expected old Selection statement must have its original kind
and all 88 public fields must match. Genuine canonical-source and Selection SDK
proofs verify before the Encoding trace factory. Composite verification checks
those two prerequisites again before checking the new proof. VersionSelection
is deliberately outside this new profile; the published version-certificate
and warm-query profiles retain their encodings and behavior.

The private source consists of four tuples, each containing presence, ordinal,
original age/amount and all eight RowId words. Projection never substitutes an
answer for the original amount. Only twelve fixed SIMD positions can be nonzero;
all other inputs are zero. A deterministic public inverse-SIMD/NTT matrix maps
them to all 8192 natural-order coefficients, modulo 114689. Integer constraints
then bind `W = 78307 * M mod 114689`. Boolean ranges and canonical residue slacks
exclude field-wrap and modular-alias attacks. The largest source dot product is
30181752832, below 2^35 and far below the Goldilocks modulus.

The unchanged selected commitment opens its exact tuple/salt encoding. The new
commitment absorbs public context, a fresh private salt, fixed padding and every
W coefficient in order. Three Poseidon2 gadgets share a fixed public schedule;
all current/next carry and capacity links, the first row and final word are
constrained. The producer intentionally discards its returned native digest:
acceptance comes from the AIR's final digest equality and actual SDK verifier.

Public matrix and periodic caches contain no private values. Their payloads are
393216 and 839680 bytes. The module exposes no proof codec, owner-key handle,
network verifier or production capability. New FHE dependencies are test oracles
only; runtime dependencies and core library ownership remain unchanged.

## Native and numerical validation

Windows MSVC Rust/Cargo 1.99.0, release, `-C target-cpu=native`, two Cargo jobs
and two Rayon threads, locked/offline dependencies. A fresh R3 target preserves
earlier binaries and failed attempts. Release build, test compilation and strict
all-target Clippy passed. All thirteen prior actual security reports matched
field for field, followed by the new actual analysis before any Encoding trace.

| Width / height | Public fields | Constraints | Actual degree | Periodic columns | Quotient chunks | Batched functions | Decoding bounds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 3580 / 512 | 100 | 5215 | 4 | 205 | 16 | 7340 | 128 / 128 |

Both full-width current/next openings remain. Degree hint 5, 192 FRI queries,
five random codewords, extension degree 5, four salt fields, both hiding MMCS,
fresh OS randomness and the single-opening rule remain unchanged. Per-proof
model bounds do not establish composition-wide 128-bit security.

Before any new private trace, three exact trace-free tests passed: every one of
the twelve public basis columns against every upstream coefficient; all M/W
coefficients for twenty empty/sparse/full and LIMIT 0..4 cases; and literal
original-slot placement with every other slot zero. These checks validate public
root 64917 and the native NTT convention against pinned fhe 0.1.1.

The three direct dev-dependencies are pinned to 0.1.1. The resolved lock preserves
all 82 prior package identities/checksums, adds 44 known oracle packages, and
enables the existing optional num-traits-to-libm edge. The oracle uses rand
0.9.2/rand_chacha 0.9.0/rand_core 0.9.5; the backend retains rand 0.10.3. Native
NTT remains selected; the alternative tfhe-ntt feature is off.

The first attempt failed compilation on a missing field-trait import. The next
release and test compilation passed; strict Clippy rejected precedence, three
range loops and an unused must-use return. R3 fixes those issues without changing
equations, parameters or the public matrix. No Encoding trace/proof/test ran from
either failed attempt. Their outputs are retained separately.

All 114 serial tests passed once, with zero failures, ignored or filtered tests,
in 693.23 s (693566.4031 ms observed process duration). They include all 97 prior
cases plus 17 new Encoding cases: genuine empty/nonempty composites; missing,
stale or foreign prerequisites; source/identity/salt mutations; a thirteenth
nonzero slot; coefficient-packing substitution; Boolean/range/quotient/slack
attacks; canonical modular aliases; carry/checkpoint mutations; the final word;
fresh-context replay and changed expected inputs before trace construction.
Rebuilt malicious cases reach the raw SDK prover and actual verifier. The only
stderr was the expected caught single-opening-budget panic.

The actual repository requirements-sync test also passed, compiled directly with
`rustc --test playground/tests/requirements_sync.rs -O`, without a GUI/Cargo suite.
The canonical requirements and AGENTS mirror matched after line-ending normalization.
Final edits after the frozen successful run change only three README files,
this report and two nonexecutable comments; all executable Rust text is preserved.

## Measured composite and process observations

The genuine CLI composite proved and verified successfully. Its proving timer
was 6151.8355 ms and verification timer 1355.7401 ms. Proving includes source and
Selection production/checks followed by Encoding Backend/trace/STARK work;
verification checks all three proofs with fresh Backends. Fixture preparation,
construction of the committed Encoding witness and the preceding public security
report are outside those timers. These numbers are neither Encoding-only timing
nor end-to-end SQL/FHE encryption/network timing.

The composite observer measured 7595.771 ms externally, with 40 samples at actual
165.097–209.418 ms gaps (mean 187.073282). Maximum sampled working set and observed
OS peak were 844034048 bytes; maximum sampled private bytes were 841768960.
Trace/masked/main-LDE array estimates are 14663680/29368320/234946560 bytes;
they are not whole-process memory measurements.

Matrix tests had respectively 3, 6 and 0 samples. The third was explicitly
optional and completed without a memory sample; no peak is inferred from it.
The observer requests 100 ms waits with a 1792 MiB soft observed-counter fuse.
Actual scheduling gaps, initial/final blind intervals and unobserved transients
prevent a hard or lifetime RAM claim. Each owned child is joined and its output
drained; same-source pre/post guards and immutable evidence bind every phase.

The complete test observer collected 3188 samples. Actual gaps were
150.166–749.555 ms (mean 217.445263), first sample at148.159 ms and last
at693146.213 ms. Maximum sampled working set and observed OS peak were
1002078208 bytes; maximum sampled private bytes were1022963712. These values
belong to the test process, not to a deployed peer or a lifetime RAM guarantee.

Generated local evidence remains ignored and is not committed:

| Evidence | SHA-256 |
| --- | --- |
| Frozen R3 source, parent `274be37` | `A239EC196BBC0B6A527516EA1EAA2395511A53BCA37FC0A71AF05CF7846A717E` |
| Three-command compile receipt | `B0A7456767D28B5027805691484A7B1BE9BEE9966DD71F633C041E98D6760445` |
| CLI executable | `6C1EADC553FED1174AC34A67B10846119AC70A8FE8DEC340535E4F60DE1F018B` |
| Test executable | `7F0FD9D446EBCBD6DAA584EA39292C9F107E590BFD64C91D5457A62C11A625D7` |
| Fourteen actual numerical reports | `A1E6D86B470B59CFD89DFB8FA130BC80FABC6183291C9BF0120497F4F7D369BC` |
| Three trace-free matrix tests | `3F06985557652330F37F589120F487DD64C4F9FD0A6EF24557ECA207A68CFCD5` |
| Genuine composite | `1C20A250DB6C40C196648E1EC0B3BEF1BF2BED6E914962870F749D5ADD08AB70` |
| Full 114-test observation | `4DE2907DD4EA7026EE055645131F69992F1F5AB39393ED9993D8A4098B3E77F8` |
| Lifecycle observer | `76AF1EBF787FBEB5FA84098B8016E6EE27B27A4F0D5C98D0F1C286B02D53C609` |


## Reproduction

Use the pinned toolchain and environment above. The standalone experiment is
outside Cargo default/core members:

```powershell
cargo build --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
cargo test --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --no-run
cargo clippy --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --all-targets -- -D warnings
```

Run all security cases first, then the three exact upstream matrix tests, then
`hiding-fri-source-primitives prove selected-encoding`, then the complete serial
test binary with `--test-threads=1 --nocapture`. The ignored local observer
records actual argv, binary/source hashes, outputs and samples. This order keeps
the public coefficient convention and numerical security gates ahead of the new
private trace. Fresh dependency resolution must preserve the recorded oracle
versions/features; previous-profile results do not validate a changed profile.
