# Native streamed lookup validation

This record covers the isolated `p3-multi-stark 0.8.0` counted-lookup prover
extension. Both dense and streamed modes compiled, and all selected runtime
tests passed against the original verifier. This is an SDK compatibility gate,
not a complete NTT batch, private SQL proof, decentralized head or SQL grant.

## Source and dependency boundary

[UPSTREAM.json](UPSTREAM.json) pins the registry archive SHA256
`0437304B3289D7A0FE3E758E5998CB909FC7D2131F6F1FEE9ED78C679F8C70FA`,
its 83 packaged file hashes, and archive VCS metadata
`a21e3ed42905040ad49c519e402f018381c12d0c` (`multi-stark`). The external VCS
checkout was not acquired. [LICENSE-MIT](LICENSE-MIT) preserves the chosen
upstream permission. Cargo.toml.orig remains the original manifest.

Exactly six packaged paths differ: Cargo.toml, Cargo.lock,
src/fractional_gkr/materialize.rs, src/fractional_gkr/prover.rs,
src/lookup/mod.rs and tests/whir_fibonacci.rs. The other77 packaged paths are
byte-identical. Original dense materializer/prover and inherited WHIR test file
prefixes remain byte-identical; new test code is appended. No inherited test body
was changed, removed or newly ignored. Three serialized upstream compatibility
fixtures remain exact public, nonsecret test inputs.

The standalone manifest restores ten normalized-out upstream path-only development
edges and adds p3-goldilocks for the new EF5 parity test, all at exactly 0.8.0.
Its reviewed lock has 149 packages (148 registry dependencies and
the local package), with every p3 package at 0.8.0.
The root Cargo manifest, lock, members and default dependency graph are unchanged.
The original registry SDK, prior executable artifacts, tools and validation
receipts were guarded against modification throughout native validation.

## Executed checks

Windows x86_64 MSVC, Rust 1.99.0, release mode, locked offline dependencies,
`RUSTFLAGS=-C target-cpu=native`, `CARGO_BUILD_JOBS=1` and
`RAYON_NUM_THREADS=2` were used. Both modes selected the library and all six
integration targets. Test bodies ran sequentially within each target.

| Mode | Discovered cases | Executed and passed | Explicit fixture-writer skips |
| --- | ---: | ---: | ---: |
| Original dense, default features | 515 | 513 | 2 |
| `streaming-lookups` | 516 | 514 | 2 |

The total is 1027 runtime invocations, covering 514 distinct runtime cases.
All 11 new cases executed: ten in both modes and one streamed full-WHIR case.
The 14 target processes exited successfully. Originally ignored heavy unit tests
were included. Exactly two originally ignored tests that WRITE compatibility
fixtures were excluded: `generate_the_compatibility_fixture` and
`generate_whir_fixture`. Compatibility readers and checks still ran.

Coverage includes scalar/packed, tiny, base/extension, BabyBear, binary and actual
Goldilocks/EF5 parity; byte-identical proofs and equal final challenger state;
nonzero intermediate rational numerators; mixed table heights, preprocessing,
public values, clamped next rows, boundaries, neutral padding and malformed
source geometry. Genuine foreign reductions are rejected through actual AIR
links. The added WHIR consumer creates a full proof, roundtrips its canonical
bytes, verifies with the original fresh verifier and rejects damage.

The feature-enabled doctest command also succeeded, discovering **zero doctest
cases**. It is not counted in the runtime totals above. Requirements and their
AGENTS.md mirror matched before and after the native checks.

## Reproduction

Use the pinned toolchain, this standalone Cargo.lock and a fresh target. These
commands explicitly select tested targets rather than compiling upstream examples:

~~~powershell
$env:CARGO_BUILD_JOBS = '1'
$env:RAYON_NUM_THREADS = '2'
$env:RUSTFLAGS = '-C target-cpu=native'
$sdkTargets = @(
  '--lib',
  '--test', 'backend_contract',
  '--test', 'tiny_machine',
  '--test', 'whir_bus_boundary',
  '--test', 'whir_fibonacci',
  '--test', 'whir_periodic',
  '--test', 'whir_preprocessed'
)
$sdkTestArgs = @(
  '--include-ignored',
  '--skip', 'generate_the_compatibility_fixture',
  '--skip', 'generate_whir_fixture',
  '--test-threads=1'
)
cargo test --release --locked --manifest-path experiments/p3-multi-stark-streaming/Cargo.toml @sdkTargets -- @sdkTestArgs
cargo test --release --locked --manifest-path experiments/p3-multi-stark-streaming/Cargo.toml --features streaming-lookups @sdkTargets -- @sdkTestArgs
cargo test --release --locked --manifest-path experiments/p3-multi-stark-streaming/Cargo.toml --features streaming-lookups --doc
~~~

The recorded harness first compiled with `--no-run --message-format=json`,
checked executable discovery and source pins, and then invoked each selected
test executable with the arguments above. Its receipts include source and
executable hashes, complete results and sampled process observations. Generated
artifacts, receipts and local helpers are deliberately untracked.

## Resource observations and remaining limits

At a padded Goldilocks/EF5 lookup cube N=2^24, the old dense leaves plus all
reduced layers require 2,147,483,488 bytes. The new principal GKR arrays have a
calculated 45N bound, 754,974,720 bytes, plus bounded scratch, metadata and proof
messages. It regenerates leaves from the same committed immutable tables, drops
the current layer before the next and drops input equality before allocating
folded arrays. It does not spool a witness to disk.

This is an array calculation. Committed traces, preprocessing, PCS state, keys,
allocator overhead and process memory remain outside that bound. The largest
sampled working set among these small test processes was 155,553,792 bytes;
sampled private bytes reached 143,937,536. These are not resource measurements of
the N=8192 NTT batch. Sampling nominally every 100ms and a 1792MiB per-process soft
fuse do not establish a hard process memory limit. No whole-batch fit or speed
claim follows from these regressions. Repeated leaf evaluation adds work.

Earlier revisions exposed test import/type errors, which were fixed before the
final frozen run. A broader compile attempt also reached the unchanged upstream
`prove_boolean_trace` example and failed in LLVM allocation with rustc exit
`0xc0000409`. The successful gate selects all library/integration tests; that
example and upstream benches remain unvalidated here. Failed receipts and
targets were preserved rather than overwritten or reported as passing.

No proof format, verifier, full transcript source, security analysis, proof cap
or cryptographic acceptance policy changed. The original non-hiding protocol
remains non-hiding. In particular, this extension does not conceal WHERE,
establish full BFV multiplication/relinearization, prove SQL completeness or
supply fresh decentralized agreement. Historical SQL failures are not made
green or included in this SDK test total.

## Local evidence pins

These SHA256 pins identify ignored local receipts, not portable build outputs.
The frozen native source predates final README/report edits; the final closure
checks that subsequent differences are documentation only.

| Local receipt | SHA256 |
| --- | --- |
| `.local/streamed-sdk-validation-r5/source.json` | `BCA56715ADA55D25ACE20DFFE67864A07D50E10E712D97C07B0C6D75834061A1` |
| `.local/streamed-sdk-validation-r5/compile/success.json` | `322D4041A7B0FE203D81D602A16FC447240614870909BFDB2172C056156DE6A6` |
| `.local/streamed-sdk-validation-r5/tests/success.json` | `E679CAC40DB9A9F5755DAC414FD1BCAFF0E5B8EF90BABBE98486DD39DB78486D` |
| `.local/streamed-sdk-validation-r5/docs/success.json` | `B7C7AEBA90F7354801E69B3026615F68CC639EFDB559E4109288BD163C6325A8` |
| `.local/streamed-sdk-review-r1/success.json` | `6FF308044BA304DC5AED9C5AC48745636CD69CB5495864003012626FA96C74D4` |
| `.local/native-output-batch-r1.py` | `271EBD4FAB2D54C7F7F71CBCB065CA637906F7526C6FE6559CDD012D224FAC35` |

These component tests do not complete the repository Goal.
