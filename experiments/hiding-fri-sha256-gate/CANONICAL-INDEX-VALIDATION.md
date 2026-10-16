# Canonical four-row private index opening: validation

Status on 2026-10-16: native release build, test compilation, strict all-targets
Clippy, nine numerical analyses, one genuine proof/verification and all 60 serial
tests passed. All fixture keys, rows and identities are PUBLIC NONSECRET.
This nonaccepting gate extends the [whole-pair opening](src/opening/README.md)
with the real canonical N4 index invariant. It is not typed SQL or a lock API.
The [historical byte-opening report](PAIR-OPENING-VALIDATION.md) is unchanged.

## Exact bounded relation

Complete public CSTORE images contain 172 data bytes and 2496 index bytes,
including independently supplied 112-byte expected heads. The core canonical/root
parser audits every packet before AIR construction. The SAME exact source enters
691 public fields and verifier-owned AIR constants. Public SHA verification
outside AIR replaces no private AEAD computation.
One private master key opens BOTH actual XChaCha20Poly1305 packets with exact
packet-revision AAD, nonces, 42 H/Cha jobs, 163 MAC blocks and ciphertext XOR.
C_key must be fixed independently. Fresh private salts bind all 2348 authentic
plaintext bytes under C_open and the NEW semantic profile. Keys, salts, ages,
TableId and RowIds are not public values or periodics. Candidate commitments and
the hiding backend are experimental, not production key custody/cryptography
or an independently certified ZK construction.

The real four-row age/u16LE-amount index is 2336 bytes:

| Bytes | Enforced content |
| --- | --- |
| 0..111 | Exact data head |
| 112..143 | Nonzero private TableId |
| 144..1167 | All 256 age counts |
| 1168..2195 | All 257 prefix offsets |
| 2196..2199 | Four canonical one-byte postings |
| 2200..2207 | Eight zero unused/alignment bytes |
| 2208..2335 | Four nonzero pairwise-distinct 32-byte RowIds in ordinal order |

A Boolean 4x4 permutation covers every ordinal once and sorts (age,ordinal).
Bounded differences/zero tests enforce ties; postings use absolute first ordinals
and positive within-bucket deltas. Counts/offsets match the SAME authentic ages.
Eight reusable comparison slots check every header word at the existing P2
input, including stale-word carries. Ages/P are constant on all 512 rows, with
actual data binding at row 80. TableId capture covers both halves; IDs are checked
together at row 485. No permanent bucket/ID bank or second full trace is added.
The [core-owned vector](../../crates/compact-query/tests/fixtures/README.md) is
checked against the actual private core encoder at its owning boundary.
The experiment consumes its suffix plus the REAL data-head prefix: ages
[255,0,255,128], amounts [0,65535,256,255], TableId 31hex repeated 32 times, RowIds
with last bytes 1/2/3/4, postings 01/03/00/02. No compact-query dependency, encoder
API or Owner-key exporter is added.

## Actual numerical gate

All nine security-only calls exited 0 with blank stderr and no trace/proof/test.
The prior eight reports exactly match their recorded R5 values.

| Canonical item | Actual value |
| --- | ---: |
| Height / width / public values | 512 / 11521 / 691 |
| Opening points / periodic columns | 2 / 512 |
| Constraints / inferred degree | 28949 / 4 |
| Declared bound / quotient chunks | 5 / 16 |
| Batched functions | 23222 |
| Unique / list decoding estimates | 128 / 128 |

Both full-width openings count: 2*(11521+5)+10*16+10=23222. The conservative
declaration was not lowered. PCS/MMCS, OS-seeded RNGs, 192 queries, five random
codewords and proof-degree bits 10 are unchanged. These are pinned SDK-model
estimates, not empirical security/privacy certification.
Separate arrays are trace 47,190,016B, masked 94,420,992B and main LDE 755,367,936B.
The 512x512 periodic payload is 2,097,152 B; estimated periodic LDE is 33,554,432 B.
These are not additive process peaks and omit quotient, DFT, tree, expression,
stack and proof-copy overhead.

## Genuine proof, tests and observation

One prove canonical-index-opening process exited 0 after genuine verification:
2759.8668ms proving /649.3903ms verification. Proving includes witness trace
generation and STARK proving. Fixture encryption, complete public source audits,
numerical analysis and Backend construction precede that timer. Verification
uses the same in-memory Backend/proof. No codec, network, Owner API, SQL or
finalized acceptance is timed. Outer observation was 4055.3742ms including
process/setup/sampling overhead, not clean end-to-end SQL latency.
One complete executable invocation with --test-threads=1 --nocapture passed
60 tests, 0 failed, 0 ignored, 0 filtered, in 544.77s. All 47 old cases remain.
The 13 new cases cover native/core-vector equivalence, boundary/reordered ages,
genuine cross-profile rejection, all counts/offsets/carried header words,
postings/padding, nonzero identities/all six differences and fresh commitments.
Rebuilt malicious cases preserve real AEAD/roots and recomputed C_open and reach
the raw SDK. Coherent fake-age/index banks and forged retained TableId halves
isolate actual source capture. Only the expected caught single-opening-budget
test panicked on stderr. The full run was not retried or filtered.

The owned-child observer requested 100 ms waits, two Rayon threads, a 1792 MiB
observed WS/private/OS-peak fuse, and 600 s proof / 1200 s suite timeouts.
Only its own child is killed/joined on failure. Neither actual run aborted:

| Run | Samples | Actual gaps, ms | Max observed WS | Max observed private | Max sampled OS peak |
| --- | ---: | --- | ---: | ---: | ---: |
| Genuine proof | 22 | 160.432–200.289 | 842698752B | 839798784B | 842698752B |
| Full60 | 2372 | 156.674–683.871 | 1004400640B | 1025351680B | 1004400640B |

Suite outer duration was 544845.6938ms. Sampled OS high-water values are not final
lifetime peaks or a hard memory cap; private bytes are not RSS. Numerical calls
were not memory-observed. One instrumented fixture proves no median/p95,
causal speedup, whole-query, 500 ms or general RAM result.

## Source, failures and reproduction
Parent 5a4eba146a85119ee2e1fe8b27d0e270247e6ea7; compiled R2 source freeze
0E429C3F4A12B7CDA3786D0E5CCB75AD724B62B0B83BFED35EB9E8E11258866D.
The audited 9C2136B7... standalone lock is unchanged; no resolution occurred.
First source 860756F1... built CLI/tests, then strict Clippy failed only on
manual_is_multiple_of. The ONLY repair changed the modulo predicate to
is_multiple_of(256), preserving its meaning and all equations/profile.
First source/logs/target and both original/archived executables remain.
The second build/no-run/Clippy all exited 0. Publication changes only documentation
after compilation; Rust, manifests, lock, core inputs and executables remain exact.
Current executable SHA256:
    CLI  0195D204584C8742F7F3192BC0DB59751133B4E42B279D4BEC5736DC08133548
    Test 0C217768D952FFCD9CDAB5F6E1239F8C4E7F7179607BFD57F995C06EED2CE0DF

Retained MAIN .local raw directories: canonical-index-opening-runs/
20261016-181404-964-compile, 20261016-181648-949-compile-r2,
20261016-181923-415-numeric; canonical-index-opening-observations/
20261016-182230-333-Prove and 20261016-182315-212-FullSuite.
Receipt prefixes: A9B19BB5/A415437F/9727AB23/E01B3951. The external untracked
observer is observe-canonical-index-opening.ps1, SHA prefix FCA779D2.
Reproduce on native Rust1.99 MSVC with a FRESH target and observed resources:

    $env:RUSTUP_TOOLCHAIN='1.99.0-x86_64-pc-windows-msvc'
    $env:CARGO_HOME='.local/cargo-home'; $env:CARGO_TARGET_DIR='.local/target-canonical-index-repro'
    $env:CARGO_BUILD_JOBS='2'; $env:RAYON_NUM_THREADS='2'; $env:RUSTFLAGS='-C target-cpu=native'
    cargo build --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --release --offline --locked
    cargo test --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --release --offline --locked --no-run
    cargo clippy --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --release --offline --locked --all-targets -- -D warnings
    $exe=Join-Path $env:CARGO_TARGET_DIR 'release/hiding-fri-source-primitives.exe'
    & $exe security canonical-index-opening
    & $exe prove canonical-index-opening
    & (Get-ChildItem (Join-Path $env:CARGO_TARGET_DIR 'release/deps') -Filter 'hiding_fri_source_primitives-*.exe').FullName --test-threads=1 --nocapture

Numerical controls also used security sha256/hchacha20/chacha20/poly1305-raw/
poly1305-padded/pair-opening, plus both Poly modes with empty. No numerical,
proof or suite rerun or hidden warmup was used; the compile repair is retained.

## Remaining requirements
Only the current bounded N4 map is proved. Independently expected private TableId,
cross-version/shard continuity and global uniqueness need separate anchors/
transition proofs; a fresh well-formed mapping is allowed. Typed/NULL catalogs,
semantic plans/predicates, BFV original-input formation, private locks/conflicts/
SKIP/OFFSET, production key custody, freshness/finality and live proof acceptance
remain unmet. The full encrypted PostgreSQL/500ms goal is not narrowed to this gate.
