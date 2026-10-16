# Whole-pair AEAD byte-opening validation

On 2026-10-16 the frozen R5 experiment passed release compilation, strict
all-target Clippy, eight fresh security-only analyses, all **47 serial tests**
(33 retained primitive/backend cases and 14 opening cases), and one separately
observed genuine whole-pair proof followed by verification. No tests were ignored.

This is a fixed, experimental **byte-opening**, using an explicitly PUBLIC
NONSECRET fixture key/plaintext in private witness columns. It adds no Owner-key
export/import, production acceptance API, network proof codec or SQL path.
The construction and hiding assumptions remain research candidates, not a
production cryptographic selection or empirical witness-secrecy certification.

## Relation actually exercised

The [module contract](src/opening/README.md) fixes two complete public CSTORE
images: 172 data bytes and 2,496 index bytes, including their 112-byte heads.
Their plaintext lengths are 12 and 2,336 bytes. The same private-in-proof key
must authenticate/decrypt BOTH packets; all 2,348 decrypted bytes enter a fresh
salted opening commitment. The first 112 decoded index bytes equal the public
data head. Other index bytes are fixture bytes: this does not prove index grammar,
RowId uniqueness, candidate coverage or a logical SQL source relation.

The verifier's canonical core audits bind every public packet to independently
supplied exact heads before AIR construction. Public SHA/root work stays outside
AIR; exact ciphertext/head words are also public values, not merely an outer label.
One relation links all 42 HChaCha/ChaCha jobs, 163 padded Poly1305 blocks, actual
ciphertext XOR, header linkage and both fixed-encoding Poseidon2 commitments.
Packet revision, not global snapshot revision, supplies the exact 106-byte AAD.

There are 691 public fields. K/subkeys/Poly keys, plaintext, salts and intermediate
states remain witness columns, not public values or periodic columns. The fixture
fixes C_key independently before its request and uses a fresh salted C_open.
A random key-domain alone is not an anchor. Production anchor authorization,
key custody/rotation, erasure and recovery are not implemented by this experiment.

## Actual geometry and numerical gate

| Field | Actual R5 report |
| --- | ---: |
| Trace height / width | 512 / 11,079 |
| Constraints / inferred degree | 27,835 / 4 |
| Declared conservative degree bound | 5, retained unchanged |
| Quotient chunks / batched functions | 16 / 22,338 |
| Opening points / public periodic columns | 2 / 512 |
| Unique / list decoding estimates | 128 / 128 bits |

Both **complete** width openings are counted: `2*(11079+5)+10*16+10=22338`.
The inferred degree and declared sizing bound are distinct; no hint/profile was
lowered after observing degree four. All eight analyses passed the pinned SDK
model: SHA-256, HChaCha20, ChaCha20, nonempty raw/padded Poly1305, both empty
Poly1305 modes, and the fixed pair. Empty Poly1305 infers degree two; nonempty
Poly1305 and ChaCha infer degree three. These estimates are not production
security certification, empirical ZK evidence or a general composition theorem.

Separate source-derived payload estimates are 45,379,584 trace bytes,
90,800,128 masked-trace bytes and 726,401,024 main-LDE bytes. The public selector
table occupies 2,097,152 bytes; its full LDE payload estimate is 33,554,432 bytes.
They are not additive process peaks. Quotients, symbolic expressions, trees,
DFT scratch, salts, copies, stacks and allocator overhead remain additional.

## Genuine and malicious behavior

The current full run passed all 47 exact test names once, with zero ignored or
filtered cases. Ten SHA/shared-backend, nine ChaCha and fourteen Poly1305 cases
were retained; fourteen cases exercise the linked opening. The raw test output
contains only the expected caught panic for reusing one hiding opening budget.
The test harness reported 303.08 seconds; this is an observed test run, not SQL.

| Boundary | Examples exercised by the current tests |
| --- | --- |
| Native arithmetic | RFC/oracle bytes, canonical Poly1305 boundaries, internal Poseidon2 equivalence at field boundaries, partial stream tails |
| Public source | Complete canonical images, altered roots/packet revision/tag/nonce/head, noncanonical digest encoding |
| Private coupling | Genuine same-key packets, inconsistent H/subkey/counter0/stream jobs, wrong plaintext despite a correct MAC |
| Retained state | Key banks, output buffers, ten carry words and inactive/gap/padding rows |
| Commitments | Fresh salt, wrong anchor, overwrite/capacity/reset/padding mutations, exact public-statement replay |
| MAC semantics | Full hibits, independent segment padding, length blocks, page reset and matching false packet tags |
| Isolated anchor failure | BOTH packets and components valid under another key, old C_key retained, native C_open recomputed with the old-anchor context |

Malicious cases rebuild proofs through the raw SDK, rather than relying only on
honest generator rejection or an early wrapper guard. A positive native trace
alone was insufficient to catch the selector regression described below.
Five selected native cases and an earlier genuine proof also ran on R3; those
are retained historical evidence, not separate validation credit for R5.

The fresh R5 CLI proof verified successfully: **3,170.7397 ms proving** and
**743.99 ms verification**. These are one process's internal timers, not medians,
a clean benchmark, a full SQL operation or a causal comparison with R3.
The proving timer includes witness generation through the trace factory and
STARK proving. Fixture construction, complete public-source audits, security
analysis and Backend construction occur before that timer. Verification uses the
same in-memory Backend and proof; neither timer includes serialization, network
transport or Owner SQL. The external observation includes process/setup/sampling
overhead and is not a clean end-to-end latency benchmark.

## External observations and limits

| R5 process | Samples | Actual sample gaps (ms) | Max sampled WS / private / observed OS peak (bytes) |
| --- | ---: | --- | --- |
| Numerical pair analysis | 2 | 220.771 | 122,417,152 / 122,650,624 / 122,454,016 |
| Full 47-test process | 1,446 | 152.936-717.783 | 982,437,888 / 1,000,947,712 / 982,437,888 |
| Genuine pair proof | 22 | 181.369-239.595 | 813,002,752 / 810,115,072 / 813,002,752 |

The observer requested 100-ms waits and aborted an owned child on observed memory
at 1,792 MiB or a 600-second timeout, with bounded output drain and final kill/join.
Actual gaps above remain included. Several tiny numerical controls finished with
zero samples: their memory is unknown, not zero. Full-suite outer observation
was 303,220.8347 ms; the proof process's outer observation was 4,898.7496 ms,
including work outside its two internal timers. All current runs exited normally.
Sampling and sampled OS counters do not establish final/lifetime peaks, a hard
OS memory limit, general resource compliance, throughput or 500-ms performance.

## Reproduction and provenance

Validation used Windows x86_64 MSVC, Rust `1.99.0 (b940084d7 2026-09-28)`,
`RUSTFLAGS=-C target-cpu=native`, Cargo jobs 2, Rayon threads 2 and P3 0.8.0.
The isolated standalone lock has 82 packages: all 75 prior registry versions and
checksums remain exact; five pinned registry records and local compact-store
were added. The only changed old active edge is crypto-common to rand_core 0.6.4.
All 19 P3 records remain pinned. The compact-store path dependency's compiled
source controls are included; root workspace changes cannot be assumed irrelevant.

```powershell
cargo build --offline --locked --release --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
cargo test --offline --locked --release --no-run --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
cargo clippy --offline --locked --release --all-targets --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- -D warnings
& $binary security sha256
& $binary security hchacha20
& $binary security chacha20
& $binary security poly1305-raw
& $binary security poly1305-padded
& $binary security poly1305-raw empty
& $binary security poly1305-padded empty
& $binary security pair-opening
& $tests --test-threads=1 --nocapture
& $binary prove pair-opening
```

`$binary` and `$tests` denote the recorded release CLI and test executables.
The actual runs used the external observer; these direct commands do not supply
its memory/timeout fuse. No rebuild followed the authorized documentation edits.
Compiled Rust, Cargo manifest/lock and compact-store controls remain the R5 bytes;
the publication record separately identifies README/report-only changes.
The build parent was `5940df3521a8cd420aec6d5e09788c6201658338`, with reviewed
uncommitted source; that parent alone does not identify the compiled candidate.

`MAIN` is `E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage`.
Local evidence remains under `MAIN/.local/` and is not committed:

| Evidence | Local identifier |
| --- | --- |
| R5 source freeze | `whole-pair-opening-source-r5-20261016-171237-412.json`, SHA-256 `90A81C847C7F5B5B743D6B86A8CB75EB2BBBDD77E42B3C9F443C1E26AD7219D1` |
| Resolved lock | SHA-256 `9C2136B7108DDE3F5C9C58ACEEBF0A4D19EAA1D234149B98C2B470DEF726F777` |
| Successful compile | `private-pair-opening-runs/20261016-171258-935-compile-r4`, receipt `D385136A...` |
| CLI / test artifacts | `target-private-pair-opening-r4/release/`, SHA-256 `559EF2E4107BEE26D1BB21C70D33A08F91E971262C77E02A173F55E31F8D2000` / `3EA72A5DD10051C52F64CF241BB580CCD6184C2D2AD40351E3E1233C6C2A21A8` |
| Fresh numerical / full suite / proof | `private-pair-r5-observations/20261016-171802-650-Numeric`, `171828-723-FullSuite`, `172400-896-Prove` |

All first failures remain, rather than being excluded or overwritten. The first
R2 compile ended 0/0/101 on four Clippy findings; R3 corrected only those lints.
The first R3 numerical SHA command exited zero with correct math but no memory
sample, stopping its observer; its report was reused once and the remaining
seven analyses ran without rerunning SHA. R3's full suite then failed **45/2**:
shared tag-carry code incorrectly used `1-is_last_row`. The pinned SDK's last-row
selector is unnormalized `Z_H/(X-g^-1)`, not a Boolean flag; the native checker
uses Boolean flags and missed it. An explicit inactive-tag selector restores
`is_transition()` for the public wrapper while preserving the opening's periodic
complement. R4's new nonzero-final-carry regression assertion triggered one
manual-contains lint; R5 changed only that assertion to `contains`. Fresh R5
compilation, all eight analyses, all 47 tests and the CLI proof passed afterward.

Historical [SHA](VALIDATION.md), [primitive](PRIMITIVES-VALIDATION.md),
[Poly1305](POLY1305-VALIDATION.md) and [source-relation](SOURCE-RELATION.md)
records are unchanged. This bounded result does not implement production key
custody/anchors, private index/control completeness, BFV input formation,
freshness/finality, live SQL or locks, and supplies no production accepting grant.
