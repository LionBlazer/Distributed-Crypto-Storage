# Registry200 logical WriteImage validation

This change proves a separate fixed-N4 AddAmount eligibility and complete logical
afterimage relation. It adds no SQL admission, encrypted data writeback, mutable
Source application, transaction data overlay or commit/rollback implementation.
All native fixtures are explicitly PUBLIC NONSECRET. Parent labels alone do not
establish history, agreed freshness or controller-signature possession.

The shared [write module](../../crates/registry200-proof/src/write/README.md) owns
the statement, layout, AIR and profile. The [private consumer](src/opening/registry_lifecycle/write/README.md)
owns SQL compilation, witnesses, traces, bounded framing and tests. Its
[Journal preparation](src/opening/registry_lifecycle/journal/write_input.rs)
uses genuinely accepted, owner-signed Bootstrap, Begin and Acquire transitions.
No production wire allowlist or control application accepts the new relation.

## Proven relation and preserved contracts

- Every one of the four original rows is selected iff its actual Source age
  matches the private 256-age mask. Each selected row requires the active,
  nonfailed actor's own NoKeyUpdate or Update holding, including zero delta.
- Exact integer u16 addition preserves every unselected amount, age, full RowId,
  TableId and original ordinal. One selected overflow rejects the entire result.
  Empty selection still requires a valid actor and counter room.
- Full u64 actor/revision/sequence limbs and Boolean successor/carry constraints
  prove counter room; no counter or registry is advanced by this relation.
- The client compiler retains its nonce and independently reconstructs q from
  SQL identity and parent before binding Source or hashing the private command.
  AIR proves the committed semantics; it does not parse arbitrary SQL text.
- The Source proof is genuinely verified before the child trace factory. Fresh
  decoding verifies and drops Source before decoding the child, with independently
  selected statements, canonical encoding, fixed topology and allocation budgets.
- The extracted canonical registry, opening and predicate gadgets preserve the
  old expression and constraint order. All 25 old profile digests and all three
  old Source/Bootstrap/Lifecycle security reports are exactly unchanged.

The new profile is
`1197af7799932348864e41c6a355af7a0a213022fc49b9557b0c6ce36938d118`.
Actual symbolic analysis reports width 4216, PV128, height 512, 15,095 constraints,
degree 3, quotient chunks 16 and 8,612 batched functions. Both individual security
bounds are 128 bits. This is not a composed 128-bit or whole-protocol security claim.
The main-LDE estimate of 276,627,456 B counts that array, not process RAM.

## Actual native validation

Validation used Rust 1.99.0 MSVC, Windows 11 Pro 10.0.26200, an AMD Ryzen 9 9950X3D2
(16 cores/32 logical processors), native CPU code generation, Cargo jobs 2 and
Rayon threads 2. The OS reported 98,190,636 KiB visible physical memory. Dependencies
were locked and offline; historical targets were copied without hardlinks into
an exclusive target. No previous executable or accepted proof was overwritten.

| Check | Actual result |
| --- | --- |
| Default core build and strict affected core/leaf Clippy | Passed |
| Owning tests | 90 passed, 0 failed, 0 ignored across 21 direct artifact commands |
| New WriteImage tests | All 10 passed; all 72 old leaf Registry200 tests and 8 shared-library tests also passed |
| Requirements and architecture contracts | 1+1 passed, compiled from their actual repository test sources |
| Library doctests | Completed, 0+0 existing examples |
| Old proof compatibility | Current verifier reverified exactly 8 historical Source/child pairs without owner, fixture or prover |
| Genuine new CLI | Signed history, Source+Write proof, encoding, private preparation drop and fresh public-only verification passed |

The new tests include real SDK rejection of coherently rebuilt hostile traces,
missing/foreign Source before the child factory, full high-u64 limbs, failed or
foreign actors, weak/other-owner/last-row holdings, empty/zero/all selections,
overflow, all four identities/amounts, padding, salts and nested decoding bombs.
High-u64 conditional fixtures do not claim reachable signed histories. A real
same-root sibling reorganization produces Journal `Reorganized`; the historical
mathematical proof remains valid without granting current-use freshness.

The old public journal replay retained 237,896,864 B, height 8 and its exact tip;
actual reopen verification took 13,356.1026 ms. It contains Bootstrap and all seven
old operations. The new CLI's three actual history bodies measured 21,731,391,
30,886,159 and 30,878,479 B, below the unchanged signed-Body limit. Chosen parent,
registry, Source and 83,501,225 B Journal accounting remained unchanged afterward.

| New CLI observation | Value |
| --- | --- |
| Source proof / child proof / frame | 19,303,743 / 7,497,327 / 26,801,190 B |
| Internal complete CLI time | 31,252.8371 ms |
| External process elapsed | 31,383.7732 ms |
| Generation including three-body history and private preparation drop | 29,946.0343 ms |
| New Source/Write/frame generation phase | 6,112.7675 ms |
| Fresh bounded public-only decode and verification | 1,306.759 ms |
| Sampled WS / private / observed OS peak WS | 1,016,107,008 / 1,013,157,888 / 1,016,107,008 B |

The distinct DCSRWI01 frame uses role 0xA1 and a 120-byte header. Hard limits remain
32 MiB total, 20 MiB Source, 12,578,091 B child, sequence length 16384 and decoded
element budgets 24 Mi/16 Mi. Decoded-element budgets count elements rather than
bytes. These caps do not establish process RSS or future two-CAS signed-Body fit.

The CLI memory observation contains 125 samples of one local process, nominally
100 ms apart, with an actual maximum gap of 521.9007 ms. The affected suite sampled
18 of 21 commands and 22 process instances; 3 short commands had no samples. Suite
maxima were WS 1,533,468,672 B, private 1,546,850,304 B and observed OS peak WS
1,533,468,672 B, with a maximum gap of 1,353.1402 ms and at most 3 aligned processes.
No soft fuse fired. The 21 command elapsed times total 2,542,468.5326 ms; the longest
was 900,927.1393 ms. These observations establish neither a hard memory limit nor
whole-peer, full-FHE-query or network-wide resource guarantees.

## Reproduction and retained evidence

Set `RUSTFLAGS=-C target-cpu=native`, `CARGO_BUILD_JOBS=2` and
`RAYON_NUM_THREADS=2`, using the pinned toolchain and a fresh target. Build
`dcs-peer` and set `DCS_PEER_EXE` to its absolute release executable for the real
process test. The two new gates are:

~~~powershell
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- security registry200-write-image
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove registry200-write-image
~~~

Run both shared-library test targets and the leaf `opening::registry_lifecycle::`
namespace with `--include-ignored --test-threads=1`. The recorded run compiled and
discovered actual artifacts, split the namespace into owning groups and ran each
new test by its exact name. It did not rerun unrelated repository suites.

Local ignored receipts preserve all earlier unsuccessful attempts and the final
R4 inputs, commands, executable hashes, output hashes and memory CSVs:

| Record | SHA256 |
| --- | --- |
| Frozen author snapshot | `69EDCFADF3242EDAD39521D8A91B9C31715D07DA43FB69CCB42C81BDF5BFE1CF` |
| Native R4 source manifest | `CC495630E69A4D4B80BF839241053132CFD46C3F1067E94D3DED70361C835A28` |
| Compile receipt | `B4D9F84D6312FDB638E37ABE5410793B71C4D902BE8A561F7A8C24470F610F0C` |
| Numeric receipt | `2199F88E8840268576E2C55E60DDFAA0D42A7D425EE7888B9C5D570971504469` |
| Prove/replay receipt | `A94F80ADE9767509033C74D4B8D540331142AD0147447191002B1266C8AD3864` |
| Tests receipt | `16932DEE6AE09A2039324F16C6B34361600C2FADD33F69D3A2C4105E5BA1341A` |
| Native closure | `291426FAF9F1DC44323E2DD4FEBACDBAD0E0CC8FB0C3D9E3381B76737521B9FB` |

There are 1,152 frozen native inputs: 1,146 project files and 6 ignored probe source,
manifest and lock files. This is not a tracked-file count. All 2,581 protected
historical PE images, 864 SDK files and 6,521 old receipt/evidence files remained
unchanged. Three failed compile attempts exposed two unused imports, one invalid
error variant and two non-Drop drop calls; the five fixes changed no mathematics.
Independent frozen-source and native-evidence reviews found no remaining issue
within this stated relation. Native field/FFT/proof scratch is not guaranteed
securely erased by dropping private owner preparation.

## Remaining implementation obligations

This relation does not establish a peer FHE predicate, ciphertext UPDATE,
Source-to-formed-operands/result linkage, new AEAD/index images, atomic
Source+control CAS, writer fencing, transaction-private data overlays, MVCC,
agreed freshness, decentralization/finality, scaling or full PostgreSQL SQL.
The SQL goal has no fixed 500 ms latency target and remains active.

The parallel audit additionally found that legacy SQL-facing selection uses an
owner-authenticated exact selection before arithmetic, and Jobs mutation admission
does not prove output equality to new encrypted images. Genuine arithmetic is
not the missing composite SQL proof. A separate fail-closed client/server change
is being prepared; this validation does not certify those legacy SQL paths.

Existing C_open and C_image include query context and cannot be renamed stable
Source-image commitments. A future stable image needs its own domain/profile,
genuine Source bootstrap and actual-parent transition invariant. Repeated writes
need a private data overlay and encrypted durable owner openings. Two current
Source proofs already exceed a 32 MiB Body before BFV/merge evidence; concatenation,
larger quotas or unproved intermediate publication cannot solve that blocker.
