# Private input producers and reusable Owner proof epoch

The actual Source and coefficient producers now live in `registry200-proof`.
The coefficient CLI and both input16/full134 consumers call those typed producers.
`bfv-query-core` additionally owns an in-memory Key opening that can serve exclusive
sequential operand jobs with different request IDs. This is a cryptographic
library change, not general SQL or network admission.

## Ownership and preserved contracts

- One Source circuit writer serves all five existing relations. The fixed Core
  producer and verifier still accept CanonicalIndex only. No other relation was
  added to Registry admission. The experiment's two old writer files were removed.
- Source production reaudits the canonical claim, assesses the actual AIR before
  trace allocation, proves, self-verifies and uses the existing bounded encoder.
  Its explicitly owned key, salts and ages are guarded buffers.
- Coefficient witnesses capture their complete immutable Expected and role.
  `coefficients()` and `statement()` have no caller-selected role/context. The
  typed producer checks full Expected, verifies the real bounded Source proof,
  drops its decoded proof/backend, then assesses, proves and self-verifies Encoding.
  Evidence exposes only public statements and bytes.
- Low-level `circuit` traces remain explicit mathematical inputs for the preserved
  adversarial AIR tests. They confer no authority. The callback-based hostile
  producer and coherent attacker helpers are test-only experiment code.
- Poly1305 row arithmetic moved into the existing Core Source module. The AIR,
  helper mathematics, profiles and codec topology are preserved. Source remains
  W11521/PV691; the two encoding roles remain W2000/PV752 and W1288/PV772.
  DCSCEP01 keeps its 184-byte header, 20 MiB Source, 12,578,091-byte child and
  32 MiB pair caps, including all original sequence/container limits.
- `OwnerProofEpoch` proves one genuine Key33/CsHat once. Each exclusive operand
  job owns its exact canonical ciphertext/parameters, request, encoding metadata,
  fresh five result salts, noise salt and optional private W opening. Formation
  checks ALL Key33, request, complete CT/parameters and producer/context/Cw, then
  verifies the actual Key plus five Basis prerequisites before witness preparation.
  Success/cancel/drop clears that job; epoch cancellation/drop clears its opening.
- The old single-operand APIs are unchanged. The old two-operand scope shares a
  private implementation helper and still has one request, exactly two operands,
  terminal completion and private-material cleanup after Input1.
- Neither opaque Owner type exposes Clone, Debug, serialization, import, secret
  getters or callbacks. Request IDs are labels, without a freshness/replay ledger.
  Guarded buffers do not establish erasure of field vectors, traces, SDK, FFT,
  allocator or PCS scratch.

The only lock graph changes are three already-present dependencies of
`registry200-proof`: Formation, p3-matrix and zeroize. Registry package identities,
versions and checksums are unchanged. Core has no experiment/GUI/fixture dependency.

## Native validation

Validated from parent `a64ef2f1f1efa17cc7a45f038679c3bfad2f8c11` on
`codex/feature/sql-latency`. The host reported AMD Ryzen 9 9950X3D2, 32 logical
processors, 100,547,211,264 bytes physical memory and Windows build 26200.
Rust 1.99.0 MSVC, release, `target-cpu=native`, two Cargo jobs and two Rayon
threads were used with offline/locked dependency resolution.

Workspace check, strict all-target Clippy for the two changed Core libraries and
the consumer, task Rust formatting, architecture and requirements synchronization
passed. Cargo JSON recorded seven executables, including five test executables,
the CLI and the integration build's GUI binary. The GUI binary was not executed.

| Owning boundary | Passed runtime tests |
| --- | ---: |
| registry200-proof, including two new API guards | 10 |
| New Owner epoch | 2 |
| Existing two-operand scope | 2 |
| Architecture and requirements synchronization | 2 |
| Bytes / canonical / packed / factorized Source | 14 / 13 / 10 / 7 |
| StateCertificate and accounting | 10 / 1 |
| Coefficient encoding | 11 |
| Poly1305 | 14 |
| Actual linked input16 | 1 |
| **Total** | **97** |

All 33 `bfv-query-core` doctests passed with `formation-proofs` enabled. These
include 13 new compile-fail examples for opaque traits, private fields, lifetimes
and exclusive operand jobs. They test available types, not missing-feature errors.

The epoch test generates 15 genuine proof components: one retained Key, two
Basis5/Formation jobs with distinct q, a cancelled partial Basis, and a separately
valid foreign-CsHat Key. It checks all 8192 phase coefficients in all five BFV
bases using the actual SDK. Wrong full contexts, final B word, encoding axes,
missing/swapped/stale prerequisites and terminal calls fail. Fresh public
verification succeeds after job, epoch, anchor and Owner drop. Its 189,579.6488 ms
wall time includes these controls and is not a query-latency measurement.

The CLI's ten security commands produced **16 full JSON objects**, including
**12 complete security reports**, exactly equal to the pre-change CLI output.
This compares every field, including degree, constraints, dimensions, quotient
chunks, openings and both individual security estimates. Randomized proof bytes
were not compared for equality. Historical 78,056 artifacts, 1,027 SDK anchors,
five tool hashes and retained receipts were rechecked. The unaffected 973-case
SDK/NTT validation and full134 output graph were not rerun for this extraction.

### Corrected validation findings and retained evidence

Clippy first found two test-only Poly1305 constant reexports after the move;
they now use `cfg(test)`. A new negative test then tried serializing a nonzero
PoW witness forbidden by the bounded codec. R2 correctly failed that test. The
original raw PoW negative remains; the new byte-path negative instead corrupts
a genuine trace commitment while preserving canonical topology. Serialization
succeeds and the typed producer must return actual Source `Proof(Verification)`.
No codec, proof floor or size bound was relaxed.

Before that test-only fix, the preceding 71 passing tests and all seven original
executables were retained with raw hashes. The one test body is inverse-exact
against R2; all other 1362 frozen files are raw unchanged. R3 reran the complete
11-test coefficient family plus Poly1305 and input16: 26 additional passes.
The failed R2 coefficient family is not counted. This gives 97 distinct passed
cases without repeating unaffected completed work.

### Actual input16 observation

The existing integration consumer uses the typed Source/Encoding producers,
genuine Key/Basis/Formation proofs and actual BFV inputs. After all private
producers are dropped, a new public setup verifies the saved evidence.

| Observation | Value |
| --- | ---: |
| Unique primary proofs | 16 |
| Through fresh verification | 129,887.7389 ms |
| Fresh public verification portion | 32,654.2674 ms |
| Key / Source bytes | 16,729,119 / 19,303,711 |
| Source / mask pair bytes | 23,219,174 / 22,066,726 |
| Formation bytes | 21,294,523 / 21,295,899 |
| Public spool, including duplicate Source | 264,207,679 bytes |

This measures a fixed-schema cryptographic integration, not a network SQL request.
The spool is multiple individually bounded components, not one transport frame.
The test reports output-MulRelin proof, fresh agreed head, SQL grant and composed128
as false. The unchanged full134 test calls the same producer path but is outside
this stage's runtime credit.

Across the 97 selected tests, maximum sampled per-PID working set was
1,323,233,280 bytes and private bytes 1,323,917,312; recorded OS peak working set
was 1,323,233,280. Sampling targeted owned processes at nominal 100 ms, with an
observed maximum gap of 411.2273 ms. Architecture, requirements and accounting
finished without samples. The sampled 1792 MiB per-PID soft fuse and 1200-second
per-command stop were not reached. These observations establish neither a hard
sampling interval nor a whole-peer RAM/latency guarantee.

## Reproduction and receipts

Use Rust 1.99.0, `RAYON_NUM_THREADS=2`, `CARGO_BUILD_JOBS=2` and
`RUSTFLAGS=-C target-cpu=native`. After caching locked dependencies:

```powershell
cargo test --release --offline --locked -p registry200-proof --lib
cargo test --release --offline --locked -p bfv-query-core --features formation-proofs --lib key_anchor::proof_epoch::tests:: -- --test-threads=1
cargo test --release --offline --locked -p bfv-query-core --features formation-proofs --lib key_anchor::two_operand_job::tests:: -- --test-threads=1
cargo test --release --offline --locked -p bfv-query-core --features formation-proofs --doc
cargo test --release --offline --locked -p fhe-playground --test architecture --test requirements_sync
```

For the standalone consumer:

```powershell
$proofConsumerManifest = 'experiments/hiding-fri-sha256-gate/Cargo.toml'
$proofTestFilters = @(
  'opening::tests::', 'opening::canonical_tests::', 'opening::packed_tests::',
  'opening::factorized_tests::', 'opening::state::tests::',
  'opening::state::certificate::accounting_tests::',
  'opening::coefficient_encoding::tests::', 'poly1305::tests::'
)
foreach ($proofTestFilter in $proofTestFilters) {
  cargo test --release --offline --locked --manifest-path $proofConsumerManifest $proofTestFilter -- --include-ignored --test-threads=1 --nocapture
}
$proofInput16 = 'opening::coefficient_encoding::input_formation::source_and_hidden_query_form_both_actual_fhe_inputs_under_one_key_and_reverify_after_private_drop'
cargo test --release --offline --locked --manifest-path $proofConsumerManifest $proofInput16 -- --exact --include-ignored --test-threads=1 --nocapture
```

The source snapshots record all commands, discovered names,
environment, raw files, executable hashes, logs and memory samples under ignored
`.local/`; generated proofs, keys and native outputs are not committed.

| Evidence | SHA-256 |
| --- | --- |
| Final native source R3 | `6F5F1E81D05673BC8FA4C794643B143A04A30ABF1B10A5FFC4A491CB562377CD` |
| Retained R2 71-pass receipt | `681EF082891421578CE197671EFB0442D416BA45641F12514B58C771CB587243` |
| R3 contracts | `32F8CB60EC479CCEE07C7D40A5745834C864304295EC893E9204E94B3003B66C` |
| R3 compilation/discovery | `0DD6E207929D31E400923B67ACF7D05CF29083DFD914954DE744D04FC7537931` |
| R3 remaining 26 tests | `D6EF09F66BDCCA597F7ACBCC2C8CD4602CFE45F32A17447285FE6C0D92F496C7` |
| R3 complete numeric comparison inputs | `ED42155404DA48649A0AF1ED3E06D864B4AF1FC05C70739C7AC927993B530CB7` |
| R3 doctests | `7FFF9AF9E003F9D0A5027ADDD53FA1A732DA944CFB82653F9C365637DF2A1B05` |
| Combined native closure | `BA9979498CBDC7D999461177D52AE3B4A07F394A679C7E31BBB561CFC6A91CE2` |

Native closure preceded documentation-status updates and this report. Rust,
manifests, locks and executable bytes remain frozen; documentation changes are
checked separately before publication.

## Remaining system work

The [Core producers](../../crates/registry200-proof/README.md) and
[Owner epoch](../../crates/bfv-query-core/src/key_anchor/proof_epoch/README.md)
do not make the existing Source Copen independent of q. The old same-q compiler
and full-product provenance contracts remain intact. Reusing an ingest certificate
requires a distinct explicit origin/query profile and actual original ciphertext
custody on peers, not relabeling old statements or re-encrypting owner fixtures.

The real ingest path still needs a clean caller-owned AEAD-key construction seam;
the compact-store Owner has no secret getter. Peer RawBundle currently holds AEAD
data/index images, without an original-BFV-CT/proof-component store. Live opaque
epoch retention does not provide encrypted owner crash recovery. Same-secret
evaluation-key consistency, source/query composition, fresh agreed state,
decentralized admission and full PostgreSQL including FOR UPDATE/SKIP LOCKED
remain separate work. No result may bypass those missing guarantees.
