# Exact BFV multiplication and relinearization validation

## Scope and source

Native validation completed on 2026-10-18 at parent
`3a47e5525dee4920bb8d84050d09c8890c612ed0`. The final immutable source receipt is
`mul-graph-validation-r4/source.json`, SHA256
`4B62297BED1214A6A1CEC64EA6A3A037F958850FBE27CF8C534108E11049AB41`.
The report and final README corrections were added after native closure; Rust
sources, manifests and lockfiles must still match that receipt exactly.

The new [graph consumer](README.md) links the complete original two ciphertexts
to the exact two-component SDK product through all134 semantic nodes. Actual
proof verification covers115 NTTs,17 arithmetic relations and2 relinearization
relations. One atomic arithmetic frame contains three SDK proofs, so the output
has118 records and120 SDK proofs. The separate input evidence contains16 unique
proofs: Key, Source, two coefficient encodings, ten Basis and two Formation.
Shared prerequisites are actually reverified, not replaced by checked receipts.

The output graph edge verifier routes complete claims without re-evaluating an
NTT or the query. Existing input16 admission separately retains its original
public ciphertext decoding, Basis representation conversion and preprocessing.
This stage does not establish transform-free input verification.

This is a standalone research composition with an independently pinned original
owner/application setup anchor. It is not a network SQL handler. Full PostgreSQL,
distributed locks, agreed-head completeness/freshness, public same-secret
relinearization-key validity and a whole input/output security theorem remain
open. Existing production SQL proof rejection and transport caps are unchanged.

## Observable behavior and adversarial cases

The actual integration test is
`opening::coefficient_encoding::input_formation::input16_and_all134_product_nodes_verify_exact_ciphertext_after_private_drop`
in the [private-input consumer](../hiding-fri-sha256-gate/src/opening/coefficient_encoding/input_formation/full_product/README.md).
Four PUBLIC NONSECRET original age/amount rows are encoded before filtering.
The private predicate `age IN (0,128)` excludes both original age255 rows. The
mask and WHERE constants are not peer statement fields. The original Owner/Core
constructs and executes the actual encrypted multiplication and relinearization;
client decryption is only the independent test oracle.

After the Owner, scope and private fixture are dropped, the graph receives the
original public setup, complete Encoding statements including C_w, original
ciphertexts and proposed encrypted output. Every coefficient of all8192-element
rows participates. The test generates and actually verifies all118 records,
then drops the prover, old prepared key, graph, verifier and checked state. A
fresh setup/key/graph/verifier reconstructs expectations from the original public
endpoints, verifies input16 again and verifies every saved output record. Only
the complete result equals the exact original SDK ciphertext bytes.

The same executed case rejects incomplete and cancelled sessions, wrong order,
the final claim coefficient, a changed derived binding, and the last Q4/c1
coefficient of a still-canonical proposed ciphertext. A foreign NTT statement
first produces a genuine proof that passes its own SDK verifier. Repairing both
its inner and graph headers cannot make it pass the honest verifier, and failure
does not advance admission. Attempt and byte budgets remain terminal even after
all valid proofs have been admitted: finish rejects an exhausted session.

Three graph unit cases cover the complete claim codec, all-node obligation
coverage and strict record grammar. Five new Core routing cases cover every
coefficient of both originals, all25 digits and all50 key rows, malformed final
residues, ordering and basis/component transposition. The old32-node complete
relinearization consumer delegates to that pure routing and retains its original
proof schedule, API, caps and native proof behavior.

## Per-call lookup storage

The initial integrated run exposed Cargo feature unification: arithmetic's
`streaming-lookups` feature also forced every small NTT/relinearization prover
onto the recomputation-heavy path. The corrected
[scoped SDK](../p3-multi-stark-streaming/README.md) makes `ProverInstances::new()`
resident under either feature set. Only an explicit
`with_lookup_materialization(LookupMaterialization::Streaming)` selects streamed
storage for one batch. Arithmetic and atomic NTT batch producers opt in; graph
single NTT and relinearization producers remain resident.

The selector changes private witness storage only. AIRs, public statements,
keys, proof types, verifier, security policy and transcript remain unchanged.
Executed SDK tests run Resident -> Streaming -> Resident and compare complete
reduction/proof bytes, private shares and subsequent challenges. The complete
WHIR test also invokes the original verifier and preserves damage rejection.
The no-lookup case proves that the selector remains inactive without counted
lookup work. This establishes parity for these cases, not a universal speedup.

## Executed gates

The final R4 native matrix passed:

| Owning group | Runtime test invocations | Direct process time, ms |
| --- | ---: | ---: |
| Scoped SDK, default library | 407 | 6,376.7945 |
| Scoped SDK, streaming library | 409 | 6,598.2444 |
| Scoped SDK, default WHIR integration | 41 | 211.9305 |
| Scoped SDK, streaming WHIR integration | 42 | 339.7309 |
| Arithmetic17 | 12 | 329,184.0551 |
| Atomic NTT batch | 9 | 684,796.4233 |
| Full graph codec/coverage | 3 | 820.9726 |
| Actual input16/product134 integration | 1 | 590,083.5815 |
| Total | 924 | |

The feature matrix contains476 distinct package/target/test names. Eight earlier
R3 groups are retained with independently rechecked unchanged implementations:
Core routing default12 and Plonky3 15, original complete relinearization7,
original single NTT13, original Relin20, requirements synchronization1, Core
coefficient9 and original coefficient/input16 consumer12. Those89 invocations
cover77 additional owning cases. Combined coverage is1013 invocations over553
distinct owning names; repeated feature configurations are not distinct tests.
These retained groups ran against R3, not final R4. The affected SDK fork,
arithmetic, NTT batch and full graph ran again under R4. Other repository tests
were not run by this stage; historical SQL success cases are not claimed green.

Formatting, strict Clippy with `-D warnings` for the affected Core/consumer
packages, default core check, and SDK `cargo check --tests` with/without the
feature passed. This is not a strict Clippy result for the entire upstream SDK.
The new graph doctest command passed with zero executable cases. The old32-node
CLI passed actual security and genuine prove modes; its direct prove process
took99,016.0229 ms. Original SDK sources/archives, previous native artifacts and
requirements mirrors were checked unchanged.

## Full product observations

These values belong to the one R4 full integration process above:

| Observation | Measured value |
| --- | ---: |
| Complete raw graph claims | 16,727,920 bytes |
| Output118-record stream, including160-byte headers | 236,826,246 bytes |
| Largest output record, atomic arithmetic | 6,510,715 bytes |
| Input15 public frames, including duplicate Source | 264,172,319 bytes |
| Repeated Source proof within the input pairs | 19,304,511 bytes |
| Claims plus input/output public spool | 517,726,485 bytes |
| Graph preparation | 1,022.9662 ms |
| Initial graph input-proof verification | 33,433.7180 ms |
| Output generation/verification/spool/negative-control loop | 374,843.6120 ms |
| Sum of actual output `prove_next` calls | 354,459.0238 ms |
| Sum of output proof verification calls | 17,569.6367 ms |
| Fresh public verification after prover drop | 51,199.5693 ms |
| Whole direct integration process | 590,083.5815 ms |

The input spool above is from the R4 full-product run. The separately retained
R3 input16 test used a different public fixture and has different byte lengths.
The old input-stage JSON is emitted before the optional graph path, so its
`output_mul_relin_proven:false` describes that earlier stage. The final product
JSON records the actual complete output proof; neither record grants SQL access.

The fresh51,199.5693 ms includes new setup/key preparation, all input16 proofs,
all118 output proofs and file reads. It is not a pure SDK-only verification
timer. Whole-process time also includes private fixture/input generation,
earlier input checks, negative controls and repeated verification. None is an
ordinary application query-latency measurement or a fixed latency target.

Single NTT `prove_next` calls had min/median/max
1,726.9460/1,860.6596/2,059.7212 ms; verification was
121.5630/138.3157/174.7897 ms. The arithmetic record took137,594.8341 ms to
generate and824.9329 ms to verify. Embed and MAC generation took143.9448 and
956.5173 ms; verification58.7684 and292.2183 ms. Timers include their documented
consumer setup/encoding work and are not isolated field-operation benchmarks.

The verified output SDK union is150.50196022260138 bits. Recomputing
`-log2(115*2^-157.41904001390932 + 2*2^-157.824854488013 + 2^-155.30104806191767)`
agrees up to floating rounding. The arithmetic bound already combines its three
phases and is counted once. Every actual report is finite and fully assessed.
Input proofs retain their individual128 policies; the output-only bound does
not establish whole128, whole144, hiding, setup authority or distributed freshness.

## Resource observations and preserved failures

Root used Rust1.99.0 MSVC, release/locked/offline dependencies, CPU native code,
two Cargo jobs and two Rayon workers in the independent copy2 target
`target-mul-graph-r4`. Owned PID/descendant observation was nominally100 ms,
with an unchanged1792 MiB per-PID sampled soft fuse and1200-second per-command
bound. Generated proofs, targets and raw observations remain local artifacts.

The full test's PID372848 has2567 samples, maximum sampled working set and OS
peak1,289,302,016 bytes (1.200756 GiB), maximum private bytes1,287,028,736
(1.198639 GiB), and maximum actual sample interval397.9791 ms. No fuse fired.
The NTT-batch test had maximum sampled working set1,109,848,064 bytes and private
bytes1,107,476,480; arithmetic had1,018,081,280 and1,017,184,256 respectively.
Both fast R4 WHIR commands completed without a live memory sample; no resource
fit is inferred for them. Sampling and OS counters do not prove a hard process
bound or the entire distributed peer's1-2 GB target.

The earlier R3 full graph was deliberately stopped after746,410.6543 ms and17
actually verified output records (ordinals0..16), after ten preceding groups
passed. Root checked the owned PID400724 and executable hash, recorded intent,
and terminated it with exit86. This is a partial stopped run, not a complete
proof PASS or a cryptographic failure. Its immutable public spool and receipts
are preserved. R4 fixes storage selection and reruns the affected gates with the
same time/resource fuses. The two runs are not a controlled end-to-end speedup
comparison.

An initial static type/Clippy revision was corrected before final execution. The
first closure checker incorrectly required at least one memory sample from each
fast command; its failure receipt is retained. The corrected closure explicitly
records missing samples without a RAM claim. This metadata correction did not
change native results or rerun/overwrite observations.

## Local receipt identities and reproduction

The immutable R4 receipts are `mul-graph-validation-r4/<mode>/success.json`:

| Mode | SHA256 |
| --- | --- |
| contracts | `F234B1CA5D025C6B680F1BDA17A4F8D39AFD026C382DDEC508CF5C9646EA51ED` |
| compile | `65CE82CB743A06D0971742E0AEE195EE6DC210526B111760AC7FE5A9017AED2F` |
| tests | `A52AB4FC7929B50CF6D6B9AD85AF662F14D3D633809A8BBB0AE91F9A4A1FC1CE` |
| prove | `DE921C5DE3530F96FA42F301CBD7E4F73E9142BC9FBE6DA9194F52449A219A35` |
| docs | `78D1FEFBDB185D1F17FE12B0A4FE242192F3A751F8A4A6FF21B6D20C1F620FA0` |

The final native closure is `mul-graph-native-closure-r3/success.json`, SHA256
`C987A36C3D049B4BFB4CE0F42E0188F80810B6C0B73FBB7DA2FF8933521BFB3D`.
Its separate retained-R3 receipt is
`FC194A1C7EAAA06C64EF5C752D63F26FC1B56D5FD835600F3C734103C0FF94F8`.
Closure checks source, executable, compiler-discovered artifact, log and CSV
hashes,1027 original SDK source/archive anchors, five tools and29,967 protected
prior artifacts. The unchanged native runner is
`9505DD6E4D9EA317EFF1C6C45BF86FAA4D3837E5C45D2DF41A9535048C8CFC38`.
R3 source is `547593B12E2CA41A35E493C07CDD031E7780A035C65463F22AD5B37F281CC843`;
its controlled-stop partial closure is
`D1EB847206DDE0A61F40A269687834A3F8D809A47DA2C907E3D3EB52B2E4FEFC`.

Use the reviewed manifests/locks, a fresh target, the Rust/environment settings
above, and the existing `DCS_CHUNK_IO_FEASIBILITY=1` /
`DCS_PACKED_IO_FEASIBILITY=1` experiment flags. Principal owning commands are:

```text
cargo check --release --locked --offline
cargo test --release --locked --offline -p bfv-relinearization-circuit --lib -- --test-threads=1
cargo test --release --locked --offline -p bfv-relinearization-circuit --features plonky3 --lib -- --test-threads=1
cargo test --release --locked --offline -p fhe-playground --test requirements_sync
cargo test --release --locked --offline --manifest-path experiments/p3-multi-stark-streaming/Cargo.toml --lib -- --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/p3-multi-stark-streaming/Cargo.toml --lib --features streaming-lookups -- --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/p3-multi-stark-streaming/Cargo.toml --test whir_fibonacci -- --include-ignored --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/p3-multi-stark-streaming/Cargo.toml --test whir_fibonacci --features streaming-lookups -- --include-ignored --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/bfv-arithmetic-batch-proof/Cargo.toml --lib -- --include-ignored --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/bfv-ntt-batch-proof/Cargo.toml --lib -- --include-ignored --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/bfv-mul-relin-proof/Cargo.toml --lib -- --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::coefficient_encoding::input_formation::input16_and_all134_product_nodes_verify_exact_ciphertext_after_private_drop -- --exact --test-threads=1 --nocapture
cargo run --release --locked --offline --manifest-path experiments/bfv-complete-relinearization/Cargo.toml -- security
cargo run --release --locked --offline --manifest-path experiments/bfv-complete-relinearization/Cargo.toml -- prove
cargo test --release --locked --offline --manifest-path experiments/bfv-mul-relin-proof/Cargo.toml --doc
```

Root compiled with Cargo JSON artifact discovery and invoked the exact frozen
test executables directly. The commands above reproduce the owning selections;
they do not imply an all-target/all-repository test run. Both WHIR groups also
executed the originally ignored `generate_whir_fixture`, which writes the public
fixture in this experimental SDK copy. Final source guards confirmed identical
fixture bytes; the original registry SDK/cache was untouched. This differs from
the historical cache gate's fixture-writer exclusions. Two independent subagent source reviews and a
separate receipt/numeric audit found no remaining discrepancy; native execution
was performed only by Root.
