# Native validation of recomputed GKR prefix rounds

The opt-in counted-lookup prover now streams the first two input rounds and the
first round of every reduced layer before allocating its folded arrays. Both
dense and streamed modes compiled and passed all selected runtime tests against
the unchanged verifier. This record supersedes the resource calculation in
[the earlier validation](VALIDATION.md); that file remains a historical record.

## Change and source boundary

Only the private streamed GKR implementation and two appended tests changed.
Reduced rational trees are evaluated before applying the same prefix folds;
interpolation is not commuted with the rational reduction. Equality vectors are
dropped before the folded arrays are allocated. Tiny constant layers close
directly. Proof types, verifier, transcript order, security analysis, commitment
scheme and public APIs remain unchanged. The default feature still runs the
original dense implementation.

The earlier 83-file upstream inventory still has exactly six modified packaged
paths and 77 byte-identical paths. The original dense materializer/prover and
inherited WHIR test prefixes remain byte-identical. The existing streamed test
file retains its complete 11,321-byte raw prefix; only two cases are appended.
No prior test was modified, removed or newly ignored. The registry SDK, prior
executables, local tools, receipts and public compatibility fixtures were guarded
against modification. Root workspace manifests, lock and default members did not
change. All resolved p3 dependencies remain exactly 0.8.0.

## Executed checks

Windows x86_64 MSVC, Rust 1.99.0, release mode, locked offline dependencies,
`RUSTFLAGS=-C target-cpu=native`, `CARGO_BUILD_JOBS=1` and
`RAYON_NUM_THREADS=2` were used with an independent target directory.

| Mode | Executed and passed | Fixture-writer skips |
| --- | ---: | ---: |
| Original dense, default features | 515 | 2 |
| `streaming-lookups` | 516 | 2 |

All 14 library/integration test processes passed: **1031 runtime invocations,
516 distinct cases**. Originally ignored heavy unit tests were included.
Exactly the original two fixture writers were excluded:
`generate_the_compatibility_fixture` and `generate_whir_fixture`. The readers
still ran. The feature-enabled doctest command passed with **zero doctest
cases**; it is not included in these totals.

The two new cases are:

- `recomputed_prefix_folds_match_dense_layers_and_quadratic_rounds_at_every_index`
- `double_streamed_rounds_preserve_complete_transcripts_at_tiny_and_packed_boundaries`

They compare reduced/folded fractions, each quadratic round, complete proof bytes
and final challenger state with the dense kernels. Coverage includes tiny and
packed boundaries, base and extension values, binary interpolation nodes and
actual Goldilocks/EF5. Existing tests still cover mixed table heights, neutral
padding, preprocessing, public values, clamped next rows, malformed inputs,
foreign AIR-link rejection and genuine WHIR verification/tamper rejection.

Type checking passed for both SDK modes and the pending NTT consumer. The
optimized SDK library and all six explicit integration targets compiled in both
modes; the pending NTT library/binary also compiled. This does not validate that
consumer's full runtime or resource gates. Upstream examples and benches remain
outside this selected gate, including the unchanged example with the earlier
LLVM allocation failure. The requirements mirror matched before and after.

Reproduce with the toolchain, complete target selection and explicit writer
exclusions in [the existing command recipe](VALIDATION.md#reproduction).

## Resource calculation and remaining limits

For a Goldilocks/EF5 lookup cube of size N, four current arrays contain at most
N/8 extension elements each: 20N bytes. Their equality suffix costs at most
2.5N bytes. The two streamed input-round equality vectors, 10N and 5N bytes,
die before materialization. The principal GKR arrays therefore have a
provisional **22.5N-byte** bound, plus bounded packing scratch, metadata and
O(log(N)^2) proof messages. This is 377,487,360 bytes at N=2^24 and
754,974,720 bytes at N=2^25. Vector capacity is counted; truncation is not
treated as freeing allocation. Recomputing prefixes adds prover work.

This is an array calculation, not a whole-process memory guarantee. The largest
sampled working set among these small SDK tests was 114,495,488 bytes; sampled
private bytes reached 102,592,512. Committed trace/preprocessing, WHIR state,
keys, allocator overhead and native resource measurements remain separate.
The earlier two-kernel NTT run passed, while four/eight-kernel runs hit the
1792MiB per-process soft fuse. Those failures remain unresolved by this SDK
gate. No new whole-batch fit or speed claim follows from the small regressions;
the nominal 100ms sampler is not a hard memory bound.

The existing protocol remains non-hiding. This change does not hide WHERE,
prove complete BFV multiplication/relinearization, provide SQL completeness or
fresh decentralized agreement. Historical SQL failures are outside these test
totals and remain failures. No proof cap or security floor was relaxed.

## Local evidence pins

Ignored receipts and helpers are local evidence, not portable build outputs.
The final documentation closure checks that changes after native validation are
documentation only. Source-only author review and independent source review
are separate from the native results.

| Local receipt | SHA256 |
| --- | --- |
| `.local/gkr-stream-rounds-validation-r1/source.json` | `09C904889F7134AA547076D3EEC8198471F6CE1145098AA85B3A8BA8C3BABE03` |
| `.local/gkr-stream-rounds-validation-r1/check/success.json` | `E6B72772FF7C4F20FF895E82FAE641CABD3F042E06B0E014EDD2E0BC5860C6BC` |
| `.local/gkr-stream-rounds-validation-r1/compile/success.json` | `518022CE2C5E30E385CAE6A1834D74C846372B38F7BDF95FE496EDF56B3133BA` |
| `.local/gkr-stream-rounds-validation-r1/tests/success.json` | `28525C4596A677A9195C30D46A1A6D59EA00FB3D32D61E1297258113F3E98FD5` |
| `.local/gkr-stream-rounds-validation-r1/docs/success.json` | `395B4D66DDAABFB862E6B2EF37AD52C3A01C2B7867FB67A8783D0978EEBC2C61` |
| `.local/gkr-stream-rounds-review-r1/success.json` | `BD0D4F5DCD777DD0210A75C221626C4A73BDBCD00D2DA13A49CD5C78AD333EC7` |
| `.local/native-ntt-batch-r1.py` | `9505DD6E4D9EA317EFF1C6C45BF86FAA4D3837E5C45D2DF41A9535048C8CFC38` |

These checks validate this SDK revision. The repository Goal remains incomplete.
