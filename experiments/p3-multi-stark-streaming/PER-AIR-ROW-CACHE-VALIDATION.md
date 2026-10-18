# Native validation of per-AIR raw-row caching

The streamed counted-lookup leaf source now retains exact current/next raw rows
per active original AIR. Both default dense and opt-in streamed SDK modes passed
their full selected library/integration suites against the unchanged verifier.
The original dense implementation remains the default and parity reference.

## Change and storage boundary

Only the private leaf source and one appended lookup test changed in this SDK
revision. Cache entries use the original AIR index even when plan order is
reversed or an earlier AIR is inactive. Each entry holds current/next main and
preprocessing rows at one exact row index. Inactive AIRs retain None. Logical
field storage per source is `2 * sum(main_width + preprocessing_width)`, plus
metadata; vector dimensions and aggregate representable Layout are checked
before cache allocation. Public preprocessing must have the same height.

Neutral padding returns 0/1 before touching the cache. A hit only reuses raw row
values: each block still resolves all symbolic fields, multiplicity, public
values, boundary selectors and its own bus prefix. The final next row is still
clamped. The cache is proof-local RefCell storage, not exported, serialized,
shared across proofs, claimed Sync or accepted by a verifier. It contains no
cached expression, fraction, trusted root or prefix receipt.

Proof types, planning, commitment scheme, security analysis, public APIs,
transcript order and verification are unchanged. The 83-file upstream packaged
inventory still has the same six reviewed deltas and 77 byte-identical paths.
Original dense kernels, verifier/proof/security sources, public fixtures and raw
inherited test prefixes remain intact. All p3 dependencies remain exactly 0.8.0;
root manifests, lock and default dependency graph did not change.

## Executed evidence

Windows x86_64 MSVC, Rust 1.99.0, release mode, locked offline dependencies,
`RUSTFLAGS=-C target-cpu=native`, one Cargo build job and two Rayon threads were
used. Library cfg(test) code and six explicit integration targets compiled in
both modes.

| SDK mode | Passed executions | Original fixture-writer exclusions |
| --- | ---: | ---: |
| Dense default | 516 | 2 |
| `streaming-lookups` | 517 | 2 |

All 14 SDK test processes passed: **1033 executions and 517 distinct cases**.
Originally ignored heavy tests ran. Exactly the original
`generate_the_compatibility_fixture` and `generate_whir_fixture` writers were
excluded per mode; readers still ran and their public files were unchanged.
The streamed doctest command passed with zero cases, outside these totals.

The new case is
`per_air_raw_rows_preserve_reversed_mixed_shapes_block_expressions_and_transcripts`.
It uses inactive AIR0 and reversed active indices3/2/1, unequal heights8/16/64,
main widths1/5/3, preprocessing widths0/2/1 and public values. Eight balanced
blocks per AIR have different expressions and multiplicities. It visits every
leaf in bit-reversed order, checks boundaries and padding, compares dense proof
bytes, per-AIR shares and final challenger state, and invokes actual
`verify_lookup`. Every prior test body remains unchanged.

The [complete NTT validation](../bfv-ntt-batch-proof/VALIDATION.md) additionally
passed 75 owning NTT executions, all three numerical reports and genuine complete
2/4/8-operation CLI proofs. That consumer uses sequential two-operation proof
units. Its observations do not prove that a monolithic four/eight-operation
prover fits, that caching speeds up a controlled workload, or that a complete
SQL/peer process meets a RAM target.

The principal GKR array calculation remains 22.5N bytes for Goldilocks/EF5, plus
scratch and metadata; see the preserved
[streamed-round record](STREAMED-ROUNDS-VALIDATION.md). Per-AIR row caching changes
neither that calculation nor the need to account for traces, keys, WHIR and
allocator behavior separately. No CPU improvement or hard memory guarantee is
inferred from the cache design. The protocol remains non-hiding and provides no
WHERE privacy, SQL admission, full-query completeness or fresh agreed head.

## Reproduction and evidence pins

Use the exact explicit library/integration targets and original writer
exclusions in [the existing recipe](VALIDATION.md#reproduction), in both default
and `streaming-lookups` modes. Upstream examples/benches, including the unchanged
example with an earlier LLVM allocation failure, are outside this selected gate.

The source snapshot is `.local/atomic-ntt-validation-r5/source.json`, SHA256
`FBFA1CAA18DB87BD8B50C0699EEE44D379A7B351F5312751D4B415CD451BD531`.
Its runtime receipt is
`479FF42A80D6BE8DC68EE392FA142DB3410A53E40AC0B20ED130E92AB4F8FA54`;
the final native audit is `.local/atomic-ntt-source5-review-r1/success.json`,
SHA256 `5928107510D31F3DD7CA338C8DAE09AFFD5229DD74F4E1CADB706C0CA248D73F`.
The NTT record lists all phase/helper pins and sampling limitations. These local
ignored receipts are not portable build artifacts. Earlier failures, original
SDKs, executables and controls remain preserved. Requirements matched before and
after native validation; historical SQL failures remain outside this gate.
