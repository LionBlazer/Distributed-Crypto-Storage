# Source joint public-image validation

Five cases passed with zero failed and zero ignored in three exact owning runs.
The private test sampler consumes the actual SourceFoldProgram and retains the
complete Expected691. All 16 active quotient chunks are exercised by physical
points 7*omega^j for j=0..15, with target/enlarged degrees 21/42.

The three algebra cases independently check native normalized factors, every
zero-divisor fiber and rank15 (including the correlated last chunk), all five
coordinate copies, native SDK recomposition, and deterministic wrong-last,
wrong-sign, mixed-normalization and swapped-chunk failures. The preflight case
checks named full-public/shape/domain refusals before RNG consumption, including
a foreign C_state on exactly the same images and version.

The opt-in real Source consumer retains MAIN7166, R10 and Q16x10. Its 304,437
ideal field cells are replayed explicitly. Every MAIN, wrapper and R value is
checked by scalar Horner; all 1,280 original chunk/base values and 80 chunk/OOD
embeddings match those SAME mask cells and independent native references.
The old 80 aggregate coordinate equalities, five fixed-z coefficient embeddings,
native reconstruction and an actual V corruption control remain. The unchanged
NativeOracle is called exactly 16+5=21 times; no extra oracle call was added
to verify the individual masks.

The original frozen consumer consumed but did not inspect those Q-mask cells.
Independent review confirmed that aggregate recomposition could miss ignored
masks. The tests-only overlay adds exact per-chunk replay and nonzero mask
contributions in every coordinate, closing that finite coverage gap.

| Run | Cases | Harness | Process wall | CPU | OS peak working set | Sampled private peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| r1004 algebra | 3 | 0.04 s | 57.3391 ms | 0.046875 s | 6,234,112 B | 1,163,264 B |
| r1005 preflight | 1 | 0.26 s | 264.7508 ms | 0.265625 s | 69,664,768 B | 61,759,488 B |
| r1006 joint/native | 1 | 1.38 s | 1388.8211 ms | 1.375 s | 211,922,944 B | 211,718,144 B |

The r1006 setup-plus-sampling marker was 890.783 ms, independent native base
comparisons 285.306 ms and OOD comparisons 85.842 ms. The first marker starts
before public program/fixture preparation and is not an isolated sampler cost.
The observed program has 16,133 constraints and 682,163 live/cached nodes;
the independent preflight process observed 683,771. Each actual program supplies
its own exact cache-entry bound. Neither fixture count is a global cap or
a whole-process memory theorem.

All runs retained the held exact executable and creation handle, 120-second/
1792-MiB process fuses, 20-ms sampling and eight Rayon workers. Source/image
pins matched; no observer fault or cleanup occurred. Optimized build r1018
executable SHA256:
`B3294281980BC79D3BE5EB04310F35A8FF584F573A7E2920832A5A23E1624D69`.

Strict Clippy r1017 and optimized build r1018 passed. Initial compile checks
found two test API/style issues: rand0.10 StdRng has no Clone, and the matrix
column loop needed enumeration. Four fresh public comparison/replay RNGs now
start from their identical explicit seeds; the independent fifteen-column
matrix is enumerated without changing an entry or assertion. The failed
receipts are preserved. Sampler arithmetic, existing Source core/oracle,
production interfaces, dependencies and resource fuses were not altered.
Independent frozen source review and the required replay overlay were checked;
terminal runtime evidence is separate from those source reviews.

These measurements cover arbitrary PUBLIC residues and repeated independent
comparisons, not FHE, honest traces, native quotient production or proofs.
The public fixture may draw OS page nonces. Native-baseline/divisibility and
conditioned mask/wrapper distribution, ideal-cell independence, adaptive privacy,
whole-B, native Source frame/FRI, five-family composition, fresh agreement and
SQL/FOR UPDATE admission remain open. The full 500-ms query target is unmet.
