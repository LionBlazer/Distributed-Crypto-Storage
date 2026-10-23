# Ordered application and LogUp equations

Executed 2026-10-23. Four owning DATA/Query tests exercise the same private
`native::FullAir`/`MetadataAir::eval` and actual P3 0.8 verifier constraint folder.
They add source-correspondence evidence for the conditional soundness argument;
they generate no proof and establish no SQL, security or freshness admission.

## Observable boundary

The shared test source is included only inside the two owning `cfg(test)` modules.
It builds small public two-row MAIN/PP/AUX arrays, not complete traces or public
preprocessing. Expected metadata comes from the existing public fixtures. The
test wrapper marks the application boundary inside the actual SDK
`LogUpGadget::eval_air_and_lookups`; it does not replace the original evaluator.
Every base/extension assertion is forwarded to the real
`VerifierConstraintFolderWithLookups<hash::Config>`.

For each emission it checks the SDK update `after = before * alpha + value`.
It also compares the final result with the independently written descending
powers sum, the original symbolic constraint layout, and the actual prover's
`ConstraintLayout::decompose_alpha` powers. Every original symbolic expression
is evaluated at the same rows and compared with its native numeric emission.
The complete emitted degree is checked against the actual packing ceiling.

Arbitrary non-Boolean PP coefficients remain field values. The first actual
graph multiplicity is `-1 = p-1` despite its static Count weight 4. No integer
magnitude/no-wrap theorem is assumed for these generalized rows. The original
single bus, tuple width 2 and additive packing are checked. First/interior/last
selector probes exercise their activity patterns, not all actual selector
polynomial values over the original domain.

All packed fractions are checked independently as `U * fraction - V`, using
cross products without division. They remain unconditional on the last row.
The final three extension equations are exactly the first-row anchor, transition
and last-row terminal binding; the committed terminal stays zero. The same
native terminal-sum check runs. The polynomial form retains denominator-zero
equations; this is not an additional randomized pole-frequency experiment.

| Family | Application equations | Fractions | Accumulator/terminal | Total C | Symbolic degree |
| --- | ---: | ---: | ---: | ---: | ---: |
| DATA | 1248 | 81 | 3 | 1332 | 4 |
| Query | 1098 | 83 | 3 | 1184 | 4 |

## Why application eligibility precedes lookup coins

For a fixed candidate MAIN, `App_mu` means **all** original local application
equations hold on every original row. It is independent of future lookup coins
and alpha. Only candidates satisfying this filter may enter the formal lookup
balance predicate. A balanced lookup does not imply valid local arithmetic.

The second test fixes constant degree 0 PP with all formal counts zero and an
inactive coefficient 2. MAIN bits `(1, -4)` violate exactly two original local
equations, whose emission indices differ by two. All lookup fraction and
accumulator equations vanish. The same fixed MAIN folds to zero at `alpha=2` and
to a nonzero value at `alpha=3`. Its application eligibility remains false at both.
This is an alpha-polynomial cancellation example, not a forged accepted proof.

If a member of a frozen joint MAIN/AUX list violates some original row equation,
the complete ordered fold at that row is a nonzero polynomial in alpha: each
equation has its own distinct exponent. Its degree is at most `C-1`. A single
joint list of size at most L therefore costs at most `L*(C-1)/|EF|` for this
transition. The list, native selectors, and exact generalized template must
already be fixed. These tests support that source association; they do not
implement the generalized instance recognizer, frozen PP extraction/degree
check, joint-list bound, or the rest of the RBR argument.

## Avoiding repeated symbolic graph expansion

The initial r701 run hit the unchanged 120 s fuse. The r703 diagnostic run reached
native numeric evaluation and alpha-layout comparison, then hit the same fuse
in original symbolic BASE resolution. Both are failed runs, not passing checks.
Each directly launched process was stopped through its held exact-image/creation
handle; no unknown or pre-existing process was terminated.

The cause was repeated expansion of shared Poseidon expression nodes. Its 22
partial rounds replace only one state coordinate with a witness variable; the
linear layer reuses a shared sum in the other coordinates. SDK recursive
`SymbolicExpression::resolve` traverses these Arc children as a tree without
caching, so evaluation work expands while the stored graph stays small.

The test now evaluates each distinct original node once per unchanged input and
selector case, using separate deterministic node-identity maps for base/ext ASTs.
All original roots and Arc children remain alive until that cache is dropped.
No raw pointer is dereferenced. Base leaves delegate to the SDK's exact leaf
resolution; extension leaves cover every pinned AST variant. A fresh cache for
each case prevents values crossing selector/input changes. No original equation,
assertion, failure condition or resource fuse was removed or weakened. This is
test evaluation work, not a production proof or SQL performance optimization.

## Executed checks

The r704 release build passed; r705 ran exactly the four owning cases in 0.06 s
(whole process 81.6023 ms). Windows/MSVC Rust 1.99.0, opt-level3, native CPU,
locked/offline dependencies, Cargo jobs2 and eight shared Rayon workers were
retained. The observer used the existing 120 s/1792 MiB fuses and 20 ms sampling.
OS peak working set was 11,165,696 bytes and sampled private peak 6,029,312 bytes.
It exited with code 0 normally with no faults or cleanup. These are diagnostic test costs,
not a cryptographic proof acceptance measurement or complete query latency.

The test image was 6,653,952 bytes with SHA256
`DF5B554181EE31CD1C46708A75E4177CB02BC16F5C317EE254EC6BBCE823CBF2`.
Generated executables and observation receipts remain outside Git.
The r705 receipt SHA256 is
`84FBF447D24E52CE2778FA56D614CCFC22B4CAC5947A9E5FBBF2405C14508F8F`.
Release all-target Clippy passed after removing an unused import; formatting,
document links and the canonical requirements mirror/test also passed.

Reproduce the affected boundary:

```powershell
cargo test --release --locked -p bfv-ciphertext-formation --lib ordered_constraint_tests:: -- --nocapture --test-threads=1
cargo clippy --release --locked -p bfv-ciphertext-formation --all-targets -- -D warnings
cargo test --release --locked -p repository-contracts --test requirements_sync
```

The broader [native RBR note](../../../../registry200-proof/src/registry_progress/word/read/NATIVE-RBR.md)
keeps the remaining extraction, transcript, composition and live-contract premises.
No production equation, proof parameter, wire format, accepting API or live
admission rule changes in this test-only step.
