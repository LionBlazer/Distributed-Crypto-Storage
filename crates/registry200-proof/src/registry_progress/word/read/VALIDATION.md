# Normal conditional Word read validation

On2026-10-21 the former private composition was moved behind the normal
`registry_progress::word::read` contract. Public Word expectations replace private
Metadata at this boundary; the receiver calls the normal independent Word and
Gold fused Query verifiers. Original association domains,33 mask public words,
Stmt96 header, codecs, resource/security assessments and native equations remain
unchanged. Standalone mask snapshots still match their original literal pins.
Owner examples and SDK encryption/decryption remain test-only.

## Executed gates

The exact final r153 release test image is12091904 bytes, SHA256
`F8E64C19D9F012A50CC8D09E9900DAD2B2D622CDE906AA8A53ED950630794D8D`.
The normal read owning case passed in26.41s; the r154 standalone mask/composition
filter passed all16 cases in7.09s on that same image. These are test durations,
including setup, repeated verification and hostile examples, not query latencies.
The bounded observer checked exact source/image identity, terminal exit0, no
remaining direct child and no cleanup action. With a120s/1792MiB research fuse,
the full read test process lived26436.870ms, used40.421875 CPU seconds, reached
561381376 OS peak working-set bytes and555831296 sampled private bytes. The
mask filter reached518930432 OS peak working-set and503775232 sampled private
bytes. These are whole test-process observations, not complete-peer resource claims.

Strict release Clippy over all normal/test targets passed with `-D warnings`.
All8 Word compile-fail checks passed, including the two new private-construction
and non-Clone read-result checks. The dependency-free requirements_sync test,
explicit rustfmt checks and diff whitespace checks passed. No runtime, finality,
SQL acceptance path, proof fallback, timeout, parameter or security flag changed.

The owning case uses the original public SkipBeforeOffset source/mask example
and exact SourceVersion/Role3 DATA witness. Actual SDK encryption uses one key.
Word production consumes public guarded owner inputs; Query production uses the
normal ScaledOpening/SecretOpening/Prepared constructors. The evaluator receives
only original ciphertexts/parameters and performs real FHE multiplication.
Decryption occurs only after the closed public receiver succeeds; a separate
public negacyclic oracle then checks all4096 coefficients and packed row values.
No fixture answer supplies the FHE computation or the receiving result.

All five native proof families have repaired canonical tampering negatives:
Source, Role3, DATA, Word and fused Query must reach their concrete native
Verification error. A product binding forgery and each missing frame reject.
After a successful receive, genuine retained immutable DATA supports a second,
different Word mask, call/invocation and encrypted QueryCt with fresh Word/Query
proofs and FHE product. Damaged Word/Query/product frames still reject after prior
success. Control cannot become a read. Swapped ordered inputs and a source with
the same version tag/images but a different C_state reject. Retention also checks
the original DATA nonce/ciphertext, Cw and Cs. No prior per-query verdict is cached.

The first r148 attempt found an overbroad fixture assertion that expected old
metadata binding even after the negative example changed C_state. The assertion
now checks only honest producer fixtures; the negative receiver still requires
full Source/DATA comparison. r150 then passed; removing an unused private fixture
getter for strict Clippy was followed by the exact final r153/r154 gates above.

## Component measurements and remaining boundary

Pinned Rust1.99 MSVC release, native CPU codegen, locked/offline dependencies,
Rayon2 and one harness thread were used. No other build/test was intentionally
run during observation. The workload is four public(age,amount) rows
(0,1),(1,2),(128,3),(255,4), one N4096/Q2 multiplication, without transport,
current weighted-head checking, lock consensus or SQL client completion.

The final r153 first cold composition measured2063.025ms Source proving,
1621.293ms Role3,2599.782ms DATA,423.465ms Word,1813.129ms fused Query,
30.008ms FHE/product certificate,2309.140ms full receiving and0.737ms decryption.
Owner setup through the checked/decrypted output took10870.309ms, before oracle
and hostile checks. Six frames total26926949 bytes.

Independent immutable DATA installation took1417.287ms. Rechecking the SAME query
after installation took877.089ms; this is not a fresh-query benchmark. The second
genuinely different query measured:

| Operation | Milliseconds |
| --- | ---: |
| Owner query preparation | 2.534 |
| Fresh Word proof | 399.784 |
| Fresh fused Query proof | 1796.358 |
| Real FHE product and certificate | 29.428 |
| Independent cold receiving | 871.769 |
| Client decryption | 0.910 |
| Preparation through checked/decrypted output | 3100.783 |

Its three query frames total8037546 bytes. Earlier passing r150 measured2211.331ms
at this same component boundary (different fresh randomness/system scheduling).
These sparse runs do not establish a latency distribution or an improvement over
historical16-thread measurements. Even this isolated mathematics exceeds500ms.
It is not a complete SQL/FOR UPDATE measurement.

Reproduction uses the repository's actual commands in the pinned environment:

```sh
cargo test --release --locked -p registry200-proof registry_progress::word::read::tests:: -- --nocapture --test-threads=1
cargo test --release --locked -p registry200-proof registry_progress::word_inventory::query_mask_inventory:: -- --nocapture --test-threads=1
cargo test --release --locked -p registry200-proof --doc registry_progress::word -- --test-threads=1
cargo clippy --release --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --locked -p repository-contracts --test requirements_sync
```

BFV confidentiality and product Fiat–Shamir assessment remain open; see the
[actual lattice-run limitations](../../../../../bfv-unrelinearized-product/MODEL.md).
Authenticated bootstrap/prior state, a fresh weighted quorum, durable Predicate
completion, independently running peers, real network SQL and a reproducible
complete-query workload still have to be joined. The live SQL and Word Journal
Predicate guards remain closed. The goal of <=500ms full query is not achieved.
