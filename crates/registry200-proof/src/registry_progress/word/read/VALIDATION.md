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

## Protected owner integration (r172/r173)

The same normal read case now generates an opaque Gold Owner, seals its key,
destroys that Owner, and restores it under independently pinned metadata before
Source/Role3/DATA/Word/Query/product composition. No raw SDK key getter,
serialization or decryption is used by this test. The actual Source encoder's
scaled W is unscaled once for original DATA encryption; Owner independently
opens the SAME Cw and Cs when preparing the real dense DATA proof. The new
`prove_dense_prepared` route freshly checks State/Role3 and the original request
before the unchanged dense prover checks its complete captured expectation.
Its forged canonical State and Role3 OOD examples must reach their actual native
Verification errors at the producer too. Foreign DATA nonce/ciphertext with
otherwise valid original prerequisites must reject the guarded preparation.

The read receiver now retains its actual sealed `ArithmeticCheckedProduct`.
After every required native proof passes, `Owner::complete_checked_product`
requires this original query's complete nonce and literal ordered ciphertext
pair before decrypting all4096 coefficients. Normal `complete` still freshly
checks its supplied certificate. Additional Owner assertions use independently
valid arithmetic theorems for a changed nonce and swapped operands; both must
reject completion despite their valid arithmetic. Different original calls reject
too. No prior Word/Query/product verdict is reused for a new call.

The original two actual query cases, independent post-check full-ring oracle,
all five repaired native proof failures, retained full Source/C_state/Cw/Cs/
nonce/ciphertext failures, Control rejection and all missing-frame cases passed.
Public fixed wrapping keys and blinding salts belong only to these explicit
nonsecret examples. Test InputScope pins are metadata, not a production compiler,
SQL authorization or a proof of authenticated prior state.

The exact r172 registry test image is12142080 bytes, SHA256
`975265B1378C6D77A3F982648BA7F7624B84AA282A5B11795CD05EE9ABCC8785`.
One full owning test passed in27.55s including hostile examples. The process lived
27558.6001ms, used37.859375 CPU seconds, reached562085888 OS peak working-set
bytes and555761664 sampled private bytes across1350 samples. The r173 Owner
image is5699584 bytes, SHA256
`4E7F8C222E389D6E4F9AF9226C195204B73D961A2B8976482F57AECFE6854295`.
All11 Gold Owner cases passed in4.03s. That process lived4047.409ms, used6.875 CPU
seconds and reached518782976 OS peak working-set bytes. Both bounded observers
confirmed exact source/image identities, terminal exit0, no faults and no cleanup.
The same Rust1.99/native/release/locked/offline/Rayon2/one-harness-thread setup and
120s/1792MiB research fuses were used; no other build/test was intentionally run
during either observation. These are whole test processes, not complete peers.

The first protected-owner setup and cold read took9913.641ms before oracle or
hostile checks: Source2052.348ms, Role31692.877ms, DATA2307.671ms, Word309.534ms,
Query1314.650ms, public FHE/product43.448ms, full cold receive2170.928ms and
protected client completion0.997ms. Six frames total26926597 bytes. Independent
immutable DATA installation took1342.336ms. The SAME query's retained receiving
took669.613ms, which is not a new query. The second genuinely different query
against that same immutable DATA measured:

| Operation | Milliseconds |
| --- | ---: |
| Protected owner query preparation | 3.022 |
| Fresh Word proof | 284.224 |
| Fresh fused Query proof | 1307.924 |
| Real FHE product and certificate | 46.107 |
| Independent cold query receiving | 815.811 |
| Protected client completion | 0.955 |
| Preparation through checked/decrypted output | 2458.043 |

Its three query frames total8044682 bytes. These sparse observations do not
establish a latency distribution or improvement over earlier different runs.
This local conditional mathematics still exceeds500ms before transport, agreed
head, lock consensus, durable Predicate completion and a real SQL client.

Strict release Clippy passed for all registry targets and all Owner features/
targets. All8 Word and5 Gold compile-fail contracts passed. Default Owner
compilation and the dependency-free requirements synchronization guard passed.
The registry's new Owner dependency is dev-only; neither normal library imports
the other's product policy. Original wire/profile equations, receiver proofs,
security/resource gates, timeouts and live SQL/finality guards are unchanged.
BFV/product composed-security assessment and the concrete owner/Word compiler,
authenticated prior state, fresh weighted finality and real network SQL still
remain. The complete-query <=500ms goal is active and not achieved.


## Structured Query v2

The later [exact range projection](../../../../../bfv-ciphertext-formation/src/gold/program/query_formation/PROJECTION.md)
keeps all original masks, hashes, coefficients and S/E/K equations while removing
only the W/slack bits already implied by the mask. Normal receiving now requires
DCSGQF02, with no v1 fallback. The old full constraint extension and unchanged PP
pin precede actual native proofs. All35 lower Gold, this complete read and all16
mask/Formation-adapter cases passed, together with14 compile-fail contracts,
strict Clippy and requirements synchronization. The new local query interval is
2666.541ms including setup; no latency improvement or complete SQL500ms result
is established. The linked record includes complete scope, resources and hashes.
