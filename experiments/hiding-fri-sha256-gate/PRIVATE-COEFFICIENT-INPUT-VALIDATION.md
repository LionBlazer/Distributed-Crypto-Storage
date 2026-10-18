# Private coefficient input provenance validation

The new [Source/private-query encodings](src/opening/coefficient_encoding/README.md)
and [two-operand Owner scope](../../crates/bfv-query-core/src/key_anchor/two_operand_job/README.md)
now have executed native evidence. One experiment links a genuine canonical
four-row Source, a privately compiled predicate, and both exact ciphertexts from
the real Core Prepared request under one actual Key. These are input proofs.
The actual FHE product still has no complete linked MulRelin proof and its result
remains Unverified. No live SQL, FOR UPDATE or SKIP LOCKED permission follows.

## Responsibilities and bindings

The shared library owns two distinct private-main AIRs. SourceAllOriginal encodes
all four originals before filtering; PrivateMask encodes the reversed256-bit age
predicate. Both constrain all8192 scaled coefficients and the existing Formation
8208-field root ABI. Source691, full setup identity and ALL Key33 remain bound.
No private mask, SQL text/constants, blind, plaintext or salt is a peer field.
The private compiler accepts only fixed-schema AgeAmount Select with the default
window; it rejects other roles. SQL parsing is client work, not proved by the AIR.
The caller must use a high-entropy private blind distinct from the public nonce.
Public fixture blinds are explicitly nonsecret test data, not entropy evidence.

The new Source-first pair contains exactly Source+encoding. A typed Key statement
is public context, not a Key proof. The complete encoding producer identity hashes
all public values including Cw. The Core scope owns guarded Shat/openings, retains
one actual Key through Input0 Basis5+Formation and Input1 Basis5+Formation, then
clears explicit private material. It emits public components individually and
borrows only the current five Basis frames. Old single-job APIs are preserved.
Native field/FFT/trace/SDK allocator scratch is not promised securely erased.

The [linked test](src/opening/coefficient_encoding/input_formation.rs) generates
16 distinct primary proofs: Key1, Source1, encodings2, Basis10 and Formation2.
Its predicate excludes both age255 originals. Those rows are still encrypted;
the same Prepared ciphertexts undergo actual ciphertext multiplication and
relinearization. Client decryption checks original ordinals and numeric results
as an owning test oracle only. After Owner/anchor handle/scope/private witnesses
are dropped, a fresh consumer decodes public setup and every public prerequisite,
reconstructs new Formation expectations from verified encoding/Basis statements,
and verifies both Formation proofs. Cross-role substitution rejects.

## Executed gates

Root used Rust1.99.0 MSVC, CPU native release, locked offline dependencies, two
Cargo jobs and two Rayon threads in a new independent target. There were
**238 unique passing runtime tests**, with no ignored selected case:

| Owning boundary | Tests |
| --- | ---: |
| Core default | 71 |
| Core affected Key/Basis/Formation/two-operand feature tests | 10 |
| Registry200 library, including vector ABI | 5 |
| Peer runtime | 86 |
| Storage client | 29 |
| Independent OS peer transport | 24 |
| SQL capability refusal | 2 |
| Locking plan refusal | 1 |
| New encoding consumer | 9 |
| Linked sixteen-proof input chain | 1 |

Fourteen runtime tests are new. The source/value/identity/scaling/gap/tail and
mask-reversal attacks include coherently rebuilt false traces checked by the real
SDK. Genuine foreign Source/key-context and fresh-salt controls distinguish valid
new statements from replay under the independently pinned original. Bounded frame
tests cover canonical roots, lengths, nested decode budgets and damaged proofs.
The independent two-operand test also produces a genuine foreign-CsHat Key proof,
checks native-prime/CRT and SDK phase oracles over all8192 coefficients per basis,
and re-verifies the actual13-component chain after private drop.

Twenty Core and two Formation compile-fail doctests passed (seven new). Default
core check and strict all-target Clippy passed for Core with all features,
Registry200, the standalone experiment and affected production consumers. Both
CLI modes passed. The actual requirements-sync and architecture test sources
each passed via direct rustc test builds; this is not a full playground Cargo run.
The 61 older SQL success/fault cases remain unchanged, unignored and known
**NOT GREEN**. They were not rerun or credited as passing. Full PostgreSQL is not
implemented by this evidence. Unaffected historical experiment suites were not
rerun merely because the primitive enum gained two exhaustive arms.

Reproduction entry points (the frozen runner used exact discovered test binaries):

~~~text
cargo clippy --release --locked -p bfv-query-core --all-features --all-targets -- -D warnings
cargo test --release --locked -p bfv-query-core --lib -- --test-threads=1
cargo test --release --locked -p bfv-query-core --all-features key_anchor:: -- --test-threads=1
cargo test --release --locked -p registry200-proof --lib
cargo test --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::coefficient_encoding:: -- --test-threads=1
cargo test --release --locked -p bfv-query-core --all-features --doc
cargo test --release --locked -p bfv-ciphertext-formation --doc
hiding-fri-source-primitives security private-coefficient-encoding
hiding-fri-source-primitives prove private-coefficient-encoding
~~~

## Security and observed resources

Actual analysis found degree4, H512, 192 queries, five random codewords, two
opening points and16 quotient chunks for each role. Existing profiles/caps were
not weakened. The new AIRs retain a conservative declared degree hint5.

| Relation | Width | Public values | Constraints | Unique/list floors |
| --- | ---: | ---: | ---: | --- |
| Existing canonical Source | 11521 | 691 | 28949 | 128/128 bits |
| All-original coefficient encoding | 2000 | 752 | 7392 | 128/128 bits |
| Private-mask coefficient encoding | 1288 | 772 | 2852 | 128/128 bits |

These are individual profile assessments. Even a conditional union of16
128-bit error bounds gives only124 bits before binding assumptions. No composed
128-bit claim is made.

The standalone encoding CLI measured15558.4086ms through fixture/private-buffer
drop, versus15800.9141ms for its whole observed command. Its two pairs were
23214726/22064486B. Peak recorded RSS was902635520B and sampled private usage
898134016B, with66 samples and a maximum actual gap339.0657ms. This CLI includes
genuine Owner/setup/Key production and verification, Source/compiler/witness
preparation, Source proof and both encoding proofs; the pair contains no Key or
Formation proof.

The linked sixteen-proof test measured159647.9611ms through fresh public checks,
including setup/encryption, proving, actual unverified FHE, client completion and
public file I/O. Its fresh-public region was43826.1533ms, including setup decode,
parent reconstruction and rejection controls; it is not one verifier's latency.
The whole observed command was160061.5418ms. Recorded peak RSS was1289125888B,
sampled private usage1285345280B,581 samples, maximum gap538.9607ms.

| Linked test component | Complete serialized bytes |
| --- | ---: |
| Key | 16734399 |
| Shared Source proof | 19306655 |
| Source+all-original encoding pair | 23221222 |
| Source+private-mask encoding pair | 22070502 |
| Each of ten Basis frames | 15955459–15963779 |
| Input0 / Input1 Formation | 21293787 / 21292859 |
| Public spool, including Source duplicated in both pairs | 264208511 |

The separate Core13-component test measured175537.6951ms through completion,
including its additional genuine adversarial Key, native oracles and rejection
checks. Its fresh setup/file-read/verification/rejection region was53519.3594ms.
These are same-process observations with public caches potentially warm. Process
startup and final public-buffer/file cleanup are outside the inner JSON timers.

Across23 observed CLI/test commands there were3368 sampled process rows and36
process instances, including target-owned descendants. Maximum concurrent sampled
RSS was1315708928B, private usage1315995648B, and recorded OS peak RSS1315708928B.
Nominal sampling was100ms; maximum actual gap was1325.8631ms. Observed commands
totaled911091.4586ms. No sampled1792MiB per-PID fuse or1200s command limit fired.
Compilers/doctests/contracts were not resource-observed. Sampling and recorded
live-process OS peaks are not hard RAM bounds or a complete cold peer operation.
There is no fixed query-latency threshold.

## Evidence identity and remaining work

Native Source froze1175 files and38 task paths at parent
`bab64a93525e6fa93188496bbb3cf73ca109aecc`. After native closure only this report
and six module README texts changed. Rust, manifests, locks and test bodies remain
byte-identical to the executed Source. The three old ChaCha files are inverse-exact
after removing only the two new Kind arms; each lock gains one existing local
dependency. Requirements copies match, including hidden WHERE/constants.

| Immutable local record | SHA256 |
| --- | --- |
| Source R5 | `70A199B4960071DD7AF129A0EC557D18B1D903DBCE796177DF63F1AF8C599A15` |
| Baseline R5 | `2644B0FD7215BECAE10400F1FE24A444AA88F8B2007AA07E4D5F8EC1135BCADA` |
| Compile | `5B9088E043985A29575AF07573C44F1BFCD3F26F98B17A7D3BE659CDC9982760` |
| CLI/security/prove | `1A0A597793C840F50C8F09E3519FFB705D0EC511A11FCFB4BC39EF965DA651F9` |
| Tests | `2ED03A9761CE648527E896486C2BD326A8F4F78BA96B221AF4217C13BCAA95A3` |
| Doctests | `BD30692E4251C4FD062E18B9175DE030412EB3C8BBE906D56D8FB63981458931` |
| Contracts | `F1AB6F505AEBE533F45B39CCFDEE601FCE1AA3C059335DA8CB6DE0A2E2916F35` |
| Native closure | `E4EB43BFB71A361428C832613186BB0769718D78BF6DA16F48E466B402EC459C` |
| Source review | `B8C191CF0D9B0C5777D49B3365812A468A2ACBD9652C2015F2818D7B849D1591` |

Records live under ignored `.local/private-input-validation-r5/`,
`.local/private-input-baseline-r5/`, `.local/private-input-native-closure-r1/`
and `.local/private-input-source-review-r1/`. Failed R2/R4 lint attempts remain
preserved; unused imports, vector argument grouping and a test iterator were
corrected without changing equations or proof parameters. The preparer's output
path substitution was corrected before R5. Earlier source-only packets are not
counted as native passes. Closure rehashed3301 protected PE files,864 SDK anchors,
five tools and8507 earlier receipts. Targets are independent copies, not hardlinks.
No generated proof, executable, key or local receipt is committed.

The new pair fits its own32MiB bound. There is no16-proof aggregate wire or
Journal operation: existing32MiB Body,64MiB transport and256MiB whole-history
limits remain unchanged. A sum of local spool files is not protocol admission.
Complete private output MulRelin, evaluation-key same-secret consistency,
fresh decentralized agreement, controller/writer authorization and integration
with live SQL remain open. This fixed four-row numeric relation does not establish
arbitrary PostgreSQL types/operators, joins, transactions, locks, bounded storage
at scale, or the whole requirements contract.
