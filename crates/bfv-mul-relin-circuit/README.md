# Fixed full BFV product routing

This library owns the mathematical134-node graph from two original Q5
ciphertexts through multiplication/scaling/relinearization to the exact two
canonical SDK PowerBasis output components. It assembles complete primitive
requests and checks proposed vector/header/wire associations. It produces no
proof, checked product, SQL permission, setup authority or freshness decision.

## Ownership and direct dependencies

| Direct project dependency | Responsibility |
| --- | --- |
| [bfv-fixed-geometry](../bfv-fixed-geometry/README.md) | Fixed N8192, ordered Q5/P5 and plaintext modulus114689 |
| [bfv-ciphertext-wire](../bfv-ciphertext-wire/README.md) | Strict borrowed canonical PB payload/seed views before SDK construction |
| [bfv-ntt-circuit](../bfv-ntt-circuit/README.md) | Typed native NTT request/output codecs; no query transform evaluation here |
| [bfv-scale-circuit](../bfv-scale-circuit/README.md) | Exact Extend5To10 and Scale10To5 codecs |
| [bfv-tensor-circuit](../bfv-tensor-circuit/README.md) | Exact Q/P tensor codecs |
| [bfv-relinearization-circuit](../bfv-relinearization-circuit/README.md) | Embed/MAC codecs and shared pure full-vector routing |
| [bfv-relinearization-key-source](../bfv-relinearization-key-source/README.md) | Immutable independently pinned original public key preprocessing |

SHA256 checks existing primitive request headers. SHA512 receives the unchanged
raw identity feed. `fhe`/`fhe-math`/`fhe-traits` build fixed parameters and expand
an original public ciphertext seed; the bridge neither decodes an SDK ciphertext
nor re-executes a query NTT. There is no proof SDK, experiment, callback, backend
factory or global patch dependency. Primitive AIRs, domains and proof profiles
remain with their existing owners.

## Public mathematical contract

`node_metadata(node)` fixes the existing kind/basis tags. `NodeRequest` and
`NodeOutput` hold the existing typed primitive objects. `GraphClaims::new` accepts
exactly four complete5N native components and all134 canonical typed outputs.
Read-only accessors and consuming `into_parts` let a producer rebind public
headers without mutable fields or a checked-prefix object.

`GraphClaims::encode(expected_profile64)` and `decode(expected_profile64, bytes)`
retain the exact BFVMRG01 ABI:96-byte header, all20 native rows and134 ordered
role-sized output frames, totaling16,727,920 bytes under the unchanged16MiB cap.
The complete64-byte profile must equal the independent argument before decode
allocates; it is an ordinary unverified context, not a library-selected backend
or allowlist. `NodeOutput::decode_for_node` also checks the exact node's role,
direction and basis. Aliases, length/count substitutions and trailing bytes fail.

`derive_request(node, native_refs, prior_outputs, prepared_key, binding32)`
requires `prior_outputs.len()==node`. It validates borrowed native rows and prior
metadata, then assembles the complete next input through the existing codecs.
It never evaluates the NTT, Scale, Tensor, Embed or MAC equations. The consumer
derives every binding32, including all17 special arithmetic instance labels,
from its own complete proof context. `require_header` checks exact typed role,
binding, full primitive request digest and the Relin keyset label; it is not a
cryptographic verification result.

| Nodes | Complete operation |
| --- | --- |
| 0..19 | Inverse Q5 for all four original native components |
| 20..23 | Extend each PB Q5 component to QP10 |
| 24..43 | Forward P5 for each extended component |
| 44..53 | Tensor at each Q/P modulus |
| 54..83 | Inverse QP10 for all three tensor components |
| 84..86 | Scale each complete QP10 component down to Q5 |
| 87..96 | Forward Q5 for downscaled c0/c1 |
| 97 | Embed PB c2 directly into25 PB digit rows |
| 98..122 | Forward Q5 for all25 source/target digit rows |
| 123 | Full target-major MAC over originals/digits/all50 public key rows |
| 124..133 | Inverse Q5 of both outputs to exact PB wire |

`check_ciphertext_bridges(parameters, input_bytes[2], output_bytes, claims)`
checks every stored PB input row, seeded c1's original native expansion and all
ten final PB rows. Both inputs and output pass the strict parser before fixed
SDK parameter construction. Original parameter bytes must match the fixed
parameters; output must be unseeded with the actual key-switch true flags.
The Ntt wire tag still stores PB coefficients: no native/PB relabel is accepted.

`feed_identity(&mut Sha512)` appends all raw native words, exact node metadata
and every raw output coefficient in the original order, excluding derived
headers. The [full proof consumer](../bfv-mul-relin-proof/README.md)
owns the domain, full Source/Encoding/Key33/setup/query/ciphertext provenance,
profile, final graph identity, proof order/budgets and real verification. It must
still verify all16 input proofs and all118 output records before yielding a
checked product. A decoded claim, prepared key or matching bridge grants none
of those obligations.

## Owning tests and validation boundary

The moved owning codec test retains its original name and assertions. Additional
tests cover complete64-byte profile matching and boundary mutations,
raw-feed/header separation, exact prefix/order
and native aliases, all134 full-vector edges, original25 digits/all50 key rows,
actual SDK PB output parity, seeded/unseeded Boolean forms and canonical last
input/output/seed substitutions. Fixtures are explicitly non-secret; primitive
evaluation and the independent SDK FHE operation occur only in tests.

[Executed extraction validation](../../experiments/bfv-mul-relin-proof/CORE-EXTRACTION-VALIDATION.md)
passes all six owning cases, strict Clippy, old-code byte replay and genuine
complete32/input16/product134 consumer regressions. These observations establish no hard
whole-process memory bound, SQL completeness, private query provenance, public
RK same-secret consistency or a composed128-bit security guarantee.

```text
cargo test --release --locked -p bfv-mul-relin-circuit --lib -- --test-threads=1
```
