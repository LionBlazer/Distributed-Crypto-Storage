# Public unrelinearized-product arithmetic

This core library owns the closed N4096/Q2/P2 unrelinearized BFV product
relation. It preserves the experiment's eighteen-point **UNASSESSED** profile,
`UCPITQ01` request, `UCPITC01` frame and `DCSUSC01` integer certificates.
The extraction does not admit a DCS computation proof.

`Expected::checked(nonce, original_ct2_pair, claimed_ct3)` parses both original
inputs and the candidate output with the bounded canonical SDK PowerBasis wire
parser. The caller independently retains its original inputs. Candidate output
bytes may come from an untrusted evaluator; constructing immutable public
metadata accepts no computation.

`produce(&expected)` returns `UnverifiedEvidence`. Its byte accessors export
unverified bytes. `check_arithmetic(&expected, bytes)` checks the exact complete
frame, canonical residues, all seven integer certificates and every product
identity using challenges derived from the same complete original bytes. Only
this function creates the sealed, move-only `ArithmeticCheckedProduct`.
Its PIT conclusion remains conditional on the Fiat-Shamir model. It grants no
Source, key validity, hidden program, SQL completeness, current head, QC or
durable mutation authority.

The private modules own distinct parts of that operation:

- `statement`: complete unseeded CT2+CT2/CT3 decoding, canonical residues,
  literal request/output bytes and an independent nonce.
- `geometry`: fixed N4096, t65537, Q2/P2 and complete row checks.
- `scale`: exact SDK constructor constants and seven integer certificates.
- `pit`: prover convolution and the fixed eighteen-point identity checker.
- `modular`: bounded Montgomery Horner verification and producer NTT arithmetic;
  coefficients stay ordinary while evaluation points and twiddles are encoded.
- `certificate`: the complete 1,737,899-byte codec, associations and transcript.

Normal dependencies are only `ethnum` 1.5.3, `num-bigint` 0.4.8,
`num-traits` 0.2.19 and `sha2` 0.10.9. No SDK, registry, consensus, storage,
GUI or experiment enters the normal dependency graph. SDK dependencies and
the private fixture are confined to owning tests.

The [experiment](../../experiments/bfv-unrelinearized-certificate/README.md)
now consumes this library directly for SDK computation and client completion.
The actual [upper consumer](../registry200-proof/src/two_lane_encoding/README.md#math-only-encrypted-product-composition)
requires both complete arithmetic and fresh Source/encoding/Formation checks.
It compares the same ordered raw ciphertexts and nonce: `GFMRQ001` and
`UCPITQ01` are different requests, with no profile or header conversion.

The [scaler contract](src/scale/README.md) concerns the pinned SDK algorithm.
For arbitrary canonical QP input, that algorithm can differ from ideal centered
CRT rounding; the native midpoint example deliberately preserves this contrast.
The full product additionally constrains its tensor input. Mathematical
assumptions and limits are recorded in [MODEL.md](MODEL.md).

The [executed validation](VALIDATION.md) covers eighteen library tests, the real
experiment consumer, the complete upper chain, privacy examples and strict
Clippy. One local product/certificate/client operation took 75.604 ms. Fresh
receiving with all input proofs took 1730.017 ms. Neither observation establishes
the 500 ms complete network query target. Frame bounds exclude other buffers;
whole-process resource observations have their own recorded scope.

The subsequent producer NTT optimization retains every product/quotient
coefficient and the same complete frame/profile. Nineteen owning cases and the
protected Gold owner's four cases passed; the validation record distinguishes
the observed local improvement from the still unmet complete-query target.
