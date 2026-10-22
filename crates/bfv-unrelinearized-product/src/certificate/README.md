# Canonical compact product wire

The private `compact` module owns the only public product certificate encoding,
`UCPITC02`. The parent `certificate.rs` owns the original logical encoder, job
bindings, producer and complete checker. Direct dependencies are the parent's
strict polynomial packer/unpacker and certificate types, fixed `geometry`,
`scale::reconstruct`, statement endpoints and SHA256. No SDK, secret input,
transport, registry or acceptance policy enters this module.

| Ordered payload | Bytes |
| --- | ---: |
| Header | 320 |
| All three Y polynomials, four bases, N coefficients | 282,624 |
| All three H polynomials, four bases, N-1 coefficients | 282,555 |
| Seven scalers, N rows, two LE66 reduction words in nine bytes each | 516,096 |
| Complete wire | **1,081,595** |

The header binds the unchanged mathematical profile, original nonce, SHA512 of
the literal original request and output, exact wire length, N, eighteen points,
the separate wire-profile SHA256, original logical length, row width and job
count. All reserved bytes are zero. Full header equality and exact length are
checked before decoded allocation. Polynomial values must be canonical; each K
must be below 2^66. Exact fixed lengths require all seven jobs and all N rows.
All decoded storage and the reconstructed 1,737,899-byte logical frame are
bounded by this fixed geometry, but that sum is not a whole-process RAM claim.

`encode` exports all Y/H coefficients and K words from the genuine producer's
private certificate. `decode` reconstructs omitted fields, without computing a
quotient/remainder, using the original fixed constants:

```text
S = sum(r_i*T_i); E = sum(r_i*theta_i)
v = (S+2^126) >> 127
w = (E+2^126) >> 127                 # signed arithmetic shift
y_j = sum(r_i*omega_ji)+w-v*gamma_j-p_j*(biased_k_j-2^64)
```

Checked I256 operations and the original v/w/K bounds apply. Each y is required
to lie in [0,p); extension copies the literal Q rows, and each downscale output
must equal the literal claimed CT3. The original input/output digests and job
headers are recomputed from those exact restored endpoints. The complete parent
checker subsequently runs all seven original integer verifications and all
eighteen PIT points per basis on the original full logical transcript.

For any accepted record, the original interval constraints uniquely fix v and
w. The reduction equality and canonical y uniquely fix K. Thus expanding a
genuine original certificate recreates every original logical byte. Conversely,
the wire is one fixed header plus canonical Y/H and all K words, so two distinct
accepted wires cannot expand to one logical transcript. This does not introduce
additional challenge-grinding encodings. The classical random-oracle bound and
all unassessed qualifications in [MODEL.md](../../MODEL.md) remain unchanged.

PIT still hashes `UCPITC01` logical bytes, not the compressed wire. The old public
frame is rejected; its decoder exists only for owning tests. There is no format
negotiation, migration, verifier-result cache, SDK replay, NTT, ciphertext product
or plaintext operation in reconstruction. Public `wire_profile_digest()` records
the encoding identity without changing the mathematical/key/input relation.

The owning genuine-SDK example compares expansion to the original independent
division producer byte for byte; it rejects the old frame, short/trailing data,
header mutations and both K words/forbidden bits for all seven final rows. The
scaler tests also cover both roles and all 4096 positions on zero, negative,
asymmetric and CRT half-boundary SDK inputs. Repaired false products still reach
and fail the original PIT. See [executed validation](../../VALIDATION.md#compact-wire-with-the-original-logical-transcript).
