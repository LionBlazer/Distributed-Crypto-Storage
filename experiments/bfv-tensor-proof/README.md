# Public BFV tensor STARK experiment

This standalone consumer proves one complete N8192 tensor stage for
one selected fixed Q5||P5 modulus. Four public native-NTT input vectors a0,a1,b0,b1
produce all three vectors d0=a0*b0, d1=a0*b1+a1*b0, d2=a1*b1 modulo p. This is the
actual intermediate relation used by pinned fhe 0.1.1 multiplication. Native
validation passed all 14 owning tests, actual SDK parity across all ten bases,
all ten genuine serialized proofs and two measured CLI examples. See the
[validation report](VALIDATION.md) for the exact scope and observations.


The new `BoundAir` alias uses the shared `ProfileAir` declaration/delegation wrapper.
The consumer still owns the exact profile digest, 32+8 public-value order,
prepared-data admission, role/shape checks and independent preprocessing key.
The [wrapper regression](../bfv-relinearization-proof/VALIDATION.md) passes all
14 owning tests, including all ten genuine stages, and preserves all ten actual
security reports exactly. Earlier measurements retain their recorded scope.

## Ownership

| Direct project dependency | Responsibility |
|---|---|
| [bfv-tensor-circuit](../../crates/bfv-tensor-circuit/README.md) | Fixed geometry, sealed canonical request/output/auxiliary codecs, exact prover arithmetic and optional TensorAir. |
| [bfv-arithmetic-stark](../../crates/bfv-arithmetic-stark/README.md) | Shared fixed linked Plonky3 configuration and actual symbolic security analysis. |
| [bounded-postcard](../../crates/bounded-postcard/README.md) | Per-decode sequence and total container-slot guards around original Postcard encoding. |

This consumer owns its transcript profile, 80-byte proof frame, caps, error
mapping, independent preprocessing setup, proof lifecycle, CLI and owning tests.
`backend::BoundAir` delegates all tensor arithmetic and adds eight consumer-profile
public words to the library's 32 words. No third SDK configuration, visitor copy,
loader, production Operation or decoder-cap widening is introduced. The Cargo
manifest has its own `[workspace]` and lock. The shared backend belongs to the
core workspace; this experimental consumer remains a standalone package.

Public entry points are `backend::analyze`, `prove`, `verify`, and the explicitly
PUBLIC NONSECRET `fixture::request`. `CheckedTensor` has private binding fields and
matches exactly one complete request/output. It cannot become CheckedOperation,
permit a mutation, or accept SQL.

## Proof and verifier contract

The profile binds the exact library relation/basis, shared SDK/hash descriptor,
fixed configuration, complete native-NTT ordering, and consumer caps. The frame
is magic `BFVTSP01`, profile32 at8, independent binding32 at40, basis72, nativeNTT2
at73, input count4/output count3 at74/75, and four zero reserved bytes. It then
contains the exact 884880-byte public auxiliary and canonical SDK proof payload.
Each of the four input and three output vectors contains all 8192 coefficients.

`prove` evaluates the public tensor and certificate, builds the public matrix and
prover preprocessing, then creates and serializes a genuine SDK STARK. `verify`
checks caps/header, canonical auxiliary, bounded Postcard, no trailing bytes,
canonical re-encoding, and exact height. It prepares its own complete public
matrix and verification key, then calls the SDK verifier. It never evaluates the
tensor, multiplies the inputs, divides by p, or recomputes any quotient/carry.
No prover-supplied verification key is accepted.

The shared linked configuration is Goldilocks/Poseidon2-12, extension degree5,
blowup8 and192 queries. Each exact AIR is actually analyzed; either individual SDK
model below128 rejects. The compiled tensor shape must remain width1/public61/PV40,
actual degree at most2 and quotient chunks at most8. Actual SDK analysis reports
25 constraints, degree2, one quotient chunk, 67 batched functions and128 bits in
both individual models for each of the ten bases. These are per-stage models;
multiple proofs do not establish a composed128 claim.

## Bounded stage policy

This new frame uses8MiB, per-container4096 and shared1048576 decoded container slots.
These limits change neither production2MiB nor RNS/NTT policies. Goldilocks binary
serialization costs eight byte-array slots plus its parent field slot; extension
and four-field hash objects cost at most48/37 with their parent slots.

For height8192/blowup8 the maximum binary tree depth is16. With192 queries, one
pruned sibling vector is bounded by sum(min(192,2^j),j=0..15)=1791, below4096.
Conservatively allowing three input commitments,16 FRI rounds, up to eight
five-column quotient chunks,61 public columns, one main column and65536 further
container slots gives198801+349798+176256+4896+147456+65536=942743 slots. This is a
source-derived profile allowance; all ten genuine serialized proof decodes pass
the native gate. The frame length remains an
independent hard bound. Container counts and raw arrays are not process RAM limits.

The public matrix alone is3997696 bytes; its blowup8 field array would be31981568
bytes. Main arrays are65536/524288 bytes. These omit SDK intermediates, copies,
keys, allocator state, proof buffers and other process memory. The validation
report records separate whole-process observations rather than treating these
array sizes as a RAM bound.

## Owning validation gates

The upstream oracle constructs real `fhe_math::rq::Poly` values in native NTT
representation and calls its multiplication/addition operators for all ten bases.
It compares all8192 coefficients of all three output components, including both
middle products. No duplicate scalar tensor implementation serves as the oracle.
A mandatory unignored test generates, serializes, verifies and drops each of the
ten genuine full-stage proofs sequentially; only Q0/P4 public representatives are
retained for rejection cases.

Other tests bind every complete input/output and last coefficient, reject foreign
basis/profile/context/representation, omitted middle terms and component swaps,
and rebuild canonical output hashes/auxiliary before testing integer equations.
Every component quotient and all seven shifted carries are attacked at the final
row. Range aliases reject before Goldilocks conversion. Raw SDK adversaries create
real proofs under chosen equations or a foreign public preprocessing key; the
normal verifier must reject. Decoder examples cover sequence/total budgets,
Goldilocks byte slots, framing, truncation and trailing payloads.

After the validation owner has resolved and reviewed this standalone lock, use
native Rust1.99 with a fresh target and recorded environment. First run actual
trace-free security analysis for each basis, then upstream oracle, genuine stages
and all owning cases. For example from the repository root:

```powershell
$ErrorActionPreference = 'Stop'
function Invoke-Checked { & cargo @args; if ($LASTEXITCODE -ne 0) { throw "Cargo failed: $LASTEXITCODE" } }
$manifest = 'experiments/bfv-tensor-proof/Cargo.toml'
Invoke-Checked build --release --locked --offline --manifest-path $manifest
Invoke-Checked test --release --locked --offline --manifest-path $manifest --no-run
Invoke-Checked clippy --release --locked --offline --manifest-path $manifest --all-targets -- -D warnings
for ($basis = 0; $basis -lt 10; $basis++) {
  Invoke-Checked run --release --locked --offline --manifest-path $manifest -- security $basis
}
Invoke-Checked test --release --locked --offline --manifest-path $manifest --lib tests::all8192_three_components_match_actual_sdk_poly_tensor_for_all_ten_bases -- --exact --test-threads=1
Invoke-Checked test --release --locked --offline --manifest-path $manifest --lib -- --test-threads=1
Invoke-Checked run --release --locked --offline --manifest-path $manifest -- prove 0
Invoke-Checked run --release --locked --offline --manifest-path $manifest -- prove 9
```

`security <basis0..9>` emits one actual analysis JSON without a trace or matrix.
`prove <basis0..9>` emits that analysis followed by one verified-stage JSON. Its
fixture is constructed before the proving timer. Proving includes exact public
arithmetic/certificate, configuration, preprocessing, genuine SDK proof and frame
encoding; verification includes bounded decoding, preprocessing and actual SDK
verification. Separate Rust timings describe these phases. Neither timer includes
process startup, initial CLI security analysis, or fixture construction; an external
owned-process observer is needed for complete elapsed time and process memory.
The validation report distinguishes measured phases from complete process time;
these examples establish no comparative speed or whole-query latency claim.

Full MulRelin still needs linked extension/NTT/downscale/relinearization relations,
complete keyset binding and its separate same-secret authority decision. This
public arithmetic proof does not establish ciphertext/source formation, private
custody, source/selection completeness, fresh agreed state, writer fences,
decentralized agreement, practical SQL latency or production query acceptance.
