# Fixed BFV key transform

This crate extracts the existing KeyTransform relation without changing its
historical profile, W9932/PV33/512-row geometry, commitment stream or transform.
The [validation record](OWNER-KEY-VALIDATION.md) covers real Owner proofs, hostile
decoding, all old regressions and sampled process resources. The direct [bfv-hiding-stark](../bfv-hiding-stark/README.md)
dependency owns the single hiding configuration, Poseidon2 gadget and bounded codec.

The input root commits exactly context8 + private salt4 + zero4 + 8192 values
`z = s + 20`, with every coefficient proved in [-20,20]. A separate salted root
commits the natural-order odd evaluations of the same signed polynomial. The AIR
proves the twist, bit reversal, all 13 butterfly stages, complete hash streams and
last checkpoints. The existing descriptor binds database, independent BFV domain,
parameter digest and epoch. It does not authorize an owner or certify that arbitrary
evaluation keys were generated from this secret.

`ProverWitness` accepts caller-owned zeroizing bounded coefficients and salts;
`prove` constructs the actual immutable KeyAir, analyzes its individual security,
uses the fixed hiding suite, verifies the emitted proof and serializes it canonically.
`verify` constructs its own actual AIR/assessment/configuration and checks a complete
bounded frame under an independently pinned Expected. `circuit` is a low-level
mathematical API for caller-owned inputs and rebuilt proof tests; it never receives
an Owner, and cannot recover an Owner handle's secret.

The distinct `DCSKTP01` envelope has a 208-byte header: magic8, unchanged profile32,
full original setup label32, unchanged descriptor68, input root32, output root32,
and payload length4. The payload ceiling is 20 MiB, the sequence ceiling 16,384,
and the nested aggregate budget 24 Mi elements. Both actual Owner frames fit
these new policies; old experiment caps/allowlists are unchanged. The validation
record distinguishes sampled resources from a whole-peer RAM guarantee. A checked result retains the full setup label, which
is still an external pin, not an extra legacy AIR public value or authority token.

The optional [core Owner path](../bfv-query-core/README.md) checks the original
complete setup against its privately retained identity before copying any secret.
That trusted owner-local mint associates the complete setup with the input root.
A peer-supplied setup/anchor/proof trio cannot create that authority. The old
parameter-only descriptor remains separate from the full setup label; BFV domain
and storage/AEAD domain are also separate.

Explicit wide/narrow coefficient and stored salt buffers use Zeroizing. Native
Goldilocks vectors, shifted vectors, FFT/trace rows, P3 LDE/PCS and scratch copies
are not securely erased; dropping a handle is not a claim of complete RAM erasure.
No secret bytes are exported or logged by the Owner API. There is no durable private
anchor persistence/recovery: recreating its handle creates a new salted input root.
Each standalone proof has a fresh output salt that is discarded. Its returned root
therefore has no reusable private Basis opening. A future combined owner-local
Key+five-Basis producer must retain its own fresh opening inside that opaque scope
and emit a newly matching genuine Key proof; it must not recover salts from evidence.

This capability does not form a ciphertext, prove evaluation-key same-secret/noise
correctness, authorize live SQL, establish freshness/finality or close the full FHE
query proof. The owning core test prints only public sizes and measured stage times
during validation; these phase observations are not SQL performance claims.


## Explicit claim and combined producer

`prove_statement` is the additive low-level mathematical entry for a caller-owned
explicit CLAIM and witness. It uses the same fixed AIR, trace, assessment,
self-verification,208-byte frame/profile and caps. A supplied claim is not trusted
witness association or Owner authority. Existing `prove` still derives its current
witness statement and delegates. The new owner job can derive and retain one Shat,
compute its claim once and use this entry without another out-of-trace native
transform; the real Key trace still performs all proved NTT steps.

The [Core Basis job](../bfv-query-core/README.md) retains a fresh
opening privately across five ordered convolution proofs. It emits its OWN newly
matching Key evidence, never reopens a standalone evidence's discarded salt. The
[basis crate](../bfv-basis-convolution/README.md) verifies actual Key bytes before
child work and pins all33 public values, including the fresh CsHat.

`Evidence::verify_owned(full_setup_id, expected, bytes)` now retains exact public
bytes only after the existing bounded genuine verifier accepts them. This lets
the separate [Core owner-state capability](../bfv-query-core/src/owner_state/README.md)
restore an authenticated private epoch without rerandomizing its Key proof.
It is neither a public private-opening import nor an owner/RK authorization token.
All old proof arithmetic, profiles and frame limits remain unchanged. All six
owning primitive tests passed, including genuine owned evidence and a repaired
frame with a damaged trace commitment; the [validation](../../docs/owner-key-recovery.md)
also covers the Core restoration consumer.
