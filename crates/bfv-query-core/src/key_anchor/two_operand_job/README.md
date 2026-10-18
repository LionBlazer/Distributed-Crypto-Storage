# Two-operand Owner scope

`OwnerKeyAnchor::two_operand_scope` owns one query-independent private Shat and its
salt, then proves one Key and two ordered Basis5 + Formation chains. `Operand`
means Input0/Input1 only. The consumer pins complete ciphertext bytes, q and each
public `EncodedCommitment`; Source/Predicate/SQL policy remains outside Core.
The [private predicate codec](../../coefficient_predicate.rs) lends the exact two
ciphertexts in `PreparedPrivateCoefficientPredicate::request` after checking its
private pending digest and labels. The scope does not encrypt replacement inputs.

The feature is the existing `formation-proofs`. Direct relations are
[KeyTransform](../../../../bfv-key-transform/README.md),
[Basis](../../../../bfv-basis-convolution/README.md) and
[Formation](../../../../bfv-ciphertext-formation/README.md). The private shared
KeyMaterial constructor also supplies the existing single-operand job, whose API,
stages, proof profiles and codecs remain unchanged.

After Key success, `bind_operands` accepts exactly two canonical inputs once.
`prove_next_basis` emits the next basis0..4 for Input0; `begin_formation` accepts
only an opening with its pinned public commitment; `prove_formation` independently
checks ALL KeyPV33, q, complete parameter/ciphertext bytes and encoding metadata.
It borrows only that role's five public Basis frames and uses the retained Key
frame. Existing library verification of the actual prerequisites precedes residual
derivation, AIR and trace creation. The same sequence then runs for Input1.

Failed calls do not advance. Successful Input0 Formation clears that role's guarded
W, result and noise salts, retaining the one shared Shat/CsHat. Complete clears
explicit private material but retains the public Key evidence for borrowing.
`cancel` is terminal and clears both private material and retained public evidence.
Drop uses guarded storage; native SDK/FFT/field/trace/PCS temporaries are not
promised erased. Cancellation occurs between synchronous calls. No secret getters,
private callbacks, serialization or private-state recovery exist.

The 13 distinct primary components have an unchanged worst-case payload cap sum
of 268 MiB plus 3568 bytes of headers (281,021,936 bytes). This is an upper bound,
not an observed size or a new aggregate format. The caller spools public components;
there is no aggregate proof vector, frame, transport request or Journal admission.
The existing per-Body 32 MiB, transport64 MiB and whole-Journal256 MiB limits are
different bounds and remain unchanged. Current-role public frames, setup, trace
and SDK scratch still require whole-operation resource measurements.

The [executed validation](../../../../../experiments/hiding-fri-sha256-gate/PRIVATE-COEFFICIENT-INPUT-VALIDATION.md)
records the scope gates and a separate Source/hidden-query integration. Tests use
explicitly non-secret generated keys/messages, a genuine 13-component primary
chain, a separately genuine foreign-CsHat Key control, native-prime/CRT and SDK
phase oracles over all8192 coefficients, and fresh public verification after the
private scope/anchor/Owner are dropped. These are mathematical formation relations,
not Source/private-query encoding, evaluation-key same-secret authority, SQL
correctness/completeness, freshness or live acceptance. Individual128-bit profiles
do not establish composed128; even a conditional union of13 such error bounds
would give124.30 bits before binding assumptions.
