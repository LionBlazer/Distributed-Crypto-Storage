# Unrelinearized encrypted selection arithmetic probe

This measurement executable is a rejectable arithmetic candidate for the full ordinary-query target of **<=500ms including FHE, proofs, fresh agreement and client result**. It implements no computation/completeness proof, Source authority, SQL admission, lock, freshness, consensus, storage or network service. Its output always says proof_verified=false, sql_accepted=false, security_assessed=false and noise_certified=false. All current production profiles and gates remain unchanged. The [native record](VALIDATION.md) covers its owning tests and one real arithmetic observation; it establishes no full-query result.

## Owned boundary and dependencies

| Direct dependency | Role |
| --- | --- |
| [bfv-fixed-geometry](../../crates/bfv-fixed-geometry/README.md) | The original ordered five baseline Q constants only; does not approve new parameters |
| fhe=0.1.1 / fhe-traits=0.1.1 | Real SDK parameters, secret-key encryption, ciphertext multiplication, decryption and canonical roundtrip |
| rand=0.9.2 | Fresh actual key/encryption/query nonce randomness |
| sha2=0.10.9 | Exact public byte association labels, never computation proof |
| zeroize | Explicit plaintext-vector/decoded-row cleanup; no claim about SDK/FFT/scratch erasure |
| serde_json | Public numeric observations; no plaintext result or private key output |

There is no library entry point or production dependency on this executable. main accepts only bounded --mode pair|baseline|candidate and --case all|none|ge128. PUBLIC_ROWS is an explicitly public nonsecret four-row fixture. Evaluator owns only Arc<BfvParameters> and accepts serialized ciphertext bytes; it has no SecretKey, Source rows, predicate mask, plaintext answer or accepting callback. It performs actual &a * &b, then serializes the resulting **three** components. The client checks the exact parameter/request response binding, canonical full ciphertext and all rows/bases/coefficients, then genuinely decrypts with its retained key. This in-process role separation is not independent-process evidence.

## Why this candidate

The current coefficient request already has multiplicative depth one. SDK bfv/ops/mod.rs produces c0,c1,c2; SecretKey::try_decrypt iterates every component, including s^2. Current bfv-query-core/kernel.rs:30–47 immediately relinearizes, but the final SELECT output need not be reduced to two components for another multiplication. Omitting relinearization therefore removes the relinearization-key same-secret/noise premise for this operation; it does not remove the SAME-secret input Formation/key association required by a future proof.

Both probe profiles use two polynomial lanes per original row: at coefficient (2*i)*512+age store 256+age; at (2*i+1)*512+age store amount. No Source row is selected before encryption. The separately encrypted private truth table puts p(age) at coefficient255-age, compiled by visiting the **public age domain only**. Any age truth table has the same operand shape. One multiplication gives p(age)*(256+age) and p(age)*amount at the two target255 coefficients. A selected packed value in256..511 decodes presence+age; zero denotes absence. Client completion consults no original rows or WHERE. All four original ordinals are retained, including a selected zero amount.

Eight lanes fit N4096: last product coefficient7*512+510=4094, so the polynomial product has no negacyclic alias. Complete polynomial decoding checks all N coefficients, including the lane gap and reserved tail. There is no rotation, bootstrapping, result calculated from Source, or dummy cryptographic work.

| Profile | N / plaintext t | Ciphertext Q | Purpose |
| --- | --- | --- | --- |
| baseline | 8192 /114689 | Original ordered5 primes, sum bit widths218, CBD variance10 | Original parameter geometry, but NEW two-lane/three-component experiment (not the old live request/proof profile) |
| candidate | 4096 /65537 | Exactly two distinct SDK-generated30-bit NTT primes, CBD variance10 | Deliberately small-Q depth-one candidate, not an approved security/noise profile |

Both moduli65537/114689 support the required ring/plaintext arithmetic. The candidate uses two30-bit limbs instead of one60-bit limb: a future secret-convolution proof can keep a much smaller per-basis integer range; the old signed63 Basis range cannot simply accommodate an arbitrary60-bit coefficient times4096 secret coefficients. The exact generated candidate primes and complete parameter digest are emitted, so Root must pin them before any future proof design. The SDK computes its actual embedding (including Q mod t); the old Encoding SCALE78307 cannot be reused unchanged.

## Source-derived proof-cost model, not timings

Current graph:134 claims,115 NTT nodes and118 output proof records, plus input16 and Core/Source. Ending at its actual Down3 would instead leave87 claims/70 NTT/71 records for the same N8192 five-Q/five-auxiliary layout. Removing47 tail claims includes Qforward10, Embed, digitForward25, MAC and finalInverse10. There is no proof implementation of that truncated graph in this module.

For a NEW variable-geometry analogue with k original and m multiplication auxiliary primes, the pre-relinearization skeleton has7*(k+m) NTT jobs and8*(k+m)+7 claims. The SDK auxiliary rule gives m=2 for this60-bit candidate, so k=2 gives28 NTT jobs/39 claims and, if the existing arithmetic batch strategy is rederived,29 proof records. This is a routing count only. NTT butterfly count becomes28*4096*12/2=688128 versus115*8192*13/2=6123520 in the old output graph. No proportional wall-time, security or500ms conclusion follows. Source/key/Formation/Core and cold/fresh network costs remain outside these counts. Key33 is a commitment/public-value layout, not a cryptographic need for8192 or five-Q; changing N still requires new actual AIR/profile, setup, encoding, catalog, App/G/Rules and resource validation, never relabelling old evidence.

A further unimplemented SIMD option is N2048 with2048 slots =4rows*2fields*256ages: Source uses an encrypted onehot at each original age and the mask repeats the private age truth table across lanes. Elementwise product can be returned in full; client decryption combines slots without WHERE evaluation and without rotations. It needs genuine Source-to-SIMD-to-polynomial encoding proofs, including the plaintext inverse NTT and slot permutation. The one54-bit upstream N2048 parameter is only a catalogue candidate; the current SDK rejects single-prime relinearization, which the three-component path does not need. Noise and security are unresolved, so this probe deliberately does not add a second algorithm or claim SIMD is faster.

## Security and correctness obligations

No lattice-security estimate is run or asserted. The local SDK labels its old catalogue only about128; current Core explicitly says upstream_about128_not_independently_validated. The [current HE security guidelines](https://doi.org/10.62056/anxra69p1), Table5.2, use classical models and give updated limits dependent on secret/error distributions; older catalogue109/218-bit choices must not be inherited as a certificate. The exact CBD sampler uses40 coin bits, support[-20,20], variance10. Future estimation must pin estimator code/cost models, exact Q and N, CBD secret/error distributions and available samples, report classical/quantum distinctions, and independently meet the required floor. The paper distinguishes security parameters from functional examples; neither guarantees our exact circuit. See the [primary community index](https://homomorphicencryption.org/security-guidelines/) and [estimator sources](https://github.com/malb/lattice-estimator).

Likewise, successful samples do not prove correctness for all admissible bounded noise or adaptive attempts. A future proof must establish the exact SDK scale/down-rounding, all-coefficient error budget and typed field bounds, using a deterministic accepted-domain bound or an explicit failure budget. No relinearization key exists in the experiment; secret power s^2 still enters decryption. There is no decryption-oracle service. The test-only public oracle independently performs plaintext ring convolution of the actual public input encodings and compares EVERY N output coefficient, plus independent expected row/ordinal values, for all/none/ge128. It is compiled only under cfg(test) and cannot supply an executable answer or fallback.

## Root validation and measurement

The experiment adds one workspace member outside default-members and one new local-package lock entry using already locked dependency versions. Suggested smallest checks:

~~~sh
cargo clippy --release --offline --locked -p bfv-unrelinearized-selection --all-targets -- -D warnings
cargo test --release --offline --locked -p bfv-unrelinearized-selection -- --skip encrypted_all_none_and_hidden_boundary_return_exact_original_ordinals
cargo test --release --offline --locked -p bfv-unrelinearized-selection tests::encrypted_all_none_and_hidden_boundary_return_exact_original_ordinals -- --exact --nocapture
cargo run --release --offline --locked -p bfv-unrelinearized-selection -- --mode pair --case all
~~~

The first test invocation has three cheap envelope/domain/full-tail tests and no FHE; the explicit owning test reuses one parameter/key setup per profile for three genuine products each (six total), compares full decoded polynomials and exact rows. The default executable does exactly one genuine product per profile (two total); it never renews/retries a failed profile or changes Q after failure. If the candidate fails, keep its failure rather than replacing parameters under the same identity.

Use the existing1792MiB/PID cap and RAYON_NUM_THREADS=2 in Root's sampler; no runtime/job/security settings change. Numeric stderr product_start/end markers allow an external process CPU/peak-memory observer to associate phases. Instant values are WALL time, not CPU. Parameter/key setup is separately reported together with setup_plus_math_wall_ms. math_full_wall_ms includes fresh Source encoding/encryption/wire, private-mask compile/encryption/wire, request association, canonical peer decode, actual product, response wire, client binding/decode/decrypt and full-coefficient checks. No original ciphertext is silently precomputed out of that interval.

If this math segment alone exceeds500ms, the measured implementation/conditions cannot satisfy the full500ms target. If it is below, that establishes only this segment: proof production/verification, cold/current-head assurance, consensus, storage and actual network remain missing. No complete SQL, resource guarantee or latency improvement is established until those relevant complete operations are measured.
