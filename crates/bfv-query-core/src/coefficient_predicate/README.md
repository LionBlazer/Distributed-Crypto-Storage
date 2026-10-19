# Private coefficient-predicate mathematical prototype

This Core consumer executes one actual pinned BFV ciphertext-by-ciphertext
multiplication and original relinearization. The four original rows and the
predicate are independently encrypted. It is a non-admitting mathematical
capability, not an SQL answer, computation/completeness proof, Source certificate
or agreed-head decision. WHERE and its constants are never placed in public wire
metadata. No live peer protocol or proof dispatcher accepts this new role.

| Direct owner/dependency | Responsibility |
| --- | --- |
| [coefficient_predicate.rs](../coefficient_predicate.rs) | Query-independent source packing/encryption, private query encryption, borrowed codec and explicitly unverified owner completion |
| [Kernel](../kernel.rs) | Existing actual SDK multiplication and original relinearization-key operation; no plaintext predicate or fixture input |
| [bfv-fixed-geometry](../../../bfv-fixed-geometry/README.md) | Original N8192, ordered Q5 and plaintext modulus114689 |
| [bfv-ciphertext-wire](../../../bfv-ciphertext-wire/README.md) | Fixed borrowed two-polynomial/level/residue preflight before SDK allocation/NTT |
| fhe/fhe-traits0.1.1 | Actual Encoding::poly encryption, multiplication, relinearization and final decryption |
| zeroize, rand and sha2 | Guard explicit plaintext vectors, use fresh OS-backed ThreadRng, bind only the complete encrypted request |

No new dependency or configuration/profile is introduced. The scalar mask remains
caller-owned private input; the caller owns its original rows/mask and their
cleanup. Explicit polynomial plaintext vectors are Zeroizing and SDK Plaintext
implements erasure, but native polynomial/FFT/RK/proof allocator scratch is not
claimed securely erased. Pending state contains only public keyset/context/query
labels and the digest of the randomized encrypted request, never original rows,
mask, selection flags or a locally calculated answer.

## Exact private operation

The source API accepts exactly four CoefficientRow values (u8 age, u16 amount).
It takes no predicate, active flag, limit, window or query. For original ordinal i
and field f=presence/age/amount, lane L=3i+f has its only nonzero coefficient at
512L+age_i, weighted by1/age_i/amount_i. Every original row is retained, including
zero-valued fields; the presence lane distinguishes a real age0/amount0 row.

The separate query API privately encrypts P[j]=mask[255-j] for j0..255, with zeros
elsewhere. All predicate shapes use the same public envelope and fixed support;
no kind, threshold, cardinality, truth-table byte or SQL digest is serialized.
The supplied full32-byte query label is opaque caller context, not an authenticated
SQL statement. In particular callers must not derive it as a publicly testable
hash of low-entropy WHERE/constants with a public nonce. A proper privately blinded
query commitment and its proof remain future work.

Both plaintexts use Encoding::poly, not SIMD. One actual SDK ct*ct plus the original
RK gives coefficient512L+255 equal to predicate(age_i)*field_i. Each lane product
has support at most510, disjoint from the next512-spaced lane; the final possible
nonzero plaintext coefficient is6142, below8192. All target values are below the
unchanged t114689. Ciphertext/noise arithmetic still wraps in the negacyclic ring.

The evaluator never receives rows or a clear mask, decrypts, evaluates a native
predicate, or substitutes owner-precomputed flags. Completion decrypts the ACTUAL
result using the original Owner, bounds all8192 public-layout coefficient values
and zero gaps/tail, then returns only four original ordinals' actual target
presence/age/amount triples. An absent target must have zero age and amount. There
is no compaction, sorting, window, update or owner-side WHERE evaluation here.

The public-product error bound20*256=5120 applies only to the rejected public-mask
alternative. It is NOT a bound for this private ct*ct operation: two input noises,
RNS scaling/rounding and key-switch noise must be accounted for. The
[executed validation](../../PRIVATE-COEFFICIENT-VALIDATION.md) records actual SDK
parity and whole owning-test-process observations; no certified noise margin,
security floor, production resource fit or SQL latency is established.
No result is presented as a fresh[-20,20] Formation.

## Public API and bounded encoding

1. Owner::encrypt_original_coefficient_rows_for_experiment encrypts all four
   original rows once, independently of queries.
2. Owner::prepare_private_coefficient_predicate_for_experiment receives that
   canonical ciphertext, ordinary QueryContext, a full query label and a private
   mask. It returns a public request and one-use PendingPrivateCoefficientPredicate.
3. PeerEvaluator::evaluate_private_coefficient_predicate_for_experiment performs
   the real FHE operation. Its encrypted output remains unproved.
4. Owner::decrypt_private_coefficient_predicate_unverified_for_experiment consumes
   pending metadata and returns UnverifiedPrivateCoefficientPredicate only.

BFVCPDQ1 requests have a328-byte fixed header: magic/version/geometry/reserved16,
complete keyset32, full query32, QueryId16, both112-byte heads and two u32 lengths.
Exactly two canonical level0 two-component ciphertexts follow. BFVCPDR1 responses
have the same320-byte common prefix plus encrypted-request digest32, output length4,
reserved4 and one canonical result ciphertext. The existing512KiB ciphertext cap
is reused; maximum request/response are328+2*cap and360+cap. No allocation is based
on a nested untrusted sequence length. Unknown roles/versions/geometry/reserved
bytes, oversized/zero lengths, truncation, trailing data and malformed ciphertexts
reject before use. Shared ciphertext preflight precedes SDK math.

The full original keyset and context are compared at evaluation and completion;
request digest binds both original ciphertexts. Raw ciphertext bytes themselves
carry no authenticated owner-key label, so same-parameter foreign ciphertext
origin cannot be certified or rejected from shape alone. These metadata guards
are not Source authenticity or malicious-result evidence. A well-shaped forged
reply can satisfy a codec; the Unverified result must never enter SQL admission.
The full WHERE remains encrypted, but formal leakage/security analysis, setup
trust and access-pattern policy are not established by fixed wire lengths.

`EvaluatedPrivateCoefficientPredicate::ciphertext_for_experiment` borrows the
complete proposed encrypted product after revalidating its existing response
frame. This readonly view adds no proof or SQL admission. The standalone
[full graph consumer](../../../../experiments/bfv-mul-relin-proof/README.md)
can independently prove and verify those exact bytes without a Core dependency
on experimental proof production.

## Owning source tests and missing proof boundary

All eight new tests passed in the [native validation](../../PRIVATE-COEFFICIENT-VALIDATION.md).
Public nonsecret fixtures cover all four original ordinals, age0/255,
amount0/65535, empty/full/range/noncontiguous masks, randomized private encryption,
all8192 coefficients against an independent plaintext negacyclic oracle, real
foreign Owner metadata, complete context/query/request-digest replay and hostile
headers/lengths/polynomials/decrypted ranges. The plaintext oracle exists only in
tests and is never the evaluator or a claimed proof. To run the owning cases:

~~~text
cargo test --release --locked -p bfv-query-core coefficient_predicate::tests:: -- --test-threads=1 --nocapture
~~~

Still missing are Source-to-all-original-onehot encoding, hidden query-to-mask
encoding/commitment, both actual Formation prerequisites and complete linked
Tensor/Scale/NTT/Relin proof. Existing32-component relinearization alone is not
MulRelin. Current standalone OwnerBasisJob consumes one transformed-key opening;
sharing identical fullKeyPV33 across two operand formations needs a reviewed
opaque multi-operand scope, not discarded-salt reconstruction or getters. No
freshness, transaction/lock/writer fence, mutable encrypted Source, production
SQL path or composed-security claim follows. Core does not depend on experiments
or proof producers, and this prototype does not change old operations or caps.

## Binding-only restoration of an exact saved request

`Owner::restore_private_coefficient_predicate_for_experiment` consumes the saved
public request `Vec<u8>` plus independently supplied `QueryContext`, full query32
and SHA25632 of that exact request. It returns the original
`PreparedPrivateCoefficientPredicate`, moving the identical request allocation
and rebuilding only its opaque public pending labels. It does not restore the
Owner or a private opening. The caller must already possess or separately restore
the correct Owner; there is no raw secret-key getter or serialized pending flag.

The method checks the unchanged complete request cap and canonical envelope,
the Owner's geometry/full keyset, both complete heads and QueryId, full query and
the digest of both encrypted operands. It then uses the existing bounded borrowed
ciphertext validators on both original operands before constructing pending state.
Restoration performs no SDK ciphertext decoding, seed expansion, encryption,
query recompilation or FHE evaluation. It never replaces saved bytes with newly
randomized encryption. Invalid scope is rejected before polynomial inspection.

These expected labels must come from the caller's independently retained binding;
copying them from an untrusted request provides no identity check. Shape-valid
same-parameter ciphertexts do not authenticate same-secret encryption origin.
Even a foreign original ciphertext can pass this binding-only API when the caller
deliberately supplies matching labels and a matching digest. Source/Encoding/Key/
Basis/Formation proofs and their complete independent expectations remain separate
mandatory checks for any accepting composition. The restored pending value gives
no proof, source completeness, fresh head, lock, finality or SQL authority.
Existing owner completion remains explicitly UNVERIFIED.
Restoration may repeat and supplies no durable phase or anti-replay policy.

Three added owning tests discard the original pending value, preserve the
saved request bytes/allocation, execute the actual evaluator's BFV product and
complete only its real encrypted result. They also cover foreign Owner metadata,
full independent context/query/digest, changed operands, repaired malformed
polynomial claims, canonical headers, truncation, trailing bytes and byte limits.
The foreign-origin control intentionally demonstrates the absence of encryption-
origin authority; it is not a successful mixed-key FHE or SQL claim.

All 13 owning coefficient-predicate cases passed on Windows/MSVC Rust 1.99.0,
release/offline/locked, native CPU, Cargo/Rayon threads 2:

```text
cargo test --release --offline --locked -p bfv-query-core --lib coefficient_predicate::tests:: -- --test-threads=1
cargo check --release --offline --locked -p bfv-query-core --all-targets
cargo clippy --release --offline --locked -p bfv-query-core --features formation-proofs --all-targets -- -D warnings
cargo fmt --all
```

The test command took 10.184 s including compilation, with 3.44 s test runtime.
The nominal 100 ms observer recorded 51 samples, maximum gap 396.613 ms, sampled
working set 204,378,112 B, private 209,936,384 B and OS peak working set 212,877,312 B.
No sampled 1792-MiB per-PID fuse or 1800-second runner abort occurred. This measures only
these mathematical BFV cases, not full proof generation, restored Owner state,
an accepted SQL operation, durable recovery or a complete-process resource bound.

The 1470-file raw source snapshot `.local/pending-restore-native-r1/source.json`
has SHA256 `0F4CD01E28D6AB67F1B2552DECD319AB5BB83A099FE87C5BFFED96884452C596`.
All files and exact inventory matched after native tests and before this
documentation update. Test stdout/stderr SHA256:
`C40CCDB9783783D25A10F661B396CCA46295C0EC1D2766942B8563849ECB4774` /
`C5757A776F69FDFD611EC21C523F2939292B3DF786C5A57922DCD9386E77147F`.
No dependency, existing request codec/profile or SQL admission guard changed.
