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
