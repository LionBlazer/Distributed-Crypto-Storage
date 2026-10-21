# Originating-owner read composition

The optional `registry200-proof/owner-read` feature joins an originating owner's
known private input to the existing public immutable DATA, Word and actual
unrelinearized FHE product relations. The distinct `owner::OwnerCheckedRead` is
conditional mathematics for that owner. It cannot serve as a transferable Query
proof, public peer admission, current weighted QC, SQL result or finalized lock.

## Premises and composition

1. Independently retain the full immutable Source/Role3/DATA expectation and
   obtain `VerifiedDataFormation` by actual native verification. Authenticating
   that version and establishing its currentness remain external obligations.
2. An opaque `bfv_query_core::gold::Owner` originates the actual masked QueryCt
   for that original DATA. Its InputBinding context must be SHA256 of the full
   independently selected Word expectation binding; its statement pin must be
   the canonical little-endian encoding of the Stmt96 Poseidon root.
3. `Owner::bind_statement` checks all 96 canonical words, exact packed 256 private
   mask bits, zero word 95 and the complete original statement pin. It checks the
   actual lower private Q0/Q1 input equations: the literal original QueryCt,
   same original SDK S/Cs, all 4096 scaled mask coefficients, one bounded shared
   error and exact quotient bounds. This evaluates no query result. Private
   statement/hash/input scratch has scoped cleanup. Only public metadata and
   an immutable borrow of the original query survive in `OriginatingStatement`.
4. `owner::Verifier::verify` requires that sealed private premise. It compares
   the complete Word binding context, original fixed header/root, full Source
   values/heads/packets, DATA nonce/literal Ct, binding, contexts and roots.
   `VerifiedDataFormation::require_expected` enforces the complete original
   installed theorem. Each call independently verifies the actual Word proof
   and the full product certificate for the original ordered ciphertext pair,
   full-request nonce and claimed canonical Ct3. No result is decrypted yet.
5. `OwnerCheckedRead::complete` checks the same owner, full original request
   nonce and ordered pair before decrypting all 4096 coefficients. The result
   retains the original public InputBinding. No plaintext fixture, echoed input,
   signature, checksum or successful decryption substitutes for the peer's
   actual computation/completeness arguments.

Under the existing conditional proof, commitment binding and arithmetic/noise
assumptions, these premises link the input mask committed by Word to the literal
QueryCt in the checked product. The immutable DATA theorem links its other
operand to the complete Source. The owner can establish its known private input
relation directly; it need not generate a zero-knowledge proof of that input to
itself. The public Word and product arguments remain necessary, as do the
existing unassessed composed cryptographic security obligations.

Another peer lacks the private input premise. `OriginatingStatement` has no raw,
decoded or serialized constructor, Clone, mask getter or transferable evidence.
`OwnerCheckedRead` cannot be converted to `ArithmeticCheckedRead`, a public Query
proof, a journal operation or a finality certificate. The ordinary public
`read::verify`, `verify_retained` and `read::Verifier` still require the actual
fused Query proof. Predicate remains closed in the journal/finality layers.
This feature changes no protocol requirements and grants no runtime SQL route.

## Setup, resource and measurement boundaries

`owner::Verifier::new` independently constructs role-only public Word setup.
`word::Prover::new(Predicate)` similarly retains only public setup. They can be
reused across different queries; private inputs, transcript randomness and
verdicts are freshly processed. No query-specific setup or proof is imported.
The receiver bounds Word and Ct3 before allocation and requires the exact fixed
certificate length. It owns the checked product and borrows the original input.

The owning example starts from a genuinely verified immutable DATA version and
an actual generated, sealed, destroyed and restored owner. It executes two new
original encrypted queries using the same role-only setup, with different masks,
calls and statement roots. It checks full-ring answers only after genuine Word,
input-equation and product verification and owner decryption. It rejects changed
Word arguments, product certificates, output, prior-call evidence, DATA nonce,
Word context/statement, Control role, missing frames and oversize output, then
rechecks honest evidence after failures. Core tests additionally reject changed
non-mask statement words, noncanonical fields, foreign owners and a well-formed
different-mask ciphertext even after repairing its public binding.

Recorded local-query intervals include case/statement construction, origination,
private equations, actual FHE/certificate production, fresh Word proving and
verification, complete DATA equality and client completion. Role-only setup and
immutable-version installation are reported separately. These intervals omit
real peer transport, authentication/current weighted head, consensus, recovery,
SQL compilation and locks. They cannot establish the 500ms full-query target.
See [executed validation](OWNER-VALIDATION.md).
