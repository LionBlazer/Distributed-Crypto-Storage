# Private predicate inputs

Owner-side production of the existing fixed-N4 private coefficient inputs from
real canonical encrypted storage. Enable the explicit `private-input-proofs`
feature. This module does not call Session SQL admission, accept an answer, publish
a mutation, preselect BFV input rows or establish agreed-head freshness.

## Dependencies and ownership

| Direct module dependency | Responsibility |
| --- | --- |
| [compact-query storage](../../../compact-query/README.md) | Canonical seal/restore/read with the actual caller-owned AEAD authority |
| [compact-store](../../../compact-store/README.md) | Exact authenticated heads, page proofs and guarded caller-supplied key construction |
| [peer-runtime](../../../peer-runtime/README.md) | Full `RawBundle` custody audit and independently pinned object address |
| [sql-plan](../../../sql-plan/README.md) | Compile an age-domain truth table without reading stored rows |
| [registry200-proof](../../../registry200-proof/README.md) | Genuine Source-first canonical-index and two coefficient Encoding producers |
| [registry200-journal](../../../registry200-journal/README.md) | Original application/intent/Request pins for the distinct joint locking producer |
| [bfv-query-core](../../../bfv-query-core/README.md) | Actual ALL-original/predicate encryption, original setup checks and exclusive proof epoch |
| [bfv-key-transform](../../../bfv-key-transform/README.md) | Existing OS-random proof salts |
| [bfv-basis-convolution](../../../bfv-basis-convolution/README.md) | Actual ordered Basis verification before Formation |
| [bfv-ciphertext-formation](../../../bfv-ciphertext-formation/README.md) | Exact encoded commitment and complete Formation expected claims |
| [bfv-mul-relin-proof](../../../bfv-mul-relin-proof/README.md) | Public provenance claims and borrowed input16 evidence contract |

`SourceOwner::new(database, key_domain, Zeroizing<[u8; 32]>)` retains a guarded
proof copy of the caller's AEAD key, the real compact-store sealer and one private
OS-random Ckey salt. The caller is responsible for fresh random keys, domain
uniqueness and private custody. There is no key getter, serialization or private
callback. This capability is currently in-memory; recreating it samples a new
Ckey salt and does not restore the previous Source commitment.

`seal_partition(&TableId, &[PlainRow; 4], RowIds)` uses the actual canonical writer
for all four originals. The caller stores/replicates its encrypted data/index
images through ordinary custody APIs and independently retains the object,
TableId and both authorized heads. No plaintext Table is retained by this module.

`FetchedSource { object, bundle, heads }` borrows those independent expectations.
They must not be adopted from a peer's own envelope. Before proving, `produce`
requires exact 172/2496-byte N4 images and 112-byte heads, audits both complete
images, restores the real Table under the supplied sealer/TableId/heads, opens all
four rows and authenticates the complete canonical index. It neither filters
originals nor substitutes an index prefix for the complete Source opening.

## Producing the fixed input relation

`CompiledPrivatePredicate::compile(sql, private_blind, public_nonce)` preserves the
existing exact compiler behavior and domains. It accepts only the supported
`SELECT age, amount FROM records` shape with its age predicate and default row
window. It rejects locking SELECT (including SKIP LOCKED), mutations, aggregates,
other projections and nondefault windows. Its hidden 256-bit truth table describes
the entire age domain; compilation does not inspect any stored row. The caller
must keep the high-entropy private blind secret and distinct from the public nonce.

`SourceOwner::produce(BfvContext { owner, setup, anchor }, &mut epoch, fetched,
&compiled, query_id)` requires an already `Ready` `OwnerProofEpoch`. The actual
owner and complete original setup/independently pinned anchor are supplied by the
caller. The epoch's genuine Key frame is verified first and all Key33 values bind
both operands. The stable pre-Source q uses the existing KeyExpected29 rule;
fresh CsHat is still bound by both complete Encoding/Formation contexts.

The producer recomputes Ckey from the real head/key/stable salt and Copen from the
entire real Source plaintext with a fresh OS-random opening salt. The Source proof
is newly produced for this query. Both typed Encoding producers verify the exact
same genuine Source frame. Command and Encoding salts are freshly sampled.

The actual BFV owner encrypts **ALL four originals**, including unmatched rows, and
the private truth table into the two ciphertexts of one prepared request. The
original setup checks that exact request; its pending binding checks the same
ordered ciphertext bytes. The peer must homomorphically apply the encrypted
predicate. The producer computes no plaintext WHERE answer.

Two exclusive epoch operand jobs then produce ordered Q0..Q4 Basis components and
one Formation each, using those same complete ciphertext bytes and actual
Encoding openings. Each Basis proof is actually verified before its statement is
used for Formation; Formation also verifies the actual Key/five Basis inputs.
Completion drops current private operand state and leaves the epoch Ready for a
later query under the same private Key opening. Failures return no partial
`ProducedInputs`; any borrowed job is dropped. Already completed proof work is
not rolled back, and synchronous proof work has no interrupt API here.

## Public result and limits

`ProducedInputs::provenance()` exposes public claims, not a verification receipt.
`request()` borrows the prepared encrypted request. Consuming `into_parts()` returns
`(Provenance, PreparedPrivateCoefficientPredicate, InputProofFrames)`, retaining the
one-use pending binding for later checked output completion. No plaintext rows,
private mask, SQL blind, Source witness or Encoding opening escapes in that result.
The caller can drop `SourceOwner`, epoch and key handle before output verification;
its BFV owner is still needed for final client decryption.

`InputProofFrames::as_input_evidence()` borrows the existing complete graph input
contract. `frames()` returns fifteen immutable wire slices in this fixed order:
Key; two Source/Encoding pairs; input0 Basis0..4; input1 Basis0..4; Formation0;
Formation1. Both pairs contain identical Source bytes, giving sixteen unique proof
roles. All downstream consumers still perform actual proof verification.

The inherited caps remain unchanged: Key payload 20 MiB plus its 208-byte header;
each Encoding pair at most 32 MiB (Source 20 MiB and child 12,578,091 bytes, with
its 184-byte header); each Basis payload 20 MiB plus 308 bytes; each Formation
payload 24 MiB plus 140 bytes. The checked worst-case sum is 348,130,800 bytes,
including both Source copies. That is a collection upper bound, not a measured
size, allocation promise or aggregate frame format. Journal Body 32 MiB,
peer transport 64 MiB and whole Journal 256 MiB are distinct existing limits;
this collection must never be inserted as one Body/transport frame.

Only current heavy proof/backend state is created per operation, but the fifteen
public frames, original setup and one owned copy of the epoch's public Key frame
remain resident. Whole-process peak RAM/time and actual frame sizes require the
owning native operation to be measured. Guarded explicit openings do not establish
erasure of every SDK temporary.

## Verification status

The six owning tests cover compiler guards, complete real storage reopening,
independent pins/key/domain/tail rejection and public producer preflight before
the Ready-stage requirement. They contain public nonsecret rows/AEAD keys and no
simulated proof acceptance. All six passed natively. The
[OS-peer validation](../../../../docs/private-where-peer.md) records actual
Source/input production, independent peer FHE computation, complete output
verification, resource observations and owning negative cases.

The inherited proof profiles are unchanged. Individual input proof bounds do not
establish a composed security theorem. Trusted owner setup association does not
add a public evaluation-key same-secret proof. This producer supplies neither
fresh agreed heads, Source custody durability after witness loss, transaction
ownership/write fences nor SQL admission. Existing SQL capability guards remain
closed; adding FOR UPDATE/SKIP LOCKED requires the missing complete composition.

The separate [joint locking producer](source/locking/README.md) prepares actual
Source/input16/Lifecycle/Link evidence for a typed private `LockingSelect`. It keeps
the plain compiler/producer above unchanged. This new path supplies no SQL grant,
finalized admission or completed answer. Its eight owning tests passed natively;
the [validation record](../../../../docs/private-locking-inputs.md) also records
the separate failing legacy integration expectations. It must not bypass the
existing Session capability guards.
