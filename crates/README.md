# Storage and protocol core

Reusable libraries form the core layer. They own cryptographic roles, storage
contracts, query plans and protocol state machines. Their dependency graph does
not include the GUI, simulated network, presets, fixture generators or measurement
executables. The root Cargo default members select this layer only.

| Library | Responsibility | Direct project dependencies |
| --- | --- | --- |
| [peer-transport](peer-transport/README.md) | Authenticated TLS/TCP and bounded frames | None |
| [peer-runtime](peer-runtime/README.md) | Peer-owned custody, proving, work/journal RPC and copies | peer-transport, compact-store, bfv-query-core, bfv-query-proof, version-journal, registry200-journal |
| [storage-client](storage-client/README.md) | Proof-first SQL acceptance, typed catalogs, owner-finalized writes and confirmed freshness | peer-runtime, compact-query, compact-store, sql-plan, relational-types, bfv-query-core, version-journal |
| [relational-types](relational-types/README.md) | Owner-side typed schema, lossless SQL dump validation and SELECT plans | None |
| [sql-plan](sql-plan/README.md) | Parse the supported SQL subset into typed plans | None |
| [compact-store](compact-store/README.md) | Owner keys, encrypted pages and authenticated version roots | None |
| [bfv-fixed-geometry](bfv-fixed-geometry/README.md) | Shared unchanged level-zero BFV degree and ordered Q5/P5 parameter contract | None |
| [bfv-linear-circuit](bfv-linear-circuit/README.md) | Canonical full-residue BFV addition relation for proof consumers | bfv-fixed-geometry |
| [bfv-product-circuit](bfv-product-circuit/README.md) | Canonical full-residue BFV public-polynomial product | bfv-linear-circuit |
| [bfv-scale-circuit](bfv-scale-circuit/README.md) | Canonical full-8192 public RNS scaling and optional limb AIR | bfv-fixed-geometry |
| [bfv-ntt-circuit](bfv-ntt-circuit/README.md) | Exact full-8192 native forward/inverse NTT for all ten Q5/P5 moduli, with optional limb AIR | bfv-fixed-geometry |
| [bfv-tensor-circuit](bfv-tensor-circuit/README.md) | Full three-component BFV tensor product over all 8192 positions of one Q5/P5 modulus, with optional limb AIR | bfv-fixed-geometry |
| [bfv-relinearization-circuit](bfv-relinearization-circuit/README.md) | Complete fixed-Q5 embedding and five-term key accumulation arithmetic, with optional AIR | bfv-fixed-geometry |
| [bfv-relinearization-key-source](bfv-relinearization-key-source/README.md) | Canonical original public seeded-key parsing and exact public c1 expansion, with independent complete setup identity | bfv-query-core, bfv-fixed-geometry |
| [bfv-arithmetic-stark](bfv-arithmetic-stark/README.md) | Shared fixed linked STARK configuration, complete profile AIR delegation and actual security analysis for public arithmetic consumers | bfv-fixed-geometry |
| [bfv-hiding-stark](bfv-hiding-stark/README.md) | Fixed private-witness hiding-FRI mechanics, analytical assessment, Poseidon2 gadget and bounded codec | bounded-postcard |
| [bfv-key-transform](bfv-key-transform/README.md) | Fixed salted BFV-secret support/odd-evaluation relation and genuine bounded hiding proofs | bfv-hiding-stark |
| [bfv-basis-convolution](bfv-basis-convolution/README.md) | Exact one-basis full-ciphertext convolution and bounded Key-first component proofs | bfv-hiding-stark, bfv-key-transform, bfv-fixed-geometry |
| [bfv-multilinear-stark](bfv-multilinear-stark/README.md) | Fixed public SHA512/WHIR multilinear protocol, checked current-only table planning and complete actual SDK security assessment | None |
| [bfv-query-proof](bfv-query-proof/README.md) | Bounded genuine arithmetic STARKs and independent verification | bfv-linear-circuit, bfv-product-circuit, bounded-postcard, proof-acceleration; bfv-query-core in tests |
| [bounded-postcard](bounded-postcard/README.md) | Bounded generic Postcard decoding with caller-owned container budgets | None |
| [proof-acceleration](proof-acceleration/README.md) | Shared fixed-profile ABI and startup CPU/OS kernel selection | None |
| [bfv-query-core](bfv-query-core/README.md) | Separate owner/evaluator FHE roles, bounded wire inputs and optional private key anchor | bfv-fixed-geometry, bfv-linear-circuit, bfv-product-circuit; optional bfv-key-transform, bfv-hiding-stark, bfv-basis-convolution |
| [compact-query](compact-query/README.md) | Complete private selection and proof-first FHE query/write lifecycle | compact-store; optional bfv-query-core, bfv-query-proof |
| [registry200-proof](registry200-proof/README.md) | Shared Source/Lifecycle circuits and genuine bounded fixed-profile verification | bfv-hiding-stark, compact-store, version-journal |
| [registry200-journal](registry200-journal/README.md) | Exact owner-authorized private-control application with actual parent CAS | registry200-proof, compact-store, version-journal |
| [registry200-finality](registry200-finality/README.md) | Closed durable multi-slot checkpoint owner for actual Registry200 proofs and mechanical Journal ancestry floors | registry200-journal, version-journal, work-finality, protocol-storage |
| [version-journal](version-journal/README.md) | Bounded cumulative-work forks, authorization, freshness and durable metadata | None |
| [protocol-storage](protocol-storage/README.md) | Shared retained-file accounting and bounded immutable public evidence lifecycle | None |
| [work-finality](work-finality/README.md) | Checked key-bound work elections, weighted quorum evidence and an exclusive durable single/multi-slot consensus signer; no live SQL authority | protocol-storage |
| [transaction-state](transaction-state/README.md) | Bounded public transaction/row-lock control state, signed intents and metadata-only witnesses | version-journal |
| [replica-store](replica-store/README.md) | Ciphertext custody, placement and local atomic repair | compact-store |
| [peer-protocol](peer-protocol/README.md) | Bounded connection/request/cancellation state machine | None |

Public entry points and their security/resource contracts are documented by each
library. Tests at those boundaries stay with the owning library. SQL statement
values, owner secret keys and public peer parameters retain separate roles.

The [peer daemon](../apps/dcs-peer/README.md) hosts the independent service.
The [proof kernel](../apps/proof-kernel/README.md) deploys fixed ISA builds of the
same proof library; the [launcher](../tools/launcher/README.md) packages them beside
portable applications. Core receives an explicit trusted directory and owns no
GUI, executable-path discovery or build policy.
The [playground](../playground/README.md) supervises it and hosts the owner-client; [experiments](../experiments/README.md) contain alternative probes and
measurement executables. Neither is imported by core. There is no facade that
silently supplies a local deployment, a test database or a simulated transport.

This separation is preparation for the intended system, not a completion of
[the requirements](../REQUIREMENTS.md). Independent TLS process transport, exact FHE
proofs and a validated work journal are implemented. Production consensus parameters,
discovery, public SQL/AEAD linkage and scale/resource targets remain unresolved.
Existing unverified diagnostic result types stay unverified.

From the repository root, `cargo build --release --locked` builds core default
members. `cargo test --workspace --release --locked -- --test-threads=1` also tests
the playground and workspace experiments. The playground architecture test rejects
reverse dependencies, core example/binary targets and application default members.

[bfv-ciphertext-formation](bfv-ciphertext-formation/README.md) owns the reusable
fixed bounded-noise integer relation and canonical component proof. Its optional
Core consumer keeps private Owner openings local; SQL/Journal producer authority
remains outside the library. Its actual emitter, hostile inputs and sampled resources
are recorded in [Owner formation validation](bfv-ciphertext-formation/OWNER-FORMATION-VALIDATION.md).
