# Storage and protocol core

Reusable libraries form the core layer. They own cryptographic roles, storage
contracts, query plans and protocol state machines. Their dependency graph does
not include the GUI, simulated network, presets, fixture generators or measurement
executables. The root Cargo default members select this layer only.

| Library | Responsibility | Direct project dependencies |
| --- | --- | --- |
| [peer-transport](peer-transport/README.md) | Authenticated TLS/TCP and bounded frames | None |
| [peer-runtime](peer-runtime/README.md) | Peer-owned custody, proving, work/journal RPC and copies | peer-transport, compact-store, bfv-query-core, bfv-query-proof, version-journal |
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
| [bfv-arithmetic-stark](bfv-arithmetic-stark/README.md) | Shared fixed linked STARK configuration and actual AIR security analysis for public arithmetic consumers | bfv-fixed-geometry |
| [bfv-query-proof](bfv-query-proof/README.md) | Bounded genuine arithmetic STARKs and independent verification | bfv-linear-circuit, bfv-product-circuit, bounded-postcard, proof-acceleration; bfv-query-core in tests |
| [bounded-postcard](bounded-postcard/README.md) | Bounded generic Postcard decoding with caller-owned container budgets | None |
| [proof-acceleration](proof-acceleration/README.md) | Shared fixed-profile ABI and startup CPU/OS kernel selection | None |
| [bfv-query-core](bfv-query-core/README.md) | Separate owner/evaluator FHE roles and bounded wire inputs | bfv-fixed-geometry, bfv-linear-circuit, bfv-product-circuit |
| [compact-query](compact-query/README.md) | Complete private selection and proof-first FHE query/write lifecycle | compact-store; optional bfv-query-core, bfv-query-proof |
| [version-journal](version-journal/README.md) | Bounded cumulative-work forks, authorization, freshness and durable metadata | None |
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
