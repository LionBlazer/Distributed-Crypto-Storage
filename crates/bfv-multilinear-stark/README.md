# Public multilinear arithmetic STARK backend

The owning seven tests and the migrated full-8192 NTT consumer pass release
validation. This is a reusable public arithmetic proof protocol, not a production
SQL acceptance path.

This library owns one fixed public, nonhiding Plonky3 0.8.0 protocol: Goldilocks,
extension degree 5, all 512 SHA512 output bits, separate consumer-selected Merkle
leaf/node/transcript domains, binary Merkle cap0, PrefixProver, WHIR unique
decoding, fold4, starting inverse rate1 with derived later rates, zero grinding,
per-phase target160 and complete-statement floor144. It uses the reviewed [vendored SDK](../../vendor/p3-multi-stark/README.md)
through an explicit path dependency shared by all multilinear consumers. In particular it does not import the older
[univariate backend](../bfv-arithmetic-stark/README.md), whose parallel feature and
configuration remain separate. Pinned multilinear SDK dependencies disable their
default features; this crate enables no parallel or nightly feature.

`Domains::new` accepts four static, nonempty, pairwise prefix-free labels: leaf,
node, transcript and statement seed. Existing NTT consumers must pass their exact
published labels. `sha512` returns all64 bytes. Hash associated types are public
only because the concrete SDK configuration exposes them; their constructors
remain internal. `PROTOCOL_DESCRIPTOR` identifies this protocol, not an operation,
key authority or acceptance token. Consumers bind their own domains and complete
semantic machine description in their operation profiles.

`AirSpec::new(&air, log_height)` supplies trusted verifier AIR/height inputs.
`config_for` uses checked dimensions and actual symbolic declarations to derive
stacked main/preprocessed arities, current-column claim counts and `ProtocolPlan`.
Before symbolic allocation, it also checks the actual SDK element layout for both
rows of main/preprocessed variables and the public-value vector. These checks
reject impossible capacities; they do not impose a whole-process memory limit.
The initial supported class has positive main widths, heights at least16,
ordinary public values (including nonzero vectors), and optional global LogUp.
Successor columns, periodic columns, Boolean assumptions, boundary declarations,
local/exclusive/indexed lookups, binary buses and extension constraints are
explicitly rejected. Preprocessing is optional; a no-PP config is assessed only
against the matching no-PP instances. Planning does not construct or authenticate
public tables and does not evaluate arithmetic or create setup keys.

`Config::challenger(profile64, complete_request_wire, complete_output_wire)` seeds
the exact concatenation `statement_domain || profile64 || SHA512(full_request) ||
SHA512(full_output)` through the domain-separated transcript hasher. Callers must
first validate and canonically encode their COMPLETE operation envelope, including
application binding, setup identity and ordered program edges where applicable.
Hashing a legacy SHA256 digest alone does not supply this binding. This helper
preserves the current NTT seed bytes without replacing its profile.

`assess(&config, &actual_verifier_instances)` rechecks supported declarations and
exact ordered table dimensions before SDK assessment, then requires the actual
SDK's complete finite union bound to meet144 with no unassessed component. It
returns the full SDK report and all terms. The bound remains conditional on SDK
assumptions; a PCS-only number is not substituted. Prove/verify consumers must
continue to call the real `prove_with_security` / `verify_with_security` with
`pow_bits=0` and `POLICY_BITS`, using their independent verifier key. Different
constraints with the same supported dimensions are assessed as the actual AIR;
a plan is not a cached assessment or an arithmetic proof.

Consumers own semantic AIRs, canonical statement codecs, operation profiles,
independent expected inputs, public preparation, prover/verifier keys, ordered
instances, frame/layout checks, bounded decoding policy, error mapping, witness
lifetime, proof verification and checked markers. Pure arithmetic libraries do
not depend on this backend. Shared configuration does not turn old public-PP
relations into compact main-witness relations or add whole-operation correctness.

One semantic machine remains the consumer's proof unit. The backend does not
rename lookup buses: concatenating independent machines with shared fixed data
buses can permit cross-machine cancellation. A future combined program must own
trusted edge namespaces and complete ordered IO binding. Only identical public
range supports may be intentionally shared. These public nonhiding proofs do not
replace private source/key proofs or establish SQL acceptance, authorization,
fresh agreed heads, finality, FHE program coverage or a whole-peer RAM bound.

Owning source tests cover exact full64 hashing/domain/seed preservation, invalid
and unsupported shapes, checked overflow, no-PP/nonzero-public-value behavior,
shape mismatch before SDK calls, full SDK assessment and a real generated proof
with a changed-public-value rejection. On 2026-10-17, release tests passed all seven
owning cases, including real proofs with and without preprocessing and nonzero
public values. Strict Clippy and rustfmt passed for both this library and the
NTT consumer. The consumer's thirteen tests passed all twenty genuine serialized
NTT proofs and its genuine weakened/foreign-program proof rejections. Full upstream
SDK parity, all twenty complete security reports compared exactly to the previous
implementation, and the repository requirements/architecture guards also passed.

Reproduce the owning gates from the repository root:

```sh
cargo test --release --locked -p bfv-multilinear-stark -- --test-threads=1
cargo clippy --release --locked -p bfv-multilinear-stark --all-targets -- -D warnings
cargo test --release --locked -p bfv-ntt-witness-proof --lib -- --test-threads=1
```

The standalone consumer retains exactly its previous resolved package features,
plus this featureless local library. Existing root lock entries are unchanged;
the seven added registry packages match the already validated standalone SDK.
See the [consumer's limits and measurements](../bfv-ntt-witness-proof/README.md).

## Canonical SHA512 compatibility gates

Three short owning tests compare the leaf, node and transcript adapters against
independent one-shot SHA512 of their complete canonical byte streams. Coverage
includes every domain-prefix offset in a 128-byte block, padding/block edges,
empty input, LE64/high-bit words and long single-pass iterators without a length
hint. Existing genuine SDK proofs and rejection cases stay intact.

The original production hash writers are retained. A fixed-buffer candidate
preserved complete proof bytes but did not demonstrate a stable complete-test
improvement in sequential native measurements. Its implementation and writer-only
observation are excluded from this revision. The
[hash validation](../../docs/hash-compatibility-validation.md) records the actual
positive/negative gates, full artifact parity and measured limits. This is no
claim of faster SQL or a cheaper cryptographic protocol.
