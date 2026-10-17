# Research and measurement consumers

This layer contains executable probes, measurement programs and isolated research
candidates. It consumes [core libraries](../crates/README.md); core never imports
this layer. Generated datasets, keys, copied candidate sources and reports stay
in ignored `.local/`, not in the library source tree.

- [core-workloads](core-workloads/README.md) owns the measurement examples formerly
  packaged with compact-store and compact-query.
- [fhe-prototype](fhe-prototype/README.md) retains the original TFHE relational and
  compression experiment.
- [bfv-addition-proof](bfv-addition-proof/README.md) is a standalone, pinned Plonky3
  proof of exact BFV ciphertext addition. It verifies serialized proofs against
  independently committed public inputs; it does not accept SQL or authorize writes.
- [bfv-rns-scale-proof](bfv-rns-scale-proof/README.md) proves both complete fixed
  degree-8192 public RNS scaling stages with independent verifier preprocessing.
  Its [native validation](bfv-rns-scale-proof/VALIDATION.md) includes actual SDK
  parity, genuine serialized proofs and rejection tests. Full ciphertext
  multiplication, relinearization and SQL acceptance remain separate work.
- [bfv-ntt-proof](bfv-ntt-proof/README.md) proves complete native NTT transforms
  across all ten fixed Q5/P5 moduli, including inverse normalization. Its
  [native validation](bfv-ntt-proof/VALIDATION.md) covers all 20 genuine stages,
  actual SDK parity, rebuilt-certificate attacks and explicit decoder budgets.
- [bfv-ntt-witness-proof](bfv-ntt-witness-proof/README.md) verifies a complete NTT
  without a verifier-supplied auxiliary certificate, using full SHA-512, global
  copy/range lookups and WHIR. Its [validation](bfv-ntt-witness-proof/VALIDATION.md)
  covers all twenty genuine stages, hostile programs and measured process memory.
- [bfv-tensor-proof](bfv-tensor-proof/README.md) proves all three complete tensor
  components for each fixed Q5/P5 modulus. Its [validation](bfv-tensor-proof/VALIDATION.md)
  covers upstream polynomial parity, ten genuine serialized stages, hostile
  proofs and regression of the shared RNS/NTT backend.
- [bfv-relinearization-proof](bfv-relinearization-proof/README.md) proves complete
  Q5 embedding and five-term key accumulation stages. Its
  [validation](bfv-relinearization-proof/VALIDATION.md) covers actual SDK parity,
  proofs on an encrypted product, both genuine stages and regression of the shared
  profile wrapper. Full key provenance and linked relinearization remain open.
- [bfv-relinearization-multilinear-proof](bfv-relinearization-multilinear-proof/README.md)
  verifies both complete public-Aux stages with full SHA512/WHIR and an actual
  whole-statement floor of 144 bits. Its
  [validation](bfv-relinearization-multilinear-proof/VALIDATION.md) records genuine
  proofs, SDK parity, hostile programs and process observations. Complete linked
  relinearization and SQL acceptance remain open.
- [source-primitive and opening gates](hiding-fri-sha256-gate/README.md) share an
  experimental private hiding-FRI backend. Genuine primitive proofs extend to a
  bounded private CSTORE opening and the
  [canonical four-row index relation](hiding-fri-sha256-gate/CANONICAL-INDEX-VALIDATION.md),
  using public nonsecret fixtures. General source/SQL completeness, production
  key custody and live locks remain unmet.
- [BFV formation oracle](bfv-formation-oracle/README.md) validates original input
  encoding and every upstream encryption residue with public fixtures and seven
  native tests. It implements no cryptographic proof or accepting SQL API.
- Other directories keep their own manifests, reproduction scripts and README
  files. Some deliberately export pinned historical source revisions into an
  isolated local workspace; these are research candidates, not core imports.

The first two packages belong to the root workspace and are selected
explicitly with `-p`; the addition-proof experiment and other probes document their
standalone commands. The
[playground](../playground/README.md) is the separate interactive GUI consumer.
Measured results and remaining limits are recorded in [research reports](../docs/).

## Private Registry200 lifecycle

The distinct [lifecycle relation](hiding-fri-sha256-gate/src/opening/registry_lifecycle/README.md) proves an empty registry and
Begin, Acquire, FailCurrent, Savepoint, RollbackTo, Release and End under bounded
N4/T2/D2 semantics. Real Source-first proofs and all 21 new owning tests passed;
see the [validation record](hiding-fri-sha256-gate/PRIVATE-REGISTRY-LIFECYCLE-VALIDATION.md) for 296 discovered versus
48 executed leaf cases, numerical security and measured component sizes. The
relation remains owner-local and has no existing wire/Journal, live SQL, MVCC,
controller-signature or encrypted data commit authority. Earlier stage reports
retain their original scope.
