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
