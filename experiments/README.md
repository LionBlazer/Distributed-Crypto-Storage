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
- [hiding-fri-sha256-gate](hiding-fri-sha256-gate/README.md) is a standalone,
  nonaccepting SHA-256 compression backend experiment with reviewed fixed hiding
  parameters, real primitive proofs and recorded validation limits. It does not
  implement private CSTORE opening, SQL completeness or locks.
- Other directories keep their own manifests, reproduction scripts and README
  files. Some deliberately export pinned historical source revisions into an
  isolated local workspace; these are research candidates, not core imports.

The first two packages belong to the root workspace and are selected
explicitly with `-p`; the addition-proof experiment and other probes document their
standalone commands. The
[playground](../playground/README.md) is the separate interactive GUI consumer.
Measured results and remaining limits are recorded in [research reports](../docs/).
