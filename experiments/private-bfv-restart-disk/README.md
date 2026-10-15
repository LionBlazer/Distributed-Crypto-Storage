# Process restart disk experiment

This isolated candidate separates a fresh writer, a trusted owner-service broker,
and a reader into three actual processes. The writer creates original encrypted
tables and shared BFV/PIR keys, saves a sealed checkpoint, performs one genuine
BFV amount addition with owner-local arithmetic authorization, rebinds the index,
and saves a current checkpoint. The broker waits for writer EOF and successful
exit before starting the reader. The reader imports the original owners and
public setup and runs complete authenticated index → data retrieval → fresh BFV
queries against the original files.

The broker holds the external wrapping key only in Zeroizing RAM. Each child
receives exactly32 secret bytes through an anonymous stdin pipe; argv contains
only bounded public configuration. No plaintext owner image, wrapping key, seed,
or secret key has a file/log/environment/CLI representation here. The encrypted
backup and public setup are retained files. A full-machine restart still needs
external wrapping-key custody and a current trusted public anchor.

## Ownership and dependencies

| Direct project module | Role |
| --- | --- |
| [Recovery candidate](../owner-recovery-candidate/README.md) | Validated owning compact/BFV secret import/export adapters copied into a new ignored source generation. |
| [BFV core](../bfv-byte-limb-core/README.md) | Original public-key predicate, exact aggregation, and bounded addition APIs; no disk or bundle dependency. |
| [Compact store](../../crates/compact-store/README.md) | Canonical ciphertext, AEAD, full Merkle commitments and page replacement. |
| [Spiral owner state](../spiral-owner-state/README.md) | Original336-byte owner image and original public setup restoration. |
| [Spiral cache core](../spiral-cache-core/README.md) | Exact-profile native cache construction. |
| [Exact disk experiment](../private-bfv-exact-disk/README.md) | Frozen complete index/query/loader source basis, copied only into this new package. |
| [Sealed bundle](bundle/README.md) | Bounded standard XChaCha20Poly1305 composition, expected-anchor binding, owned restored lifecycle. |

The new package IDs and dedicated target prevent local Cargo artifact aliasing.
Neither this package nor the sealed compositor becomes a BFV-core dependency.

## Entry points

- prepare.ps1 copies the pinned validated owner adapters/core into a NEW ignored
  source generation and rewrites only its manifests. It performs no Cargo, key
  generation, secret export, or dataset work.
- run.ps1 explicitly builds and runs the three-table probe. It accepts public
  paths only; it has no secret-key argument.
- src/bin/broker.rs owns the wrapping-key master, bounded child framing/deadlines,
  real exit barrier, and parent+active-child memory bound.
- src/bin/writer.rs creates new original files and two sealed checkpoints.
- src/bin/reader.rs performs nine restore rejection controls, original-key import,
  separately timed header bootstrap, and768 complete paired queries.
- src/child_memory.rs requires usable OS native peaks through actual child exit.
  src/runtime_support.rs counts/hashes public and ciphertext files only.

The reader creates no new encrypted fixtures or owner keys. Its independent
public fixture oracle reconstructs the synthetic plaintext test rows only AFTER
each measured query; those oracle values never feed selection or BFV inputs.
The eight cases are complete EQ0/1/16/64/256, GE256, range21 and range256, with
one posting page, one data page and at most256 rows; unsupported selections reject.

Queries compare FullPredicate and ExactIndex under the SAME restored Owner and
original full public setup, both Visible/Private, both header modes and both
AddressOnly/Fixed256 profiles, with actual capacity-one misses/hits. Fixed256
dummy page reads and encrypted inactive weights remain real work. The owner is
online. Authentication does not prove malicious-peer arithmetic.

## Validation and limits

Owning tests include original BFV rotations/products/relinearization after secret
restore, compact owner restoration, bounded AEAD/parser failures, actual held-child
post-exit native counters, and a regression for independent header/posting page
budgets. The separately launched tiny process probe is explicit, not an automatic
unit-test dataset job. See [the experiment report](../../docs/experiment-private-bfv-restart-disk.md)
for measured artifacts and results.

The [actual 1,000-table follow-up](../../docs/experiment-private-bfv-restart-disk-scale.md)
reuses the same frozen executables. It counts all 2,005 files, both sealed backups
and the reported parent/serial-child peak bound: 1.814826x of 3 GB logical.
All 384 ExactIndex reads are below 321 ms; the FullPredicate controls retain one
520.214 ms overrun. The default runner remains a finite three-table probe.

All canonical file reads and full root reconstruction occur inside miss query
timers before NTT preparation. Restore, negative controls, original public peer
setup and cached-header bootstrap are separately reported. Application misses do
not establish OS-cold disk latency. File writes have no fsync/crash-atomicity claim;
a trusted current anchor is external rollback authority. Network, malicious-peer
execution proofs, private writes and general SQL remain outside this experiment.
