# Progress AIR factoring and feasibility validation

Executed on 2026-10-21, Windows x86_64/MSVC Rust 1.99 release, opt3,
`-C target-cpu=native`, two Cargo jobs/two Rayon threads. This stage factors
private equations and provides fast structural feedback; it does not implement
the new Cmd relation or establish a faster complete SQL query.

## Actual old contract comparison

Two `registry_progress::air_snapshot_tests` cases run the actual native
`get_all_symbolic_constraints` and Postcard representation. Fixed inputs are
explicitly public/nonsecret metadata from the existing published test authority.
No Source/Encoding proof, FHE fixture, MAIN/LDE or private witness is created.
All temporary capture builders and optional golden branches were removed.

Each role has four unconditional digests: its actual math/wire profile, complete
Statement identity/public values, ordered BASE/EXT constraints with full BaseAir
metadata, and every native periodic column/cell. The complete 512x512 periodic
table is checked, including its 262144 fields; it is not sampled.

| Role | Public values | BASE constraints | EXT | Symbolic stream bytes |
| --- | ---: | ---: | ---: | ---: |
| Control |815|31823|0|2891677|
| Predicate |896|31123|0|2942576|

Both retain MAIN width 8266, H512 and the complete original next-column lists.
The eight hashes passed before and after the exact private extraction into
`equations::predicate`. Every assertion remains in its original order; the
original wrapper supplies the same SQL identity. All profiles, periodic cells,
public builders, proof/prerequisite verifiers and codecs are unchanged.

The final pair, after removing the temporary inventory, ran in 0.14s
(154.402ms process lifetime,0.125 CPU seconds), with peak sampled private bytes
26963968 and OS peak working set 31985664 bytes. Its release executable was
9407488 bytes, SHA256
`4947E4A0209211889E0A63F5F598D71B7536083D8971846E3CDFB2D6EACA99BD`.
These structural checks do not
substitute for cryptographic or behavioral validation when the relation changes.

The existing relation proves a transition relative to an independently proved
previous root. It opens the selected actor's old Progress48 on resume and its
new Progress48 when parked. For the other slot it checks presence/root shape and
exact carry or End compaction; its full semantic validity follows from bootstrap
and the verified transition history. This is not standalone validation of an
arbitrary private State supplied with public metadata. A new relation must retain
that explicit inductive contract or additionally open/check both full preimages;
an owner model or stored success flag cannot replace the required chain evidence.

## Rejected mechanical bit-level lowering

A temporary test-private compiler collected a genuine logical SymbolicExpr DAG,
shared identical ordered subtrees, and counted every producer/read/assertion
event, including repeated operands. Three cases passed in 0.09s: both-role
inventory, duplicate-read multiplicity and refusal of nonlocal symbolic leaves.
No accepting AIR, verifier, proof, trace or SQL authority was implemented.

| Role | Logical assertions | Input wires | Binary gates | Total wires | Port events | Minimum rows at64 ports |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Control |19338|7638|54215|63354|183848|2873|
| Predicate |18541|7622|57824|66942|193587|3025|

Greedy rows were 2912/3066; maximum fanout 1940/1931. Source hashing, serializers,
four authenticated mask lookups and padding were still excluded. Consequently
this specific lowering cannot fit H512 even before those missing obligations.
It is not a lower bound on word-level relations or cryptography in general.
The rejected compiler and its complete source/results remain local research
artifacts; no partial relation or guessed admissibility flag is retained in Core.

## Checks and remaining work

Strict all-target Clippy passed after the extraction. The metadata tests use the
real release test target, Cargo offline/locked and a held-process 120s/1792MiB
observer; no fuse, cleanup kill or unexpected direct child occurred.

A new relation must implement a complete typed word-level inventory, exact
canonicality and u64 limb/carry checks, authorization, physical row order,
conflict-before-OFFSET, WAIT/resume, NOWAIT, SKIP, progress, writes and Result160.
It must bind the real source/DATA and originating request and pass actual native
security/resource/proof rejection gates before runtime composition. Full FHE
computation, fresh weighted QC, durable tickets and complete SQL response remain
separate required work. No full-query speedup or <=500ms result is claimed here.
