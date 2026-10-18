# Certified ciphertext-only public projection job

This nonaccepting experiment connects a genuine successful private
lock-return BFV formation certificate to the existing public-polynomial product
proof and an actual independent TLS peer process. It adds no SQL acceptance, live
lock grant, mutation or production network API. No new AIR or proof profile is
introduced.

## Ownership and entry points

- `mod.rs` owns `Binding`, sealed `Expected`, `prepare`, `Prepared::run_remote`
  and `Prepared::finish`. `VerifiedEncryptedProjection` contains checked arithmetic,
  its exact canonical output and the restored encrypted response.
- `fixture.rs` creates explicitly PUBLIC NONSECRET source, plan, control and BFV
  inputs and keeps the client key in the Basis fixture capability. The shared
  peer lifecycle owns exclusive directories and its explicit `cfg(test)` TLS host
  for owning corruption tests. The key and witnesses are never peer-call arguments.
- [Shared peer lifecycle](../../../peer_process/README.md) owns the explicitly named
  independent `dcs-peer` CLI child, existing bounded TLS bootstrap/readers and
  Shutdown/EOF/kill/join lifetime. This adapter imports that single implementation.
- `tests.rs` and the owning `state/locking/certified_job_tests.rs` own compiler provenance, prerequisite rejection, genuine foreign
  proof, complete arithmetic, real TLS and late physical-corruption cases.

Direct dependencies are the existing returned-formation/encoding/key/basis
modules; the owning locking SQL/compiler and 144-field plan encoding;
`bfv-query-core` for public syntax, complete setup identity and output restoration;
`bfv-query-proof` for actual arithmetic proof creation/verification;
`bfv-product-circuit` for canonical client-fixture completion; and `peer-runtime`
plus `rcgen` for real TLS, public setup installation and physical custody audits;
`peer-transport` for the existing bootstrap framing, `serde_json` for its existing
public codec and `zeroize` for the temporary private TLS-bootstrap buffer.
Core libraries do not depend on this experiment.

## Client-bound compiler provenance

`CompiledLockPlan::bind_returned` recomputes the EXISTING 144-field private plan
commitment from the same compiled predicate, mode, wait policy, window and
projection, plus client-owned TableId, selected transaction/controller,
sequence/revision and private plan salt. It must equal the already independently
expected `C_plan`. The sealed capability stores the exact typed canonical or
certified producer, full 32-byte request and derived public `RowProjection`.
There is no constructor accepting an arbitrary incoming plan root/projection pair.
The actual locking AIR still proves the selected transaction belongs to the full
bounded registry. This client construction does not authenticate its controller
or establish registry provenance or finality.

## Mandatory proof and byte binding

`prepare` verifies the actual complete prerequisite chain before constructing the
BFV request: canonical source plus lock, or the actual borrowed StateLease plus
lock; returned encoding; actual KeyTransform; five ordered Basis proofs; and the
bounded signed-integer formation STARK proof. Missing, swapped or foreign proofs reject before
handoff. The full expected formation statement includes the noise root.

`Binding` independently pins the request32, QueryId16, parent, full setup ID,
serialized public-parameter descriptor and typed `TargetVersion`. The latter
must encode both exact source heads and derives the nonce-bound ObjectID before
I/O. `Expected` retains the ORIGINAL full public setup bytes and exact keyset ID;
opaque evaluation-key blobs are not decoded/re-encoded into a different ordering.
The existing parameter-only KeyTransform descriptor remains a different identity.
No arbitrary B vector, operand table, alternate ciphertext or pending token enters
this API. The complete ciphertext comes from the verified formation statement.

`Prepared` owns only public bytes/descriptors, never private witnesses, keys,
Backends, leases or prerequisite proofs. It is not a freshness cache. Its local
identity binds all independent fields and the complete formation public values.
The EXISTING BFV wire independently binds QueryId16, heads, keyset, projection and
complete ciphertext. The arithmetic proof does not additionally hash request32,
parent or ObjectID; those belong to the freshly verified composite and sealed job
identity. A valid arithmetic proof for an identical BFV wire can therefore be
reused only with a separately valid matching input certificate and job context.

`run_remote` uses the unchanged InstallSetup and Prove RPCs. Existing transport
version and u64 request-ID checks remain independent of request32 and QueryId16.
Known wrong success variants reject. `finish` verifies the actual exact BFV product
proof before restoring the encrypted response; restoration does not repeat the
multiplication. TLS, hashes, decryption and response variants confer no proof.

## Validation and limits

Release/test compilation, strict Clippy, all 23 unchanged numeric reports, six new
owning cases, four affected existing controls and the independent-process CLI
passed. Discovery lists exactly 235 old plus six new tests. The old 235 bodies
are preserved; this stage did not rerun every body. The root lock and pinned SDK
anchors are unchanged; the leaf lock now records the reviewed 211-package graph.
See the [validation record](../../../../../CERTIFIED-PROJECTION-JOB-VALIDATION.md)
for commands, exact observations and the preserved first lint failure.

The new cases cover complete canonical and actual StateLease chains, genuine
foreign plan/key/arithmetic proofs and invalid prerequisite handoff. Client
completion checks all 8192 decrypted slots and a TLS test corrupts the freshly
reread index tail. The honest CLI uses the independent process path:

```powershell
# Build both executables with the pinned toolchain and flags in the report.
./hiding-fri-source-primitives.exe prove certified-projection-job E:/absolute/path/dcs-peer.exe
```

The peer path is explicit, absolute and checked before fixture creation. There is
no environment lookup or thread fallback. Only after complete admission does the
CLI launch a hidden Windows child with `--state-dir` and `--exit-on-stdin-close`,
send the existing bounded Bootstrap frame, compare endpoint TLS identity/loopback
and verify the remote Probe PID equals its distinct owned child PID. Its stdin
writer is never cloned: EOF independently terminates the existing daemon even
when the CLI is forcibly killed during FHE. Normal completion requests Shutdown,
closes stdin, waits, then kills/joins on a bounded cleanup failure; Drop also
kills/joins. The exclusive canonical fixture child is removed only after process
handles/readers release its files. Endpoint receive waits at most 30 seconds after the synchronous bounded bootstrap
write; this is not a whole-start IPC deadline. A full-operation observer fuse is
still required. The endpoint line is capped at 4096 bytes; stdout/stderr drains retain at most 64 KiB each and reject
truncated successful completion. The JSON retains the peer PID, exit code and
captured public endpoint/backend logs. A normal `Proof backend: ...` peer stderr
marker is not required to be empty.

The CLI timer begins after nonsecret fixture/key/setup construction and includes
prerequisite proving, repeated admission verification, independent process/TLS
startup and custody setup, RPC, arithmetic verification, restoration, fixture
client decryption and peer shutdown. Owner-only process samples exclude peer RAM;
the two processes must be accounted for separately. It is one
observation scope, not an interactive SQL benchmark or a whole-process RAM bound.
No fixed latency cutoff is asserted.

The public projection is visible in the existing BFV request. Private projection
privacy and an access-leakage policy are not settled here. Owner key authority,
same-secret evaluation-key consistency, entropy, agreed-head freshness/finality,
private writer fencing, MVCC and production source/SQL completeness remain unmet.
The bounded owner-witness producers are not ciphertext-only peer query execution:
only the final public-product worker consumes ciphertext/public material alone.
No signature or setup digest replaces any computation proof.
