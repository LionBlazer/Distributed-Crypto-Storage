# Native transcript audit

The optional `bfv-hiding-stark/transcript-audit` feature records actual challenger
observations and SHA512 draw digests for source-correspondence tests. It depends
only on the parent fixed challenger and the standard library. Production builds
do not enable this feature by default.

`capture` enrolls challengers constructed inside its calling-thread scope and
their forks. `Trace` exposes exact absorbed bytes; `Draw` exposes each real draw's
prefix length, counter, retry and full digest. A challenger clone copies its
captured history into a separate branch. Captures close on return and unwind;
escaped challengers continue computing without extending a closed capture.
New challengers constructed on unrelated threads are outside this scope.

The recorder bounds stored payload to 8MiB and traces to 64. Exceeding either limit
returns an audit error after the observed operation finishes. Nested captures
reject before running their body. It cannot supply randomness, observations,
proofs, verification decisions or accepting capabilities. Captured bytes are
public transcript material; callers must scope it to their intended operation.

The owning five-proof test in registry200-proof enables the hook only as a dev
dependency and compares actual receiving calls with its closed program. The
independent audit lifecycle and primitive-vector tests run with:

```sh
cargo test --release --locked -p bfv-hiding-stark --features transcript-audit hash:: -- --test-threads=1
```
