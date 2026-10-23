# All-five public-instance association validation

This stage tests the [fixed source classifier](README.md) and its separate
first-frozen typed-word encoder. It does not implement the actual raw SHA512
notification/coin driver, prove all RBR transitions or grant SQL admission.
The classifier must be consumed synchronously before that driver's first coin;
a standalone file header does not authenticate its claimed extraction history.
All Rust additions and the reused public-fixture helper are test-only.

## Executed behavior

Five owning Rust cases cover all five source factories, complete Source/Role3
profile/image/tag/key/context rejection and different legitimate public root
claims, every fixed Word preprocessing cell, canonical framing/EOF and a
degree-32767 Query point delta that must reject before a degree-4096 bound.
DATA/Query accept non-Boolean and minus-one field coefficients as required by
the generalized low-level language; no integer multiplicity inference follows.

The independent Word case sends its original public PP through the actual PCS
`commit_preprocessing`, then compares every native public LDE cell with the
classifier's word. It uses the public constructor rather than only comparing
two calls to the same classifier helper. Exact zero interleaving, physical
coset, row order and all 714 columns are covered. It creates a public Merkle
commitment with an ordinary fresh suite, but no private commitment or proof.

The optional file case was explicitly executed on a complete Query request from
the Python encoder's first registered `Snapshot`: 545 columns, 32768 rows,
minus-one first column, zero remaining columns and complete public vector.
The request contains 142,868,800 bytes including its header and public values.
It belongs to the finite assigned-answer oracle model, not an actual native
SHA256 transcript or a network proof. Its bytes, image and sources were pinned;
expected family/public/PP metadata and complete consumption were checked.

The 15 new Python cases cover fixed five-family geometry, exact base/EF5/
codeword/salt cuts, canonical public shapes, first-notification identity,
immutable cutoff under later dictionary growth, failure consumption and actual
size degree/order checks. The combined 39-case run also includes the existing
24 typed extraction examples. No new code imports a production verifier or
mutable Expected callback.

## Observations

Windows MSVC Rust 1.99.0, optimized release/native CPU, locked offline
dependencies, two Cargo jobs and eight shared Rayon workers. The bounded native
observer held each exact process handle, executable and creation identity,
enforcing 120 seconds and 1792 MiB per process with 20 ms memory sampling.

| Observation | Cases | Harness time | Process wall | Sampled OS peak |
| --- | ---: | ---: | ---: | ---: |
| r739, all-five owning/source/PCS | 5 | 0.76 s | 791.9195 ms | 152,248,320 B |
| r740, complete frozen-model Query stream | 1 | 0.06 s | 80.7449 ms | 6,754,304 B |

Both exited zero without recorded faults or cleanup actions. The earlier same
complete file case r736 passed with 25,187.3102 ms process wall and 25.046875 s
CPU, including 23.78125 s kernel time. Its adapter issued a file read per
eight-byte field. A 64 KiB `BufReader` removed those repeated system calls;
r740 checks the identical complete request and assertions. This is a test I/O
improvement, not a SQL or cryptographic latency result.

The complete 39-case Python run passed in 1.509 s (r741); the first 15-case
root run passed in 1.500 s (r732). Strict Clippy passed after the final native
test and buffering change (r737); the default all-target check passed (r741).
The canonical requirements mirror test passed (r742).
An initial Clippy run rejected a duplicated fixture module; a narrow test-only
helper now reuses its owning module. No duplicated fixture or warning allowance
was retained. Formatting and local documentation links are checked separately.

The r739/r740 executable SHA256 was
`8FC634161DC4E3FBBAB2768580203D1D55F30E31BFAE17829A3B70651C756004`.
The complete public model request SHA256 was
`C0871DD0C14DFC3F498E092C961266C582B5EE7F971AE73BBEF86BF101AEF414`.
Generated request bytes and observation receipts are local outputs, not fixtures
committed to the repository.

## Reproduction

```sh
python -B -m unittest discover -s experiments/hash-hiding-fri/analysis -p 'test_*.py' -v
cargo test --release --locked -p registry200-proof --features owner-read registry_progress::word_inventory::generalized_mu::tests:: -- --test-threads=1
cargo clippy --release --locked -p registry200-proof --features owner-read --all-targets -- -D warnings
cargo test --release --locked -p repository-contracts --test requirements_sync
```

The ordinary Rust gate leaves the file bridge ignored. To execute that case,
first produce a complete public request with `ProtocolRecognizer`, set
`DCS_MU_REQUEST` to its path, then run the exact optional test with
`--ignored --exact`. Encoding success alone is not classifier acceptance.
No end-to-end SQL, fresh-head consensus or finalized locking result is measured
by these checks; the full 500 ms objective remains open.
