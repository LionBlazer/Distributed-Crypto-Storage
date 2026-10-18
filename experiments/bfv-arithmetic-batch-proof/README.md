# Public arithmetic proof CLI

This executable is a PUBLIC NONSECRET fixture and reporting consumer of
[bfv-arithmetic-batch-proof](../../crates/bfv-arithmetic-batch-proof/README.md).
The reusable library owns the immutable seventeen-relation frontend, private
backend, canonical proof codec, three-phase proof lifecycle, security assessment
and all twelve owning SDK/adversarial tests.

The Cargo package is `bfv-arithmetic-batch-proof-cli`; the explicit binary name
remains `bfv-arithmetic-batch-proof`. The experiment contains no library target,
proof implementation or SDK patch. Its direct project dependencies are the real
proof library plus [bfv-scale-circuit](../../crates/bfv-scale-circuit/README.md)
and [bfv-tensor-circuit](../../crates/bfv-tensor-circuit/README.md) for constructing
canonical public fixture frames. SHA256 binds those frames and `serde_json`
prints public reports.

The local `fixture` owns deterministic public ciphertext-residue requests and
the zero statement used by `security`. Its fixed role mapping is a CLI fixture
detail; it is not a second verifier or an exported internal library API. No
plaintext, secret key, participant data or private predicate belongs here.

## Modes

`security` constructs the local zero `Expected` and calls the library's
`analyze(&expected)`. The library rebuilds the actual three phase assessments
without evaluating a certificate or generating a main trace. `prove` constructs
the public fixture requests, invokes actual Core proving, saves the canonical
public envelopes, drops its original `Expected`, reconstructs a fresh one and
calls the actual Core verifier. It prints the security report and the existing
result record with `live_sql_grant=false` and `mulrelin_grant=false`.

The fixed operation covers four `Extend5To10`, ten tensors in Q0..Q4/P0..P4
order and three `Scale10To5`, all coefficients. It proves independent public
relations, not the edges of a multiplication graph. The backend is non-hiding.
Source/setup authority, same-secret keys, complete MulRelin, SQL completeness,
fresh agreed heads and network admission remain separate obligations.

The library preserves the original full SHA512 profile, canonical request/output
envelopes and `BFVABP02` frame, three mandatory phases, explicit per-call streaming,
16 MiB frame cap and shared decode budget. Whole security still uses the actual
three SDK reports and the existing conservative `min(bits)-2 >= 144` gate. No
submitted report or fixture label authorizes a result.

## Validation and timing

The [historical validation](VALIDATION.md) remains unchanged. It records the
former standalone library package, its twelve owning tests and measured
6,505,688-byte frame, generation of 172,380.3214 ms and fresh verification of
1,531.3598 ms in that run. Those measurements remain historical. The current
layout passed native build/test/CLI report validation, recorded in the linked
proof-library report. Neither record establishes SQL latency, full linked-operation
wire fit or a whole-process RAM guarantee.

The generation timer is owned by Core and includes public arithmetic,
setup/assessment, trace construction, proof generation, producer verification
and frame encoding. It excludes fixture/request creation. Fresh verification
starts inside Core `verify`, after reconstruction of canonical `Expected`.

The executable entry points remain `cargo run --release --locked --offline --manifest-path experiments/bfv-arithmetic-batch-proof/Cargo.toml -- security`
and the same command with `prove`. Owning library tests are now under
`cargo test --release --locked -p bfv-arithmetic-batch-proof --lib -- --test-threads=1`.

The [proof-library extraction validation](../bfv-mul-relin-proof/LIBRARY-EXTRACTION-VALIDATION.md) records the current
relocation, owning native tests and preserved proof policy.
