# Public RNS scaling proof experiment

This standalone consumer proves one complete 8192-coefficient Natural PowerBasis
RNS scaling stage. `Extend5To10` extends the fixed five-modulus basis with factor
one; `Scale10To5` scales the fixed ten-modulus basis back to the original five with
factor `114689/Q`. It does not prove NTT routing or full ciphertext multiplication
and relinearization, and it cannot return a production `CheckedOperation` or grant
SQL acceptance.

Status: validated arithmetic experiment. Native compilation, strict all-target
Clippy, all 14 owning tests, both complete SDK parity oracles, and two serialized
stage proofs passed. See [validation and measurements](VALIDATION.md).

| Dependency | Responsibility |
| --- | --- |
| [bfv-scale-circuit](../../crates/bfv-scale-circuit/README.md) | Fixed-role codecs, integer scaling, public certificate ranges and exact shared AIR |
| [bounded-postcard](../../crates/bounded-postcard/README.md) | Resource-limited nested SDK proof decoding |
| Plonky3 0.8.0 | Linked Goldilocks/Poseidon2 public-preprocessing STARK, extension degree 5 |

`backend` owns the fixed blowup 8 / 192-query configuration and asks the actual
SDK analyzer for constraint degree, count, quotient chunks and both security
bounds. It rejects either model below 128 bits; this is an individual-relation
model, not a composition claim. `proof` owns generation, independent verifier
preprocessing, the new role/profile/request-bound frame and the stage-only
`CheckedScaling` marker. `fixture` contains explicitly public, nonsecret residues.
The ordinary production proof loader, profiles, operations and 2 MiB frame cap are
unchanged.

Generation evaluates the actual integer scaling relation and produces its bounded
auxiliary certificate. Verification never invokes the scaler, derives Garner
quotients or reruns rounding: it validates all complete vectors and public auxiliary
ranges, constructs its own preprocessing commitment, and verifies the genuine STARK.
Extension outputs include all ten modulus polynomials; the first five must match
the trusted input exactly. The full request, output and certificate digests bind
all coefficients, their order and the fixed Natural PowerBasis representation.

The new experiment frame is capped at 8 MiB because the full auxiliary certificate
alone is about 2.58 MB. Nested SDK decoding limits each sequence to 4096 elements and
shares a 1,048,576-slot budget across containers. These are container bounds, not
whole-process RAM guarantees. Actual proofs were 3,222,283 and 3,252,971 bytes.
Both SDK security models reported 128 bits for each individual relation. Reported
raw trace/LDE arrays are structural byte counts, not RSS.

The owning tests include complete vector parity against the pinned SDK's actual
`RnsScaler`, genuine full-profile proof verification for both roles, changed
request/profile/role/order/final coefficients, malformed public certificate ranges,
rebuilt public preprocessing forgeries, and bounded decoder failures. All 14 cases
passed; the validation report distinguishes complete tests from the separately
measured CLI examples.

From the repository root, after a reviewed offline lock has been resolved:

```powershell
cargo build --release --locked --offline --manifest-path experiments/bfv-rns-scale-proof/Cargo.toml
cargo test --release --locked --offline --manifest-path experiments/bfv-rns-scale-proof/Cargo.toml --no-run
cargo clippy --release --locked --offline --manifest-path experiments/bfv-rns-scale-proof/Cargo.toml --all-targets -- -D warnings
cargo run --release --locked --offline --manifest-path experiments/bfv-rns-scale-proof/Cargo.toml -- security extend
cargo run --release --locked --offline --manifest-path experiments/bfv-rns-scale-proof/Cargo.toml -- security down
cargo test --release --locked --offline --manifest-path experiments/bfv-rns-scale-proof/Cargo.toml --lib tests::actual_sdk_multiplication_basis_and_plaintext_geometry_match_the_fixed_profile -- --exact --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/bfv-rns-scale-proof/Cargo.toml --lib tests::every_coefficient_of_both_roles_matches_the_actual_upstream_rns_scaler -- --exact --test-threads=1
cargo run --release --locked --offline --manifest-path experiments/bfv-rns-scale-proof/Cargo.toml -- prove extend
cargo run --release --locked --offline --manifest-path experiments/bfv-rns-scale-proof/Cargo.toml -- prove down
cargo test --release --locked --offline --manifest-path experiments/bfv-rns-scale-proof/Cargo.toml -- --test-threads=1
```

A successful stage proof alone does not establish encrypted predicate selection,
source completeness, key authority, fresh agreed heads, writer fencing, a live SQL
grant, full MulRelin correctness, bounded peer resources or practical latency.
