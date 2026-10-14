# BFV SIMD implementation variants

A separate package for exact owner-online COUNT/SUM over 16 or 256 public
selected input rows. It depends on compact-store and pinned fhe/fhe-traits
0.1.1. It changes no main-workspace dependency or backend. The preserved
[baseline](../bfv-simd/README.md) remains identifiable; see the
[measured comparison](../../docs/experiment-bfv-variants.md).

## Controls

- Default: full official N=16384/default_parameters_128(25), native NTT,
  original GE and output level 0.
- Feature optimized-ntt: only forwards the official fhe/tfhe-ntt feature.
  No nightly compiler, target-cpu flag or upstream patch is involved.
- Flag --fused-ge: combines the final GE merge into G_H+E_H*rotate(G+E,4r).
  EQ is unchanged. GE uses7 rather than8 ciphertext products; range14 rather
  than16. This is not an assumption that wall time must improve.
- Flag --output-level 8: after all arithmetic and rotations, uses the official
  Ciphertext::switch_to_level(8). Inputs and all evaluation keys remain at
  level 0 of the complete Q=438 profile. There is no depth schedule.

The owner retains page and BFV secrets, authenticates/decrypts pages and freshly
encrypts inputs. Peer contains public keys, public parameters and ciphertexts
only. Output remains unverified against a malicious evaluator. Native
whole-process peak working set/commit includes both roles and setup. A
completed phase rejects peak >=2,000,000,000 bytes. Security is upstream
claimed about 128 classical bits, not independently validated; no worst-case
noise/failure-probability bound is established.

## Reproduce

From repository root, with the configured shared Cargo cache/target and a CPU
lease:

    cargo build --release --locked --manifest-path experiments/bfv-simd-variants/Cargo.toml --jobs 2
    cargo build --release --locked --manifest-path experiments/bfv-simd-variants/Cargo.toml --features optimized-ntt --jobs 2

Archive each executable before the next build; the same target filename is
replaced by Cargo. Each raw setup record identifies its NTT feature, GE flag
and output level. Compare commands with identical rows, fixtures and predicates:

    compact-bfv-simd-variants --rows 16 --samples 5 --predicate ge --lower 18
    compact-bfv-simd-variants --rows 16 --samples 5 --predicate ge --lower 18 --fused-ge
    compact-bfv-simd-variants --rows 16 --samples 3 --predicate ge --lower 18 --fused-ge --output-level 8

Repeat for 256 rows, EQ and range18..128. Boundaries include EQ0/255/miss 19,
GE 0/255, full/empty ranges and256 allmax GE0 =>COUNT 256/SUM 16,776,960.
Use --noise-diagnostic only for the optional untimed owner/public-fixture
diagnostic; it subtracts the ciphertext's own decoded plaintext and cannot
assign the cause of an incorrect result.

94 measured queries passed exact public-fixture checks in the recorded
matrices/boundaries. Strict authored all-features Clippy passes. Only short
series were measured; transport, query proofs, index/PIR and UPDATE are absent.
Do not interpret local EQ times below500 ms as completion of the full goal.
