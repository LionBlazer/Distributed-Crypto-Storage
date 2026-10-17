# Relinearization arithmetic stages

This library owns two complete public arithmetic stages used by the
pinned BFV level0/0, log_base0 key-switch path. It does not implement or certify
complete relinearization, MulRelin, key validity or SQL acceptance. There are no
SDK, core, secret-key, backend, network, callback or owner-witness dependencies.

## Responsibilities and API

[bfv-fixed-geometry](../bfv-fixed-geometry/README.md) is the only direct project
dependency and owns unchanged N8192/Q5. `codec` owns sealed fixed public containers;
`profile` separates both roles; `math` evaluates all coefficients. Optional feature
`plonky3` owns the public AIR/preparation adapter; default APIs expose no P3 types.
Consumers own actual proof configuration, transcript, full setup/key/ciphertext
provenance, independent expected context and proof verification.

`encode_request(role,binding32,keyset_context32,input)` returns bytes;
`decode_request` returns immutable `Request`. `evaluate_with_certificate` returns
`Evaluation { output, aux }`; decode/accessor/encode APIs preserve canonical bytes.
The request binding and keyset context are distinct external byte identities.
Neither a matching context nor its digest proves same-secret consistency,
authorization or freshness. No CheckedOperation or proof-acceptance token is minted.

## Exact roles and ordering

`Embed` consumes five complete PowerBasis residue rows r_i. It returns 25 complete
rows E_ij, ordered source i, then target j, then coefficient, satisfying
r_i=E_ij+q_j*t_ij, E_ij<q_j. The exact quotient maxima are:

```
0 1 0 0 0
0 0 0 0 0
2 2 0 1 1
1 1 0 0 1
1 1 0 0 0
```

The decomposition is by RNS rows, not bits. A quotient 2 is reachable. Diagonal
quotients are zero. Public canonical r/E<2^44 and t<=2 give a scalar residual
below 2^46<Goldilocks, so the embedding AIR is a sound integer equality without
full multiplication limbs or field aliases.

`AccumulateAndAdd` consumes 85 complete native-NTT polynomials. For each target j,
a 17-polynomial block is ordered original0, original1, D0..D4, K00..K04, K10..K14.
Every value in that block is canonical modulo q_j. Output 10 polynomials are ordered
target j, then component c0/c1. Every output is:

```
y_c,j = original_c,j + sum_i=0..4 D_i,j * K_c,i,j  (mod q_j).
```

All 8192 positions and all five terms are mandatory. This does not generate D or
parse/validate K from a key blob. Each five-product sum plus original is below
2^91; quotient<5q_j<2^47. Three 16-bit limbs cover each residue and quotient.
Six exact digit equations cover 96 bits with five shifted carries d=c+2^24 in
[0,2^25), with both endpoint carries zero. Each digit residual is below 2^42,
well below Goldilocks. Compile-time guards enforce N8192, Q<2^44 and quotient maxima<=2.
Prover math uses exact u128 and allocation-free limb
iterators; no large product is replaced by one field equality.

## Canonical wire and public preparation

Common 112-byte header: magic8 (`BFVRELQ1/R1/C1`), profile32 at 8, request binding32
at 40, external keyset context32 at 72, role at 104, representation at 105, fixed input
count at 106, output count at 107, zero4 at 108. Request/output representation is
PowerBasis1 for Embed and nativeNTT2 for AccumulateAndAdd; Aux is3. Residues are
component-major u64 LE. Output adds SHA256(exact request) at 112, data from 144.
Aux adds that input SHA at 112 and SHA256(exact output) at 144, records from 176.

Embed sizes: request 327792 / output 1638544 / aux 204976 bytes. Aux has 8192 records of
25 u8 quotients in source/target order. AccumulateAndAdd sizes: request 5570672 /
output 655504 / aux 2130096 bytes. Its 8192 records are 260 bytes: ten 6-byte quotients
at 0..60, then ten five-u32 carry chains at 60..260. Exact lengths are checked before
input-derived allocation. Unknown roles/profiles/tags, wrong counts or
representations, residue/quotient/carry aliases, truncation and trailing bytes
reject. There are no reduced or caller-parameterized profiles.

Optional `prepare` checks canonical ranges and complete identities/hashes, then
copies/splits public values into the exact layout. It does not reduce r_i, multiply
coefficients, divide by q, perform an NTT or run key switching. Height 8192, mandatory
zero main width 1, public digest words 32 and preprocessing widths 55/365 are fixed.
Analytically Embed has 26 constraints/degree 1 and AccumulateAndAdd 61/degree 2; actual
SDK analysis and process measurements belong to the
[validated consumer](../../experiments/bfv-relinearization-proof/VALIDATION.md).
`ArithmeticAir::shape` lacks
preprocessing and is analysis-only. Consumers must require prepared data and an
actual matrix before proof setup. Aux/Prepared is never a computation proof.

## Required later composition and SDK oracle

Exact ordered 25 Forward-NTT links must tie Embed outputs to D. The five public
key c0 polynomial byte payloads are PowerBasis even when their enum is NttShoup:
25 genuine setup NTT links are needed to obtain K0. Seeded K1 is direct public NTT
PRNG material with the exact upstream seed chain. Full setup identity must be
independently pinned; matching bytes do not prove evaluation-key same-secret
consistency. Original c0/c1 need their producer/NTT links too; final NTT outputs
need inverse links before PowerBasis serialization. These are not host callbacks
or trusted stage hashes supplied by this library.

A consumer can validate the actual SDK without private-field/key export: construct
five public three-component ciphertext probes with zero NTT c0/c1 and c2 whose
PowerBasis coefficient0 is1 only in RNS row i; convert c2 to NTT and call public
`RelinearizationKey::relinearizes`. The two resulting polynomials expose the public
ordered K_i for an oracle. `relinearizes_poly` is crate-private and must not be used
by an external consumer. Compare complete random/asymmetric input results through
public SDK relinearization, not only a hand-written copy of these equations.

Owning tests cover quotient 2, all Q5 targets, all ordered MAC terms,
original additions, maximum high limbs, last coefficients, both identities and
canonical rebuilt output/quotient/carry attacks reaching AIR. On Rust 1.99.0, all
seven default tests and all ten optional-feature tests pass with no ignored or
filtered cases. Both strict all-target Clippy checks and explicit rustfmt pass.
Reproduce these owning checks from the repository root:

```sh
cargo test --release --locked -p bfv-relinearization-circuit --no-default-features -- --test-threads=1
cargo test --release --locked -p bfv-relinearization-circuit --all-features -- --test-threads=1
```

These checks establish public arithmetic and actual AIR constraint rejection;
the [separate consumer](../../experiments/bfv-relinearization-proof/VALIDATION.md)
also passes actual SDK parity and genuine serialized proof gates for both roles.
These remain individual public stages. Source certificates, key
consistency/authority, fresh agreement, writer fences and complete SQL remain open.
