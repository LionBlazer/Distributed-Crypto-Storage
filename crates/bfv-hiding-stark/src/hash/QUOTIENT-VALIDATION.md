# Joint trace/quotient algebra regression

The [joint image statement](QUOTIENT-IMAGE.md) is conditional on honest original
AIR validity, successful AUX construction, the stated degree bound, ideal fresh
masks and independently fixed public inputs/coins/locations. These checks test
finite algebra and actual SDK source correspondence. They do not establish
salted-MMCS hiding, adaptive FS composition, an actual owning-AIR privacy theorem
or live SQL acceptance. Production parameters and admission remain unchanged.

## Independent coefficient and residue-ring calculation

`quotient_image_tests.rs` uses actual Gold/EF5, original N = 512 and 2048, all
192 base locations, and deliberately disjoint S/hS. The resulting disclosure
moduli have their full degrees 197 and 394. It checks the two rotation maps
into the smaller ring against full coefficient rotation. A separate valid
mask perturbation Z*M_T demonstrates why rotation inside the larger ring is
not well-defined, while its projection into the smaller ring remains zero.

Its polynomial AIR fixture is explicitly algebra-only:
`C=(P^2-P)*(A(hX)+u)`, with a masked original constant Boolean P and five
separately masked base coordinates of A. For both original Boolean values,
it compares all five full quotient coordinate polynomials with the tensor-ring
calculation `C/Z`. Full reference products use DFT convolution; residue-ring
products and long division use independent coefficient arithmetic. No claim
is made that this fixture is one of the owning SQL AIRs. The source-associated
degree/divisibility premises of the general statement remain necessary.
The fixture uses deterministic masks and is linear in A; it neither exhausts
arbitrary extension products nor tests the distributional equal-fiber theorem.

The explicit `Q=X-u, z=u` case has collapsed Q(z)=0 but separate coordinate
openings `(u,-1,0,0,0)`. This prevents replacing the full receiver disclosure
with one collapsed extension-field value.

## Actual native quotient transformation

`native_quotient_tests.rs` passes public synthetic five-coordinate quotient
polynomials through the normal OS-seeded suite's actual `get_quotient_ldes`.
The three actual `(N,c)` geometries are `(512,16)`, `(512,8)` and `(2048,8)`.
It checks ten raw columns, height 16N, coefficient degree < 2N, physical shift
7, all ten columns' normalized mask relation and weighted coefficientwise
mask cancellation. The first five original chunk polynomials are checked
against independent coefficient reduction modulo `X^N-s_i^N`.

For appended columns the original baseline is inferred from the native rows on
U_i, where masks vanish; it is not independently supplied or an RNG-distribution
test. Native barycentric OOD interpolation is checked against coefficient Horner
for every raw column. All five coordinate recompositions are checked at z and
on the entire common coset D, including roots of individual v_i and D outside U.
This uses division-free Lagrange products, retaining the vanishing-factor case.
It invokes neither a full PCS opening nor a FRI proof and makes no honest-AIR
validity claim about the supplied synthetic quotient.

## Exhaustive small-field fiber check

The separate research runner
[`exhaustive_quotient_fibers.py`](../../../../experiments/hash-hiding-fri/analysis/exhaustive_quotient_fibers.py)
enumerates every one of 17^4 coefficient masks for each of four squarefree
moduli over F_17. It compares literal polynomial masking against a target
defined by independent RREF of the full affine selector equation, and compares
complete multiplicity counters for two different originals with the same Q
residue. The moduli include a point inside U, a point outside U, an irreducible
quadratic, and a linear-times-quadratic product. Their support/fiber sizes are
17/4913, 17/4913, 289/289 and 4913/17. Thus the vanishing-factor branch and
equal fibers are checked exhaustively in that finite universe. This is not
random sampling or a finite-field estimate of a cryptographic failure rate.

```sh
python -I -B experiments/hash-hiding-fri/analysis/exhaustive_quotient_fibers.py
```

## Reproduction and scope

```sh
cargo test --release --locked -p bfv-hiding-stark hash::quotient_image_tests:: -- --test-threads=1
cargo test --release --locked -p bfv-hiding-stark hash::native_quotient_tests:: -- --test-threads=1
cargo test --release --locked -p bfv-hiding-stark --features transcript-audit hash:: -- --test-threads=1
cargo clippy --release --locked -p bfv-hiding-stark --features transcript-audit --all-targets -- -D warnings
cargo test --release --locked -p repository-contracts --test requirements_sync
```

The bounded local harness uses release opt-level 3, Rust 1.99.0 MSVC, native CPU,
locked offline dependencies, two Cargo jobs and eight shared Rayon workers.
It holds the exact process handle/image/creation identity, with a 120-second
fuse and 1,792 MiB process memory limit sampled every 20 ms. Generated matrices
are public nonparticipant fixtures, are not persisted and carry no admission.

The first accepted coefficient/tensor observation (r724) passed three tests in
0.07 s; process wall was 90.6014 ms and sampled OS peak was 7,335,936 bytes.
The prior r723 native process also passed, but its observation was not accepted:
the root-created contract omitted a required scope field. The corrected contract
retains that failed receipt; r724 reran the same pinned image successfully.

The actual native quotient case (r727) passed in 0.10 s across all three
geometries; process wall was 120.7493 ms and sampled OS peak was 32,436,224
bytes. Both accepted native observations exited zero with no recorded faults
or cleanup actions. The imported F_17 runner passed independently in 5.484 s
(root r728); all four exact counters matched their RREF target and alternative
originals. Strict audit Clippy passed after both Rust modules were added (r725).
The final combined transcript-audit gate passed all 32 hash tests in 0.20 s
(r729), and the requirements mirror test passed (r730). Rust formatting and
changed documentation links passed. Full-proof and peer-process gates were
not repeated for these test-only and research changes.

All durations here are component-test observations. They exclude complete
proof generation, SQL, network transfer, version agreement and lock finalization.
They do not establish the full 500 ms request target.
