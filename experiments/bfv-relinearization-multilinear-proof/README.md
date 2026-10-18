# Public-Aux relinearization arithmetic with a multilinear STARK

Release compilation, strict all-target Clippy, rustfmt, both actual SDK security
reports and all twenty owning tests passed on 2026-10-17. The two pure SDK oracle
cases passed before the first proof. See [validation and measured limits](VALIDATION.md).
These are results of this new protocol; the older consumer remains unchanged.

The consumer certifies one complete public arithmetic relation over all 8192
positions: `Embed` maps five PowerBasis RNS rows to 25 source/target rows;
`AccumulateAndAdd` maps 85 native-NTT rows to ten target/component rows. The latter
includes each original c0/c1 and all five ordered digit/key products. It is not a
complete relinearization or MulRelin proof, a key-authority result, or a SQL permit.

## Ownership and API

[`bfv-relinearization-circuit`](../../crates/bfv-relinearization-circuit/README.md)
owns sealed canonical Request/Output/Aux, exact arithmetic, integer bounds and
optional `plonky3::ArithmeticAir`/`prepare`.
[`bfv-multilinear-stark`](../../crates/bfv-multilinear-stark/README.md) owns the
fixed serial SHA512/WHIR configuration and actual complete SDK assessment.
[`bounded-postcard`](../../crates/bounded-postcard/README.md) owns fresh per-decode
allocation accounting. No older proof consumer or univariate backend is imported.
The standalone private workspace does not change root membership or dependencies.

This consumer owns its domains/profile, full statement envelope, independent
public preparation, PK/VK lifetime, bounded canonical proof frame, complete report,
direct SDK prove/verify calls and the opaque `CheckedStage` marker.
`prove(&Request)` evaluates a public certificate, prepares the real AIR and proves
it. `verify(&Request,&Output,frame)` decodes the public Aux, rebuilds its own
preprocessing/VK and verifies; it never reduces residues, runs NTT/key switching,
performs the five-term MAC or regenerates quotients/carries. Public preparation
still copies/splits complete vectors and encodes/commits public tables. That work
is real verification work, not a cached geometry key or a proof-free shortcut.

`CheckedStage::matches` compares full SHA512 request/output digests plus the role
and exact external context32. The context is an opaque byte label. It does not
validate a key blob, same-secret-key consistency, authorization or freshness.
A future complete caller must independently bind its full trusted setup64 and
exact producer/key/digit/output edges; hashing this context32 is insufficient.

## Public relation and transcript

All input, output, quotients and carries are PUBLIC preprocessing. The one main
column is constrained to zero. This is not a private main-witness computation or
a zero-knowledge proof. The AIR has legacy PV32 digest words for consistency;
those SHA256 fields are not the sole cryptographic statement binding.

The new 64-byte operation profile binds the shared exact protocol descriptor,
four distinct domains, full Q5 values, all embedding quotient bounds, both roles'
ordering, carry/radix bounds, shape, frame/decoder policy and semantic exclusions.
The request passed to `Config::challenger` is the unambiguous byte envelope:

```
fixed Request-and-public-Aux tag || u64LE(Request length) || COMPLETE Request
  || u64LE(Aux length) || COMPLETE canonical Aux
```

The shared challenger seeds `statement_domain || profile64 || SHA512(envelope)
|| SHA512(COMPLETE Output)`, retaining all 64 bytes. All leaf/node hashes retain
eight u64LE words; Fiat-Shamir retains all 512 bits. Setup uses its own throwaway
challenger; proving and verifying each start fresh. No prover-selected VK enters
verification. Canonical decode/range/binding checks precede preparation and seed
construction during verification.

Embed uses public canonical residues below 2^44 and quotients up to two, with
scalar residual below 2^46. MAC uses three 16-bit limbs, six complete digit
equations and five 25-bit biased carries per component; quotient is below 5q.
Both endpoint carries are fixed zero in signed form, and each digit residual is
below 2^42, below Goldilocks. The existing pure library owns these equations and
checks every public range before field conversion; this consumer does not clone
or weaken them.

| Role | Main / PV | Public width / cells | Main PCS arity | Public PCS arity |
| --- | ---: | ---: | ---: | ---: |
| Embed | 1 / 32 | 55 / 450560 | 13 | 19 |
| AccumulateAndAdd | 1 / 32 | 365 / 2990080 | 13 | 22 |

The symbolic count/degree and actual SDK schedules/bounds come from the linked
SDK, not the expected shape or a requested security target. The fixed protocol
uses Goldilocks EF5, full SHA512 with collision cap256, UniqueDecoding, phase
target160, zero PoW and whole-statement floor144. `assess` must return a finite
complete bound with no unassessed term before proof/verification. Both main and
public PCS are assessed. Missing, unsupported or below-floor reports reject.
These remain individual-stage bounds, not a composed whole-Relin security claim.

`backend::analyze(role)` constructs a valid zero public statement without
arithmetic evaluation, then allocates and commits actual public tables and builds
an actual VK for SDK assessment. It generates no main trace/proof, but it is not
a no-matrix or negligible-cost analysis path.

## Frame, decoding and conditional resource budget

New magic `BFVRLM01` has a 144-byte header: magic8, new profile64, binding32,
key-context32, role/representation/input-count/output-count and four zero bytes.
It is followed by exactly the role-sized canonical Aux and one canonical
MultiStark payload. Request/output are independently supplied complete vectors.
The new cap is 16 MiB including Aux; sequence cap is 16384 and aggregate budget is
8 Mi decoded slots. These policies leave all old consumers/caps unchanged.

Before SDK evaluation, layout checks require one AIR, current openings1/55 or365,
no successor/indexed/bus/lookup proof, 13 sumcheck rounds of two values for Embed
or three for MAC, and real SDK-derived WHIR query counts/rates. Main folding is
[4,4] with final5; public folding is [4,4,4,4] with final3/6. OOD/PoW are empty
only because the fixed UniqueDecoding configuration requires zero. Query row
widths, Base/Extension variants, exact phases and final-polynomial lengths are
checked; sibling arrays are bounded by queries times depth22. Trailing bytes,
noncanonical reencoding and SDK panics reject.

For the exact 13/19/22 arities there are six TOTAL PCS query phases, not twelve.
Using at most512 queries, row width16 and Merkle depth22, authentication wire is
at most `6*512*22*8*10 = 5406720` bytes; two base and four extension phases use at
most `512*16*(2*8+4*40) = 1441792` row bytes. Less than256 KiB is reserved for
remaining evaluations, roots, lengths and sumchecks. Maximum Aux is2130096 bytes,
plus header144, putting this conservative envelope below9.3 MB and16 MiB. Decode
query slots are at most1657856 plus608256 sibling slots, fewer than18000 opening
slots and64 Ki other slots, below the new8 Mi budget. Actual serialization must
still pass the decoder/frame policy; these are source bounds, not measured proof
size, RAM or latency. Raw public tables occupy3604480/23920640 bytes and exclude
codewords, Merkle trees, temporary copies, allocator overhead and complete peers.

## Owning examples and reproduction

Public nonsecret fixture vectors are not accepted ciphertext/key provenance.
Pure SDK oracle tests use real `Poly` embedding and five public c2 impulse probes
to expose the actual ordered `RelinearizationKey` K_i. They compare every result
against real level0/0 relinearization for arbitrary three-component ciphertexts
and an actual encrypted product. No host duplicate MAC computes the expected
result. The separate proof-coupled product test also proves/verifies BOTH derived
arithmetic requests and compares checked output with all SDK coefficients. Those
native NTT transformations are oracle-only and are not certified by this stage.

Owning examples cover both genuine roles sequentially, every last input/output
polynomial, quotient two, all ten MAC quotients/carry chains, all five digit
terms, key/component ordering and canonical aliases. Real weaker/foreign AIR
proofs first verify under their own exact AIR/VK, then reject under the honest
expected program. Rebuilt public output/quotient/carry attacks reach the integer
AIR; they do not rely solely on broken headers. All twenty tests pass, with no
ignored or filtered cases.

The reviewed standalone lock resolves offline to existing pinned registry versions;
the leaf enables no parallel, diagnostics, test-util or nightly SDK feature.
Validation used a fresh target, both `security` commands and both pure SDK oracles
before any proof. Proof/test gates used an owned-process sampled memory fuse and
actual time/resource receipts. Reproduce the owning gates with:

```sh
cargo build --release --locked --offline --manifest-path experiments/bfv-relinearization-multilinear-proof/Cargo.toml
cargo test --release --locked --offline --manifest-path experiments/bfv-relinearization-multilinear-proof/Cargo.toml --no-run
cargo clippy --release --locked --offline --manifest-path experiments/bfv-relinearization-multilinear-proof/Cargo.toml --all-targets -- -D warnings
cargo run --release --locked --offline --manifest-path experiments/bfv-relinearization-multilinear-proof/Cargo.toml -- security embed
cargo run --release --locked --offline --manifest-path experiments/bfv-relinearization-multilinear-proof/Cargo.toml -- security accumulate
cargo run --release --locked --offline --manifest-path experiments/bfv-relinearization-multilinear-proof/Cargo.toml -- prove embed
cargo run --release --locked --offline --manifest-path experiments/bfv-relinearization-multilinear-proof/Cargo.toml -- prove accumulate
cargo test --release --locked --offline --manifest-path experiments/bfv-relinearization-multilinear-proof/Cargo.toml --lib -- --test-threads=1
```

CLI security setup and public fixture construction precede the library prove
timer. Prover total includes certificate arithmetic, public setup/security, zero
main proof generation and frame encoding. Verifier total includes bounded decode,
public setup/security and SDK verification; its SDK interval excludes envelope
encoding/hash preparation. An outer process timer additionally includes startup,
CLI analysis and fixtures. No timer is whole Relin/MulRelin, an FHE peer query or
SQL latency. These process observations establish no performance improvement or
whole-operation resource guarantee.

`CheckedStage::security_report()` borrows the actual `backend::SecurityReport`
rebuilt by this verifier and retained only after genuine proof verification
succeeds. It exposes the existing whole-stage bound, terms and unassessed-component
list for explicit composition; no report is accepted from a frame or producer.
It adds no complete-Relin, same-secret-key, SQL or freshness guarantee. The
[full graph validation](../bfv-mul-relin-proof/VALIDATION.md) includes all twenty
owning tests and actual use of both relinearization reports in the complete graph.
