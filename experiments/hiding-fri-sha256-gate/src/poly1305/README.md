# Public Poly1305 small-fixture AIR

Current shared arithmetic/witness helpers are validated with the fixed
[whole-pair candidate](../opening/README.md): release build, strict Clippy, eight
fresh analyses and all 47 serial tests pass, including this module's 14 cases.
The [current validation record](../../PAIR-OPENING-VALIDATION.md) preserves the
initial selector regression and every failed attempt. The older record below
retains its separate historical meaning.

Historical status: release build, strict Clippy, seven security-only analyses, five observed
public-fixture proof/verify processes and all 33 serial tests passed for the
recorded revision. Fourteen tests exercise this module. Exact provenance and
observation limits are in [POLY1305-VALIDATION.md](../../POLY1305-VALIDATION.md).
This private module is part of the nonaccepting
[primitive experiment](../../README.md), not a reusable storage/Owner API.
All inputs and keys are explicitly PUBLIC NONSECRET fixtures. It proves neither
private-witness custody, AEAD composition, CSTORE opening, SQL completeness, live
locks, finality nor a performance/resource target. Existing SHA/ChaCha reports
belong to their recorded source, not this extension.

## Responsibility and boundaries

| File | Owned responsibility |
| --- | --- |
| `statement.rs` | Checked raw/padded layout, fixed public inputs, statement identity, pinned independent oracle |
| [shared arithmetic](../../../../crates/registry200-proof/src/source/poly1305.rs) | Single canonical state, bounded cyclic product/tag constraints and caller-owned row writer; imported by mod.rs |
| `air.rs` | Boolean radix constraints, bounded witness generator, exact public schedule, canonical state and final tag |
| `tests.rs` | Public oracle examples, genuine proofs and rebuilt malicious-proof rejection tests |
| `mod.rs` | Explicit experiment policy, radix and standard clamp constants |

Direct consumers are sibling private `primitive.rs` dispatch and `backend.rs`
profile calculation. This module imports registry200-proof::source::poly1305;
the shared Source AIR uses that same implementation. It reuses the backend's OS-seeded
RNGs, hiding PCS/MMCS, shape checks and both numerical security floors; no backend
or validator is copied. Oracle dependencies are exact `poly1305=0.8.0` with its
`zeroize` feature and `universal-hash=0.5.1`, already available in local source.
Only the standalone manifest/lock changed; their offline resolution and exact
active oracle graph were independently audited. No root dependency changed. Fixture/SDK buffers do not gain a private-key zeroization guarantee.

`Statement::raw(key, bytes)` and `Statement::padded(key, segments)` first validate
shape, then copy at most 48 original bytes into a fixed array and compute a public
oracle tag. The fixture generator is separate from AIR witness generation, which
never reads the claimed tag. Statement request/key/tag can be altered by local
adversarial tests; payload and layout are immutable behind checked construction.
`Poly1305Air::new` derives identity and layout from that exact typed statement.
There is no deserialization or unchecked schedule constructor.

## Public layout and policy

This experiment alone caps input at three 16-byte blocks and three segment
descriptors, with at most 48 original bytes. Descriptor count is independently
bounded, including empty descriptors. Raw input is exactly one descriptor of
length 0..48. Padded mode admits 0..3 descriptors, each 0..48 bytes, provided the
sum of `ceil(length/16)` is at most three. Bounds reject before oracle, trace or
proof creation. They are not proposed production page/message limits.

Raw mode appends `2^(8*L)` to a nonempty short L-byte final block. A full 16-byte
block appends `2^128`. Empty input has no block. Padded mode applies
`UniversalHash::update_padded` to each segment in order: only a nonempty short tail
is zero-extended to 16 bytes, then receives the full `2^128` bit. Empty and aligned
segments add no extra block. Separately padding `[a],[b]` is not padding `[ab]`.
The public shape binds mode, descriptor count and all three original lengths,
including empty/trailing descriptors, original payload, key, tag and request.
This is not the full CSTORE AAD/ciphertext/length construction.

The 97 public field values are eight identity words, 32 key bytes, 48 original
payload bytes, three lengths, descriptor count, mode and four little-endian tag
words. Unused payload positions are zero. Identity covers the complete primitive
profile plus all those typed values and request; the AIR constrains its digest.
The verifier independently derives the byte-position/block/append-bit mapping
from checked original lengths. It never accepts a prover's schedule.

There are 512 rows, 813 boolean witness columns and three fixed public selector
columns. The selectors identify rows 0, 1 and 2 respectively. Only the first
validated block-count selectors are active; all later transitions preserve state.
The profile binds both modes, caps, radix/clamp, schedule, geometry, byte order,
canonicalization, carry widths and unchanged backend parameters. All assertions
are emitted for every admitted shape, including constant-zero unused-byte checks;
empty/partial/full inputs retain the same assertion count, committed quotient
sizing and opening geometry. The declared degree bound is three. Source inspection
of SDK 0.8 and actual reports agree: inferred degree is two for active-count zero,
and three for nonempty inputs; the hint does not overwrite that inference. All
seven security-only reports reached both 128-bit floors under the pinned SDK/model.

## Integer arithmetic

Let `B=2^26` and `p=B^5-5`. State H has five 26-bit limbs, starts at zero and is
canonical `0<=H<p` on every row, including inactive/final padding. Effective R is
formed directly from the same raw 128 key bits and the standard clamp mask;
raw key bytes are bound on EVERY row. A clamped-away raw bit is a valid key bit:
changing it leaves the MAC unchanged but changes statement/proof identity. It
cannot contribute to R. S is the same raw key's final 16 bytes.

For message limbs N (with the mode-specific appended bit) put `A_i=H_i+N_i<2B`.
For each k in 0..4, define

```text
D_k = sum(i+j=k, A_i*R_j) + 5*sum(i+j=k+5, A_i*R_j)
D_0 + 5*C_4 = H'_0 + B*C_0
D_k + C_(k-1) = H'_k + B*C_k, k=1..4
```

Each C is a nonnegative 32-bit integer, constrained by bits. Telescoping gives
`sum(D_k*B^k)=H'+p*C_4`; canonical H' makes the residue unique. Every `D_k<42B^2`.
Each local integer side is below `42B^2+5*(2^32-1)<2^58`, strictly below the
Goldilocks modulus `2^64-2^32+1`. There is no 130-bit field equality or u128
accumulator. The entire folded integer can exceed u128; the generator only uses
five bounded u64 coefficients and radix carries.

Completeness also fits the carry range: with `q=floor(U/p)`, `q<43B<2^32`.
The congruence gives integral recursive carries; their numerators exceed `-B`, so
they are nonnegative multiples of B. `C_0<42B+215<43B`, and the remaining carries
are below `42B+43<43B`. The generator performs four fixed radix passes, then a
conditional subtraction of p, and derives/verifies those exact cyclic carries.
These bounds are source reasoning, not an executed security report.

Canonical H uses the five-limb equality `H+5=Z+B^5*c` with 26-bit Z limbs and
boolean intermediate carries; the last carry MUST be zero. Its 130 result bits
and five carry bits stay populated/checked on EVERY padding row. Only message
bits/product carries are zero inactive; tag carries are zero on nonfinal rows.
Without the final canonical check, `U=p` permits both `q=1,H=0` and `q=0,H=p`.

The final row takes the low 128 bits of canonical H and adds the same key's S in
four little-endian u32 words with four boolean carries. Each local side is below
`2^33`; only the last carry is discarded. The tag is modulo `2^128`, not modulo p.
First H=0, all active arithmetic, padding state transitions, every comparator and
the final tag are constrained. Active products have degree at most three after
the public selector; no extra transition gate increases that degree. Next-row
access covers 130 state columns, but SDK 0.8 opens the complete width at both
points. Actual reports give 1,361 constraints, eight quotient chunks and 1,726 batched
functions, with both decoding bounds 128 under the pinned SDK/model.

## Executed validation

The validated tests include the literal RFC tag; independent raw and padded
RustCrypto oracles at empty/partial/full/three-block lengths; zero and maximal
clamped keys; descriptor/block/byte rejections; all fixed schedule/shape reports;
genuine proof verification with an independent backend; key/request/tag/mode/
original-boundary binding; missing full next opening and altered randomization.

Rebuilt malicious proofs bypass the honest generator and claim matching false
tags where applicable: noncanonical H=p, wrong fold factor five, omitted full
hibit, wrong short-tail bit, raw/padded substitution, omitted/reordered/extra
blocks, forbidden clamp contribution, first H, nonboolean/negative/lost carries,
inactive witness data, missing S, wrong byte order and mod-p finalization.
The canonical boundary uses public R=1, first payload `2^128-1`, second payload
`2^128-4`, giving unreduced p. Neighbors exercise p-1 and p+1. The false p trace
recomputes its cyclic carries and tag and fills the comparator, isolating its
nonzero final canonical carry. Final-tag fixtures force all four real carries,
including the discarded 128-bit overflow.

A separate offline lock audit, compile/strict-Clippy/test-no-run phase, seven
actual security-only analyses and independent numerical review preceded observed
proof/test execution. The five public fixture proofs and all 33 tests passed;
first failed compile attempts remain recorded. See the linked validation report
for exact source/binary hashes, commands and sampling limitations. Previous
validation reports are untouched and do not stand in for these new gates.
The optional `security poly1305-raw empty` and `security poly1305-padded empty`
commands expose the two active-count-zero shapes without creating a trace. JSON
reports explicitly label `statement_case` as `fixture` or `empty`; `prove ... empty`
and empty cases for other primitives reject before statement/trace creation.

Primary sources: [RFC 8439 section 2.5.1](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5.1),
[RustCrypto Poly1305 0.8.0](https://github.com/RustCrypto/universal-hashes/tree/47a72962e8898fc70ab79d4ab40949efe61a23d2/poly1305),
its `src/backend/soft.rs` and `src/lib.rs::compute_unpadded`, and pinned
UniversalHash 0.5.1 `src/lib.rs::update_padded`. No private source-completeness
relation is implemented by this public primitive gate.
