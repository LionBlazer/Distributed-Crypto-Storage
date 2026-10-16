# Hiding-FRI source-opening research gates

Historical validated source: the [whole-pair private AEAD byte-opening
candidate](src/opening/README.md) passed release build, strict Clippy, eight fresh
security analyses, all 47 serial tests and one genuine whole-pair proof/verification.
Its [validation record](PAIR-OPENING-VALIDATION.md) retains every earlier failure,
exact scope and observation limits. One composed witness opens both fixed public
packets; it does not add an Owner-key API, logical SQL proof or live accepting path.
The shared primitive wrappers are included in that exact 47-test run.

Current canonical N4 relation: canonical-index-opening passed release build,
strict Clippy, nine actual numerical analyses, one genuine proof/verification and
all60 serial tests. It constrains the real fixed index, every count/offset,
canonical postings/padding and nonzero/distinct private identities inside the SAME
AEAD opening. Its distinct semantic Kind/profile and
[core codec vector](../../crates/compact-query/tests/fixtures/README.md) are recorded in
[CANONICAL-INDEX-VALIDATION.md](CANONICAL-INDEX-VALIDATION.md) and the
[module contract](src/opening/README.md#canonical-n4-index-relation).
No typed SQL, identity-history or live acceptance claim follows.

Historical public-primitive status: the Poly1305 raw and separately padded-segment modes passed their
isolated lock audit, release build, strict Clippy, seven actual security analyses,
five observed genuine public-fixture proof/verify processes and all 33 serial
tests. Their small-fixture policy is at most three blocks, 48 original bytes and
three segment descriptors. Exact source/artifact identities, retained failed
compiles and observation limits are in
[POLY1305-VALIDATION.md](POLY1305-VALIDATION.md). See the private
[Poly1305 module contract](src/poly1305/README.md).

The preceding revision `128a7f1` validated fixed public SHA-256, full HChaCha20 and
normal ChaCha20 fixtures: release build, strict Clippy, both 128-bit SDK reports,
three observed genuine proof/verify processes and nineteen serial tests passed.
Its exact source, lock, artifacts, failure and observations remain unchanged in
[PRIMITIVES-VALIDATION.md](PRIMITIVES-VALIDATION.md). Those results do not validate
the new source or its manifest. The historical directory name remains; the
package/CLI uses one private shared backend with explicit typed primitive modes.
There is no compatibility binary or production consumer.

The earlier SHA-only revision was experimentally validated. Its unchanged
[VALIDATION.md](VALIDATION.md) records that exact old source, lock, binary and
process observation; its measurements/security reports are **not** results for
this refactored backend or its new AIRs.

These are nonaccepting experiments. All exercised fixture keys/plaintexts are
explicitly PUBLIC NONSECRET; the new candidate puts those known values in private
witness columns rather than public inputs. The bounded byte-opening is exercised
under experimental assumptions; it does not certify witness secrecy/ZK, production
AEAD/key custody, general/cross-version index validity, BFV formation, SQL completeness, live locks
or finality. No owner key export/import,
network API, proof-byte codec, acceptance marker or root Cargo change is added.

## Ownership and dependencies

| Private module | Responsibility |
| --- | --- |
| `main.rs` | Local command and explicit primitive selection |
| `primitive.rs` | Typed primitive AIR dispatch and local statement contract |
| `backend.rs` | Shared OS RNGs, hiding PCS/MMCS, profiles, security reports, array accounting, proving/verification |
| `air.rs`, `statement.rs` | Published P3 SHA compression wrapper and public fixture binding |
| `chacha/air.rs` | Bit/carry constraints, complete schedule, transitions and boundaries |
| `chacha/statement.rs` | Public fixtures, little-endian identity, independent RustCrypto oracle |
| `opening/` | Shared fixed private whole-pair opening, validated byte relation and bounded canonical N4 index relation |
| `poly1305/` | Checked small-message layout, canonical radix AIR, public oracle and validated adversarial tests |

The standalone workspace depends on pinned P3 0.8.0, Rand 0.10.3 and RustCrypto
SHA-256 0.10.9, ChaCha20 0.9.1, Poly1305 0.8.0 and UniversalHash 0.5.1.
P3's VCS pin is `a21e3ed42905040ad49c519e402f018381c12d0c`; ChaCha20's is
`b5d39c45c45df97335f4b6effb853cde97810de1`. The current manifest also uses local
compact-store for its complete canonical checker, XChaCha20Poly1305 0.10.1 for the
known fixture oracle and native P3 Poseidon2 helpers. There is no reverse library
edge. Fixture buffers/SDK matrices do not gain a production key-custody contract.

The isolated lock has 82 packages: 75 prior registry records remain exact; five
pinned registry records and local compact-store were added by an audited offline
resolution. Its only changed old active edge is crypto-common to rand_core 0.6.4;
all 19 P3 records remain pinned. Earlier 76-package/33-test lock and validation
records below retain their own historical meaning. No root dependency changed.

Related contracts: [private source proofs](../../docs/private-lock-source-proof.md),
[production arithmetic](../../crates/bfv-query-proof/README.md), and
[the full source-relation contract](SOURCE-RELATION.md).

## Exact ChaCha relation

Both ChaCha modes use exactly 512 rows and 788 boolean witness columns:
16 state words x 32 bits, four 32-bit addition results, four 32-bit XOR results,
four addition carries, and sixteen final-feedforward carries. Eight public
periodic columns encode a fixed 512-row schedule: one selector is 1 in each of
rows 0..79, with four column then four diagonal quarter-rounds repeated ten times;
all selectors are 0 in rows 80..511. They contain only fixed scheduler values,
never keys, state words, rows or other witnesses.

Every row constrains all witness cells to bits. Active quarter-round inputs come
from the current state; each addition satisfies `a+b=sum+2^32*carry`; XOR satisfies
`x+y-2*x*y`; rotations are fixed bit permutations by 16, 12, 8, 7. Integer sides
of addition are below `2^33`, strictly below Goldilocks, preventing field wrap.
Inactive rows select zero inputs and have zero intermediate/carry data.

Each nonfinal transition carries every state bit unchanged except the four words
selected by that row's schedule, which become the quarter-round's final `a,b,c,d`.
Exactly 80 quarter-rounds are linked; remaining rows preserve the final state.
The first row packs all sixteen initial words into public inputs. The first four
public words are independently constrained to the standard ChaCha constants.

On the final row, HChaCha binds state words 0..3 and 12..15 to eight public output
words, constrains other output slots and all feedforward carries to zero, and
performs **no feedforward**. Normal ChaCha binds each final state word **plus the
same original public input word** to its public output plus `2^32*carry`; earlier
feedforward carries are zero. Public inputs/outputs are bounded `u32` words. Both
variants have 1,492 constraints and degree three, confirmed by SDK inference;
both decoding reports reached 128 under the stated experimental model.

Statement identity covers all input/output words, request identity and complete
fixed primitive profile. Its digest is actual public values constrained by the
AIR, not an outer label. The profile includes the variant, geometry, constants,
rotation/index tables, complete public schedule and backend parameters. The
verifier derives the same AIR/periodic values; no supplied preprocessing key is
trusted. The trace generator computes all rounds and ignores claimed output.

Independent oracles use pinned RustCrypto `hchacha::<U10>` and `ChaCha20`, plus literal
[draft-03 section 2.2.1](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#section-2.2.1)
and [RFC 8439 section 2.3.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3.2)
vectors. XChaCha draft-03 is an expired draft, not an IETF standard.

## Fixed backend and resource gates

The private backend retains Goldilocks/degree-five extension (319-bit floor),
Poseidon2 width 12/rate 8/four-element digest with an experimental 128-bit collision
model, cap zero and four-element salts. BOTH main and FRI MMCS are hiding. Main
salts, FRI salts and masks use independently OS-seeded `StdRng`; SDK clones fork
fresh seeds and cloned prover data shares the single-opening guard. No fixed seed,
testing preset, grinding or auxiliary witness commitments are introduced. FRI uses
blowup 8, 192 queries, five random codewords, binary folding, terminal log degree zero.

SHA retains one opening point/no periodic columns. ChaCha reads only the 512 state
columns in the next row, but SDK 0.8 opens the **entire 788-column next row**. The
calculator must use `max_combo=2` and both full-width openings. Hiding requires
`512 >= 2*(192+5*2)=404`, with five random codewords. No preprocessing is used.
Analysis starts with the original 512-row domain and reports post-ZK degree bits
10, including actual constraints/quotient/masking/opening counts. Each private
Backend is bound to one complete typed public statement (691 fields for the
fixed pair; at most 97 in the public primitive modes), so cached analysis cannot cross empty/nonempty shapes.
Prove and verify compare those exact values before trace/verification work and
reuse the compared vector in the SDK call. A different statement uses a fresh
Backend. Negative replay tests also use that fresh path, preserving actual SDK
rejection coverage rather than relying only on the wrapper's early guard. BOTH decoding
reports must reach 128 before the normal Backend/CLI path allocates the full trace
or proof. Direct public-fixture tests may construct a trace first; their actual
execution followed numerical review. Verification checks shape and repeats the gate.

ChaCha's counted arrays are 3,227,648 bytes original, 6,496,256 bytes masked and
51,970,048 bytes main LDE (49.5625 MiB). The separate public schedule table is
32,768 bytes. SHA's arrays remain 31,653,888 / 63,348,736 / 506,789,888 bytes.
These are separate payload sizes, not additive peak RSS or resource compliance.
Quotient work, copies, DFT scratch, trees, salts, proof, stacks and allocator
overhead remain outside them. Masking does not guarantee zeroization.

Pinned [security adapter](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/uni-stark/src/security.rs),
[hiding PCS](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/fri/src/hiding_pcs.rs),
[hiding MMCS](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/merkle-tree/src/hiding_mmcs.rs),
[RustCrypto HChaCha](https://github.com/RustCrypto/stream-ciphers/blob/b5d39c45c45df97335f4b6effb853cde97810de1/chacha20/src/xchacha.rs)
and [ChaCha backend](https://github.com/RustCrypto/stream-ciphers/blob/b5d39c45c45df97335f4b6effb853cde97810de1/chacha20/src/backends/soft.rs)
are review inputs. Calculator/hash/random-oracle assumptions are not production
security certification or proof of private-data composition.

## Previous SHA/ChaCha validation and reproduction

The previous revision's actual sequence separated reviewed offline lock generation, release build,
strict Clippy/test `--no-run`, security-only CLI modes, and observed proof/test
processes. Exact commands, native environment and immutable identities are in
[PRIMITIVES-VALIDATION.md](PRIMITIVES-VALIDATION.md). Its historical compile/security commands were:

```powershell
cargo build --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
cargo test --release --locked --offline --no-run --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
cargo clippy --release --locked --offline --all-targets --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- -D warnings
& $binary security hchacha20
& $binary security chacha20
& $binary security sha256
```

`$binary` is the built `hiding-fri-source-primitives.exe` in the recorded isolated
target. The three observed public proofs and nineteen serial tests passed. HChaCha
and ChaCha each have only one memory sample: these observations do not establish
lifetime peaks, a hard RAM bound, clean latency, private witness secrecy, AEAD or
500-ms SQL. Earlier SHA observations belong only to historical VALIDATION.md.

Tests include literal vectors, zero/all-one/boundary-word oracles, genuine
proofs with an independent verifier, public input/output/mode/request binding,
missing next-row/randomization rejection; rebuilt malicious wrong-output, XOR,
actual overflow-carry and nonboolean traces; a skipped last quarter-round with a
matching false output/carry claim; incorrect HChaCha/ChaCha feedforward; and a valid
alternate entire trace under the original input. Existing SHA and shared RNG,
masking-budget and single-opening tests remain. Rebuilt tests use the raw SDK
prover rather than only replay or generator rejection.

## Poly1305 public primitive gate

The CLI selectors `poly1305-raw` and `poly1305-padded` use the same private backend,
randomness, hiding and verification gates, with a distinct primitive profile and
typed statement. There is no separate Poly1305 prover, proof codec or production
acceptance. These two public modes do not themselves accept an AEAD opening. Actual reports show 1,361 constraints, eight
quotient chunks and 1,726 batched functions: inferred degree is three for nonempty
fixtures and two for empty shapes, with a declared bound of three. Both decoding
bounds reached 128 under the pinned SDK/model. The [module README](src/poly1305/README.md)
specifies arithmetic/layout; [POLY1305-VALIDATION.md](POLY1305-VALIDATION.md) records
the genuine proofs, 33 tests, exact provenance and sparse external observations.
These results establish no private-source, production security, latency or RAM
guarantee. Historical validation reports and SOURCE-RELATION.md stay unchanged.
