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

Validated combined candidates: `packed-canonical-index-opening` adds the distinct
W7161/82-row-group source profile; `selection-opening` proves bounded complete
private selection using the OLD canonical source proof. Release build, strict
Clippy, eleven numerical analyses, two observed CLI proofs and all85 serial tests
passed. The [combined validation record](SELECTION-PACKED-VALIDATION.md) preserves
failures, exact timer/resource scope and unmet guarantees. See the packed
[module contract](src/opening/README.md#packed-canonical-source-candidate).
No composed128-bit, SQL, RAM or causal speedup claim follows.

The subsequent [owned-AIR validation](OWNED-AIR-VALIDATION.md) covers reuse of the
analyzed public AIR and its immutable schedule. All eleven numerical reports
remained exact; both CLI proofs and all 86 serial tests passed. Timer scopes and
remaining SQL/FHE/locking limits are recorded there.

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

The [private bounded Selection module](src/opening/selection/README.md) opens the
same canonical C_open, an independently expected private semantic plan and fixed
original-row/RowId slots. Its validated composite verifies the genuine OLD
canonical source proof first; it does not accept the packed profile or add BFV
formation, SQL acceptance or a cross-request state certificate.

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
Backend. Each Backend retains the exact public AIR it analyzed and uses it for
proving and verification. Opening and Selection AIRs lazily retain their immutable
512-by-512 public schedule in a per-instance `OnceLock` and return borrowed columns.
This removes repeated constructors and schedule generation; SDK symbolic degree,
constraint-layout, periodic interpolation and proof checks still run. The retained
schedule payload is 2,097,152 bytes per initialized AIR, excluding allocation
overhead; this is not a peak-memory or latency claim. No witness, prover data,
random stream or proof-dependent interpolation is cached.
Negative replay tests also use that fresh path, preserving actual SDK
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

## Version-bound certificate validation

The [state-certificate module](src/opening/state/README.md) proves one fixed
version and supports fresh private Selection queries over its genuinely verified
certificate. Release build, strict Clippy, thirteen actual numerical reports,
both CLI gates and all 97 serial tests passed. The
[validation record](VERSION-STATE-VALIDATION.md) separates cold admission and warm
query timings, owned cache accounting and sampled process observations. Its
distinct profiles preserve earlier gates; production acceptance, freshness,
full SQL/FHE linkage, private locks and practical complete-operation latency remain open.

## Selected-encoding validation

The distinct [private selected-encoding module](src/opening/selection/encoding/README.md)
links the existing request-bound Selection composite to all 8192 BFV plaintext
coefficients and their modular scaling. Release build, strict Clippy, fourteen
actual numerical reports, all three upstream matrix gates, the genuine composite
and all 114 serial tests passed. The [validation record](SELECTED-ENCODING-VALIDATION.md)
describes exact provenance, measured composite timings and sampled resources.
Ciphertext formation, peer-only computation, production SQL acceptance and the
practical latency remain open. Earlier reports retain their original scope.

## Factorized periodic-basis source candidate

The [opening module](src/opening/README.md#factorized-public-periodic-source-profile)
adds one distinct packed profile with 48 public periodic columns instead of 512,
while sharing the existing packed evaluator and schedule. All fifteen numerical
reports, six observed genuine proofs and all 121 serial tests passed. The
[validation record](FACTORIZED-PERIODICS-VALIDATION.md) reports lower observed
source memory together with a slower outer interval and verification; it
establishes no speedup. Existing consumers retain their original profiles.

## Single checked setup for simple proof gates

Simple primitive/source CLI prove modes report and use one retained checked
Backend. The fifteen numerical reports remain field-exact; genuine old/new
proof comparisons and all 122 serial tests passed. The
[validation record](SOURCE-GATE-SETUP-VALIDATION.md) gives complete cold-process
intervals and limitations. Security-only and composite lifecycles remain unchanged.

## Validated private locking candidate

The [closed N4/two-transaction locking relation](src/opening/locking/README.md) links complete
private source candidates to exact ownership/conflict/window transitions. It is
nonaccepting; old profiles remain unchanged. Sixteen numerical reports,
three genuine source-plus-locking proofs and all 146 serial tests passed. The
[validation record](PRIVATE-LOCKING-VALIDATION.md) reports seconds-long fixed-fixture
operations. Registry anchoring, lifecycle, FHE formation, writer enforcement, MVCC
and finality remain open.

## Validated version-bound locking candidate

The [VersionLockingSelection module](src/opening/state/locking/README.md) is a new
nonaccepting candidate. A typed lease requires actual cached VERSION
source verification, while fresh independent request/control context binds a
separate lock proof. Shared canonical-lock arithmetic and stable Registry112 are
preserved. Release build, strict Clippy, all seventeen numerical reports, one
genuine cold/two-warm chain and all 158 serial tests passed. The
[validation record](VERSION-LOCKING-VALIDATION.md) gives one fixed observation;
no comparative speedup, composed security or production acceptance is claimed.

## Compiled and numerically gated BFV prerequisites

The distinct [full8192 KeyTransform](src/opening/key_transform/README.md) and
[complete-ciphertext BasisConvolution](src/opening/basis_convolution/README.md) profiles passed release build,
test compilation, strict Clippy and all nineteen numerical CLI gates. Both new
actual AIR reports have degree3 and unique/list bounds128. Three native oracle
filters and both genuine proof commands also passed in single observed runs. The
complete 189 serial behavior suite also passed; see the [validation record](BFV-KEY-BASIS-VALIDATION.md).
These nonaccepting owner-witness candidates add no Owner key export, authorized
BFV/evaluation-key binding, entropy proof, complete formation, live SQL/lock grant,
writer fence or fresh final agreement. Earlier validated profile/report facts
remain unchanged.

## Fixed SQL locking-plan consumer

The canonical and version-bound locking CLI gates now consume the real
[`sql-plan` compiler](../../crates/sql-plan/README.md) through a
[private bounded adapter](src/opening/locking/README.md#sql-compiler-adapter).
This normal experiment dependency does not connect a locking plan to the live peer
executor. The [SQL locking-plan validation](SQL-LOCK-PLANS-VALIDATION.md) records actual
142-package offline resolution, unchanged 19 numerical reports, six focused new
experimental cases, both parsed-query CLI gates and owning parser/script/TLS/GUI
checks. All 195 experiment names were discovered; this was not a full195 rerun.
All previous BFV/AIR profiles remain unchanged, and historical reports retain
their original frozen source and measurements.

## Signed local BFV formation

The [bounded full8192 local relation](src/opening/local_formation/README.md) opens all five Basis roots and the existing SelectedEncoding root with common bounded signed noise and integer-safe equations. The [validation record](BFV-LOCAL-FORMATION-VALIDATION.md) retains the R1 lint failure, actual 20 numerical reports and one observed genuine full-composition CLI.

All 212 serial behavior tests passed: the 195 earlier cases and all 17 Local cases, with no failures or ignored tests. The actual Local degree 3 differs from the unchanged declared hint 5; both model floors reached 128 per proof, without a composed-security theorem. Its owner/client-local witness, key authority, entropy, network freshness and live SQL/lock acceptance remain open. The observed 58.3s process is not an interactive SQL result or general resource/latency guarantee.

## Successful lock-return encoding and formation (validated experimental relation)

The distinct [Return168 bridge](src/opening/locking/encoding/README.md) connects
actual canonical or certified locking evidence to all 8192 original scaled BFV
plaintext coefficients. The distinct [returned formation](src/opening/locking/formation/README.md)
opens that exact new C_enc with the shared full integer kernel and actual same-key,
five-Basis prerequisites. Typed producer/profile bindings keep both new Kinds
separate from old Selection88/SelectedEncoding/LocalFormation.

Release/test compilation, strict Clippy, all 23 trace-free numeric calls, three
owning oracles and three genuine CLI compositions passed. The returned-formation baseline at `c46817d` passed its full 235-case suite;
see the [validation record](LOCK-RETURNED-BFV-VALIDATION.md) for exact
scope, two preserved compile failures, times and sampled resources. This is an
owner-local witness experiment; it adds no peer-only SQL execution, authority,
fresh agreement, writer fence, projected answer or live network/lock acceptance.
Earlier validation reports retain their original scopes.


## Validated experimental certified public projection job

The [certified projection job](src/opening/locking/formation/job/README.md) connects
real returned-formation admission to the existing ciphertext-only BFV product
proof and an independently running TLS `dcs-peer`. A sealed client compiler opening
binds the public projection to the same private `C_plan`.

Release/test compilation, strict Clippy, 23 unchanged numeric reports, six new
owning cases, four existing controls and one independent-process CLI passed.
Discovery lists 241 tests; this stage did not rerun every body. The
[validation record](CERTIFIED-PROJECTION-JOB-VALIDATION.md) records exact scope and
observations. This adds no network SQL acceptance, key authority, fresh agreement
or live lock grant. Upstream source/selection witnesses remain owner-local; the
final public-product worker alone receives ciphertext/public material.

## Private registry initialization candidate

The distinct [RegistryBootstrap](src/opening/registry_bootstrap/README.md) candidate
opens a separately anchored enrollment and the exact stable Registry112, with two
Active IDs, revision2, sequence1 and no held locks. It verifies an actual canonical
source prerequisite before the child. Its actual W1082/PV104/T512 layout,
24 numerical modes, 85 affected tests and genuine source/child composition passed;
see the [validation record](PRIVATE-REGISTRY-BOOTSTRAP-VALIDATION.md).
Owner enrollment authorization, post-genesis registration/freshness, live grants
and peer-only FHE execution remain separate obligations.

## Canonical private proof transport

The [private proof wire](src/opening/proof_wire/README.md) transports both complete
SDK proofs for Source+Bootstrap or cold Source+Locking. Both real emitters and fresh
decoding/verification passed, with no receipt/cache shortcut. The
[validation record](PRIVATE-PROOF-WIRE-VALIDATION.md) separates 263 discovered cases
from 15 executed leaf cases plus shared decoder/contract checks. This adds no
Journal admission, owner/controller authority, agreed freshness or live SQL grant.

## Owner-authorized private-control Journal

The [experimental Journal adapter](src/opening/private_journal/README.md) verifies
complete Source+Bootstrap/Lock proof pairs under owner-signed real parent
transitions. A genuine Bootstrap -> FOR UPDATE -> conflicting SKIP LOCKED lineage,
durable replay, and rejection cases passed. See the
[validation record](PRIVATE-CONTROL-JOURNAL-VALIDATION.md) for the 275 discovered
versus 27 executed leaf cases, Journal checks and observed complete Body sizes.
The adapter supplies experimental lineage; live grants, private transaction
lifecycle, writer fencing, agreed finality and peer-only FHE SQL remain open.
