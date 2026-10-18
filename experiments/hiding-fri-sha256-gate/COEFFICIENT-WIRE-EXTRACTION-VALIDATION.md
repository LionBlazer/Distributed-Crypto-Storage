# Source-first coefficient verifier extraction

## Scope

At parent `f4ad88acd8d4f3afb01cfc93eff1727d2b6853fc`, the coefficient
Source/Encoding byte verifier was private to this executable. It now belongs to
[registry200-proof::coefficient_encoding::wire](../../crates/registry200-proof/src/coefficient_encoding/wire/mod.rs).
The executable's local `frame.rs` is removed; its CLI, adversarial tests and actual
two-operand input16 integration use the library directly. No dependency or lockfile
change is required. Compiler, witnesses, trace writers, fixture generation and
proving remain experiment-owned.

The private fixed backend gains one finite Encoding AIR variant. It constructs the
actual statement's AIR, security parameters, assessment and canonical topology
using the original hiding engine. Source verification completes in an inner scope;
its decoded proof and backend are dropped before child backend construction and
bounded decoding. Failure returns no partial result. VerifiedEncoding retains
only the complete public Statement including C_w. There is no caller-selected
configuration, verification key, report, factory or prerequisite bypass.

The producer Source encoder now reaudits mutable low-level Source claims before
AIR construction. Serialization helpers check canonical topology and caps; they
do not verify cryptographic proofs. BorrowedFrame is a byte grammar view only.

## Preserved contract

DCSCEP01 retains its exact 184-byte header, distinct role/source profiles, all
eight context words, canonical C_mask/C_w, reserved bytes and exact lengths. Pair,
Source and child ceilings stay 32 MiB, 20 MiB and 12,578,091 bytes. Sequence cap is
16,384; Source/child total decoded-container budgets stay 24 Mi/16 Mi elements.
Element budgets are not byte or process-memory bounds. The existing engine and
individual 128-bit assessments are unchanged; no composed 128-bit claim follows.

Actual Key proof remains separate. Both encoding expectations retain the full
setup identity, q32, original Source691 including complete heads/packets and all
Key33, including transformed secret commitment. Formation receives the complete
verified encoding Statement/C_w, actual Key and five actual Basis prerequisites
per operand. These mathematical inputs do not establish evaluation-key same-secret
proof, complete output MulRelin, distributed freshness or SQL admission.

## Validation

Native execution passed on 2026-10-18 against Source2
`8D9FA11C18B6B25902FE7925E96AA0010B3C5584130F33A1D37A8E06B6DF7C33`.

| Gate | Executed result |
| --- | --- |
| Library owning tests | 8 passed, including all 5 existing and 3 new cases |
| Coefficient/input16 consumer | All 12 selected cases passed: 9 original, actual input16 and 2 new cases |
| Original lifecycle-wire consumer | All 8 selected cases passed |
| Strict Clippy | Library and executable, all targets, `-D warnings`: passed |
| Formatting and default core check | Passed |
| CLI security and genuine prove modes | Passed, both roles independently decoded and verified |
| Library doctest command | Passed; 0 executable cases |

There were 28 distinct runtime test cases, with no ignored or skipped cases in
these selected groups. Other executable tests were filtered; this is not an
all-repository test result. The shared backend's real Source, Bootstrap and
Transition consumers passed, including actual signed-Body transport for both
2716-byte and 4096-byte request envelopes.

The unchanged nine original coefficient cases retain actual all8192 SDK polynomial
and Formation-root parity, empty/full/noncontiguous masks, compiler rejection,
coherently rebuilt false source/mask traces, all independent public context,
genuine foreign statements and fresh C_w controls. New cases compare both genuine
pairs byte-for-byte with the original header ABI and reject malformed mutable
Source claims before AIR construction. The nested-proof case additionally damages
a canonical genuine Source commitment: both a valid child and a child length-bomb
must return Source cryptographic Verification. The same bomb with valid Source
must instead return ResourceLimit. The original malformed-cap rejection remains.

The actual input16 integration constructs one Key, one Source, two Encoding, ten
Basis and two Formation proofs for the exact Prepared ciphertexts. It performs
actual FHE on those bytes as a separate unverified-output test oracle, drops
Owner/private state, then independently verifies all public prerequisites and
rebuilds Formation expectations. Wrong roles and substituted complete encoding
statements must fail. No output computation proof is verified here; decryption is
only an oracle.

Three new core tests own borrowed header grammar, strict framing rejection and full
transformed-key/setup binding. The original four frontend tests, existing all8192
Formation digest test and all eight original lifecycle-wire tests retain coverage
of the shared backend and commitment ABI.

The security CLI returned degree4, 16 quotient chunks and individual unique/list
decoding floors128 for Source width11521, source-encoding width2000 and
mask-encoding width1288. Public-value sizes remain 691/752/772.

| Observation | Measured value |
| --- | --- |
| Standalone source/mask pair bytes | 23,218,758 / 22,067,334 |
| CLI generation through explicit private/public drop | 14,821.87 ms |
| New pair decode, verification and mathematical opening check | 1,256.93 / 994.73 ms |
| Actual input16 through fresh public verification | 139,175.70 ms |
| Input16 fresh public-verifier segment | 35,833.54 ms |
| Input16 public spool, including duplicate Source | 264,168,671 bytes |
| Maximum sampled working set across selected runtime gates | 1,287,036,928 bytes |
| Maximum sampled private bytes across selected runtime gates | 1,304,150,016 bytes |
| Maximum observed sampling gap | 473.03 ms |

The pair and input16 numbers come from separate runs with separately generated
public fixtures. These measurements do not establish a controlled speedup over
the prior verifier, an aggregate transport fit or full SQL performance.

Local immutable receipts are `coefficient-wire-validation-r2/{contracts,compile,
tests,prove,docs}/success.json`. Their hashes respectively are
`C15CDD580105E680A0B449D6B71C33BE3CAC26F82DEC9B1CDDEC2D31A775D555`,
`4A9A5AE483FABFA06796DD54450F019A9F40648E0BA2B3B4E477FF065E258539`,
`88DD9A6EC04294FF0C8D4D810875D1CD0E91A2E902AB620BCC308450F4D41577`,
`B3B6755C117BF69FCA767DB8597236747F92293FFAB64557BB29557E74A9C699`,
`BA1C39B3F4BB7A7D9A86EE032667310F8508CAFEBB24B3C63319FFABF8D02AF7`.
The final native review is
`28160899DB4D94FE2B536892B4F8D3E4FC7030F9679B8DAF42147AB698C46534`.
It rechecks source/PE/log/CSV hashes, all 6,530 original cache files, preserved
original test names/bytes and requirements synchronization.

Preparation inherited an empty SDK-anchor map from the arithmetic baseline.
A separate audit, performed after initial native preparation and repeated at
closure, compares 1,027 SDK source/archive anchors and 5 tools with earlier
immutable input/arithmetic receipts. Its hash is
`CB90D58F42C96E6851D088A7D8609F27C2DF1504BBE967709929C9E70DEEAFAA`.
The original runner
`9505DD6E4D9EA317EFF1C6C45BF86FAA4D3837E5C45D2DF41A9535048C8CFC38`
was reused unchanged. A source-review correction before the first native run
retained the original malformed-cap rejection and added canonical commitment
damage to test actual Source cryptographic failure before child decoding.

Reproduction uses Rust 1.99.0 MSVC, release, locked dependencies, CPU native code,
two Cargo jobs and two Rayon workers. Run:

```text
cargo clippy --release --locked -p registry200-proof --all-targets -- -D warnings
cargo clippy --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --all-targets -- -D warnings
cargo check --release --locked
cargo test --release --locked -p registry200-proof --lib -- --test-threads=1
cargo test --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::coefficient_encoding:: -- --test-threads=1 --nocapture
cargo test --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::registry_lifecycle::wire::tests:: -- --test-threads=1
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- security private-coefficient-encoding
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove private-coefficient-encoding
cargo test --release --locked -p registry200-proof --doc
```

Root runs native tools in an independent copy2 target. Original SDK sources,
previous targets, helpers and receipts remain unchanged. The observer samples
owned processes nominally every 100 ms with a 1792 MiB per-PID soft fuse and
1200-second command bound. These are observational controls, not a whole-peer
resource guarantee or a fixed query-latency target.

Full PostgreSQL, hidden-WHERE execution/completeness, distributed locking,
`FOR UPDATE`, `SKIP LOCKED`, agreed heads and production SQL grants remain incomplete.
The 61 historical SQL success cases remain unchanged and known not green; this
extraction does not claim to cover or repair them.
