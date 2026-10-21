# Hiding internal LogUp wire experiment

This standalone experiment tests one real private arithmetic flow through native
`p3-batch-stark` 0.8.0 LogUp. It has its own Cargo workspace and does not change the
repository workspace, any DCS profile, source relation, FHE evaluator or SQL path.
The release tests and explicit public fixture have run with the actual native
prover and verifier. The fixture's complete local round trip took 72.6042ms in
one observed run; see [validation](VALIDATION.md) for scope and reproduction.
This small arithmetic primitive does not establish SQL latency, freshness or
complete-protocol security.

The fixed program proves `a = x*x + 3`, then `b = a + z`, then a public `b`, with
private `x` in 0..255 and `z` in 0..65535. Separate rows send/receive real
`(node_id,value)` tuples over one fixed native global bus. There is exactly one
AIR and one terminal, so another AIR cannot cancel its imbalance. The source
contains no fake lookup completion or serialized checked flag. The public output
is deliberately informative; this is not a confidential database query.

## Ownership and dependencies

`main.rs` owns the closed Expected/Witness/prove/verify functions and explicit
non-secret CLI fixture. `air.rs` owns the immutable row plan and zeroes its local
MAIN buffer on drop. `setup.rs` owns the sealed public preprocessing constructor.
`assessment.rs` derives the complete native symbolic/security shape. `wire.rs`
owns canonical bounded decoding and the exact native five-round topology.
`tests.rs` exercises these concrete paths; it supplies no verifier callback.

The direct project dependencies are
[bfv-hiding-stark](../../crates/bfv-hiding-stark/README.md), for the unchanged
Gold/EF5 hiding PCS types, constants and fresh-OS private config, and
[bounded-postcard](../../crates/bounded-postcard/README.md), for allocation budgets
on hostile sequences. The other direct dependencies are the pinned native Plonky3
0.8.0 family, Postcard, SHA2, Rand and Zeroize. No code is vendored or patched.

## Exact fixed shape and setup boundary

The original trace is 512 rows by 19 columns; hiding extends its domain to log10.
Three public PP columns select rows 0,1,2. Row0 holds x and a; row1 holds z,
received a and b; row2 holds received b. Sixteen Boolean bits range-constrain the
scalar; row0 high eight bits are zero. All unused cells and inactive bits are zero.
There is no MAIN.next or PP.next access. Native AUX still opens at both rotations.
The 17 public values are eight profile words, eight context words and the output.
Each is actually constrained, rather than only supplied to the transcript.

The deterministic PUBLIC-only helper seeds three streams from a separate domain,
full profile, Expected context, Expected output and stream label. It builds only
the fixed public PP using native `ProverData::from_airs_and_degrees` with default
automatic packing, then explicitly drops the seeded config. Only public PP data
escapes; a seeded config/PCS/RNG is never returned. Both independent prover and
verifier derive this setup from their retained Expected. Every private MAIN, AUX,
quotient, random commitment and joint opening uses a separately obtained genuine
`bfv_hiding_stark::config()` with fresh OS randomness. Verifier drops its rebuilt
PP prover buffers before native verification. There is no cross-call mask reuse.

The unchanged suite uses Goldilocks/EF5, log blowup3, 192 queries, salt4, five
random codewords and zero grinding. The public setup seed is not private entropy.
Public PP reproducibility is a scoped construction, not trusted remote setup or
an application acceptance receipt. General statistical ZK or a production proof
profile needs a separate security review even if the SDK assessment passes.

## Canonical frame and resource limits

The 96-byte header is magic8, profile32, context32, outputLE32, payload lengthLE32
and 16 zero reserved bytes. The native BatchProof payload is capped at 4MiB.
Decode permits at most4096 elements per sequence and1048576 total container slots,
requires EOF, exact shape and identical canonical reencoding before SDK verify.
The profile includes the immutable AIR/row plan/bus, native packing recipe,
public-only seed domain, suite and all frame/decoder limits. There is one instance at log10,
one nonempty actual lookup set, a sole zero terminal and exact hiding presence.
All original native roles remain: random, MAIN, quotient, public PP and AUX.

Only the PP round has zero random openings. Every private round has five, and
AUX has both local and next openings. Exact query/round/matrix/column counts and
bounded Merkle frontiers are checked before native PCS verification. The native
verifier still checks the original transcript, commitments, openings, ordinary
AIR, lookup equations and final terminal sum. Shape checks do not replace these.
The decoder budget accounts for nested field arrays and the complete native
proof, rather than equating a field element with one container slot. Pruned
frontiers have independently derived depth-specific caps. The complete analytical
bound and its limitations are in [decoder accounting](DECODER-BOUND.md).
The SDK security and logical allocation report is distinct from the external
whole-PID observation in [validation](VALIDATION.md).

The private assessor compares native automatic packing against a rederived plan,
including the original four width-two tuples, magnitude-one bounds and symbolic
expressions. It checks actual base AND extension constraints, degree/chunks and
flattened AUX openings at both points. The LogUp error extra charges original
tuples over the larger committed height conservatively; it is not silently
omitted by a uni-only report. The actual SDK UDR and LDR terms and the independent
baseline must both reach 128 before private MAIN allocation or native proving.
The unchanged suite's declared commitment-collision cap is 128; this conditional
individual assessment is not a composed security theorem. A checked-arithmetic
logical allocation prescreen includes codewords, salts, quotient banks, trees and
FRI workspace, with overlap reserve, and rejects above 1792MiB. External whole-PID
observation is still required. The assessor emits only public numeric metadata.

## Owning gates

Root alone resolves the standalone lock and runs the commands from the repository
root after source review:

```sh
cargo test --release --locked --manifest-path experiments/hiding-logup-wire/Cargo.toml
cargo run --release --locked --manifest-path experiments/hiding-logup-wire/Cargo.toml -- --public-fixture
```

Without arguments, or with `--show-profile`, the executable prints public profile
metadata and performs no proving. Only `--public-fixture` runs the public example;
other arguments are rejected.

One genuine proof is reused for independent PP reconstruction, wrong retained or
repaired context/output, wrong PP cap, damaged AUX/MAIN, terminal/instance/degree
and random-presence changes, trailing/corrupt bytes, a noncanonical Gold word,
oversized and cumulatively oversized sequences, excess Merkle frontier nodes and
a fresh verification after failure. Metadata negatives use the same actual
CommonData. A separate real
release proving attempt receives `a+1` at row1 and uses `z-1`, retaining the SAME
public output and all business equations. Actual native verification must reject
with `Lookup(TerminalSumNonZero)` after PCS and ordinary AIR verification; no
unbalanced private terminal is serialized or exported. SDK debug builds reject
this intentionally false bus earlier via their actual debug replay. A third
cheap gate checks bounded Expected/input/header rejection before SDK setup.

The CLI emits only public output, byte counts, durations and explicit false
FHE/SQL/freshness flags. It never prints the private x/z, MAIN/AUX buffers or RNG.
It is not Formation, a whole N4096 graph, a query proof, a current-head check,
distributed finality or a measurement against the complete-query 500ms target.
