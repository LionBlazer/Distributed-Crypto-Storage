# Private Control-kind link

This new fixed hiding relation proves that the opcode inside the **existing**
Cmd160 commitment is one of Begin0, FailCurrent2, Savepoint3, RollbackTo4, Release5
or End6. Acquire1 cannot satisfy membership. The exact member remains private;
Bootstrap is a separate existing relation and is rejected by this constructor.
The full owning library suite passed; the executed validation below records
its actual fixed-AIR assessment and scope.

## Boundary and public API

| Dependency/owner | Responsibility |
| --- | --- |
| [Lifecycle](../lifecycle/README.md) | Original Cmd160 ABI, seven-op semantics, Result144 and actual private state transition |
| [Source](../source/README.md) | Original canonical data/index opening and full691 public statement |
| [bounded wire](../wire/mod.rs) | Actual Source-first then Lifecycle proof verification, dropping Source before child allocation |
| [hiding backend](../../../bfv-hiding-stark/README.md) | Existing fixed Gold/Poseidon2 AIR gadgets, actual hiding proof/assessment and bounded codec |

`Expected::new(&LifecycleStatement)` retains immutable canonical Source and the
complete Transition statement. Checked metadata is not proof evidence. Public
PV815 contains the new profile8, full original Source691 and all Lifecycle116,
including old/Ccmd/next/result. Full original heads and packets also enter the
length-delimited SHA512 frame identity. No public opcode, selector, name, actor,
controller, salt or new plaintext DATA field is introduced.

`circuit::Opening::new([u64;160])` consumes caller-owned original command fields,
rejecting noncanonical Gold words. The caller can use the existing
`lifecycle::circuit::commitment::command_fields_opening`; there is no new command
format or policy compiler. `Witness::new` matches the original public prefix,
zero last field, non-Acquire member and actual Ccmd. Opening and witness retain
guarded private buffers without Clone/Debug/serialization or opening getters.
This association check is not acceptance of the prerequisite proofs.

`Prerequisites { lifecycle }` borrows the original complete DCSLFPW1 Transition
pair, including its actual Source proof. Both typed `prove` and `verify` genuinely
verify that Source-first pair and match **all** Lifecycle fields and output roots
before constructing a Link backend/trace or decoding its proof. A cached receipt,
typed Expected, wire header, serialized proof object or peer signature is never a
substitute. `VerifiedLink` exposes mathematical expectations only, with no Journal,
finality, SQL or row-lock grant.

## Exact relation and resource scope

The new AIR reuses `lifecycle::opening::command_prefix` unchanged for fields0..108.
Six private Boolean selectors sum to one, and field109 is their weighted existing
opcode. Fields110..158 are private canonical field elements; field159 is zero.
The original genuine Lifecycle proof already proves the suffix's complete field
shape, u64 counters, actor/controller, savepoint/Begin-parent/End policy and result.
The Link does not duplicate that state machine. Binding the two private openings
uses the existing salted Ccmd commitment and its collision-resistance assumption.

One original20-block Poseidon2 overwrite8/capacity4 stream opens that Ccmd.
Checkpoint starts at zero, root is checked at row19, and the entire private bank
and carry persist through row511. The layout is width315/height512 with declared
maximum degree5. Native assessment measured actual degree3 and 128 unique/list
decoding bits for this individual relation; it is not composed protocol security.
All six operations use the same public topology, hiding proof configuration and
new immutable profile. Existing AIRs, profiles, opcode ABI, caps and seven-op
semantics are unchanged.

The detached `DCSPCL01` frame has a fixed120-byte header, maximum16MiB proof,
16,384 per-sequence and16Mi total decoded-element limits, exact identity/length,
canonical topology and EOF checks. Header/serialization alone verify nothing.
No SignedBody cap, original wire allowlist or Journal admission is extended.
Source/Lifecycle/Link aggregate size, full-operation resources and any composed
security statement require actual measurement/analysis; the old individual proof
assessments are not silently upgraded.

## Owning tests

Conditional mathematical tests check every original field and high u64 limbs,
coherent hash padding, selector Booleanity/sum, immutable last-row bank/carry,
complete context, frame bounds and prerequisites before child work. The genuine
producer test supplies an actual canonical Source proof, all six real controls,
failed EndAbort outcome3, and a valid successful Acquire prerequisite. Fractional
selectors or a rehashed forced Acquire field reach the actual AIR and reject.
Foreign controls and a genuinely different own-verified Source/Lifecycle/Link
reject under the honest full expectation even with repaired outer headers.
Malformed payloads also reach the bounded decoder after genuine parents. Tests
use explicit public nonsecret fixtures and no accepting verifier callback.
Two owning compile-fail examples protect private opening ownership and fields.
The Core producer scenarios use mathematical G/parent labels, not a signed,
admitted or finalized Journal history.

## Executed validation

Windows/MSVC Rust 1.99.0, release/offline/locked, native CPU, Cargo/Rayon threads 2:

```text
cargo test --release --offline --locked -p registry200-proof -- --test-threads=1 --nocapture
cargo check --release --offline --locked -p registry200-proof --all-targets
cargo clippy --release --offline --locked -p registry200-proof --all-targets -- -D warnings
cargo check --release --offline --locked
cargo fmt --all -- --check
```

All 21 library runtime cases and four ownership compile-fail examples passed,
including the four new runtime cases and two new ownership examples. This also
repeats the existing Source-first Lifecycle producers, coefficient framing,
Predicate/Acquire linkage and original-profile geometry checks. The genuine
control scenario produces actual Source/Lifecycle prerequisites for all six
operations, failed EndAbort and a successful Acquire, then exercises real Link
verification and cross-source/context substitutions. The other three new cases
are explicitly conditional AIR, ABI or missing-prerequisite tests. None uses a
fake accepting verifier, signed-body simulation or SQL grant.

The logged `control_kind::analyze` report for the high-u64-limb fixture is:

| Field | Actual value |
| --- | ---: |
| Width / height / public values | 315 / 512 / 815 |
| Constraints / actual degree | 1153 / 3 |
| Quotient chunks / batched functions | 16 / 810 |
| Unique / list decoding bits | 128 / 128 |

The unchanged backend requires the target on every actual expected statement.
This report does not establish joint Source/Lifecycle/Link security, whole-query
security or confidentiality of an entire distributed SQL protocol.

The complete command took 161.473 s including 55.70 s compilation; unit runtime
was 104.76 s and ownership examples 0.30 s. The nominal 100 ms observer recorded
1036 samples, maximum gap 992.455 ms. Sampled/OS peak working set was
1,041,182,720 B; maximum private bytes were 1,057,943,552 B. No sampled 1792-MiB
per-PID fuse or 1800-second runner abort occurred. These are owning-library
observations, not SQL latency, full FHE-operation resources or a formal RAM bound.

The 1478-file raw source snapshot `.local/control-kind-native-r1/source.json`
has SHA256 `AD8ECE4A9B919FCAAAE0367545A8DE50CF0BADA94CBB3F7C7DB46B138B6B7F0F`.
All files and exact public inventory matched after the native test and before
these documentation updates. Test stdout/stderr SHA256:
`1B87C4270F8BA3826B8EC3DD2438D17EDDA0D4C53F74453193ABE657C445B78D` /
`2883ADD6C6D1A614E01D4121FE90937FDDDD2396FF8D08444306C0E0A72449D4`.
The source-only donor11 aggregate was
`B9BBDE7ED657C4926A63678669D0695C35C4DB34D942D242872048C11A2F71D7`;
Root formatted it and added only the public assessment log before freezing.
No dependency or existing operation, profile, allowlist or cap changed. Existing
experimental CLI report sources were byte-identical throughout; those report
commands were not rerun in this stage.

## Remaining application work

This relation is a prerequisite for a **new** closed composite Control lane. It
does not implement that application, authenticated request/owner admission,
independent finalized-head selection, hidden predicate/FHE completeness, durable
evidence custody, work-roster activation or live PostgreSQL. None of those
permissions follows from constructing or verifying this mathematical Link.
