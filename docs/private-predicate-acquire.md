# Private predicate / Acquire linkage: native validation

This validates a separate mathematical relation, not live SQL admission. It
opens one hidden 256-bit predicate in Cmd48 and Cmd160 and links an exact
successful Acquire Result144, including all four returned/skipped/visited flags.
The implementation belongs to
[registry200-proof](../crates/registry200-proof/src/predicate_acquire/README.md).
The existing lifecycle AIR still proves actual row scanning, conflicts, actor
counters and the window; the link does not replace those checks with native
model execution.

## Executed proof consumer

On 2026-10-19, Windows x86_64/MSVC, Rust 1.99.0, release, locked/offline,
`RUSTFLAGS=-C target-cpu=native`, Cargo jobs2 and Rayon threads2:

```powershell
cargo test --release --offline --locked -p registry200-proof predicate_acquire:: -- --test-threads=1
cargo test --release --offline --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::registry_lifecycle::journal::predicate_acquire_tests:: -- --test-threads=1 --nocapture
```

All three Core tests and all five consumer tests passed. Core tests cover original
public-field order and high u64 limbs, bit255 substitution and nonzero command
padding after repairing commitments, complete context identity, missing
prerequisites and wire caps. Consumer tests construct genuine Source/Query/
Lifecycle/link proofs and owner-signed Bootstrap, Begin1, Begin2, other Acquire,
SKIP Acquire history. They cover real conflict/offset/limit behavior, all skipped,
empty/limit0 success, WAIT/NOWAIT and End abort rejection, independently valid
same-SQL-identity/nonce/q but different hidden masks, and bad Source before child
resource bombs. The complete Source proof and full public contexts are verified
before link decoding; a claim, repaired header or cached Boolean is insufficient.

The full consumer command took 238.687s including compilation; its five tests took
124.97s. The positive case's fixture production and fresh verification took
59,206.789ms, including five signed bodies and all its prerequisite/link proofs.
This excludes network RPC, full input16/output computation proofs and fresh
weighted finality; it is not SQL latency. Fixtures are explicitly public,
nonsecret mathematical examples. They do not claim that the plain SELECT
compiler accepts locking SQL.

The fixed link assessment reports width1005, height512, PV896, degree3,
2664 constraints, 2190 batched functions and 16 quotient chunks. Its analytical
unique- and list-decoding estimates are individually128 bits. This is not a
composed128-bit proof or a whole-protocol security theorem.

## Actual bytes and bounded admission blocker

| Serialized item | Bytes |
| --- | ---: |
| Shared Source proof | 19,302,911 |
| Query child proof | 2,766,735 |
| Lifecycle child proof | 11,580,031 |
| Link proof payload | 2,303,039 |
| Detached link frame | 2,303,159 |
| Query pair, including framing | 22,069,830 |
| Lifecycle pair, including framing | 30,883,094 |
| Sum of both pairs and link frame | 55,256,083 |
| All four unique raw proof payloads, no framing | 35,952,716 |
| Shared Source plus both children and complete link frame | 35,952,836 |

Even the deduplicated raw proof payload exceeds the existing Body cap of 33,554,432
bytes by 2,398,284 bytes, before composite headers. The detached frame's 16MiB proof
cap, old proof caps, Body32MiB and transport limits remain unchanged. There is no
new aggregate Body codec or application allowlist entry. A compliant bounded
dependency transport/store must fetch, verify and durably retain all required
proofs before vote, admission and reopen; references or hashes alone cannot grant
authority. No such integration is asserted here.

## Measurement attribution

The test process's actual Windows OS peak working set was 1,125,011,456 bytes;
maximum sampled private bytes were 1,118,789,632. The observer retained 1447 samples
across Cargo and its test process with maximum sampling gap 538.162ms. The
1792MiB per-process soft fuse and 1800s runner budget did not trigger. These are
observations of this proof consumer, not complete-peer RAM or disk guarantees.

Ignored receipts are under
`.local/private-peer-native-r1/predicate-acquire-full-r1/`. Stdout SHA256 is
`7D2A6D7A8AF4CAF302C8F8CF31337C71A6223114B5F0692A403384D08CA96D56`;
stderr is
`6B40A9BDE0C16C35C493AA814CA8D0928C12A777524E40D0860D434F6B9CD193`.
The frozen 1400-file source manifest SHA256 is
`DBE4A872BE5660A3D01C9EBF5A574BCC0AA84D92F2DC225A6E326498069B5366`;
all 1400 raw hashes matched after the run. Its parent was
`8002559089ec94e15a7ea671d5729ae7c1b930d3`. Afterwards only an unused retained
fixture field and initializer were removed from the consumer; strict Clippy
checks passed for both the Core package and standalone experiment. No AIR or
proof equation changed in that cleanup. Generated receipts and witnesses are
not committed.

The rebuilt actual CLI's `security registry-lifecycle-bootstrap`,
`security registry-lifecycle` and `security private-coefficient-encoding` outputs
matched all seven complete preceding JSON reports exactly, field for field.
The preceding binary was retained before rebuilding; its SHA256 is
`65FC026F51153D3D2BB3BCCEBBAB1323348F2168536950BD39E4847085E0AEE9`.
The rebuilt binary SHA256 is
`3FD1F2549FCA42ECFCCDDAD3963ED2C59FEA7BA0CB40F51432B4F82538C7F438`.
Receipts are under `.local/predicate-acquire-native-r1/{before,after}/`. This
checks actual analytical profiles, not an inferred estimate from source text.

All 21 pre-existing `opening::registry_lifecycle::tests::` regressions passed
after the unused-field cleanup, including genuine Source-first Bootstrap and all
seven operation proofs and repaired-root AIR attacks. That suite took 91.33s
(156.660s including compilation), with OS peak working set 905,588,736 bytes and
no fuse/budget abort. Its stdout SHA256 is
`AB750DE7ED31EB50984C793B9C823C480E5DE67E1616610A1CFF393EE80D9C4A`.
Root and standalone-experiment `cargo fmt -- --check` passed. The requirements
mirror matched and all 55 local links across the five updated module/validation
documents resolved. These checks do not imply that the full SQL suite passes.

## Remaining live requirements

The compiler must independently derive an acyclic jointly authorized query
context from the hidden exact SQL, private blind, actor and actual Source/control
parent. The output must undergo the real input16 and full FHE graph verification
and bind its original ordinal/RowIds to the proven Result144 flags and projection.
Owner signatures remain required authorization; enrolled controller labels alone
are not proof of possession. Valid evidence must be admitted atomically at an
independently fresh finalized head, with durable lock state and writer fencing.
Without the required confirmed-work quorum, lock issuance waits. This module
supplies none of those grants and does not complete PostgreSQL support.
