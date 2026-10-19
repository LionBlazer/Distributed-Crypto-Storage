# Single-slot consensus and durable signer: validation

The [work-finality consensus module](../crates/work-finality/src/consensus/README.md)
implements a bounded single-slot round/lock/POL machine and exclusive signer WAL.
It uses the checked bootstrap work roster, actual strict Ed25519 verification and
strictly more than two thirds of work weight. Nil votes and local timeouts cannot
unlock a value or decide without a quorum. This is a library kernel; no network
actor, finalized database head or SQL/row-lock grant is supplied.

The algorithm reference is
[Algorithm 1, arXiv:1807.04938v3](https://arxiv.org/pdf/1807.04938v3).
The module records its own complete rules identity before bootstrap work. Its
finite round/storage bounds, attached POL certificates, latest future vote per
key and certificate-plus-checked-descriptor commit delivery are explicit local
choices. The paper does not establish a safety/liveness theorem for this
implementation or its unimplemented production composition.

## Executed owning checks

On 2026-10-19, Windows x86_64/MSVC, Rust 1.99.0, release/offline/locked:

```powershell
cargo test --release --offline --locked -p work-finality -- --test-threads=1
cargo clippy --release --offline --locked -p work-finality --all-targets -- -D warnings
cargo check --release --offline --locked
```

All 33 runtime tests and five compile-fail examples passed. This comprises the
preceding 16 election/QC tests and two ownership examples plus 17 new consensus
tests and three owned-signer examples. The new tests exercise:

- Complete rules-before-work and genuine foreign contexts; proposer signatures,
  older POLs, nil/ANY and exact-round future weight; late valid-value updates
  without a second precommit; delayed older-round commits.
- Three actual owned signer state machines and real prevote/precommit quorums.
  Their application verifies real key-bound work tickets and strict possession
  signatures under an explicitly easy public test target. This is a mathematical
  application, not a substitute for Source/FHE/Journal proof acceptance.
- Application rejection before signing/WAL growth, exclusive file ownership,
  exact lost-reply replay, duplicate-vote quota preservation, missing files,
  bounded malformed codecs, torn/corrupt tails and replay application rejection.
- Controlled errors after actual partial/full writes and sync: poisoned handles
  publish no actions, never truncate, and a complete synced record replays its
  exact original signatures. These are local filesystem fault tests, not
  independently killed OS peers or a distributed recovery demonstration.
- Actual WAL and external reservations sharing one byte budget; rejected growth
  leaves exact file bytes unchanged, and dropping/reopening the handle does not
  forget its retained file charge.

The passing command took 4.578s including compilation and doctests; runtime tests
took 0.48s and compile-fail examples 0.25s. These are not network finality, SQL
latency or whole-peer memory measurements. Strict Clippy and the default core
build passed. No manifest, dependency version, lockfile or old stateless
ticket/vote/QC profile changed.

Workspace formatting and the requirements mirror check passed; all five local
links in the owning module/crate/validation documents resolved. Independent source
review rechecked the complete kernel, WAL, codecs and corrected vote-domain paths
and reported no remaining safety/durability blocker within this stated scope.

## Review corrections and attribution

The frozen donor's ten files had raw aggregate SHA256
`8CF65FC7F2B3F40D230F77750CB296DAE95FED68B91B81D0D0D9DDF64F376C94`.
Each exact raw file was verified before import against parent
`602cbfcf44956f6529057929a0421a912e839049`; the import snapshot manifest SHA256 is
`B1E39F4C6B1ED5D1CFBB20F7410EF709E75C977C5369606FC1BFBD99BBB05117`.
Root formatted the code and reviewed it separately; an independent source review
identified a missing previous-anchor pin in the new consensus vote domain.

The corrected consensus vote envelope derives its domain from complete
`ContextId`, including the independently selected previous decision, while the
actual journal Genesis remains separately captured. `RulesId` binds that
derivation before work. This preserves the preceding stateless mathematical
profile and wire format. A new test first verifies 64 genuine foreign-anchor
votes (four keys, two rounds, two steps, nil/non-nil) in their own context, then
rejects them through both remote bytes and local typed input. No timer, future
jump, WAL growth or outbound action occurs.

The first native run passed 31 of 32 tests; the quota test attempted to read an
exclusively locked WAL through a second file handle, which Windows rejects. The
test now reads before opening and after dropping the owner, preserving actual
exclusive locking and comparing exact rejected-write bytes. No runtime file
lock was weakened. The complete corrected suite then passed.

Ignored native receipts are under
`.local/private-peer-native-r1/consensus-{test-r1,test-r2,clippy-r1,default-check-r1}/`.
Passing test stdout SHA256 is
`CFDCB15A316DF7A5A01B214901CB21543634838A1DAA1A975DB9F7D937CFB6ED`;
stderr is
`9FED2489FDDFD1970E5629B904B133A7AD69375D4B52619F9925CEC12B2312C5`.
Failed/intermediate receipts are retained; generated files and secret material
are not committed.

## Outstanding production obligations

The application verifier is an explicit trusted integration contract. A concrete
closed adapter must actually verify candidate authorization, complete computation
proof dependencies, correct parent and durable availability before voting or
deciding, and repeat verification after reopening. The library's bounded
descriptor or generic callback is not such an adapter.

Monotonic multi-slot handoff, finalized journal-floor enforcement before fork
adoption, peer transport/clock ownership, epoch activation and a peer-admission
system lane remain missing. All retained journal/evidence/WAL artifacts must
share actual participant quota accounting on restart as well as append. Missing
quorum must continue waiting; it must not lower weight thresholds. Protection
against malicious whole-WAL rollback or duplicated signer key installations is
outside this crash/corruption contract and cannot be inferred from checksums or
exclusive file handles. These gaps prevent live SQL lock admission.
