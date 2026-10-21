# Executed two-lane encoding validation

On 2026-10-21, Root executed the fixed mathematical SourceAllOriginal/PrivateMask
boundary described in [README](README.md). Both child roles genuinely verified
the original Source691 and their new hiding proofs. This is a partial input
relation for the separate N4096 unrelinearized-product candidate. It does not
grant Key/Formation, full FHE evaluation, SQL, current-head or network authority.

## Reproducible gates

The original trusted Windows/MSVC CPU policy used Cargo jobs=2 and Rayon=2, with
all DCS feasibility switches removed. Dependencies were locked and offline.
Run from the repository root with the same pinned Rust 1.99 toolchain:

```sh
cargo clippy --release --offline --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --offline --locked -p registry200-proof --lib two_lane_encoding::tests::sdk_scaling_matches_independently_built_full_two_lane_plaintext_and_all_private_mask_patterns -- --exact --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib two_lane_encoding::tests::all4096_vector_words_match_an_independent_sequential_hash_including_first_prefix_and_last_flush -- --exact --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib two_lane_encoding::tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

Strict all-target Clippy passed. Root then ran the compiled release test image
directly with the exact owning-test filter above, under a held-process Windows
observer. All 7 tests passed in 17.18 s; no tests were ignored. One explicitly
public, nonsecret Source proof and two honest child proofs were shared only
inside this test process. Two additional malicious child proving attempts
failed after repairing their commitments. Every production verify invocation
still freshly checks the real original Source proof.

The tests cover actual SDK scaling of all 4096 plaintext coefficients and zero/
all/threshold masks; independent sequential hashing of all 4112 vector fields;
genuine Source and both child roundtrips; repaired foreign key/epoch/SQL/nonce/
mask headers; Source/child corruption; the final coefficient after root repair;
complete TableId/RowIds, private banks, integer scaling and mask constraints;
and full Expected/role, canonical framing, cap and EOF rejection. The fixed
backend assesses the actual immutable AIR before allocating its trace and
requires each original individual 128-bit floor. Passing these checks does not
establish composed 128-bit or lattice security.

Nine existing public boundary cases also passed in 0.76 s: complete Source
packet/geometry re-audit, mutable low-level claim rejection, malformed Source
rejection before trace allocation, private witness Expected ownership, original
three profile bytes/geometry, lifecycle header/root/limit rejection, and all
three existing coefficient-wire parser/context cases. Requirements
synchronization passed. No production transport or consensus boundary changed,
so the unrelated expensive multi-process/recovery gates were not repeated.

## Single-process observation

The public fixture stage timers report complete named intervals. Prove includes
the original Source verification and child self-verification where applicable;
wire verify includes framing, Source verification and child verification.
These are one observation, without a controlled before/after speedup claim.

| Observed stage | Wall time | Proof bytes |
| --- | ---: | ---: |
| Original Source prove |3896.146 ms|19,299,551|
| SourceAllOriginal child prove |2017.296 ms|3,359,943|
| PrivateMask child prove |1317.072 ms|2,363,655|
| Source-first SourceAllOriginal pair verify |1084.735 ms|Source plus 3,359,943|
| Source-first PrivateMask pair verify |964.233 ms|Source plus 2,363,655|

Original Source bytes are supplied separately, never copied into a child frame.
The two children use distinct DCS2LE01 role and profile bindings and the unchanged
per-child 12 MiB cap. Their combined payload and the 19,299,551-byte Source still
require an explicit future composite transport/accounting contract.

The held process exited 0 after 17,197.2262 ms of OS lifetime, with 20.875 CPU seconds.
Across 842 nominal 20 ms memory samples, peak private bytes were 856,334,336 and OS
peak working set was 845,721,600. The 1792 MiB and 120 s fuses did not fire. There was
no cleanup kill, observer fault, unexpected terminal child or source/image
drift. These observations cover this test process, not an entire peer or a
worst-case process-memory guarantee.

Source-first verification already exceeds the 500 ms target for a **complete**
ordinary query. No full query was timed here. Same-secret bounded-noise
Formation, assessed product proof composition, independent SQL compilation and
fresh agreed-head admission must still be implemented and measured together.
The separate public product arithmetic result cannot fill these missing gates.

## Evidence identities

Generated proof bytes, public test images, process logs and observer records stay
in ignored local storage and are not committed. Root's exact evidence:

- `.local/two-lane-native-r1-observe/result.json`, SHA256
  `8F9FDA6E01C5274DEE128F84CF551CF330ADEC8DC5262A0A7B2065BB23417D0E`.
- Observer `.local/observe-two-lane-r1.py`, SHA256
  `EBF371F5BE9D49EB66C17680560115F89222C0DC9C5AB739C8E3AF40BED8BF16`.
- Release image `registry200_proof-5076f82234ff8d30.exe`, 6,264,832 B, SHA256
  `5DA4B503933C507BC78194D70642095B0648D5DFACF2BE5E573E2E958A23652D`.

The record contains exact source hashes before/after, image identity, exit and
memory counters. The source-only packet received two independent hash-bound
reviews before Root compilation. Root subsequently applied Rust formatting,
the explicit existing-package dev lockfile edge and test-only API/lint fixes;
the actual arithmetic, profiles, proof gates and canonical limits were retained.

## Joint verification of one Source and two children

A subsequent change adds `wire::verify_pair` without changing any AIR, profile,
single-child wire byte, cap or existing single-child proof policy. The function
first requires exact SourceAllOriginal/PrivateMask roles, equal complete
Source691/raw heads/packets and equal candidate key29. Both child headers are
preflighted. One concrete Source verification precedes two sequential child
verifications, with each backend/decoded proof dropped before the next. The
opaque pair is returned only after all three proofs pass. No verified Source
token, persistent success cache or caller-selected verifier is introduced.

Strict all-target Clippy passed again. The same owning-test command above now
runs 9 tests; all passed in 35.62 s, without ignored tests. The new cheap role/source/
key mismatch test also passed independently before the real gate. The existing
public Source/child fixture is reused inside one process. New pair attacks cover
repaired foreign expected contexts, the genuine corrupted Source and both damaged
children. The new genuine pair case checks both complete public statements
against two independent single-child verification calls.

Within that one case, on the **same exact proof bytes**:

| Complete mathematical verification call | Wall time |
| --- | ---: |
| Two independent single-child calls, each including Source |2674.165 ms|
| One fresh pair call, including Source and both children |1595.910 ms|

This comparison is one ordered observation, not a statistical latency guarantee
or a full-query benchmark. Source verification is still mandatory on every pair
call. The pair remains above 500 ms before same-secret Formation, FHE evaluation,
transition/freshness, transport/consensus and client completion. No component
subtraction is reported as a standalone Source-verification measurement.

The actual Source payload was 19,298,495 B; children were 3,359,047 B and 2,363,559 B.
Those generated proof sizes differ slightly from the first gate because hiding
proofs have fresh randomness; the frame/profile and limits did not change.
The process exited 0 after 35,641.0147 ms OS lifetime with 39.65625 CPU seconds.
Across 1736 nominal 20 ms samples, peak private bytes were 856,317,952 and OS peak
working set was 845,717,504. No 120 s/1792 MiB fuse, observer fault, cleanup kill,
unexpected terminal child or source/image drift occurred.

Exact ignored local evidence for this later gate:

- `.local/two-lane-native-r2-observe/result.json`, SHA256
  `467BB770537B9253661E7DB47295BAF47BB831C8662202F4037E77A6DA05CC2B`.
- `.local/observe-two-lane-r2.py`, SHA256
  `690D89EF6BAE9170F0CDB5C093C7B0CC92086D5EE3C4F109AD38185606D4BA8C`.
- Release image `registry200_proof-5076f82234ff8d30.exe`, 6,254,592 B, SHA256
  `73882E22F58BED70AE3A0571487F295259E73C59FA8F2A911133C297AFF1D6CE`.
- Independent source review `.local/two-lane-pair-review-r1/review.md`, SHA256
  `C3AC3C9467E1C5D2FCC8F346A3E3C7A3469460AC12B35549662E3F5006C11A2A`.

The earlier nine old-boundary checks and requirements synchronization retain
their original scope; these new changes touch only the two-lane pair frontend,
its context check, tests and documentation. No expensive production-network or
recovery boundary was changed or rerun.
