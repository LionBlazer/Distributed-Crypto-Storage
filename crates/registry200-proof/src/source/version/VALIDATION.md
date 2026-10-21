# Closed Source version validation, 2026-10-21 UTC

The new core capability establishes the existing fixed StateCertificate
mathematical relation over both complete encrypted data/index images. It derives
the version tag itself from independently supplied canonical images/heads and
C_key, while separately binding the complete independently retained C_state.
Only actual native verification creates the move-only result. It adds no live
cache, agreed-head check, BFV key/Formation, query result, SQL admission or network
path. The complete-query 500 ms target remains unachieved; even this observed cold
verification alone exceeded it.

## Executed gates

Using Rust 1.99.0/MSVC, release, `-C target-cpu=native`, two Cargo jobs and two
Rayon threads, from the repository root:

```sh
cargo clippy --release --offline --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --offline --locked -p registry200-proof --lib source::version::tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-proof --doc source::version::VerifiedSourceVersion -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib tests::canonical_frontend_reaudits_last_packet_byte_and_all_geometry -- --exact
cargo test --release --offline --locked -p registry200-proof --lib tests::mutable_low_level_claims_never_bypass_sealed_canonical_admission -- --exact
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

All four owning runtime tests passed in 7.00s. They share one explicitly public
compact-data/key fixture and one honest proof; no live Owner, SDK config or
verified result is cached. A separate false-key trace reached real native release
proving, produced a genuine argument, then failed receiving verification with
exactly `Proof(Verification)`. The release test accepts neither panic nor a
generic Proving/Shape/Resource error as a passing cryptographic oracle. Debug-only
early SDK constraint rejection is separate and was not used by this run.

The honest proof verifies under the complete expected claim. A changed C_state
retains the same version ID but fails the actual native verifier; changed C_key
and a canonically repaired genuine OOD opening also require native Verification
errors. Full-image/digest/cap/EOF/truncation failures are covered. A final fresh
honest verification passes after all failures. The two compile-fail examples
reject external private-field construction and cloning the move-only result.
Both affected old Canonical policy regressions, formatting, strict Clippy and
the requirements-mirror gate passed.

Runtime-test compilation took 33.34 s; the separate non-test library/doc build
took 29.53 s. The two compile-fail examples then ran in 0.40 s. Build time is not query
latency. No expensive FHE/network/recovery scenario was repeated: existing
application admission, math, profiles, actors and failure semantics did not change.

## Observed time and resources

| Boundary | One observed time |
| --- | ---: |
| Honest unverified production: setup, trace, native proving, canonical serialization | 1930.865 ms |
| Honest cold receiving verification: fresh setup, decode, native verification | 527.465 ms |
| All four runtime tests, including false proof and receiving negatives | 7.00 s |
| OS process lifetime for the complete four-test run | 7022.6795 ms |
| Summed CPU time of that process | 9859.375 ms |

The genuine raw certificate was 12254783 bytes under the unchanged 20 MiB cap.
There is no before/after full-operation speedup claim: the new producer
intentionally returns UNVERIFIED bytes without self-verification, while the
receiving native check remains mandatory. Existing Canonical source::prove still
keeps its self-verification contract. Neither a producer output nor version ID
alone supplies a verified mathematical result.

The observer retained the actual Windows process handle and checked executable
identity, creation time, release artifact profile, exit code and source hashes.
The process exited 0 without cleanup termination, timeout or resource fuse. It
sampled 343 times at 20 ms intervals, with sampled peak private bytes 552013824 and
OS peak working-set bytes 557457408. Sampling may miss private-memory peaks; these
are distinct OS counters for this isolated process, not a whole-peer guarantee.
The unchanged observation fuse was 1792 MiB and 120 s. No production timeout or
resource limit was relaxed.

The executed release test image was 6417408 bytes, SHA256
`0C8D45E4CEC7E04C54F6469B6C328754431E6E7DE9A54C0B3D7E53B5BC32A519`.
Its Cargo artifact had optimization 3 and debug_assertions=false, so the strict
release false-proof receiving path was required. Raw logs, process samples and
source guards remain local and are not committed.

## Preserved contracts and remaining work

The original StateCertificate profile, packed AIR 7161/PV691, deterministic
version-tag transcript and raw proof encoding remain unchanged. The new closed
constructor selects that fixed policy; it accepts no caller request, callback,
remote configured verifier or from-Statement shortcut. Decoder limits remain
sequence 16384 and 24 Mi total slots, with canonical fields/reencoding, exact hiding
topology and EOF. The fixed backend retains actual analytical/native gates and
fresh OS configuration. These individual checks establish no composed security
or whole-application theorem.

The executed four Rust files (fixed.rs, source/mod.rs and version/{mod,tests}.rs)
total 33452 bytes, sorted POSIX-path/NUL/raw-bytes SHA256
`D000D7DD012F41067526A0DF2F13D436FC5DC26A8228887A34EBAD55CEF11DF8`.
The independent frozen six-file packet and final formatted Rust changes were
source-reviewed. Root's only behavioral delta to that packet was tightening the
release negative oracle. Old Canonical admission/source producer, Source-first
encoding/lifecycle paths, root manifest/lock and requirements remain unchanged.

A future bounded immutable-version query contract must retain the complete
expectation, link genuine all-row Encoding and actual data-ciphertext Formation,
and separately require a fresh agreed head to select that exact data/key epoch.
Current query-dependent Source and old checkpoints cannot be relabeled. Cold
load/restart requires full actual verification, never a persisted success flag.
Fresh mask/Formation, actual peer FHE and its proof, authorization, transition/QC,
client completion and durable result remain necessary. This capability implements
none of that composition yet and does not make the current DCS request faster.
