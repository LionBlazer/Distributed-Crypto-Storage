# Packed-container I/O feasibility

Validated on 2026-10-16: release test compilation, strict all-target Clippy,
84 ordinary runtime tests and one guarded ignored fixture passed. This single
fixed-order observation is a test-only candidate, not a selected production
backend or a complete SQL speedup.

The earlier [raw-file observation](README.md) found expensive initial Full/Copy
writes from hundreds of separate creates and syncs. This candidate tests whether
one append-only extent container avoids that cost while preserving complete
physical object reads and both CSTORE root audits. It does not select a backend.

## Owned test boundary

The private child
[`packed.rs`](../../crates/peer-runtime/src/store/chunk_io_feasibility/packed.rs)
reuses the parent module's real PUBLIC NONSECRET million-row fixture, actual
`Store::put_delta` reconstruction, unchanged `objects::write_disk`, I/O counters,
complete canonical auditor, exact version/byte comparison and final owner checks.
The generic encrypted index is not a semantically valid compact-query Table.
There is no SQL/FHE answer, computation proof, network Copy RPC or production
storage path in this experiment.

The canonical object is 37,604,602 bytes, divided into 574 extents of at most
64 KiB. A retained creation handle appends payload and owned test metadata to
one fresh container, then `sync_all` completes the version. Metadata records
canonical length, the real target ObjectId and all exact offsets/lengths. It must
match its owned expected bytes before reading extents. There is no persistent
manifest parser, journal, crash recovery protocol or accepting reopen API.

Full and Copy use independent fresh containers without reuse. Delta can reuse
only positional bytes equal to a freshly physically read and completely audited
base from the same container. Its private permission is consumed by that write;
no custody validation is cached across later reads. The actual Delta must change
canonical chunks 0 and 48. Unchanged encrypted byte ranges retain their addresses.

Each read opens the actual container anew, checks exact owned file length, reads
its complete manifest and reconstructs every canonical object byte. Physically
adjacent extents are coalesced into ranges, including all bytes in each range.
The existing complete data-first/index-second root audit, exact target version
and complete byte comparison follow reconstruction. Corrupt unrequested index
tail bytes and a freshly serialized coherent wrong extent mapping must reject.
A fully read base from another container must reject reuse before any write.

Retirement writes an eight-byte marker through the original creation handle,
then rereads/audits the surviving target. This does not reclaim interior holes.
Compaction separately rereads/audits the target, decodes that actual disk buffer,
serializes it into a fresh independent container and rereads/audits the result.
Only then is the old owned container closed and unlinked. The new target is
physically read/audited again and every final data page is owner-authenticated
and decrypted against the public fixture. Final retained container length must
equal canonical bytes plus exactly one manifest; this bounded exercise proves
no general active-version registry, quota accounting or global GC policy.

## Measurement contract

Write intervals include serialization/comparison, actual buffered writes and a
successful file sync. The Delta interval excludes its separately timed fresh
base read/audit, actual Delta reconstruction during fixture preparation, and its
separately timed target read/audit. Reuse must not be reported as full UPDATE
latency. Compaction is a full rewrite and must not disappear from accounting.

Read intervals include the full physical reads, complete root/version checks and
exact byte comparison. Owner decryption, public fixture preparation and decoding
the already audited compaction source are outside these intervals. The baseline
uses its existing 16-KiB buffer; the candidate coalesces writes with a 1-MiB
buffer and retains its creation handle. These differences are part of the tested
candidate; a single fixed order cannot identify their individual causal effects.

`CHUNK_IO_SAMPLE` records every timed result, including the expected rejection
controls. `PACKED_IO_RUN`, `PACKED_IO_PREPARATION` and `PACKED_IO_RESULT` describe
the fresh directory, untimed corruption preparation and final EOF byte sums.
Counters measure explicit successful Rust file opens, data read/write calls and
bytes, file syncs, unlinks and reused payload bytes. They do not count seeks or
provide device-I/O/syscall tracing, allocated disk space or a RAM guarantee.

The run retains its own public artifacts in a fresh OS-temp directory and never
deletes another run. Sum of retained fixture file contents must stay below
512 MiB, excluding allocation rounding/metadata. Namespace/hardlink attacks,
arbitrary power loss, failed-append recovery, persistent reopen, production
quota/Status accounting and a growing active-version population are unimplemented.

The [runtime reproduction command](../../crates/peer-runtime/README.md#opt-in-packed-container-io-feasibility-fixture)
is explicitly opt-in. Validation must use an isolated native Rust 1.99 target,
strict all-target Clippy, the owning runtime suite and one guarded exact ignored
test under an external owned-process resource observer. Record actual source,
artifact, toolchain, command exits, all intervals and sampling limits before
making a performance statement. OS caches and the observer perturb measurements;
no causal speedup, median/p95, complete SQL latency or 500-ms claim follows from
one fixture observation.

## Actual validation and observation

The reviewed four-path source freeze was
`EF65C0CB6157F9F78B1F76C8BCBCC2459EA1444AA10542E616DA85ECE3B76408`,
parent `d97dcd20c836ed8627b31784a35b78d95313e8d2`. Its two Rust files have not
changed since compilation; only documentation was completed afterward. All
24 source controls and 185 crate Rust/manifest files matched before and after
the run. The latter inventory SHA-256 is
`7404A248330587837B8DB9567B69FBE297827053D96D9AF1A05AAA1A04F3C65E`.
Root manifests/lock, production code, runtime dependencies and the old raw-file
fixture body are unchanged.

Actual validation used native Rust 1.99.0 (`b940084d7`),
`x86_64-pc-windows-msvc`, `RUSTFLAGS=-C target-cpu=native`, two Cargo jobs,
two requested Rayon workers and a fresh isolated target. No explicit Cargo
`--target` or dependency resolution was used. Release test `--no-run` and strict
all-target runtime Clippy both exited zero on their first attempt, without a
source fix. The frozen test executable was `peer_runtime-68a2a27ce11195d5.exe`,
4,830,208 bytes, SHA-256
`7711721D86F58A34299C92405251DA0060442647F65DED273B2E162A08BA1275`.

That binary first ran the owning suite serially: **84 passed, zero failed,
two explicitly ignored, zero filtered**, in 4.56 harness seconds. The ignored
raw-file fixture was not rerun. The same immutable binary then ran the exact
new ignored test once with `DCS_PACKED_IO_FEASIBILITY=1`, `--ignored --exact
--nocapture --test-threads=1`: **one passed, zero failed, 85 filtered**, in
2.12 harness seconds. Both stderr logs are empty. No native attempt, interval
or sample was excluded, and the measured fixture was not rerun.

All 24 emitted intervals follow in order. Milliseconds are rounded to four
decimal places here; original JSON retains the emitted floating-point values.
Read intervals include complete canonical reconstruction/auditing as described
above. Cross-container rejection occurs before writing; the other two rejection
controls read all canonical bytes before the auditor rejects them.

| Interval | ms | Opens | Read bytes | Written bytes | Syncs | Outcome |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Single initial write | 169.0262 | 1 | 0 | 37,604,602 | 1 | accepted |
| Single initial read + audit | 33.1982 | 1 | 37,604,602 | 0 | 0 | accepted |
| Packed initial write | 162.1724 | 1 | 0 | 37,613,850 | 1 | accepted |
| Packed initial read + audit | 34.8045 | 1 | 37,613,850 | 0 | 0 | accepted |
| Single full-copy write | 162.0911 | 1 | 0 | 37,604,602 | 1 | accepted |
| Single full-copy read + audit | 32.3937 | 1 | 37,604,602 | 0 | 0 | accepted |
| Packed full-copy write | 164.0885 | 1 | 0 | 37,613,850 | 1 | accepted |
| Packed full-copy read + audit | 27.5068 | 1 | 37,613,850 | 0 | 0 | accepted |
| Packed base read + audit before Delta | 22.3642 | 1 | 37,613,850 | 0 | 0 | accepted |
| Single Delta full write | 177.6023 | 1 | 0 | 37,604,602 | 1 | accepted |
| Single Delta read + audit | 31.4592 | 1 | 37,604,602 | 0 | 0 | accepted |
| Packed Delta write | 6.0921 | 0 | 0 | 140,320 | 1 | accepted |
| Packed Delta read + audit | 32.6326 | 1 | 37,613,850 | 0 | 0 | accepted |
| Copy fresh read for cross-container control | 23.3934 | 1 | 37,613,850 | 0 | 0 | accepted |
| Cross-container reuse attempt | 1.0312 | 0 | 0 | 0 | 0 | rejected as required |
| Corrupt unrequested tail read + audit | 25.9755 | 1 | 37,613,850 | 0 | 0 | rejected as required |
| Coherent wrong mapping read + audit | 17.3401 | 1 | 37,613,850 | 0 | 0 | rejected as required |
| Owned-handle base retirement | 0.7702 | 0 | 0 | 8 | 1 | accepted |
| Target read + audit after base retirement | 27.9947 | 1 | 37,613,850 | 0 | 0 | accepted |
| Fresh target read + audit before compaction | 23.2168 | 1 | 37,613,850 | 0 | 0 | accepted |
| Full compaction write | 173.1007 | 1 | 0 | 37,613,850 | 1 | accepted |
| Compacted read + audit before old unlink | 30.5376 | 1 | 37,613,850 | 0 | 0 | accepted |
| Retired-container unlink | 4.1672 | 0 | 0 | 0 | 0 | accepted |
| Final target read + audit after unlink | 24.0333 | 1 | 37,613,850 | 0 | 0 | accepted |

Initial Full/Copy used one open and one sync each, not hundreds. Their costs in
this observation were close to the paired single-file operations; this does not
establish a median, tail latency or a causal comparison with the earlier raw-file
run. Single-file serialization emitted four metered writes; the buffered packed
writer emitted 37, including its manifest. Their different buffers are disclosed
above. Full packed reads used two metered reads; this Delta used five, always
including every canonical byte and the manifest. Read-call counts can vary when
an underlying read returns fewer bytes.

The actual Delta reused 37,473,530 bytes and appended exactly two 65,536-byte
extents plus a 9,248-byte manifest. Its 6.0921-ms write interval excludes the
22.3642-ms complete base read/audit and 32.6326-ms target read/audit, actual
StoreDelta reconstruction and all SQL/FHE/network/proof work. The retained
creation handle was already open. No full UPDATE latency follows from this number.

Untimed corrupt-tail preparation appended 52,474 payload bytes plus one manifest:
61,722 written bytes, two metered writes and one sync. The coherent wrong mapping
appended one fresh 9,248-byte manifest with one write and one sync. Neither
preparation reopened an existing path for writing. Retirement overwrote only its
owned eight-byte marker; it did not shrink the container. Compaction performed
the recorded full rewrite and audits before unlinking the old 37,825,140-byte
container. The retained container has exactly 37,613,850 EOF bytes, including
one manifest. A successful unlink/EOF sum is not a measurement of filesystem
allocation reclamation or a general active-version GC/accounting policy.

The retained fresh public directory is
`dcs-public-packed-io-398452-1792178575799568900` under OS temp. Final root files
sum to 188,041,506 EOF bytes; the actual-Delta source Store adds 75,209,244 bytes,
for 263,250,750 bytes total, below the fixture's 512-MiB bound. No previous run
was read, modified or deleted by the fixture.

## External process observations and evidence

An owned-process observer used requested 100-ms waits, a 180-second timeout and
separate 1,792-MiB working-set/private/observed-OS-peak soft abort checks. Both
children exited zero without an abort and were joined. These are observations,
not hard OS limits, peak-RAM guarantees or whole-system measurements.

The unit run had 21 valid samples, actual gaps181.017-337.327ms (mean219.0352ms),
first244.988ms/last4625.692ms, and outer4647.0389ms. Maximum sampled working set
was239,931,392 bytes, private235,413,504 and live sampled OS peak277,565,440.
The ignored fixture had ten valid samples, actual gaps198.836-253.573ms
(mean219.8547ms), first193.711ms/last2172.403ms, and outer2186.6334ms. Its separate
maxima were272,998,400 working-set bytes,268,509,184 private bytes and348,979,200
live sampled OS-peak bytes. Sampling can miss transients, and the observer
perturbs timing. There was no concurrent task-managed native workload.

Ignored local evidence remains under `.local/packed-container-io-validation/`
and `.local/packed-container-io-runs/20261016-192243-559/` (unit) /
`20261016-192255-714/` (fixture): exact source/workspace freezes, commands, exits,
tool metadata, executable identity, complete stdout/stderr, observer and resource
CSV, all emitted intervals and results. Observer SHA-256 is
`9C4DFA40E0C9BA7913159C38D3CC9FE035B905B9808CBCA4789F0616448EBDC7`.
The post-run receipt is `.local/packed-container-io-observed-20261016-192420-422.json`,
SHA-256 `7ED66564B3D75FD179ED6CF84CA899903140DDC9E4D00847E8AEC196D86BDB26`.
All compiled sources, task controls and the executable were rehashed unchanged
after both actual runs. This report adds no production interface or speed guarantee.
