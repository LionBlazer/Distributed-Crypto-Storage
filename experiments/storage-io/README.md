# Single-run chunk-file I/O feasibility

This PUBLIC NONSECRET test-only candidate does not select a production backend.
In this one fixed-order observation, creating and syncing a full chunked image
was much slower than the single-file writer: 3010.4663 versus 182.2495 ms initially,
and 2456.8801 versus 297.2359 ms for a full copy. The smaller Delta write interval
excludes its complete base read/audit and subsequent target read/audit. These are
not complete SQL timings, causal comparisons, repeated-sample statistics or a
500 ms guarantee.

## Fixture and unchanged boundaries

The ignored [owning runtime test](../../crates/peer-runtime/src/store/chunk_io_feasibility.rs)
uses genuine CSTORE AEAD/Merkle images and actual `Store::put_delta` reconstruction.
Its million-row data image is 3,187,648 encoded bytes; the generic encrypted index
is 34,416,624 bytes. This index is **not a semantically valid compact-query Table**.
No SQL query, FHE computation, proof acceptance, network Copy RPC or production
backend is simulated or measured here. Copy denotes a complete target custody
write within this filesystem fixture.

Both writers call the unchanged `objects::write_disk`. The single-file writer
uses the existing 16-KiB buffered serialization path; the candidate partitions
that identical canonical stream into 64-KiB files and a test-only manifest.
The canonical object is 37,604,602 bytes: 574 chunks, with a 52,474-byte last chunk.
The manifest is 18,416 bytes. Full/Copy performs no chunk reuse. Only a freshly
physically reread and fully audited immutable base permits exact positional
byte reuse for that one Delta write; no custody audit is cached across reads.

Every recorded successful read reassembles all canonical bytes, runs the existing
complete data-first/index-second custody audit, checks the exact target version,
then compares all bytes with the expected input prepared outside timing. The
owner separately checks every final data page's membership and AEAD plaintext
against the complete public byte vector, and the index header's embedded data
head. Those owner checks are outside the recorded intervals.

## Actual observation

Run `20261016-183717-891` used source parent
`5a4eba146a85119ee2e1fe8b27d0e270247e6ea7` plus the reviewed three-path patch
`7B1426E8FA301E328C5AE7A4B899BC33DCD957C4BA4EDC1AA7C1A902F318BF91`.
The source manifest SHA-256 was
`898F1DF258530BC19CC6FD976F70A97B184104DAA48B66FFBDED21B3A7C3BC5B`.
Rust 1.99.0 (`b940084d7`), host `x86_64-pc-windows-msvc`,
`RUSTFLAGS=-C target-cpu=native`, two Cargo jobs and two requested Rayon workers
were used in a new isolated target. There was no explicit Cargo `--target`.

The owning test executable was `peer_runtime-68a2a27ce11195d5.exe`, 4,751,872 bytes,
SHA-256 `E46BBA5B2338BE33FA6FC46FEF8BD78B5AE81A8E0FDC887F08034BBC0FB88F4E`.
Release test compilation without execution and strict all-target runtime Clippy
both exited zero without a source fix. The executable then ran **once**, directly,
with the exact ignored test name, `--ignored --exact --nocapture --test-threads=1`
and `DCS_CHUNK_IO_FEASIBILITY=1`. It passed: one test, zero failures, 84 filtered out.
There was no rerun or excluded interval.

All 15 intervals appear below in execution order. Milliseconds are displayed to
four decimal places; the original JSON retains its emitted floating-point values.
Opens and syncs count explicit successful Rust file API operations. Read/write
counts and bytes are not device I/O, syscall tracing or filesystem allocated space.

| Interval | ms | Opens | Read bytes | Written bytes | Syncs | Outcome |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Single initial write | 182.2495 | 1 | 0 | 37,604,602 | 1 | accepted |
| Single initial read + audit | 23.8829 | 1 | 37,604,602 | 0 | 0 | accepted |
| Chunk initial write | 3010.4663 | 575 | 0 | 37,623,018 | 575 | accepted |
| Single full-copy write | 297.2359 | 1 | 0 | 37,604,602 | 1 | accepted |
| Single full-copy read + audit | 45.1428 | 1 | 37,604,602 | 0 | 0 | accepted |
| Chunk full-copy write | 2456.8801 | 575 | 0 | 37,623,018 | 575 | accepted |
| Chunk full-copy read + audit | 76.3650 | 575 | 37,623,018 | 0 | 0 | accepted |
| Chunk base read + audit before Delta | 95.0749 | 575 | 37,623,018 | 0 | 0 | accepted |
| Single Delta full write | 182.4299 | 1 | 0 | 37,604,602 | 1 | accepted |
| Single Delta read + audit | 38.5210 | 1 | 37,604,602 | 0 | 0 | accepted |
| Chunk Delta write | 16.2338 | 3 | 0 | 149,488 | 3 | accepted |
| Chunk Delta read + audit | 78.6690 | 575 | 37,623,018 | 0 | 0 | accepted |
| Corrupt unrequested index tail read + audit | 58.7327 | 575 | 37,623,018 | 0 | 0 | rejected as required |
| Owned-handle retirement + GC | 9.3888 | 0 | 0 | 8 | 1 | accepted |
| Complete target read + audit after base GC | 62.6414 | 575 | 37,623,018 | 0 | 0 | accepted |

The actual Delta changed chunks 0 and 48. Its write reused 37,473,530 exact payload
bytes and created two 65,536-byte chunks plus one manifest. The 16.2338 ms interval
includes serialization/comparison, these writes and three successful file syncs;
it excludes the separately recorded 95.0749 ms base audit and 78.6690 ms target
read/audit, as well as actual Delta reconstruction prepared before the comparison.
No end-to-end UPDATE improvement follows from that write-only number.

Corruption preparation created a new private bad final chunk and manifest:
70,890 written bytes, two opens/writes/syncs, recorded separately without a timing.
It did not overwrite an existing file. The complete auditor rejected that tail.
Retirement used only the retained original manifest creation handle, synced its
eight-byte marker, then unlinked the base manifest and two unshared chunks.
The surviving target passed the subsequent complete audit and owner checks.
This fresh-owned-directory exercise establishes no persistent parser, hostile
local namespace/hardlink race defense, restart protocol or power-loss ordering.

The fixture created 1,151 chunk files, removed two, and retained all public run
outputs. Final EOF byte sums were 75,261,678 in chunks, 112,869,054 in root files
and 75,209,244 in the actual-Delta source Store: 263,339,976 total. These sums
exclude filesystem allocation rounding and metadata and change no quota/Status API.

An external owned-process observer sampled 31 valid rows with requested 100-ms
waits. Actual inter-sample gaps were 183.959–707.422 ms (mean 240.3398 ms); the first
and last samples were at 298.451 and 7,508.645 ms. Separate 1,792-MiB working-set,
private and observed-OS-peak abort checks and a 180-second timeout were configured. The run exited zero without an abort in 7,605.0938 ms;
the test harness reported 7.39 seconds. Maximum sampled working set was
218,210,304 bytes, private bytes 231,809,024, and live sampled OS peak working set
275,533,824. Sampling can miss transients; this is not a hard OS limit or a
whole-system/resource guarantee. The observer itself perturbs the observation.

## Evidence and reproduction

Ignored local evidence is retained under
`.local/chunk-io-feasibility-validation/` and
`.local/chunk-io-feasibility-runs/20261016-183717-891/`: compile/Clippy logs and
exit records, source/tool metadata, executable identity, observer, all stdout and
stderr, resource CSV, all intervals and the result. The fresh nonsecret filesystem
outputs remain in the OS temp directory printed by `CHUNK_IO_RUN`; no other run
was deleted. The [runtime README](../../crates/peer-runtime/README.md#opt-in-chunk-io-feasibility-fixture)
contains the explicit guarded reproduction command and disk-space scope.

There is one fixture, one order, uncontrolled host caches and no cold-cache control.
Its repeated reads are warm-cache observations with complete audit and full byte
comparison. Initial Full/Copy costs of thousands of milliseconds are material
negative evidence for this simple file-per-chunk layout. Production accounting,
bounded large-population startup/GC, crash/reopen safety and namespace policy remain
unimplemented. No overall speedup, selected backend, SQL latency, causal median,
p95, general resource bound or cumulative improvement is established.
