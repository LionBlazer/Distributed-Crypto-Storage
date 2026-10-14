# Actual shared-key amortization across 210 encrypted tables

Measured on 2026-10-15 local date (2026-10-14 UTC). This is a separate storage
accounting experiment over the unchanged narrowed-wire compact-query kernel
promoted as `59c7200`. It does not replace the
[narrower-wire comparisons](experiment-query-wire.md) or the
[composed backend report](experiment-compact-query.md).

One Owner/Evaluator pair actually retained 210 independently freshly sealed Table
handles, each with 1,000,000 public synthetic age:u8/amount:u16 rows. There were
210,000,000 rows and 630,000,000 logical packed bytes. Data, padded V2 indexes,
every trusted data/index head, one complete serialized shared FHE key set and
owner state totaled **1,244,370,176 bytes, or 1.975190756x**. Adding the actual
rebuildable hash payload gives **1,257,601,856 bytes, or 1.996193422x**.
These are actual retained images, not a projection, cloned table or multiplied
one-table count. The remaining margin below 2x with hashes is only 2,398,144 bytes.

This validates a particular shared-owner, single-replica storage configuration.
It does not establish a <=2x bound for every database size or include a complete
distributed SQL system. The separate 2-table process was 31.795467x before hashes,
showing the same keys are expensive when poorly amortized.

## Ownership, fixture and accounting boundary

The isolated [key_amortization example](../crates/compact-query/examples/key_amortization.rs)
uses the existing public Owner/Evaluator/Table API; no core API, cryptographic
parameter, index format, selection cap or security/privacy policy changed. Exactly
one Owner::generate call creates the key authority. All tables share its secret
key, symmetric authority and public evaluation material, while maintaining separate
trusted data/index heads. This is one owner's trust domain, not independent
per-tenant key isolation.

For table ordinal t and row ordinal i, the public fixture normally uses
age=(73*i+17*t+11) mod200 and amount=(137*i+997*t+29) mod65536. One row at
(4729*t+17) mod1,000,000 instead has age250 and amount=(997*t+101) mod65536.
Thus plaintext tables vary as well as receiving fresh page nonces. Each fixture
Vec is generated, sealed and dropped sequentially. At most one 4,000,000-byte
PlainRow fixture Vec is present, plus the bounded library scratch. Neither source
fixtures, participant data nor keys are saved to disk.

Each table uses 2048 three-byte rows per data page, not the earlier 256-row data
page setting. Its index is the same padded V2 format and page geometry. The harness
actually serializes each independent data image and index, checks those lengths
against their owned APIs, drops each temporary serialization, and retains the Table.
It checks all 210 data roots and all 210 index roots for distinctness. No Table::clone,
fork, deduplication or repeated reference supplies the reported table count.

Both manifests already belong to the canonical images. The accounting additionally
reserves their two independent trusted-head encodings per Table, 224 bytes, rather
than treating peer-supplied manifests as independent trust. Owner symmetric
key/database/domain plus query domain are counted once as 80 bytes. The owner FHE
secret-key serialized length is counted via the existing non-exporting size API;
no secret-key bytes are written. The public evaluation key is actually serialized
once, counted and dropped before sealing the tables. Object headers, Vec capacity,
allocator retention, routing handles and live key allocations are represented in
native process memory rather than added to the canonical wire/disk byte count.

| Accounted material | Two-table dry run, bytes | Actual 210-table run, bytes |
| --- | ---: | ---: |
| Logical three-byte row payload | 6000000 | 630000000 |
| Canonical encrypted data | 6047168 | 634952640 |
| Canonical padded encrypted indexes | 4083128 | 428728440 |
| Additional independently trusted heads | 448 | 47040 |
| Shared serialized public evaluation key | 180610708 | 180610708 |
| Owner FHE secret-key serialized length | 31268 | 31268 |
| Shared owner symmetric/domain state | 80 | 80 |
| Joint canonical material | 190772800 | 1244370176 |
| Rebuildable hash payload, extra | 126016 | 13231680 |
| Joint material including hashes | 190898816 | 1257601856 |
| Canonical expansion | 31.795466667x | 1.975190756x |
| Expansion including hashes | 31.816469333x | 1.996193422x |

Per actual million-row table, encrypted data is 3,023,584 bytes and the encrypted
index 2,041,564 bytes. All table sizes are individually measured, with no permanent
FHE rows, pads, plaintext row cache or update overlay. Replication is one; another
replica, independent authority key set, authentication/routing structure or
production metadata would require additional accounting. This experiment has no
large global routing index whose cost could be silently omitted.

## Memory limits and two-step execution

The Windows-only example-support memory probe reads only its own process through
GetProcessMemoryInfo. It rejects the next table/query allocation if current RSS or
private commit plus a 64 MiB reserve exceeds 2,000,000,000 or 1,850,000,000 bytes
respectively, and rejects an already excessive high-water counter. Key generation/
serialization uses a 256 MiB preflight reserve. The source hard-limits the table
count to 210 and row count to 1,000,000.

The companion hidden child wrapper assigns only its newly launched benchmark
process to a Windows JobObject with a 1,850,000,000-byte process commit limit and
kill-on-job-close. A 25 ms watchdog stops that child if its RSS high-water exceeds
2,000,000,000 bytes. No parent shell, GUI, unrelated process or system-wide setting
is changed. The wrapper retains its own child handle after exit to capture kernel
peak working set/commit, wall time and child CPU time; a failed gate invalidates
completion. The process-local commit cap is a hard OS limit; the RSS watchdog is
sampled, supplemented by the in-process reserve checks. Actual high-water counters
below, rather than a universal allocation proof, establish this run's memory bound.

First, a separate two-table process completed successfully. Its explicitly labeled
planning estimate for 210 tables was 1,579,709,260 bytes of private commit, below
the 1.85 GB cap. The model adds the remaining per-table measured canonical/hash
payload, 128 KiB/table metadata allowance, 20% margin and 64 MiB scratch reserve to
the measured current commit. It is only a planning heuristic, not an actual 210-table
result. The 210-table process repeats that two-table planning check internally and
rejects before table3 if unsafe; its fresh-process estimate was 1,579,369,292 bytes.
Only after the safe dry run was the one actual 210-table process launched.

| Native whole-process measurement | Dry2 | Actual210 |
| --- | ---: | ---: |
| Peak working set, bytes | 371834880 | 1385590784 |
| Peak process commit, bytes | 368041984 | 1401331712 |
| Wall time, ms | 1082.8384 | 4819.2326 |
| Child CPU time, ms | 3859.375 | 7875.000 |
| All table sealing + actual image encoding, ms | 35.5110 | 3504.7072 |
| Memory-watchdog stop | false | false |
| Exit code | 0 | 0 |

Memory includes both owner and peer roles, actual live ciphertexts, hash trees,
keys, fixture/library scratch, public-key serialization peak, query ciphertexts,
Vec overhead and allocator retention. It is not isolated peer RAM. Actual peak RSS
was 1.386 GB decimal and peak commit 1.401 GB, both below the experiment limits.
No image/secret-key files or durable IO were created; only JSONL metrics, stderr,
metadata and an executable archive exist under ignored .local.

## Actual first, middle and last table queries

While all 210 Tables remained retained, the harness supplied table IDs 0,105,209
and evaluated age=250 through each table's complete owner-built encrypted equality
index. The matching ordinal differs by table. One selected row still undergoes
genuine encrypted equality, conditional amount selection and COUNT/SUM, using the
unchanged security parameters and 256-row materialization limit. No plaintext
answer enters the peer or replaces evaluation.

Each timed flow includes owner encrypted-index page lookup/proof/decryption, data
authentication and encrypted pad/predicate preparation, complete request encode,
peer decode/page proof verification, compact-to-FHE conversion, FHE predicate and
aggregate, complete output encode/decode and owner decryption. Only after stopping
the timer is the public fixture reconstructed as an oracle and compared. The owner
also rejects that output against a different live Table sharing the same keys.
These checks passed for every sample. The first measured query includes cold
first-use effects; the remaining samples are warm in the same process. There are
three observations per selected table, not a tail-latency estimate.

| Supplied table ID | Sample0, ms | Sample1, ms | Sample2, ms | COUNT | SUM |
| --- | ---: | ---: | ---: | ---: | ---: |
| 0, first | 100.1377 | 56.6953 | 61.0069 | 1 | 101 |
| 105, middle | 57.5830 | 60.7915 | 56.6651 | 1 | 39250 |
| 209, last | 56.4397 | 61.0634 | 57.4336 | 1 | 11866 |

Each of these nine actual210 queries has the same measured wire sizes:

| Message/page response | Bytes |
| --- | ---: |
| Full serialized encrypted request | 263669 |
| Full serialized encrypted output | 148497 |
| Authenticated owner index page responses | 8896 |
| Authenticated owner data page response | 6496 |
| Authenticated peer data page response | 6496 |
| Total counted flow | 434054 |

Page responses are counted separately, once each, in addition to request/output
messages. Full per-stage timings and byte counters are retained in the raw JSONL.
This is a local serialization roundtrip without measured transport/network delay.
Setup, key generation and public-key serialization are reported separately from
queries. There is no hidden key download inside those warm-query times.

**The table/shard choice is supplied.** This experiment neither routes arbitrary
SQL over 210 tables nor scans/aggregates all 210 million rows. It measures an indexed
point predicate within three selected tables while demonstrating the real retained
storage/key denominator. It does not measure multirow UPDATE, global atomicity,
range aggregation across tables, PIR/concealed index access, durability/restart,
replication, consensus or malicious-peer computation proofs. Prior multirow/range
latencies remain in the other reports; their failures of the 500 ms goal do not
disappear through key amortization. Outputs remain explicitly unverified outside
the owner-local experiment.

## Reproduction, checks and provenance

No full core-test rerun was needed for this unchanged kernel. The focused release
example build, strict Clippy and rustfmt check passed. The dry2 and actual210 runs
exercise independent table lifecycle, actual image encoding, root distinctness,
complete indexed genuine FHE queries, exact owner output and wrong-table output
rejection. No API/manifests/frozen kernel files were changed.

~~~powershell
$env:CARGO_HOME='E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home'
$env:CARGO_TARGET_DIR='E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target'
& E:/Users/white/.cargo/bin/cargo.exe build --release --locked --offline -p compact-query --example key_amortization --jobs 2
& E:/Users/white/.cargo/bin/cargo.exe clippy --release --locked --offline -p compact-query --example key_amortization -- -D warnings
& ./crates/compact-query/examples/support/measure_key_amortization.ps1 -Label dry2 -Tables 2 -Rows 1000000 -Samples 3
# Check the completed dry-run estimate and memory before running the larger case:
& ./crates/compact-query/examples/support/measure_key_amortization.ps1 -Label actual210 -Tables 210 -Rows 1000000 -Samples 3
~~~

The example uses eight shared Rayon workers and the existing opt-in row-worker
budget8; one-row evaluation starts no extra scoped row threads. The CPU lease was
exclusive across the research agents. The wrapper reports 32 logical processors;
there was no CPU affinity or global power/OS change.

Frozen new source SHA-256:

| File relative to crates/compact-query/examples | SHA-256 |
| --- | --- |
| key_amortization.rs | 12F52940985F6213790C55F06BF724FC86B405C105FE69D7347A9AC57D787C34 |
| support/key_amortization_memory.rs | F7B1A0310BC96B4498BB4C57EB833CE71F0B53006B80782847993C84D3E3A50F |
| support/measure_key_amortization.ps1 | 0249786BEEE540ABD7152F0CC5552C546C488706B6E0D996D75E56F0D56D88D4 |

The archived executable is key-amortization.exe, SHA-256
`A9372AD88D6B9EEE9C12D630CB68A9FCBF23112A8485742365F8392E10F6712C`.
Both runs used that same binary. Raw records and archive remain under
`E:/Users/white/.codex/worktrees/compact-fhe-query/DistributedCryptoStorage/.local/fhe-research/key-amortization/`:
`dry2` and `actual210`, each with .jsonl, .stderr.txt and .process.json. Both stderr
files are empty. UTC completion times are 2026-10-14T21:52:29.7017899Z and
2026-10-14T21:52:55.8175617Z. These generated local files are not publication inputs.
The experiment worktree is detached at
`9b95d2113f755ec5222216940332fc31f050fdd5`; the source hashes and unchanged promoted
kernel identify the actual build rather than that old base revision.

After the actual210 result, only the wrapper's executable-path default was made
portable: use CARGO_TARGET_DIR when set, otherwise taskRoot/target, while retaining
an explicit -Executable override. New metadata also records the runner SHA-256.
The original dry2 and actual210 runs used runner hash
`F3898FF18C68F9193D0F818CDB6D0F3C7EFBE21CA2F981FB9B936C45F5DB40B9`;
the current portable runner hash is the table entry above. The Rust source, binary
and original raw records were not changed or rerun.

A small `dry2-portable` confirmation used the same executable hash, resolved from
the shared CARGO_TARGET_DIR, with two actual million-row tables and one query per
table. Both exact-result/wrong-table checks passed; exit0, empty stderr, no watchdog
stop. Wall time was 1013.1760 ms, child CPU3500.0000 ms, peak RSS369,840,128 bytes
and peak commit366,460,928 bytes. UTC completion was
2026-10-14T21:56:05.7108925Z. Its three raw files are retained beside the original
records. This validates the runner portability change, not another210-table
measurement.
