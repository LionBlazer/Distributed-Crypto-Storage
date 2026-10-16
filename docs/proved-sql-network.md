# Proved SQL over independent peer processes

Status on 2026-10-15: genuine proof-first SELECT, INSERT and additive UPDATE are
connected to the live network client and playground. These operations run against
actual encrypted files in separate processes. Target requirements are unchanged;
production deployment, full SQL and 50–100 ms queries are not achieved.

## Implemented acceptance boundary

The owner authenticates a complete encrypted index and selected data pages at exact
data/index commitments. No matching entry is silently truncated when the fixed
256-row operation budget is exceeded: unsupported workloads reject. It encrypts the
original selected values into a fresh, query-bound BFV request. A peer executes the
homomorphic operation and generates a genuine Plonky3 STARK for all 81,920 residues
of the unchanged N8192/Q218 profile. The client independently derives the canonical
statement, verifies before decrypting, and checks the confirmed version again.

SELECT uses a public column-only polynomial over every padded slot. Match/presence
bits stay encrypted; the mask does not encode the private number of matches. The
old encrypted-mask operation remains separate and cannot be substituted across
domains. Projection/order/LIMIT are bound by the client plan; LIMIT applies after
all logical shards have complete verified results. Final decryption is owner work.

INSERT encrypts old rows and the incoming row separately, already at its public
append position. The proven operation adds the two ciphertexts; there is no
preassembled encrypted answer or staging rotation. UPDATE proves encrypted amount
addition with carry/overflow handling. Only decrypted **proved output** is compactly
resealed. No owner recomputation of expected SQL values substitutes for a proof.
One overflowing shard prevents every shard of the write from publishing.

The client stages real ciphertext copies and signs a complete old/new head manifest.
Public peers check owner authorization, exact source heads, every encrypted job and
its real proof. A canonical internal journal verifies SHA256d work, exact targets,
retargets, timestamps and cumulative-work forks. Durable append fsyncs before ACK;
the client independently validates the same blocks and requires confirmations and
read-after-write ancestry. Missing proof/body/ciphertext/freshness rejects.

Private index authentication and compact AEAD finalization are designated-client
responsibilities. The public job proof binds exact FHE operands/result and agreed
heads, but is not an independently public proof of AEAD decryption or all private
SQL semantics. An owner signature provides authorization, never arithmetic evidence.

## Failure handling and remaining trust

Corrupt/unavailable holders are skipped in favor of actual surviving copies. A
missing table never falls back to GUI fixtures or a previously displayed answer.
Synchronized snapshot metadata changes only after every required shard authenticates.
Transient heavy-operation `Busy` has bounded retry; quota/proof failures remain
distinct. An endpoint found unreachable is skipped for subsequent phases of that
operation, then retried on the next operation.

Write confirmation can fail after the transition is durable. Such an outcome must
remain pending, with the original transition/result retained: recovery confirms that
exact write rather than executing INSERT or addition again. A different statement
must not obscure an ambiguous write. `Error::PendingMutation` exposes its stable
identity; `Session::resume_pending()` or identical SQL retrieves the original outcome.
The real-process interruption test clamps the actual peer quota immediately after
the transition ACK, prevents its confirmation append, then restores quota. INSERT
and additive UPDATE both resume exactly once, with no extra row or increment.
Owner-process recovery remains unimplemented;
pending state and authorization/decryption keys currently live with the owner.

Self-signed transport identities require no invitation CA and still verify real
certificate/handshake signatures and endpoint pins. Node-local administrative
credentials do not confer consensus weight. Public work validation has no fixed
voter roster or external network. Automated discovery and autonomous production
mining are unimplemented; the manager currently requests bounded real work RPCs.

The caller pins genesis and the entire `ProtocolProfile`. Core provides no default
work target or confirmation count. Tests/playground explicitly choose an easy
target and one descendant confirmation. Those values demonstrate protocol behavior,
not a production attack budget. Consensus security needs adequate honest effective
hashpower, honest network reachability and propagation/clock bounds. Confirmation is
probabilistic; reorganization is surfaced. An eclipsed client cannot prove that no
unseen newer state exists.

The initial logical shard set is fixed. Adding infrastructure holders does not add
votes. Copies on the local machine share its failure domain. Independent placement,
automatic distributed repair, storage proofs, owner key recovery, arbitrary schemas,
DELETE, joins and general transactions remain open. COUNT/SUM parse but lack the
required proof circuit and are explicitly rejected by the live verified path.

## Cost and optimization

The initial product proof used 91 Boolean witness bits per residue and required
19.059 s to generate. Moving public-ciphertext-derived quotient/carry values into
a bounded certificate with independent verifier preprocessing reduced the cost.
Integer limb constraints prevent Goldilocks wraparound; all original residues,
192 FRI queries, degree-five extension and the model's 128-bit floor remain intact.
The complete certificate/proof checks are described in
[bfv-query-proof](../crates/bfv-query-proof/README.md).

Peer `JobVerifier` caches at most 128 verified digests, keyed by all bytes of the
canonical input, output, proof and parameter commitment. Only successful genuine
verification inserts an entry. Authorization, manifest coverage, source contexts,
head structure, work and freshness are always checked again. The cache saves repeated
arithmetic verification during mining and subsequent publication, not initial proof
generation or client completeness/freshness checks.

Single observed full-query run on Windows, AMD Ryzen 9 9950X3D2 (16 cores/32 threads),
Rust 1.99 release, `-C target-cpu=native`, two Rayon threads per process, two actual
loopback peers, four initial public rows and two physical copies per shard:

| Complete accepted operation | Observed latency |
| --- | ---: |
| SELECT all four rows | 1,488 ms |
| SELECT projected/filter/LIMIT | 1,513 ms |
| INSERT, including durable journal confirmation | 1,126 ms |
| UPDATE three selected rows across two shards, including confirmation | 1,978 ms |
| SELECT after both writes | 1,561 ms |
| SELECT with one process stopped, including failure detection | 3,564 ms |

Setup took 951 ms separately. The final three-test run passed in 23.09 s, including
pending-write recovery, overflow rejection, process loss and journal restart. The
highest observed OS peak working set of an individual peer was 265,420,800 bytes
(253.1 MiB); the owner/test process peaked at 212,639,744 bytes (202.8 MiB).
Monitoring the owned process tree at 50 ms intervals observed at most 430,604,288
bytes simultaneous working set (410.7 MiB), including its Windows console helper.
Child discovery ran every 500 ms. Individual OS peak counters and sampled simultaneous
totals are different metrics; these single-run development-load observations are
not workload-independent memory bounds or tail-latency guarantees.

For comparison, the earlier portable two-shard SELECT observations were 6.2–6.6 s;
its initial INSERT/UPDATE measurements preceded the duplicate-verification cache.
These historical measurements used CPU-native compilation. The current launcher
instead packages a portable host plus fixed AVX2 and AVX-512 proof kernels and
selects a compatible kernel once at process startup. SIMD changes no FHE or proof
security parameters. The earlier measurements do not establish the latency of this
new packaging, and neither previously measured configuration meets 50–100 ms.

A product proof frame alone is approximately 1.6 MiB, plus 655,400 canonical output
bytes and the request. This overhead matters on real links. No WAN latency or
large-dataset throughput is inferred from loopback tests. Journal bodies retain
encrypted jobs/proofs and grow until the pinned metadata/quota cap; proof pruning
is unimplemented. Compact collection reclaims superseded known versions while
unknown failed staging remains. The tiny test database demonstrates no 2x storage
ratio, indefinite update capacity or production-scale 1–2 GB memory guarantee.

### Ten-lane proof layout (2026-10-16)

The arithmetic engine now packs all 81,920 residues into ten lanes and 8,192 rows,
removing the eight-lane trace's 37.5% padding. Both complete public traces shrink
without changing BFV parameters, integer constraints, FRI settings or the runtime
128-bit security-model floor. New proof magics and backend profile v2 reject old
frames and stale kernels; existing journals containing old proofs are not migrated.
Rebuild the packaged applications and both kernels together with `dcs-launch`.

One before/after run of `proved_sql` on the same Windows host, with two Rayon
threads per process, native owner/test compilation, AVX-512 peer kernels, the same
easy local confirmation profile and four public initial rows on two peers:

| Complete accepted operation | Eight lanes | Ten lanes |
| --- | ---: | ---: |
| SELECT all four rows | 1,666 ms | 970 ms |
| SELECT projected/filter/LIMIT | 1,826 ms | 979 ms |
| INSERT, including durable confirmation | 1,241 ms | 879 ms |
| UPDATE three rows across two shards, including confirmation | 2,221 ms | 1,444 ms |
| SELECT after both writes | 1,854 ms | 1,196 ms |
| SELECT with one process stopped, including detection | 3,715 ms | 3,031 ms |

These are individual development observations, not tail-latency guarantees. The
500-ms goal requested on 2026-10-16 remains unmet. The six real-process SQL/fault
tests passed, including pending-write recovery and rejecting unavailable,
corrupted or unauthorized state. Portable/AVX2/AVX-512 proofs cross-verified and
rejected tampering. Memory was not remeasured in this run. Full PostgreSQL SQL,
transactions, `FOR UPDATE` and `SKIP LOCKED` remain unimplemented; this optimization
does not change their fail-closed status or the owner-online index trust boundary.

### Bounded concurrent SELECT (2026-10-16)

The fixed-schema client now processes at most two shards concurrently, with a
query-local queue per exact executor endpoint. Both SQL clients share the same
proof-request/failover implementation. All shard results must authenticate and
verify before the final freshness check, global ordering and LIMIT; writes remain
sequential. Two requests failing over to one surviving peer queue their own work
without increasing its heavy-operation allowance.

At the unchanged two-thread budget, one subsequent development run observed
839 ms for the initial two-shard SELECT and 743 ms for projected/filter/LIMIT.
With eight Rayon threads in the owner and explicitly eight in each peer, the
same four-row real-process scenario observed 329 ms and 351 ms respectively;
SELECT after writes took 436 ms. INSERT still took 653 ms and the two-shard
UPDATE 1,094 ms including durable confirmation. A stopped-process SELECT took
2,417 ms including failure detection. These tiny-loopback observations establish
neither a larger workload bound nor a 500-ms guarantee for ordinary writes.

A second eight-thread run monitored the owned test process and its direct peer
children using Windows process counters, with 100 ms sleeps between discovery
and sampling. Owner peak working set was 237,297,664 bytes (226.3 MiB); the
largest individual peer peak was 194,654,208 bytes (185.6 MiB). The largest sampled
simultaneous owner/peer working set was 310,743,040 bytes (296.3 MiB). Individual
OS peaks and sampled simultaneous totals differ; this is no process-memory bound.
Under that monitoring, the same SELECTs took 381/336/373 ms, but INSERT and UPDATE
took 1,749/2,322 ms. These slower writes are retained as observed outliers rather
than attributed conclusively to the monitor. The complete measurement excludes
compilation and includes normal setup separately; generated logs stay in `.local/`.

The two-thread default remains the reproducible low-CPU test profile. To repeat
the eight-thread observation, add `DCS_TEST_PEER_THREADS=8` and
`RAYON_NUM_THREADS=8` to the native-build environment and run the exact
`proved_select_insert_update_survive_a_process_loss_and_journal_restart` test.
The test helper accepts peer budgets from one to eight; production resource
policy remains outside the storage-client library.

Real-process regressions observe both proof frames sent before either response
is read, reject LIMIT 1 when both copies of a later shard are corrupt, and cancel
both SELECT workers before successfully running a new query. Typed streaming,
existing replica failures and pending-write recovery remain covered separately.

The [PostgreSQL implementation contract](postgresql-contract.md) records the
remaining operator, transaction, lock-state and finality work. No SQL locking
behavior is supplied by the internal RPC queue.

## Reproduction and module ownership

```powershell
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
cargo test --release --locked -p dcs-peer --test proved_sql -- --nocapture --test-threads=1
cargo test --release --locked -p dcs-peer --test proved_faults -- --test-threads=1
```

The single Zed GUI task and `cargo run --release --locked -p dcs-launch -- playground`
build both SIMD kernels with explicitly bounded instruction sets. Add
`--build-only` to package them without opening the GUI. The
[kernel interoperability test](../apps/proof-kernel/README.md) cross-verifies real
proofs between portable and supported SIMD engines. Tests use
fresh in-memory keys, explicitly public rows, hidden owned child processes and
ignored `.local/` state. No GUI launch, desktop focus or accepting proof stub is needed.

The [arithmetic proof crate](../crates/bfv-query-proof/README.md),
[compact query composer](../crates/compact-query/README.md),
[version journal](../crates/version-journal/README.md),
[peer runtime](../crates/peer-runtime/README.md) and
[owner client](../crates/storage-client/README.md) own their separate contracts.
The [playground](../playground/README.md) manages processes and displays results;
core depends on none of its fixtures, widgets or simulation logic.

Final portable workspace validation passed 427 tests with zero failures and three
intentional opt-in GUI/process exclusions. The two opt-in ProcessBackend scenarios
also passed separately with actual hidden peers. Strict all-target/all-feature
workspace Clippy, formatting, architecture and requirements-mirror checks passed.
The native three-test measurement additionally passed the same genuine network
acceptance and pending-recovery contracts. Historical unverified diagnostics remain
separate and cannot convert to checked arithmetic evidence.
