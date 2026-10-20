# Joint participant process validation

The full fixed-N4 Acquire scenario also passed: four OS validators certified
the actual hidden-predicate FHE operation, and the client freshly checked and
completed its exact result. This establishes the bounded historical operation;
general SQL admission, durable owner-state installation and a current lock lease
remain unavailable. The separate two-Acquire gate also passed with a genuinely
held conflicting row, SKIP LOCKED before OFFSET/LIMIT and fresh client completion.

The owning Joint control scenario passed with four independently running
`dcs-peer` validators. The original participant's separate four-process
regression also passed. These are bounded prototype process gates; they do not
admit SQL queries or establish a current database lock.

## Actual process gates

The source inventory contained 1,535 files and had SHA-256
`2E99F5B16AADC2594A15B83C10A3649CB6FB19138455438FB007DA3AF60C6764`.
All file hashes and the complete Git file inventory were unchanged after the
following release/offline/locked tests:

```sh
cargo test --release --offline --locked -p dcs-peer --no-fail-fast \
  --test joint_finality --test participant_finality -- \
  --nocapture --test-threads=1
```

| Test | Result | Runtime |
| --- | --- | --- |
| `four_os_joint_peers_prefetch_genuine_bootstrap_begin_wait_for_quorum_and_reopen_exact_decisions` | Passed | 292.03 s |
| `four_os_source_lifecycle_peers_certify_one_competing_acquire_and_recover_without_quorum_shortcuts` | Passed | 676.75 s |

The whole monitored command, including compilation, took 992.869 seconds. Its
stdout SHA-256 is
`A6771C7E435D52B12DDC6966B4C49DFE663D216B6421462FE99E478D7E754AF6`;
stderr SHA-256 is
`0516114101F3821F044F972445D314316A960D7CC25055BFD58D42E08D67D9A3`.

The Joint scenario uses genuine Source/Lifecycle/ControlKind evidence and
owner-signed Bodies. A reachable 2+2 partition produces no QC. After healing,
the validators finalize Bootstrap and Begin. Missing, tampered, foreign-request
and unauthorized evidence is refused. A lost acknowledgement and exact retries
produce no second decision. All four independently retain genuine QCs for one
semantic Empty decision. After restart, each node replays its own exact QC bytes
and the same semantic decisions; different valid signer subsets are permitted.

The original regression covers competing lifecycle candidates, a 2+2 partition,
healing, independently verified followers, a three-node quorum and offline
catch-up. Its lifecycle Acquire is not a hidden-predicate FHE computation.

The Windows observer retained the actual process handles. Across 19,656 samples,
the largest working set was 1,404,706,816 bytes, the largest private usage was
1,404,674,048 bytes and the largest OS peak working set was 1,404,719,104 bytes.
The largest observed sampling gap was 605.56 ms. The existing 1,792-MiB-per-process
soft fuse did not fire. Sampling is not a formal peak-memory bound or a complete
DCS resource guarantee.

## Subsequent replay and queue corrections

The next source inventory contained 1,536 files and had SHA-256
`72EB302B55F05AA8031FE75599F51999E5C30EF5E0051963F6F714014E3C3EB8`.
It adds authenticated PREVOTE duplicate/stale handling and makes the Joint
relay's local Outbound/GetBlock calls retain the same absolute Joint expiry.
The original service's wire protocol and timeouts are unchanged.

All 44 work-finality and 19 registry200-finality runtime tests passed. Three new
queue-boundary tests also passed: exact metadata expiry, lease release on queue
refusal, and joining an actual queued reply after its admission expiry. Those
tests use the real bounded channel and accounting leases; they contain no
signer, simulated proof or SQL authority. Fourteen doc/compile-fail tests,
strict all-target Clippy for the five affected packages, formatting and
`requirements_sync` passed. All 1,536 file hashes and the file inventory were
unchanged after these checks.

The PREVOTE shortcut authenticates the full Context, value and actual QC first.
Only a noncurrent PREVOTE is rejected before application replay; only an exact
retained current `(value, QC)` is a whole-apply no-op. Different certificates
still run the actual application. PRECOMMIT, signer advance, durable recovery
and closed client checkpoint validation retain their full application checks.

## Immutable profile and equivalent PREVOTE validation

The next 1,537-file source inventory had SHA-256
`533D771BE568D0587152C6C022980A888359FC8EFEA47BBBA4DAD19DF6B9ED24`.
It caches only the process-constant graph protocol identity and ignores an
independently authenticated current PREVOTE QC when the first retained POL has
the same exact value bytes. Different signer subsets never replace that first
QC or add vote-map entries. PRECOMMIT, new values, durable recovery and closed
client verification retain their actual application checks.

All 73 runtime tests passed: eight graph-proof, 19 registry200-finality and
46 work-finality cases. The graph identity also passed a separately launched
cold eight-thread test and the unchanged independent published-profile golden
test. Fourteen doc/compile-fail cases, strict Clippy for all six affected
packages, formatting and a direct canonical requirements/mirror comparison
passed. All source hashes and the file inventory were unchanged afterwards.

The four-OS Joint process test passed again in 318.19 seconds; the whole command
took 344.897 seconds. Its stdout SHA-256 is
`EC5E15A24150F1A2ACE7530AF2D0D2B72304098466BABC07FCAEE1F3B1AEC4C3`;
stderr SHA-256 is
`83671BA40A6C7A1F76AF4A0208986AF3B97B03CF0F4398C370EC301A378C3144`.
Its partition, rejection, acknowledgement-loss and exact-own-QC reopening
assertions are unchanged. This is no end-to-end query speedup claim.

The opt-in profile-only observation measured 35.3611 ms for 16 uncached identity
computations and 0.0470 ms for 65,536 warm cached calls. These measurements concern
constant identity hashing, with equality checks; they measure neither proof
verification nor SQL latency. No query, proof or authorization result is cached.

## Full FHE Acquire validation

The successful run used the 1,537-file source inventory
`83E7312E084F722003AD65369186BC4864BA0DAB320840893C00BCE11D1D8682`
and the explicitly rebuilt peer binary
`16D1549F582ADEED2413A0C31D3F6505B4646504118F77F3FF5E678C53977918`.
All source hashes, the complete Git file inventory and the binary were unchanged
after the run. The four validators and the separate FHE peer were actual
`dcs-peer` processes; no local fixture assembled a QC or supplied a query answer.

With an explicitly selected `DCS_PEER_EXE`, the owning command was:

```sh
cargo test --release --offline --locked -p storage-client \
  --features private-input-proofs --lib \
  private_predicate::source::locking::joint::tests::full_acquire::four_os_quorum_and_fhe_peer_complete_only_the_exact_own_joint_acquire_after_fresh_replay \
  -- --exact --ignored --nocapture --test-threads=1
```

The test passed in 2,352.46 seconds. The whole monitored command, including
compilation, took 2,366.191 seconds. These times include setup, Bootstrap/Begin,
four-validator admission/finality, fresh client verification and hostile-artifact
checks; they are not a steady-state SQL latency measurement.

| Completed phase | Cumulative scenario time |
| --- | --- |
| Genuine Bootstrap/Begin QCs and client replay | 98.038 s |
| Source/input16/Lifecycle/Link preparation; private producers dropped | 207.085 s |
| Separate OS FHE input16/output118 through clean END/EOF | 754.224 s |
| All fixed-role evidence uploaded to all four validators | 786.833 s |
| All four candidate import acknowledgements | 1,280.403 s |
| All four QCs and exact candidate bytes fetched | 2,161.776 s |
| Fresh keyless proof/QC replay matched the own operation | 2,255.359 s |
| One decrypt and one committed projection | 2,255.365 s |

The hidden query selects ages 0 or 255 with OFFSET 1, LIMIT 1 and FOR UPDATE
SKIP LOCKED. The actual FHE result returns original ordinal 3 with age 255 and
amount 65,534. The checked next Registry holds both OFFSET-stepped ordinal 0 and
returned ordinal 3. This case has no competing held row, so it gives no positive
credit to actual SKIP LOCKED contention.

The same genuine operation rejects each changed private Result144 flag bank,
actor transaction and salt before decryption. A foreign intent and an older
genuine Begin QC are refused. A latest semantic retry freshly verifies again.
A real QC cannot replace missing output record 117, and a fresh depot rejects a
corrupt retained Link. Before that independent Link challenge, the test restores
the exact public output bytes and opens a new healthy participant ledger; the
refusal cannot be attributed to the earlier missing-evidence poison.

Across 57,519 observations, the largest working set was 1,487,007,744 bytes,
private usage 1,514,885,120 bytes and OS peak working set 1,487,884,288 bytes.
The largest sampling gap was 3,007.38 ms. The unchanged 1,792-MiB-per-process soft
fuse did not fire. Sampling does not establish a formal whole-process RAM bound.
The stdout SHA-256 is
`68F6D07958D9503946FEACD3D55EF50BC42F9536AA05D86EEE345568E63333A0`;
stderr SHA-256 is
`DD485625CF988FC08F83237AFC94586CC5DEA1B6DF559D79CC60A3205AF040B9`.

### Earlier failed attempts

The first complete Acquire scenario generated genuine input16 evidence, ran a
separate OS FHE peer to produce output118, and uploaded the fixed-role evidence
to all four validators. It failed before an Acquire QC became observable within
the test's 30-minute consensus observation window. The whole failing command
took 3,139.417 seconds. Client-side fresh Acquire replay and completion were not
reached and receive no positive validation credit.

The successful run above resolves that first gate. The separate real prior-lock
scenario passed later, as recorded below. Source-only tests, control QCs, cached
presence, TLS success and successful decryption cannot substitute for that gate.

The next full run used the 1,537-file inventory
`039FF2B7ED674755EFF124B0F2F030D6985F816EC914653181B2CB33A07A9F12`
and the rebuilt peer binary
`6EB2E2A7B3A284F7B405312200B53EAD440EB5D9AB7D2FD202532FB720BB59C7`.
It again completed genuine FHE input16/output118 through clean END/EOF, at
664.390 seconds from scenario start. An upload then failed with
`connection timed out`, before all four validators had the fixed-role evidence
and before candidate admission or an Acquire QC. The whole command failed in
741.172 seconds. All source files, the complete file inventory and the binary
were unchanged after that failure. Its stdout SHA-256 is
`2D0229799B935F680B3592A22C58BB0A17D44A87288307BD15E55E5EC5AA3D40`;
stderr SHA-256 is
`F416D5D94D56573A1DFB14627AB67D685A102FE62F140439126AF3FB46B03495`.
The retained error does not distinguish TCP connection, TLS handshake or
established-connection timeout. This run establishes no Acquire consensus or
client completion result.

The successful owning gate retries only interrupted public proof-blob uploads, using
the exact same signed Body, role, BlobId and bytes. Invalid-data/authorization
errors remain terminal. The original bounded observation window, whole-test
supervision, production connection/I/O deadlines, proof checks and quorum are
unchanged. FHE stream completion and candidate/QC/client verification are never
replaced by an upload acknowledgement.

## Bounded relay and real prior-lock contention

The next 1,539-file source inventory had SHA-256
`8E7DF7A50EE65D889649013356EFA693A6125DC0CB4BA028031307BADDDBF801`.
The explicitly rebuilt `dcs-peer` binary contained 21,413,888 bytes and had SHA-256
`9F2CA4E7E4EEED6C07A979480647854F4BF4D6034087C74BDA0E0A62F9CB68E3`.
Every source file, the complete Git inventory, both supervision runners, the
binary and all recorded native logs/results matched after validation. The final
local audit receipt had SHA-256
`B513A58A8A06F0E0FDF0A479F884711267317381803CC461431533D71723438D`.
Documentation was updated after that audit.

Joint relay delivery now uses at most three owned, joined workers over disjoint
rotating neighbor lanes. The same `synchronize` implementation, proof gate,
control ledger, signer, protocol and production deadlines remain in force. An
internal prefetch snapshot superseded by a genuine decision returns Busy; retry
captures a new snapshot and repeats actual verification. Bad evidence still
fails. The owning test overlaps only its four initial exact-candidate offers,
joins all workers and requires four real acknowledgements before fetching QCs.
These changes establish no quantified query speedup.

The peer-runtime library passed 110 tests, with two unrelated opt-in tests left
ignored. All five new relay scheduling/lifecycle cases passed. The original
four-OS participant regression passed in 602.04 seconds and the Joint four-OS
regression in 246.72 seconds; their whole monitored command took 868.605 seconds.
Strict all-target Clippy for all six affected packages, formatting and the direct
canonical requirements/mirror comparison passed. The earlier relay candidate's
local-reader shutdown test failed on Windows; the revised peer-EOF test passes
but does not resolve prompt local-receive interruption. See the owning
[relay record](../crates/peer-runtime/src/finality/joint_server/README.md).

With the explicit binary above, the contention command was:

```sh
cargo test --release --offline --locked -p storage-client \
  --features private-input-proofs --lib \
  private_predicate::source::locking::joint::tests::full_acquire::contention::four_os_real_prior_acquire_makes_skip_locked_conflict_precede_offset_and_limit \
  -- --exact --ignored --nocapture --test-threads=1
```

It passed in 3,049.43 seconds. The whole monitored command, including compilation,
took 3,062.618 seconds. Four OS validators and one separate OS FHE peer performed
two actual sequential Acquire operations. Each produced genuine input16/output118
through clean END/EOF, uploaded the fixed-role evidence to all four validators,
obtained actual Acquire QCs and completed fresh Source/input/product/Lifecycle/Link
verification before one consuming client completion. No fixture fabricated a held
Registry, QC, FHE result or accepted answer. Private producers were dropped before
the second public replay; the client BFV Owner remained only for allowed decrypt.

The first hidden query is `WHERE age IN (0) LIMIT 1 FOR UPDATE`: it returns
ordinal 0 with age 0 and amount 65,535. Its actually completed Registry holds only
ordinal 0 for transaction 1, with revision 3. The second query is
`WHERE age IN (0,255) LIMIT 1 OFFSET 1 FOR UPDATE SKIP LOCKED`. It consumes that
exact completed state. The conflicting ordinal 0 is skipped before OFFSET;
available ordinal 3 is locked and consumed by OFFSET, leaving an empty result.
The final Registry retains transaction 1's ordinal 0 and transaction 2's ordinal 3,
with revision 4, transaction-2 sequence 2 and agreed slot 5. The expected behavior
matches [PostgreSQL's locking clause](https://www.postgresql.org/docs/18/sql-select.html#SQL-FOR-UPDATE-SHARE).
There is only one available matching row, so this case needs no ordering assumption
among multiple available matches. Every validator and the FHE peer joined cleanly.

Across 89,393 process observations, maximum working set and OS peak working set
were 1,525,182,464 bytes; maximum private usage was 1,550,684,160 bytes. The largest
sampling gap was 496.91 ms. Neither the unchanged 1,792-MiB-per-process soft fuse
nor the finite whole-run supervisor fired. Sampling does not prove a formal RAM
bound. This includes two full operations, setup, prior-history replay, consensus
and cleanup; it is not a steady-state SQL latency measurement.
The stdout SHA-256 is
`1968BA4374E3187121AFC1D15A204BD0555D2A2D9FA35CEE1497A4C8FC7236A2`;
stderr SHA-256 is
`06DE843F51CAD8E281C73C4432C537F69FD36115FD5331C8CE1755A5A40B90A9`.

Owner restart/Vault reconciliation, a fresh-head barrier, delegated rights,
encrypted data mutation, general SQL session admission and unrestricted
PostgreSQL semantics remain separate work. No Session/GUI guard is opened by
these process or queue tests.
