# Progress private owner validation

This change connects the separate `private_predicate::progress` owner to genuine
Source/input16/Core896 preparation, the existing independent OS FHE worker,
exact Progress application and weighted-QC replay, typed private Result160
opening, and a strict encrypted owner WAL. It keeps the existing Session SQL
capability guards closed. It does not establish four-validator WAIT continuation
or general PostgreSQL support.

## Implemented boundary

One closed owner keeps its actual Progress History and evidence ingress in the
same participant depot and quota, with the embedding process's shared ProofGate.
Fresh predicate attempts restore original BFV Owner/Anchor/Ready custody and
verify full Key33. Only actual remote input16/output118 computation can supply a
sealed Computed object. The exact Request/Manifest/owner-signed Body is synced
before submission. Completion freshly checks its own operation expectation,
application proofs and weighted certificate, opens the captured private result,
and checks the complete successor bank. Bank and client ledger are installed
only after their single AEAD Commit record is synced.

Done rows come from decryption of that operation's proven encrypted product and
its proven selected flags. Completion and replay do not run another WHERE or
OFFSET/LIMIT pass. Parked has no rows, terminal ACK or lastCompleted advancement;
its synced private statement and stable transaction ID permit the other client
to End. Resume preserves the original statement and Key33 while creating fresh
attempt identities. The latter behavior still needs the separate genuine
network contention gate.

## Native checks

| Check | Result | Test body | Complete Cargo invocation |
| --- | --- | ---: | ---: |
| Strict storage-client Clippy, all targets | PASS | n/a | 3.252 s |
| Fast owner tests | 6 passed, 1 heavy ignored | 0.07 s | 36.299 s |
| Explicit OS FHE / local QC / recovery | 1 passed | 584.93 s | 585.768 s |

The fast test set covers exact private extents and canonical encodings, stable
transaction compaction, explicit SQL syntax boundaries, the private Parked/End/
terminal-ACK ledger, real AEAD round trips, wrong authority and strict truncation.
Its scoped-quota fault test starts with a synced record: BeforeWrite preserves
that prefix, PartialWrite rejects the torn tail, and AfterSync recovers both
records. An uncertain write poisons sibling budgets; fresh inventory after all
handles close charges the actual disk extent.

The ignored gate uses public non-secret fixture rows and one independently
running OS FHE peer. It genuinely performs Bootstrap803, Begin815, one
Predicate896 plus remote product118, exact local weighted QC completion and
Result160 opening. It injects loss of the Commit acknowledgement after fsync,
requires the live owner to reject further use, drops the original owner/quota,
strictly reopens all proofs/QCs and private records, decrypts the original
encrypted response, checks the selected values, acknowledges it and performs
actual End815. Its certificates use three actual distinct signatures under a
four-member weighted fixture; they are locally assembled, not obtained from
four validator processes.

## Full owning scenario intervals

| Interval | Time |
| --- | ---: |
| Original Source/BFV custody fixture | 6.882 s |
| Bootstrap803 and local weighted QC | 7.751 s |
| Owner installation and bootstrap replay | 1.675 s |
| Begin815, QC, fsync and ACK | 11.722 s |
| OS peer launch and original setup installation | 0.183 s |
| Original Ready restoration, Source/input16/Core896 preparation | 104.026 s |
| Remote FHE/product118 verification and recording | 362.121 s |
| Exact submission/QC, Result160 and fsync with lost acknowledgement | 37.578 s |
| Cold full proof/QC replay, decryption and ACK | 42.527 s |
| End815, QC and fsync | 10.365 s |

These are cumulative test milestones converted to consecutive intervals. They
include computation, verification and any waits in each interval. The complete
scenario includes recovery and multiple control operations; it is not the
latency of one SQL request. It is not directly comparable with the historical
39-minute four-validator scenario.

The observer recorded a maximum OS peak working set of 1,523,871,744 bytes and maximum sampled private bytes of 1,593,991,168 across individual observed processes. Maximum sampling gap was 675.654 ms. The 1,792 MiB per-process soft fuse and 1,800-second whole-test budget did not fire. These are observations of this bounded fixture, not a production-wide RAM guarantee.

## Reproduction and source receipts

Use Rust 1.99 MSVC, the locked dependencies, two Cargo jobs and two Rayon threads.
The recorded run uses the original production proof profiles, verification,
resource accounting and operation timeouts. Select the independently checked
absolute path of the actual `dcs-peer` binary in `DCS_PEER_EXE`; this gate reuses
the unchanged binary from the preceding Progress network validation.

```text
cargo clippy --release --offline --locked -p storage-client --features private-input-proofs --all-targets -- -D warnings
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::progress::tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::progress::tests::actual_remote_product_qc_result160_sync_reopen_ack_and_end -- --ignored --exact --nocapture --test-threads=1
```

Parent commit: `565077ef869722a5096fed04699c04f40181edfa`. All three successful gates used identical inventories of 1,684 source files; each was unchanged through its command. Only module documentation and this record were edited afterwards.

| Gate | Source receipt SHA256 | After receipt SHA256 |
| --- | --- | --- |
| clippy | `50AFFFCEEFA39002EE23364E236009FBBB86AD1F62EB8E1DF3CF2C9D85AF7AF2` | `FBE5CBD2A88E9E4AC2E29D26BF9F9769E7615762564B9A2E5CC7B45A8197AD50` |
| fast | `50AFFFCEEFA39002EE23364E236009FBBB86AD1F62EB8E1DF3CF2C9D85AF7AF2` | `0AED8CDD829C43192DF05466A3E82118624806FC055BC3B2C8A03A073F1A6696` |
| heavy | `2752147457C37E1B733051A2C9C9F4073001244FCEE759E5CEC7EB3A2A0202F7` | `EAB677B65E364479EF1E6B3BDB2137B830C4451324D68487D84D3C732B3BEC64` |

The local combined profile is `.local/progress-owner-validation-r1/profile.json`, SHA256 `3DF1514463087F94E59D886386AC33F1B99F81283E1246A4ED87DC8C5C7D5DD6`. It pins exact logs, process samples and final sampled CPU counters. The unchanged worker executable is 22,098,944 bytes, SHA256 `DA2A94D12EC36FCC2F54210D8CA73B79980D482BEBA7993BBE899CA797254825`.

Independent source review covered the frozen Owner17 manifest `84087576B930D81D094B90BD0C4BFBAC80431B1D591100D59E25635E0B0252C3` and final controlled Root17 review manifest `3C61A00120DEF266DE098DE7C65CD01CB51382A89832D15A1BE4FFB78B856408`. It is source review, separate from the native passes above.

First strict Clippy exposed five API/ownership errors; a subsequent pass exposed
unused storage and lint diagnostics. The first fast run caught the new test's
incorrect table name `rows`; the fixed schema uses `records`. All five test SQL
literals, including the ignored scenario, were corrected before expensive FHE
execution. The controlled fixes preserve proof, QC, canonical decoding and fsync
ordering. The added ledger workflow and strengthened WAL fault case require no
additional Source/Key/FHE proof generation. Failed native receipts are retained
locally; generated logs, keys and state are not repository artifacts.

## Remaining acceptance work

The next actual network gate needs A Acquire, B Parked, owner cold replay, A End
and B fresh Resume, with three genuine remote products and four independently
running validators. Combined NOWAIT coverage needs a fourth genuine product,
the actual failed bank and typed error/savepoint behavior. No model lock bank or
fixture-computed response can replace these gates.

The Progress network Driver, Session/PGwire bridge, current-head policy, parked
rollback/cancellation, deadlock handling, mutable-row EPQ, arbitrary schemas,
writers/MVCC and general SQL remain unfinished. Existing fail-closed guards are
retained. The architectural and arithmetic tests above do not grant network SQL
acceptance or a current lock lease.
