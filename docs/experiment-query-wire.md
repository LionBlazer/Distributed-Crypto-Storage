# Narrower encrypted query wire experiment

Status: integrated experimental backend after library, SQL-adapter and headless
GUI validation. The candidate was measured in `compact-fhe-query` and then checked
in `compact-playground`. The preceding baseline was published as `6763556`;
this report keeps its results separate from the
[composed backend report](experiment-compact-query.md). No kernel changes were
made between the two comparison pairs below.

The consistent result is smaller request/response encodings. Sixteen-row COUNT/SUM
improved in both pairs. One- and four-row timings regressed in the first pair and
improved in the confirmation, during which the same baseline executable ran much
slower. The experiment therefore establishes a traffic improvement and a promising
large-group kernel, not a universal speedup or a 500 ms query guarantee.

## Changes and cryptographic boundary

The public Owner, Evaluator, Table, PreparedQuery and Aggregate APIs stay the same.
The private experimental wire format changes; no compatibility/migration layer is
provided. The canonical peer table and encrypted index are unchanged. Neither
plain rows, masks nor FHE row overlays are persisted at the peer.

- The owner emits a public canonical predicate shape: Equal when both bounds are
  equal; otherwise AtLeast for upper=255, AtMost for lower=0, or Range. Every
  transmitted threshold remains FheUint8. Equality/one-sided predicates encrypt
  one bound instead of two, and the evaluator performs the corresponding genuine
  encrypted comparison. This exposes the canonical one-sided operator shape in
  addition to the already visible selected addresses/count; the leakage model
  remains an explicit experimental policy. Canonical AtLeast also reveals the
  implicit upper endpoint 255, and AtMost reveals the implicit lower endpoint 0.
  Neither this leakage nor the alternative concealed-access policy is approved
  as the project's final privacy contract.
- Exactly one selected row returns the encrypted predicate bit as COUNT and an
  encrypted u16 conditional amount as SUM. For zero or 2..256 selected rows the
  output holds FheUint10 COUNT and FheUint24 SUM. Owner-facing fields are still
  u32. The baseline already accumulated COUNT in ten bits but widened its output
  to FheUint32; its SUM and SUM output were FheUint32.
- MAX_ROWS=256 implies count <=256 and sum <=256*65535=16,776,960 <2^24.
  Compile-time bounds and a real 256-row FHE API test protect this exactness. The
  independently enforced 1,000,000-row table limit is not the selected-row limit.
  Complete indexed groups exceeding the selection budget still fail before any
  FHE mask materialization; results are never truncated.
- The SUM selection uses the official CPU `IfThenZero::if_then_zero` operation.
  The pinned implementation clones the encrypted amount and invokes
  `zero_out_if_condition_is_false` under the encrypted predicate. It does not
  decrypt the predicate or replace the encrypted computation with owner answers.
  Overflow detection, encrypted global rejection and the final original/candidate
  UPDATE CMUX remain in place. Overflow still preserves every selected amount.

TFHE-rs stays at 1.8.1 with the unchanged
`PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128` ConfigBuilder parameter set. The
crate enables TFHE's `extended-types=[]` feature solely to export FheUint24. No
parameter, noise, key or security setting was reduced. Primary source inspected
from the pinned local registry package (VCS commit
`187fc0b95ab35352422deec6c027d0bd8743b6db`):
[IfThenZero implementation](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/high_level_api/booleans/base.rs#L565),
[prelude export](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/high_level_api/prelude.rs#L12),
[extended integer exports](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/high_level_api/integers/mod.rs#L8).

Page proofs establish exact encrypted data membership under the trusted head.
They are not proofs of query evaluation or index completeness from an untrusted
index builder. Index completeness depends on the owner-built authenticated V2
index, trusted independent index head and exact encrypted table-head binding.
Aggregate decryption is explicitly unverified. UPDATE verification repeats the
selected plaintext work locally at the owner before staging fresh compact pages;
it is not the project's required succinct query proof.

## Validation and source identity

Release tests passed: 23 compact-query tests (including 11 padded-index tests) and
21 compact-store tests, 44 total. The new behavior tests exercise Equal/AtLeast/
AtMost/Range hits and misses with amount=65535, reduced one-bound wire size, empty
UPDATE preserving the head, and the real maximum complete 256-row result
COUNT=256/SUM=16,776,960. Existing tests cover wrong owner/domain, stale heads,
duplicate addresses, tampering, full-scan predicates, mixed matches/misses,
overflow global atomicity, unchanged storage size, forks and restart. Strict
release Clippy for both crates and all targets passed; formatting/diff checks
passed. This is library validation; dependent GUI/SQL validation is separate.

~~~powershell
$env:CARGO_HOME='E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home'
$env:CARGO_TARGET_DIR='E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target'
$env:RAYON_NUM_THREADS='8'
& E:/Users/white/.cargo/bin/cargo.exe test --release --locked --offline -p compact-query -p compact-store
& E:/Users/white/.cargo/bin/cargo.exe clippy --release --locked --offline -p compact-query -p compact-store --all-targets -- -D warnings
~~~

The original candidate was uncommitted on detached base
`9b95d2113f755ec5222216940332fc31f050fdd5`; the following frozen file hashes identify
the measured kernel rather than that old base revision:

| Candidate change | SHA-256 |
| --- | --- |
| crates/compact-query/Cargo.toml | 4652DFAD56CB3F87320A30CCA4F0D48AA468A98467EE25985F30919571F60043 |
| src/wire.rs | 55FB342AEB54AC3CB2D1C1796F1796BB89CAE903173A2A47FFE4D37CDAC20039 |
| src/owner.rs | 12999E4AD2659AF7A306639B0538160245CE72055DCE76A7BE4A692DCFE2E955 |
| src/evaluator.rs | B4026ED213DD0AF802A6E2CC99558749CE916D3E16C03F91615E9652A42A2700 |
| src/tests.rs | 45A1B6AE4BE29E4E439B5F17C823AA75CD3121ADEE2736E27353B81548849FEA |

Shared with the scoped/padded baseline: src/lib.rs SHA-256
`B4A64DE28BA8B053859260903344867A71A1C3FECC4C9FDE9C9CCEA9F797D065`,
src/index.rs `0E6A64731D4FB85397DEFDD5B2CAAABDE2F908AB3327113B16A6F2ACDB146296`,
src/index/tests.rs `44EADE2E658C342F0F7869F5180895D9A769D376D51541390A7961CDAD75C679`,
and examples/compact_query.rs
`5C1326B393974EA0C7FC1B096C3219F79D928E1F1288DB43F1C2C2545BF56FE9`.
Only the manifest, four source/test files above, module README and this separate
report were transferred for candidate integration. Cargo.lock differs in that older worktree
because it lacks the already integrated GUI adapter; it must not replace the
current integration lockfile. The extra TFHE feature adds no package dependency.

Archived executable SHA-256:

| Role | Local filename | SHA-256 |
| --- | --- | --- |
| scoped+padded baseline | padded-scoped-baseline.exe | 6270031806379DB785AE278AC2762D5D1E70FFDBA2743762DF03DB5CF0C142FE |
| narrower candidate | width-candidate.exe | 5F0A6AA061511C6DD5A97EBD3B3EDFCD214AE9BF1974540ED10008E0089EDCF8 |

Both archives and raw records are retained under
`E:/Users/white/.codex/worktrees/compact-fhe-query/DistributedCryptoStorage/.local/fhe-research/compact-query/`.
They are local generated artifacts, excluded from publication. The baseline is an
exact copy of the owner's `combined-padded-baseline.exe`; that original was not
overwritten. The benchmark executable is identical in both candidate runs.

## Measurement protocol

Each process creates fresh keys and the same public 1,000,000-row fixture, one
logical table, one replica, 256 rows/data page, padded V2 index, eight shared Rayon
workers and an opt-in budget of eight scoped initiating threads. The fixture is
dropped before timed queries. There is no process affinity or global OS change.
The machine reports 32 logical processors and Windows NT 10.0.26200.0.

Every aggregate includes owner index lookup/proofs/decryption, compact data page
verification/mask and predicate encryption, complete request serialization, peer
decode/lookup/proof verification, compact-to-FHE conversion, genuine FHE predicate/
COUNT/SUM, encrypted output serialization, owner output decode and decryption.
Setup and cold in-memory image/key restore are reported separately. Network
transport, disk IO, replication, consensus and computation proofs are unmeasured.

Each point UPDATE additionally verifies every selected output locally, atomically
stages fresh-nonce/revision data and index binding pages, writes the in-memory Table,
encodes and freshly decodes both complete canonical images, rebuilds hashes and
rejects its old output against the new trusted head. The example also runs actual
4-row, 16-row and empty UPDATEs, and a 21-row range aggregate. UPDATE figures below
include writeback and fresh complete-image decode. Samples are sequential; a
request never runs concurrently with another timed request.

The hidden headless child wrapper uses Windows GetProcessMemoryInfo after exit
with a retained process handle for whole-process peak working set/commit. It
includes fixture/key setup and serialization peaks, not just the FHE kernel.
Child CPU time was not captured and the handle was already disposed when reviewed;
wall time cannot separate scheduling/frequency changes from useful CPU work.
Other research agents were held to source/read-only work. External load/frequency
was not established, and no cause is assigned to the observed variation.

Pair A executes baseline then candidate with `1000000 5 30 8 8`. Pair B executes
baseline then candidate with `1000000 20 1 8 8`. Example arguments are
`rows aggregate_samples_per_selection repeated_point_updates rayon_workers row_workers`.
Pair B increases read samples, not UPDATE samples; its one point UPDATE is a single
observation. Percentiles use the example's nearest-rank rule; p99 with 5 or 20
samples is the maximum and is not a tail-latency estimate.

Reproduction after checking each archive hash:

~~~powershell
& ./padded-scoped-baseline.exe 1000000 5 30 8 8
& ./width-candidate.exe 1000000 5 30 8 8
& ./padded-scoped-baseline.exe 1000000 20 1 8 8
& ./width-candidate.exe 1000000 20 1 8 8
~~~

Local raw labels, each with `.jsonl`, `.stderr.txt` and `.process.json`:
`width-pair-padded-baseline`, `width-pair-padded-candidate`,
`width-confirm20-baseline`, `width-confirm20-candidate`. All stderr files are empty
and every child exited zero. Per-stage times, byte counts, result assertions,
constant-size checks and stale-output checks are retained in those records.

## Read comparisons

All times are milliseconds. A p95 from five samples is their maximum.

| Selected rows / predicate | Pair A baseline p50 / p95 | Pair A candidate p50 / p95 | Pair B baseline p50 / p95 | Pair B candidate p50 / p95 |
| --- | ---: | ---: | ---: | ---: |
| 1 / Equal | 72.579 / 78.229 | 78.357 / 95.546 | 141.526 / 161.792 | 57.781 / 62.652 |
| 4 / Equal | 347.042 / 358.023 | 373.950 / 399.150 | 544.388 / 586.753 | 273.694 / 303.775 |
| 16 / Equal | 1347.193 / 1471.353 | 1079.411 / 1101.860 | 1769.848 / 2008.327 | 973.731 / 1080.275 |
| 0 / Equal | 0.657 / 0.990 | 0.261 / 0.548 | 0.642 / 0.720 | 0.237 / 0.364 |
| 21 / Range, one sample | 2068.594 | 1674.573 | 2452.346 | 1523.785 |

Pair B aggregate maxima (1/4/16/0 rows): baseline
165.377 / 642.818 / 2075.437 / 1.572 ms; candidate
64.713 / 318.475 / 1080.348 / 0.486 ms.

For the same immutable baseline, Pair B p50 rose relative to Pair A by about 95%
for one row, 57% for four and 31% for sixteen. The candidate also varied between
runs. These are separate fresh processes rather than randomized/interleaved
trials, and the source cannot explain that environmental difference. Pair A's
small-group regressions remain part of the result. No configured case is silently
capped or removed to meet a latency target. Sixteen-row/range reads exceed 500 ms
in both candidate runs.

Mean aggregate stages below expose the full accounting for candidate Pair B,
in milliseconds. Separate stage means are descriptive, not interchangeable with
the full-query p50 above. Tiny differences from the measured full mean are ordinary
framework/loop bookkeeping.

| Selected rows | Index proof/decrypt | Data auth + mask/predicate encrypt | Request encode | Peer decode + proof | Compact-to-FHE | FHE predicate/aggregate | Output encode + owner decode | Owner decrypt | Full mean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | .041 | .694 | .062 | .084 | 23.251 | 34.183 | .052 | .010 | 58.402 |
| 4 | .037 | 2.327 | .171 | .285 | 70.648 | 203.694 | .182 | .014 | 277.534 |
| 16 | .038 | 9.487 | .661 | 1.123 | 313.283 | 659.457 | .200 | .016 | 985.301 |
| 0 | .010 | .171 | .006 | .007 | .000 | .006 | .050 | .010 | .261 |

For Pair A, mean FHE aggregate time at 1/4/16 rows was baseline
47.422 / 265.716 / 954.693 ms versus candidate
48.066 / 277.426 / 715.663 ms. Mean compact conversion was
23.478 / 75.498 / 348.483 versus 32.328 / 96.293 / 354.804 ms. This supports keeping
both the small-group regression and large-group improvement visible rather than
attributing every full-query difference to narrowed arithmetic alone.

## Updates, cold restore and process resources

| Measurement | Pair A baseline | Pair A candidate | Pair B baseline | Pair B candidate |
| --- | ---: | ---: | ---: | ---: |
| Point UPDATE p50 / p95 (A n=30; B n=1) | 245.968 / 262.380 | 231.799 / 259.089 | 325.725 / 325.725 | 208.371 / 208.371 |
| Point UPDATE max | 262.656 | 267.735 | 325.725 | 208.371 |
| 4-row UPDATE, one sample | 871.300 | 954.644 | 1195.656 | 755.783 |
| 16-row UPDATE, one sample | 2996.530 | 2952.467 | 4131.786 | 2797.231 |
| Empty UPDATE + fresh decode, one sample | 5.994 | 6.180 | 8.305 | 5.656 |
| Cold in-memory key/image restore + first query | 213.429 | 182.821 | 368.240 | 198.733 |
| Whole child wall time | 22997.233 | 21351.709 | 59175.549 | 32748.830 |
| Kernel peak working set, bytes | 392089600 | 391356416 | 392351744 | 392478720 |
| Kernel peak process commit, bytes | 388800512 | 388796416 | 389541888 | 389255168 |

UTC process-completion timestamps: Pair A baseline
2026-10-14T21:18:33.927547Z, candidate 21:18:55.3186052Z; Pair B baseline
21:23:31.0036576Z, candidate 21:24:35.3815818Z. Pair B's candidate launch followed a
wrapper orchestration gap; no extra benchmark ran in that gap. The wrapper's
PowerShell exit-code check was corrected for a .NET-launched child; the already
completed baseline process/raw record was preserved.

All processes verified exact expected counts/sums and UPDATE outputs. Every
repeated point UPDATE freshly decoded both images and rejected its stale output.
Data+index stayed exactly 5,229,212 bytes after 30 point updates plus the two
changing multirow updates in Pair A (revision32), and after one point update plus
those two updates in Pair B (revision3). Empty UPDATE did not change the trusted
head. The earlier stable combined-backend 100-update run remains recorded in its
own report; these two comparison pairs contain 30 and 1 point updates. The final
integration run below separately exercises 100 point updates on the new kernel.

## Traffic and persistent accounting

Request/response numbers are full serialized encrypted COUNT/SUM messages, not
just logical values. Equality uses one bound in the candidate. General Range
continues to carry two encrypted bounds; AtLeast/AtMost carry one. The request
savings below include enum/discriminant changes rather than a rounded FHE estimate.

| Selected rows | Baseline request | Candidate request | Baseline response | Candidate response |
| --- | ---: | ---: | ---: | ---: |
| 1 | 329546 | 263669 | 527169 | 148497 |
| 4 | 922418 | 856541 | 527169 | 280217 |
| 16 | 3293906 | 3228029 | 527169 | 280217 |
| 0 | 131922 | 66045 | 527169 | 280217 |

Request savings are 65,877 bytes for every displayed equality. Response savings
are 378,672 bytes (one row, 71.8%) or 246,952 bytes (other groups, 46.8%). These
exact byte counts repeat in both process pairs despite timing variation. One-row
request+response still costs 412,166 bytes, before compact/index page responses or
network framing; reduced wire does not imply a low-bandwidth distributed SLA.

Authenticated index page responses add 8,896 bytes per nonempty displayed query or
4,448 bytes for empty selection. Owner data page responses add 1,216 bytes and peer
page lookup/proof responses another 1,216 bytes for these co-located selected rows;
empty selections add neither. Full externalized bytes for the one-row flow are
423,494 when those separately measured page responses are counted once each. The
index remains owner-assisted and reveals candidate count/addresses at the peer;
this experiment does not implement private distributed index access.

For the 1,000,000-row fixture (logical three-byte rows, 3,000,000 bytes), both
versions have identical permanent accounting:

| Item | Bytes |
| --- | ---: |
| Canonical compact encrypted data | 3187648 |
| Canonical padded encrypted index | 2041564 |
| Data + index | 5229212 |
| Rebuildable data/index hash material, extra | 281824 |
| Owner serialized FHE secret key | 31268 |
| Shared public evaluation key wire | 180610708 |
| Owner symmetric keys + domain | 80 |
| Trusted independent data/index heads | 224 |
| Joint canonical data/index + complete keys/owner state | 185871492 |

Data+index expansion is 1.743071x, or 1.837012x including rebuildable hashes. Joint
storage with the complete shared FHE key set is 61.957164x at this fixture size;
the 2x all-material target has not been established. Replication is one and no
persistent FHE rows/plaintext/pads are stored at the peer. The unchanged bounded
256-row materialization limit, index leakage, lack of computation proofs and
multirow query latency still prevent an arbitrary-SQL feasibility claim.

The next possible experiment is a public-cardinality kernel dispatch retaining
the older small-group kernel and narrow wire while using the measured 24-bit/
IfThenZero path for larger groups. No such hybrid is implemented or measured here;
a cutoff needs separate paired evidence rather than selection from this jittery
pair alone.

## Final integration validation

The prototype now uses this kernel for its consistently smaller wire and measured
large-group improvement. It does not claim that every small-group query became
faster. The measured executable retained SHA-256
`5F0A6AA061511C6DD5A97EBD3B3EDFCD214AE9BF1974540ED10008E0089EDCF8`
after integration. No cryptographic parameters, table/index format or GUI SQL
adapter were changed during this transfer.

The final release check reran all 23 compact-query tests, 59 headless GUI
library/UI/worker tests and 13 real SQL workflow tests. The unchanged compact-store
passed its 21 tests in the candidate check above. Strict release Clippy for
compact-query and fhe-playground, all targets, and workspace formatting passed.
The SQL integration build encountered the user's already running, locked GUI
executable; the freshly compiled integration-test executable was identified by its
build timestamp and run directly. All 13 tests passed. The running application
was not stopped and no GUI was opened.

An additional full million-row run used `1000000 5 100 8 8`, with the same fixture,
accounting, serialization, independent image reconstruction and exact result checks
as the comparison pairs. Raw local label: `narrow-padded-r8-final`, completed at
2026-10-14T21:34:32.6066829Z. Every child exited zero.

| Measurement | Final integrated kernel, milliseconds |
| --- | ---: |
| 1-row COUNT/SUM p50 / p95, n=5 | 85.809 / 91.732 |
| 4-row COUNT/SUM p50 / p95, n=5 | 392.984 / 419.419 |
| 16-row COUNT/SUM p50 / p95, n=5 | 1248.963 / 1334.402 |
| Empty COUNT/SUM p50 / p95, n=5 | 0.591 / 0.696 |
| 21-row range, one sample | 1854.610 |
| Point UPDATE + fresh full-image decode p50 / p95 / max, n=100 | 278.394 / 329.034 / 361.888 |
| 4-row / 16-row UPDATE + fresh decode, one sample each | 1059.821 / 3499.743 |
| Empty UPDATE + fresh decode, one sample | 7.321 |
| Cold in-memory key/image restore + first query | 190.623 |
| Whole child wall time | 44657.653 |

Every repeated UPDATE reconstructed both complete encrypted images, rejected its
stale output and kept data+index at exactly 5,229,212 bytes. Final revision was
102. GetProcessMemoryInfo reported peak working set 391,892,992 bytes (373.74 MiB)
and peak process commit 389,259,264 bytes. This run confirms the lifecycle and
resource results, not a 500 ms bound for larger selections. Its timings also show
why the faster confirmation pair is not used as a universal SLA.

The unchanged real SQL adapter was separately exercised headlessly with
`cargo run --release --locked --offline -p fhe-playground --example sql_workload -- 128 8 5`.
Five one-row queries took 85.219–96.613 ms; five four-row queries took
402.836–423.426 ms; five absent queries took 0.740–0.847 ms. One actual point UPDATE
took 251.653 ms and retained the tiny fixture's 3,125 data+index bytes (544+2,581
for 384 logical bytes). These are local SQL boundary measurements without network,
replication or malicious-peer computation proofs. Raw local label:
`gui-compact-narrow-r8.jsonl`.
