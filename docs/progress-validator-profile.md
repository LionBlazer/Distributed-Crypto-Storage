# Progress validator timing experiment

On 2026-10-20, an isolated four-process replay passed in **254.89 seconds**.
It reuses original public encrypted evidence, omits FHE production, and still
requires actual cold application verification and a newly obtained weighted QC.
This gives a smaller gate for investigating validator and transport behavior.
It establishes no full-query speedup or full SQL acceptance.

## Measured boundary

The experiment used four fresh independently running `dcs-peer` processes with
scratch WALs and the original public signing fixtures. It cold-imported original
prefix slots 1--3, then offered the exact original slot-4 Header/Body and all
141 proof roles. The archived target QC was reference metadata only: it was
discarded before child launch and was never seeded into the new validators.
The client independently verified the first new-process weighted certificate,
cancelled outstanding RPCs, joined every worker, and required all four peers to
exit successfully. No FHE producer or owner private bank was started.

The [opt-in timing instrument](../crates/peer-runtime/src/finality/README.md)
was enabled with `DCS_PUBLIC_TIMINGS=1`; Rayon remained at two threads per
process. The 1,792-MiB per-process observation fuse, absolute 1,800-second
operation budget and 180-second transport I/O budget were unchanged. There
was no forced cleanup, observed fuse, monitor fault or source change during
the run. Observed per-validator peak private usage was 651.9--656.0 MB; this
sampling does not prove a formal whole-process memory bound.

| Interval or observation | Measured value |
| --- | ---: |
| Complete Rust test, including prefix and joined peer shutdown | 254.890 s |
| Target start to all four uploads complete | 13.843 s |
| Each target Submit RPC, including cold import | 45.552--45.894 s |
| Target start to first independently valid QC | 188.878 s |
| Selected QC to all RPC workers joined | 0.477 s |
| Actual target application checks | 12: three on each validator |
| Duration of an individual target application check | 41.187--45.063 s |
| Longest observed target actor queue wait | 43.989 s |
| Longest target floor append/sync section | 0.000711 s |
| Longest target voter advance section | 0.000771 s |

Every measured finality call invoked the application checker at most once.
Repeated checks occurred across separate calls: import, local Propose or remote
Proposal, and the deciding Vote or Certificate. They include Source, Core and
product verification; the instrument does not isolate a particular proof or
attribute all of that time to cryptographic arithmetic. Queue wait, handler
and library intervals overlap. Their sums are not elapsed query time.

The result identifies repeated application verification and actor queueing as
the largest observed costs in this workload. It provides no evidence that disk
sync or raw bandwidth dominates this case. Skipping those application checks
would require a separately designed, bound reuse contract; a successful hash,
earlier QC or decode is not a replacement for proof verification.

## Provenance and limits

This was an **unpublished v3 implementation/test snapshot on top of**
`03151fa322ecf442d8c205737174f6837623f0b0`, not validation of that commit alone.
Its 1,704-file source-map SHA-256 was
`7C58AA6A9FBC278BDD4B56E8E3791A7044E5A6B8FE35C512AF7501DD2078B75E`.
The source map is encoded as sorted-key compact UTF-8 JSON mapping repository
paths to uppercase RAW file SHA-256 values. Generated local outputs are excluded.
The locally retained observer result SHA-256 is
`0317FB13FB937017A51B6AAD85FAC9AB0B7F4CDDC232D50C80D43D7846ED8691`;
the audited profile is
`D9A758A6940CA41F03BEBE21BCDC3678A725F561CB1F4645A8B14529070BF97B`.
Public archive files and generated diagnostics are not committed.

The test has separate upload and control scheduling, unlike the full Driver.
It is not a controlled before/after latency comparison. It does not exercise
fresh FHE generation, owner completion, SQL lock contention, WAL recovery,
production signer restart or a fresh agreed-head lease. The complete five-job
WAIT/SKIP LOCKED/NOWAIT gate remains open for the v3 implementation.

The [fast-check rule](../AGENTS.md#verification-and-completion) keeps ordinary
changes on the smallest relevant checks and reserves expensive gates for
affected boundaries or unresolved failures. The replay target's 11 cheap
negative/lifecycle tests passed in 0.02 seconds; compilation and execution
took 12.52 seconds. Those tests do not count as mathematical or distributed
acceptance. The original longer measurements remain documented in
[Joint participant finality](joint-participant-finality.md).
