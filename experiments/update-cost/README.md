# Full UPDATE RPC observation

A standard-library-only analysis consumer for the optional metadata recorder in
[dcs-peer's real process fixture](../../apps/dcs-peer/README.md). It does not execute
SQL, generate an answer or change proof, freshness, admission or durable behavior.

Build the process test first. Run its exact full scenario with
`DCS_TEST_RPC_PROFILE=1`, `RAYON_NUM_THREADS=8`, `DCS_TEST_PEER_THREADS=8` and
`--exact --nocapture --test-threads=1`, saving stdout/stderr to an ignored log. The
fixture still checks real STARKs, actual changed rows, fresh heads, process loss
and journal restart. Profiling is separate from ordinary latency samples.

```sh
python experiments/update-cost/analyze.py .local/update-cost/run.log
```

The reader allows at most 4,096 events plus one summary, bounded lines and a
bounded total line count. It rejects a missing/multiple summary or incomplete/
truncated envelope. Successful RPCs require ordered sent/read callbacks with matching
operation names and Trace byte counts; all offsets and durations must be finite,
nonnegative and inside the envelope. Failed calls may lack frame callbacks. It
rejects duplicate phases/completions and orphan activities. It ignores ordinary
fixture output and reads only
`rpc_observation=` JSON records. Generated `trace.jsonl` and `analysis.json` are
written beside the supplied log; keep them under ignored `.local/`.

`rpc_covered_wall_ms` merges overlapping RPC intervals; `rpc_elapsed_sum_ms` sums
individual calls and must not be treated as an exclusive wall-time cost. Phase
sums separate combined wire encode/TLS/connect/write, sent-to-reply-read, and
response-decode tails. Local gaps combine owner verification, completion/staging
and request construction. Public callbacks cannot isolate peer proof/FSYNC or
separate TLS from listener waiting. A source-correlated hypothesis still needs a
matched complete-operation before/after experiment; this tool sets no clock
threshold or pass/fail latency target.

Run the owning metadata-contract tests with:

```sh
python -B -m unittest discover -s experiments/update-cost -p 'test_*.py'
```

The [2026-10-16 measurements](MEASUREMENTS.md) record the matched peer-listener
comparison, all observed ordinary SQL operations, exact artifact identities and
separate memory-observation limitations. The samples support those fixtures only.
