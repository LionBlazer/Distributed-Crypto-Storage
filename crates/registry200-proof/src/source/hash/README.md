# SourceVersion under the separate SHA suite

`prove(&SourceVersionExpected, &Witness)` and
`verify(&SourceVersionExpected, &[u8])` reuse the complete original Source AIR
and its private trace writer. The low-level configuration and bounded canonical
codec now belong to `bfv-hiding-stark::hash`; core never depends on an experiment.

The original measured candidate `DCSHSF01` profile/encoding is retained by this
extraction. Source width7161, height512, PV691, sixteen quotient chunks and all
hiding budgets are unchanged. The caller independently retains the full sealed
expectation, not just a version identifier. Limits remain20MiB,16384 sequence
elements and24Mi container slots. The shared codec already checks canonical
proof bytes, so the wrapper does not serialize the complete proof twice.

Success returns unit and mints no old VerifiedSourceVersion or current-head
token. SDK panics fail closed. The owning native tests retain honest independent
verification, old-suite baseline, changed state/key/native opening/context,
cross-suite and malformed/resource rejection examples.

The composed hash model remains conditional. This API is mathematical evidence
for the separate candidate, not SQL admission or an end-to-end latency claim.
