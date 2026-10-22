# Fused Query SHA mathematical facade

[`hash`](hash.rs) selects the engine SHA suite for the same closed fused Query
AIR and original guarded `query::Prepared`. `query::Expected` still independently
captures the original QueryCt, Cw/Cs contexts and roots, full Stmt96 root and
header13. All4096 coefficients, mask reversal/high zeros, S/E/K equations and
private-key custody use the existing writer and
[H2048/MAIN416/PP545 backend](../program/query_formation/README.md).

`hash::prove(&expected, prepared)` returns unverified bytes;
`hash::verify(&expected, bytes)` performs the actual receiving native check and
returns mathematical unit success. It creates no original `VerifiedFormation`,
Word/DATA installation, fresh-head or SQL result. `hash::profile_digest()` and
the distinct `DCSHQF01` identity bind the new suite and original mathematical
profile. `hash::MAX_EVIDENCE_BYTES` retains the4MiB cap. There is no frame fallback.

`hash::Prover` retains independently reconstructed PUBLIC PP for one exact full
Expected; every proof consumes new protected inputs under a fresh private OS
configuration. `hash::Verifier` independently reconstructs the public setup and
retains only CommonData, the same immutable AIR, assessment and Expected. It
drops producer-only PP and all setup configuration/RNG owners. Every subsequent
`verify(bytes)` decodes and checks the actual proof, including after a previous
success or failure. Both constructors take only `&Expected`; no supplied setup,
config callback, checked flag or cross-query receipt is accepted.

Direct dependencies are the original private dense backend/writer, the
[engine hash suite](../../../../bfv-hiding-stark/README.md), pinned P3 batch,
bounded Postcard and SHA2. New setup, codec and lifecycle source is instantiated
at compile time against the two closed DATA/Query host families. The original
profiles, native verification and result types retain their behavior.

PUBLIC PP preparation is reusable only for this captured query and belongs to
the complete latency measurement. Local native proof success establishes no
composed security, agreed freshness, lock result or complete500ms SQL timing.
