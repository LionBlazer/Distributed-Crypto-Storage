# DATA SHA mathematical facade

[`hash`](data_hash.rs) provides a separate SHA-suite proof path over the same original
`data::Expected`, move-only `data::Prepared`, dense H2048 AIR and complete private
writer. It preserves every Formation equation, all4096 coefficients, Cw4112,
Cs528, original secret custody and independent public association. There are no
new private-input getters, raw-trace APIs or caller-selected configurations.

`hash::prove(&expected, prepared)` returns unverified bytes;
`hash::verify(&expected, bytes)` returns unit success only after canonical bounded
decoding and actual native `verify_batch`. It does not construct the original
`VerifiedDataFormation`, an installed DATA result or a SQL/freshness grant.
`hash::profile_digest()` identifies the distinct `DCSHDD01` frame; its cap is
`hash::MAX_EVIDENCE_BYTES` (4MiB). Original DATA profiles and frames remain separate.

`hash::Prover::new(&expected)` independently derives and retains PUBLIC PP for
that complete captured expectation. Each `prove(prepared)` consumes new guarded
inputs and creates fresh private OS masks/salts. `hash::Verifier::new(&expected)`
independently rebuilds the same public commitment and drops producer-only PP.
Every `verify(bytes)` repeats canonical decoding and actual native verification;
neither success nor failure is cached. Neither setup accepts a supplied SDK object,
replacement Expected or alternate verifier. Preparation belongs to total latency.

The [closed backend](program/dense_data_inventory/README.md) reuses the original
FullAir, metadata assessment, PP factory and protected writer. Its SHA path depends
on the [engine hash suite](../../../bfv-hiding-stark/README.md), native P3 batch,
bounded Postcard and SHA2. Deterministically seeded public setup configurations
die before private proving. All SHA digests remain raw32 bytes; field and EF5
values retain canonical Gold decoding. Full framing binds the hash-suite profile,
original mathematical/native profile and independent Expected binding.

These APIs provide local mathematical components. Composed cryptographic
security, lattice assurance, agreed freshness and the complete500ms SQL target
still require their separate owning assessments and measurements. Native results
and failure coverage are reported by the full-chain consumer's executed gates.
