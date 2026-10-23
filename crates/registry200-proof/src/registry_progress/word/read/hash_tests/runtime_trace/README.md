# Typed commitments in actual receiving traces

`typed_caps` is a test-only consumer of the parent complete-stream parser,
already accepted native fixture frames, engine fixed SHA MMCS, P3 proof types,
matrix dimensions and field operations. It binds each observed CAP to its fixed
MAIN/PP/AUX/quotient/random/FRI role and ordered base/EF5 matrix/salt/depth schema.
The STARK observation order and PCS opening order are mapped explicitly.

The helper decodes each genuine proof once and authenticates its actual input
opening rows against the captured roots using the same 192 sample-derived indices.
An explicitly public unused RNG seed constructs only this test's fixed MMCS;
verification draws no randomness and supplies no setup to a receiving facade.
Five damaged DATA PP openings must reject. No extra AIR/PCS/FHE execution is used.

Every FRI cap, sibling EF5, per-query salt row and frontier bound is mapped to the
fixed two-EF5 binary schema. The other EF5 coordinate is computed internally by
the original native verifier; this helper does not claim independent capture of
that computed row. It neither extracts complete PP words nor implements an
adaptive raw-oracle parser, accepting capability or live SQL path.
