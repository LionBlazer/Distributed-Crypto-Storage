# Semantic main-witness NTT machines

`prepare_public(Request, Output)` preserves the original complete single N8192
relation, fixed native arithmetic, data bus labels and four range tables. Its
private auxiliary certificate is prover input, never verifier input or authority.

The additive `batch_shape` / `prepare_batch` boundary accepts exactly 2, 4 or 8 complete
ordered independent operations. Directions and Q5/P5 bases may differ per instance.
Each request binding must be distinct. Constructors mint only complete machines;
there are no public raw stages or arbitrary bus names. Data edges are scoped by
instance and stage; the four fixed range buses are shared. `PreparedBatch::witness`
reuses the original sealed certificate writer one instance at a time, checks
complete bindings, and sums u64/canonical-Gold frequencies before emitting each
provider exactly once. Main/PP cell totals and interaction weights are exposed
as metadata for the consumer's actual SDK assessment.

This module owns semantic rows, routes, canonical integer bounds and public
preprocessing. Consumers own hash domains, transcript/envelope, proof backend,
keys, exact security analysis, framing/caps and acceptance policy. Local constraint
tests discard lookup messages and therefore do not establish global LogUp soundness.
The separate [batch experiment](../../../../experiments/bfv-ntt-batch-proof/README.md)
contains genuine proof and adversarial gates. The four feature suites passed
7/9/17/20 tests, and the consumer passed all nine owning tests, including genuine
2/4/8-operation proofs and four altered-program rejection cases. See its
[native validation](../../../../experiments/bfv-ntt-batch-proof/VALIDATION.md)
for exact scope and resource observations. A batch remains independent arithmetic,
not a causal MulRelin chain or SQL result.
