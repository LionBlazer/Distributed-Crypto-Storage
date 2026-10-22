# Fixed hash-suite native composition checkpoint

2026-10-22. The extracted `bfv-hiding-stark::hash` suite now runs the actual
Source, Role3, dense DATA, Predicate Word and fused Query AIRs, followed by the
original conditional product certificate. Protected Owner preparations, original
AIRs/writers/PP cells, independent complete expectations and hiding budgets are
retained. Core has no dependency on the historical experiment package.

The optimized owning test
`registry_progress::word::read::hash::tests::five_real_hash_air_proofs_and_original_product_bind_all_endpoints_before_completion`
passed in native capture r542. It uses real BFV encryption/multiplication, five
independent native proofs and the original product checker; owner decryption and
the independent ring oracle occur only after verification. A second genuine
Role3 proof with another Cw verifies independently and is rejected when spliced
into the original DATA chain. Canonically reframed native OOD damage, each missing
proof, changed Key29/Cs/Cw/DATA nonce/ciphertext, changed Word context at the same
Stmt96, changed Query vector/nonce/ordered pair/output and stale query proofs
are rejected. New frames do not mint old verified tokens. Retained DATA compares
the full immutable expectation; Word, Query and product checks remain fresh.

The complete test process, including hostile cases and a different retained-DATA
query, lasted 13628.9216 ms. OS peak working set was579022848 bytes, peak private
bytes567406592, with666 samples and no observer faults or cleanup. The exact-image
held-handle observer enforced120 seconds/1792MiB and sampled every20ms.

The initial owner setup plus complete local mathematics took5814.995ms. A
different query using the independently verified immutable DATA and reusable
role-only Word producer setup took **1402.567ms**: Word285.129ms,
Query964.945ms, real FHE product/certificate42.194ms, receiving setup259.679ms,
fresh receiving102.480ms and client completion1.492ms. Receiving setup overlaps
proof generation and is included in the enclosing timer; rounded phases must
not be summed as a sequential execution. All threads share the two-worker Rayon
pool. Total six-frame bytes were25867857; different-query frames were6969666.

These are local component observations, **not full network SQL latency**.
Network I/O, current agreed head, decentralized locks and the quantified composed
hash/Fiat–Shamir/Merkle model remain incomplete. The live Predicate admission guard
is unchanged. The500ms full-query target is not met.

The passing native build is r541, executable14270976 bytes,
SHA256 `BA4C716155769E082570439B51B4A6659074A7FCB96FA1BB17B8A1057572E126`.
The r542 receipt SHA256 is
`25F164ACE811B06A902AA14A339ED7551C39AA71B14530F9E2F5416B0DE6E82E`.
Final all-target strict Clippy passed for the engine, Formation and Registry proof
crates (r546–r548). Its only code repair after the native capture was an unused
`Default` implementation forwarding to the unchanged explicit challenger `new()`;
the validated native paths continue to call `new()` directly. Newly authored
standalone primitive/wire tests and doc guards were compiled/type-checked as
applicable, but were not separately executed in this checkpoint. Generated
receipts, proofs, logs and binaries remain local.
