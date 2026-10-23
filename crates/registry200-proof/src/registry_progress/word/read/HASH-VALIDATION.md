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

## Buffered leaf updates and CPU scaling, 2026-10-23

Commit `edce852` batches the identical canonical SHA leaf message into fixed
512-byte stack blocks. Independent byte vectors, block-boundary/unknown-length
iterator cases and overflow rejection passed in the engine's 17 focused primitive
tests. Hash domains, profiles, transcript, randomness, AIRs and query counts are
unchanged. The read test now records `current_num_threads()` instead of a fixed
two-worker label; the observer checks that it matches its configured pool.

Native build r553 includes this leaf implementation and the actual thread label.
On an AMD Ryzen 9 9950X3D2 (16 cores, 32 logical processors; reported maximum clock
4300 MHz), captures r554–r561 ran the SAME complete owning test in separate
processes. All eight passed, including the original hostile/replay cases. No
other build or native capture ran concurrently. The 120-second / 1792 MiB held-handle
guards and 20 ms sampler were retained; every capture had zero faults and cleanup.

| Shared Rayon workers | Captures | Different-query local ms, min / median / max |
| --- | --- | --- |
|2|r554|774.150 /774.150 /774.150|
|4|r555|516.870 /516.870 /516.870|
|8|r556,r558,r560|449.693 /472.261 /486.425|
|16|r557,r559,r561|455.883 /459.932 /498.397|

The enclosing different-query timer includes fresh protected request preparation,
real BFV product and certificate, fresh Word/Query proving, independent receiving
setup (overlapping proving), fresh Word/Query/product checking and client
completion. Only previously verified immutable DATA and role-only Word public
setup are reused. It is the same scope as r542, whose earlier two-worker single
observation was 1402.567 ms. That historical comparison is not a throughput or tail
latency guarantee; CPU scheduling and OS-seeded proof randomness vary between runs.

Across these captures, maximum whole-process OS working-set peak was 594530304
bytes. The different-query proof frames occupied 6959714–6975682 bytes. Even
the below 500 ms local observations exclude network I/O, a fresh agreed head and
decentralized locks. They establish neither the 500 ms full-query target nor a
production security grant. The live Predicate guard remains closed.

The r553 executable is 14294528 bytes, SHA256
`46CAFAC08800A4261C2BA873440513395436C46860E9CAB86C5E5A6BA355682A`.
Receipt SHA256 values for the three 8-worker captures are:

- r556:`E51D0339F2580DEC77B9C4033E439F2B4B8A0E251B5F9FD2091A51EAF12C4EFC`
- r558:`3D48859FA1A23A6B7554EC8C5271B2D2C808D846793B9CF6458E55C6FCC0D1B0`
- r560:`1C74840F53C7B1B1DE9DC15D7E2A42F60D39D70AF61DDC2D54033DD15D610737`

Each receipt pins the source hashes, exact executable, sampler, test contract,
actual pool size, per-process resources and all phase lines. Reproduction uses
the same owning test with `RAYON_NUM_THREADS=2`, `4`, `8` or `16` and the release
native build; comparing worker counts requires separate processes because Rayon
initializes its global pool once.
