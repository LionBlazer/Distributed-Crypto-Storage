# CPU budgets and parallel product checking

Executed2026-10-22 on AMD Ryzen9 9950X3D2,16 cores/32 logical processors,
Windows/MSVC Rust1.99.0, release opt-level3 and native CPU. Each image ran in a
fresh process with2,8 or16 Rayon workers. Tests now report the actual pool size
through the existing pinned `p3-maybe-rayon` API. The new direct dependencies in
the two proof test crates are dev-only; runtime worker selection is unchanged.

## Before changing the checker

The same owning read image first proves/verifies real Source, Role3 and DATA.
It then issues a genuinely different query against that actual immutable DATA
theorem, including original input preparation, actual FHE/product certificate,
fresh Word and fused Query proofs, independent public receiving setup/checks and
protected client completion. Receiving setup overlaps production in the SAME
Rayon pool. Overlapping phase durations must not be added. Full-ring oracles and
repaired/missing/foreign proof failures remain outside the measured operation.
All query answers come from the genuine homomorphic product before the oracle.

| Local new query, ms | 2 workers,390 | 8 workers,391 | 16 workers,392 |
| --- | ---: | ---: | ---: |
| Original input preparation | 3.212 | 3.268 | 3.148 |
| Actual FHE/product certificate | 36.081 | 37.623 | 33.501 |
| Fresh Word proof, with receiving setup concurrent | 763.253 | 298.783 | 196.556 |
| Fresh fused Query proof | 1226.641 | 461.461 | 341.703 |
| Receiving setup, overlapping production | 715.588 | 266.815 | 153.150 |
| Prepared Word/Query/product verification | 182.770 | 187.536 | 195.775 |
| Protected client completion | 1.019 | 1.035 | 1.140 |
| **Entire new local query, setup included** | **2214.093** | **990.879** | **773.210** |
| Three query frames, bytes | 7871370 | 7867178 | 7873290 |
| Whole-process OS peak working set, bytes | 562798592 | 576180224 | 594345984 |
| Whole owning test, including cold setup/hostile cases, ms | 27091.579 | 19503.510 | 19157.333 |
| Whole-process CPU seconds | 37.688 | 43.844 | 54.844 |

A separate lower Query-only case produced and cold-verified the unchanged fused
argument in1726.014/683.002/582.655ms with2/8/16 workers (captures387/388/389).
Actual proof production was1273.757/457.526/387.968ms; cold receiving was
452.257/225.476/194.687ms. Whole-process OS peaks were488366080/489082880/489439232
bytes. Canonical/old-format/statement/native corruption checks still passed.
More workers reduced wall time and increased CPU work. Public preprocessing
depends on literal ciphertexts, contexts, commitments and statement values; a
different query cannot reuse that setup as though it had the same expectation.

The distinct originating-owner route uses its guarded original input premise
instead of a transferable public Query argument. Its two new calls measured
333.271/329.582ms with2 workers,239.582/241.211ms with8, and248.852/232.699ms with16.
Role-only public setup cost222.184/100.013/85.167ms respectively, outside those
calls; immutable DATA installation remains separate. Its receiver stayed near
103–106ms. This is not peer Predicate admission or SQL/lock authority; the
[owner-specific scope](OWNER.md) remains mandatory.

## Four read-only field checks

The public product checker now schedules exactly four fixed-basis PIT jobs on
the host's existing Rayon pool. Shape/canonical checks precede dispatch. Each
job retains all18 original full-transcript points and all three component
identities. No polynomial copies, new pool, randomness changes, accepting flags,
NTT/query reexecution or detached work are added. Tasks are joined before return.
The original UNASSESSED mathematical profile,1,737,899-byte frame, integer
certificates and transcript are unchanged. The existing repaired-endpoint test
now separately alters every component in every basis and must reject all12.

| Comparable local observation after parallel PIT | 2 workers,397 | 8 workers,398 | 16 workers,399 |
| --- | ---: | ---: | ---: |
| Entire public new query, ms | 3129.618 | 1142.688 | 752.678 |
| Prepared Word/Query/product verification, ms | 218.316 | 204.802 | 166.826 |
| Owner-only receiving, call2/call3, ms | 101.896/107.628 | 112.160/111.748 | 93.854/91.252 |
| Entire owner-only call2/call3, ms | 410.683/433.917 | 273.559/256.158 | 224.302/210.104 |
| Whole-process OS peak working set, bytes | 562642944 | 576430080 | 595185664 |
| Sampled private-byte peak | 556150784 | 569995264 | 588488704 |

The16-worker observation improved receiving and the complete local interval.
The2/8-worker whole intervals regressed, including unrelated proof/setup phases.
These sparse, freshly randomized runs do not establish a causal overall speedup
or latency distribution. A deterministic basis scheduling change is not evidence
that the complete SQL target is met. All19 product tests passed, including real
SDK endpoints, exact integer/scaler checks, independent polynomial oracles,
repaired scalar/output/proof failures and the original profile/frame golden.

A separate fixed dense-polynomial control interleaved1/2/4-worker processes three
times each (captures407–415, same product image as400). Every process constructed
and checked the SAME complete public polynomial certificate, pinned by the
existing all-coefficient golden. Whole process medians, including startup and
certificate production, were30.213/26.849/23.878ms respectively; raw lifetimes
were[40.254,30.213,29.941]/[27.040,25.502,26.849]/[25.656,23.439,23.878]ms.
This control supports the bounded kernel scheduling choice, not an isolated
verification-time ratio or a full-query speedup.

Capture402/build401 also passed the real independent daemon/TLS/FHE/product/
client-completion gate, including original-pair, foreign nonce and malformed
response rejection. Its actual math RPC was72.098ms (RPC41.416ms, independent
arithmetic receiving/decryption30.681ms). This excludes Source/Word/SQL/freshness/
locks. The unchanged120s/1792MiB aggregate fuse and held image/creation/parent
checks covered the actual parent/daemon processes; all exited0 without faults
or cleanup. This confirms the affected real transport consumer still works.

The full public local route still exceeds500ms before transport, current agreed
head and lock consensus. It carries about7.87MB of query proofs. The owner-only
route carries about4.77MB and still lacks SQL compilation, real transport,
weighted Predicate finality and durable SQL/locking completion in this test.
Neither is a full SQL/FOR UPDATE measurement. Full composed cryptographic
assurance remains unassessed. All SQL/freshness/network/security flags stay false.

## Reproduction and observation

Run each worker budget in a fresh process; a Rayon pool is initialized once:

```powershell
$env:RUSTFLAGS = '-C target-cpu=native'
$env:CARGO_BUILD_JOBS = '2'
foreach ($queryWorkers in @(2,8,16)) {
    $env:RAYON_NUM_THREADS = $queryWorkers.ToString()
    cargo test --release --offline --locked -p bfv-ciphertext-formation --lib gold::program::query_formation::tests::real_fused_proof_cold_verifies_and_damaged_native_argument_fails -- --exact --nocapture --test-threads=1
    cargo test --release --offline --locked -p registry200-proof --features owner-read --lib registry_progress::word::read::tests::original_version_word_data_query_and_real_product_are_all_required_before_client_completion -- --exact --nocapture --test-threads=1
}
cargo test --release --offline --locked -p bfv-unrelinearized-product --lib -- --nocapture --test-threads=1
cargo test --release --offline --locked -p bfv-unrelinearized-product --lib pit::tests::dense_public_convolution_retains_every_product_and_quotient_coefficient -- --exact --nocapture --test-threads=1
```

Actual captures directly launched previously built exact images, without
concurrent builds/tests. Held process handles, creation identity, source/image
hashes,120s/1792MiB fuses and20ms samples covered every run. All exited0 with no
fault or cleanup action. Memory observations concern whole test processes, not
complete peers. Generated reports remain local under
`.local/word-cmd-native-rREV-PACKAGE-observe-tests/`; source and image hashes in
each result pin the exact before/after implementation. See [original validation](VALIDATION.md)
and the [conditional arithmetic model](../../../../../bfv-unrelinearized-product/MODEL.md).

| Report revision | SHA256 |
| --- | --- |
| 387 | `1C4A77875E438055A2F4EC4152115BD3E012B6F892A218611A32580404453326` |
| 388 | `B686285AA34D9C0E26A75DFB76FCA8B738E58DA69AC4B66956CD34B264E2FCF1` |
| 389 | `EC6DDCBDA0513BC3744BE5AA4F904F8155A294D6EB1C6A4EC5FAA333FCB3C38C` |
| 390 | `727DDBA1960278723CA235CA2569C2E478FB68F7B06D8E405F0DB4F855A24C2C` |
| 391 | `64A79DBB146A2413E07CA4C7EC1AD33EEAF254ACC0407A421A904AD5596C1A0F` |
| 392 | `64148B4C35C711A08929E7D81ABD132B8ADE581AE8E9C9401788549DEAD096BF` |
| 397 | `9DFD4919F25D198AFCAD768DF8559EBEC9039655C33CC6DEC6002BA12CAD3939` |
| 398 | `ACE4D046EF826A712988DF7E558C2FE36792B603C231D8113F8F0462847520D1` |
| 399 | `7297EEEA92C7802908EFBEA25988A64223ED30D7DE76475F86CB92DDFAB5DA83` |
| 400 | `3E8878A9A9695032B82A55FD5F58BA605A792FBB7419087E244BF89609A5F35C` |
