# Actual Owner key anchor and reusable hiding transform validation

The fixed hiding engine and KeyTransform relation were extracted into reusable
libraries. The optional `bfv-query-core/key-proofs` path now associates a real
`Owner::generate` key with its original complete PublicSetup, mints a private
borrowing handle and emits a genuine bounded hiding transform proof. This is a
transform prerequisite, without live SQL admission or ciphertext formation.

## Source and dependency boundary

`bfv-hiding-stark` owns the fixed Plonky3 mechanics, analytical assessment,
Poseidon2 gadget and bounded typed codec. `bfv-key-transform` owns the unchanged
W9932/PV33/512-row relation. The experiment retains Kind/request policy and public
fixtures; Core has no dependency on experiments or applications. Both new library
targets are core default members. The Owner feature remains optional for consumers.

Offline lock resolution added exactly two local packages: root lock 552 to 554,
standalone lock 213 to 215. All prior third-party package dictionaries, versions,
checksums and edges are exact. Filtered Windows metadata contains 408 and 193 nodes;
these are distinct from all-platform lock counts. Published README prefixes were
retained byte-exact. Russian requirements and their mirror are unchanged.

## Executed gates

All gates used Rust 1.99.0/MSVC, release, locked/offline dependencies,
`-C target-cpu=native`, Cargo jobs 2 and Rayon threads 2 on an
AMD Ryzen 9 9950X3D2 (16 cores/32 logical processors).

* Default core check and strict Clippy for selected Core libraries and the experiment passed.
* All 337 original experiment scenarios and all 103 selected library/integration tests passed.
  The latter include 10 new owning tests; all 440 compiler-discovered tests were executed.
* All 33 historical security invocations retained their complete ordered JSON lists exactly.
* All seven compile-fail doctests passed, including four new Owner handle contracts.
  The two actual requirements/architecture tests passed.
* The actual SDK KeyTransform proof retains the individual 128-bit analytical floor.
  Individual reports do not establish composed protocol security.

The actual Owner test independently reads its upstream secret in test scope only,
checks all 8192 coefficients in the input commitment, derives a native coset DFT and independent
Poseidon2 output stream, and verifies two real proofs after dropping Owner/handle.
It also own-verifies a genuine foreign-owner proof before rejecting it under the
original pin. Wrong scope/epoch/full setup/parameter digest/roots, coherently
rewritten headers, rotation-only setup changes, Gold aliases, nested omissions,
randomness/FRI/OOD mutations, allocation bombs and exact cap boundaries reject.
The old transform and other experiment tests exercise real rebuilt SDK proofs.

## Observed Owner operation

One test invocation measured these separate phases; native-oracle test work is
excluded. This is neither a cold benchmark nor a SQL latency measurement.
The first verification includes setup decoding; the repeat reuses the decoded
immutable public setup.

| Observation | Actual value |
| --- | ---: |
| Original complete setup bytes | 8,930,306 |
| First complete proof frame (208-byte header) | 16,730,687 |
| Second complete proof frame | 16,731,935 |
| Owner generation and setup encoding | 152.2673ms |
| Prequery anchor | 12.0972ms |
| First proof generation, self-verification and serialization | 3102.9705ms |
| Fresh setup decode and independent frame verification | 993.3780ms |
| Second proof generation | 3880.9231ms |
| Repeated independent verification | 1050.9887ms |

Both genuine frames fit the new 20MiB payload ceiling, sequence ceiling 16384 and
nested budget 24Mi elements. They preserve the same input anchor and have different
fresh output roots/proof bytes. Historical experiment caps/allowlists are unchanged.

Across 136 observed CLI/test processes, 28682
memory samples and 28546 measured intervals, the largest sampled
working set was 1,333,522,432B, private usage
1,354,874,880B, and sampled OS peak working set
1,333,522,432B. Maximum observed interval was
177.3883ms (nominal 100ms). No 1792MiB sampled soft fuse or 1200s
per-child timeout fired. Compiler/child processes were outside observation; these
measurements do not establish a whole-peer RAM bound, concurrency quota or full
query resource guarantee. Raw logs, proof runs, CSVs and binary hashes remain in
ignored local receipts; no key material or raw generated outputs are published.

## Scope and retained failures

The complete setup identity is an independent Owner-minted pin, outside legacy
PV33; its parameter-only descriptor is unchanged. This does not prove arbitrary
external evaluation-key same-secret/noise consistency, key sampling entropy,
authorization, agreed freshness/finality, source-to-FHE linkage or complete SQL.
BFV and storage/AEAD domains remain separate. Standalone output openings are
discarded; later combined Key+five-Basis production needs its own opaque scope.
Private anchor persistence/recovery and complete native/SDK-buffer erasure are
not implemented. Network locking-plan rejection remains unchanged.

R1 default Core check passed, then Clippy rejected two new-test fixed-chunk style
calls. R2 corrected those and passed Core Clippy; leaf Clippy found a missing
private test height import and an unused duplicate constant. R3 restores the
import and removes the obsolete constant. Both failed runs and all artifacts are
retained; no cryptographic profile or old test body was weakened.

* Author source: `5179F0EE9F55970D382AE2EC2CFB7BF271C5E35D805314E002BC76C2FF9ADB08`.
* Exact executed R3 source: `829007D3435DAA26FD9D56E247E2710EAF03CD6BA230CCADF911FA88D5DE6DFE`.
* Complete gate closure: `4166AF3D46604CF633602886ADB7A9FE9163B94ACEC2791010042464D6353C2A`.
* R3 compile: `467B06C4BD9685B91D6E7622E64734FE3082B9F9AD479485EA6F638565E3B7DD`.
* R3 numeric: `36500595D3D253FEABB3A602D9F5FC3C6B408AB958A2FA4F8A00EE18D1A62075`.
* R3 tests: `5E192BFD6BBD12F491F5794A5B84F5BE4F10D78B4CFFF439855E8D2F9A7A9E4C`.

The overall PostgreSQL/FHE/decentralized-storage goal remains active.
