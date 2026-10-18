# BFV proof libraries and SDK relocation validation

## Actual ownership change

At parent `85250a745e2e2fbe8bd4658fe51d0e7f38f47d6f`, the NTT,
relinearization, arithmetic17 and complete134 proof implementations belonged to
standalone experiments. Their actual backends, canonical codecs, proof producers,
bounded verifiers, statements and owning hostile tests now belong to
[bfv-ntt-witness-proof](../../crates/bfv-ntt-witness-proof/README.md),
[bfv-relinearization-multilinear-proof](../../crates/bfv-relinearization-multilinear-proof/README.md),
[bfv-arithmetic-batch-proof](../../crates/bfv-arithmetic-batch-proof/README.md) and
[bfv-mul-relin-proof](../../crates/bfv-mul-relin-proof/README.md).
These are implementations, not forwarding wrappers. CLI parsing, public fixture
construction and reporting remain separate experiment consumers. The original
binary names remain explicit; the three package names now end in `-cli`.

Backend configuration, SDK proof types and PK/VK stay private. Public `analyze`
receives the caller's actual typed statement and performs real security
assessment without evaluating a query, constructing a fixture or generating a
main witness. Existing zero-input CLI analysis fixtures now belong to the CLI.
Core test fixtures and hostile programs compile only under `cfg(test)`.

All 90 reviewed SDK payload files move byte-for-byte to
[vendor/p3-multi-stark](../../vendor/p3-multi-stark/README.md), including the license,
upstream hash inventory, manifest, lock, implementation, tests and compatibility
fixtures. Its README is separately updated for the new location. Five explicit
direct dependencies select this single version 0.8.0 SDK. Root excludes its
standalone owning-test workspace and has no global registry patch. All 38 default
members are Core libraries. The architecture guard accepts only that exact SDK
name and canonical vendor directory in addition to ordinary Core dependencies.

All retained registry package identities, versions and checksums are unchanged
across eight Cargo graphs. CLI extraction prunes unreachable packages and the
now-unused `num-traits -> libm` edge; dependency spellings normalize to the same
resolved identities. No new registry package or dependency edge is introduced.
Requirements and their AGENTS mirror remain unchanged and synchronized.

## Native verification

The native source freezes 1354 repository files, 121 deletions and four original
CLI executable hashes. The final validation report and README links follow
native closure. Rust and lockfiles retain those exact source bytes. The final
two new primitive manifests each lose one empty EOF line; their parsed TOML and
the entire locked Cargo metadata JSON equal the native baseline. No dependency,
feature, target or profile changes in this formatting amendment.

- Base source B1 SHA256: `B1A777529B35FE47902AB2744447DAC697B97F02DB77A5524C2E2A09EFB16EAB`.
- Continuation source R5 SHA256: `8010EE08EE44975394553FEEA336784C4287E700A4986481A7F257A4D9D29770`.
- Fresh resource source SHA256: `7A7B860F5E93B159D29EE0FBE5AA8C69881C515D4999E624F950F461D243BA9D`.
- Local closure `proof-libraries-core-native-closure-r2/success.json` SHA256:
  `0F296FBC7E3C6ED0708B05D25E8744689982773FABFDD99AB3E783D4A6CD0FF3`.
- EOF-only amendment `proof-libraries-core-format-r2/success.json` SHA256:
  `9035E237D315A623A99A0B1929A25529D9086E2A91229DC845AFB4815B5E4D12`.

Root alone ran native commands with Rust 1.99.0 MSVC, release/offline/locked
resolution, native CPU code generation, two build jobs and two Rayon threads.
Formatting, strict all-target Clippy for five proof/shared libraries and six
consumers, default Core check, both SDK feature checks and five doctest commands
passed. Doctests contain zero executable examples and add no behavioral cases.

| Owning selection | Passed cases | Direct process time, ms |
| --- | ---: | ---: |
| all-shared | 7 | 230.6645 |
| all-ntt | 13 | 94,736.4137 |
| all-relin | 20 | 22,826.4493 |
| all-arithmetic | 12 | 331,513.3071 |
| all-graph | 3 | 219.1774 |
| all-old-relin | 7 | 104,587.5614 |
| all-ntt-batch | 9 | 693,868.5341 |
| all-sdk-default-lib | 407 | 6,487.8951 |
| all-sdk-stream-lib | 409 | 6,711.0723 |
| all-sdk-default-whir | 40 | 239.8925 |
| all-sdk-stream-whir | 41 | 240.1759 |
| current-fixture | 1 | 238.0503 |
| retired-fixture | 1 | 227.8567 |
| all-requirements_sync | 1 | 226.9900 |
| all-architecture | 1 | 255.7815 |
| full-input16-product134 | 1 | 586,999.4645 |

There are 973 credited successful test invocations: 526 distinct package/target/test identities
and 447 feature-matrix repeats. Library default/streaming selections contain 407/409
cases; fresh WHIR default/streaming selections contain 40/41. Both ignored
`generate_whir_fixture` invocations are explicitly excluded. Two exact read-only
backend compatibility cases verify the current fixture and reject an older
revision; `generate_the_compatibility_fixture` never runs. The current backend
fixture uses its own small upstream test policy, not the BFV144 policy. The older
revision case tests framing/revision rejection, not a new BFV proof.

The moved 13 NTT, 20 Relin and 12 arithmetic tests retain all original assertions,
all 8192 coefficient oracles, complete genuine proofs and hostile AIR controls.
An altered or foreign program must first verify with its own SDK setup, then
fail the honest verifier. Original complete32, atomic NTT batches of 2/4/8, full
profile64 pinning and terminal proof-session limits remain covered.

The original and current four CLIs produce 35 complete numerical JSON reports
across 24 command selections: all twenty NTT direction/basis shapes, both Relin
roles, arithmetic17 and twelve complete32 component reports. Every full JSON
object is equal, with finite accepted assessments and no unassessed component.
No proof cap, field, AIR, transcript, mode selector or security floor changes.
Resident remains the default even with unified features; arithmetic and atomic
NTT batches explicitly select Streaming per call.

## Full encrypted product observation

The real input16/full134 integration passed in 586,999.4645 ms.
It creates genuine Key, Source, two Encoding, ten Basis and two Formation input
proofs, then 118 ordered output records containing 120 actual SDK proofs. It drops
the original private/prover state and verifies through a fresh public consumer.
The accepted output is the complete original SDK encrypted ciphertext; decryption
and plaintext fixtures are independent test oracles only.

Claims occupy 16,727,920 bytes and output proof records
236,852,246 bytes. Including the actual input collection with its duplicate
Source frame gives 517,744,773 public spool bytes. This is a
collection of bounded records, not one permitted network frame. Output component
generation totals 352,921.0647 ms. The 115 NTT proof generation
times range from 1,737.8816 to 2,118.9209 ms, median
1,841.6696; initial per-component verification ranges from 118.6341 to
168.5392 ms, median 135.1676. These component timers cover the
first verifier while the prover still exists. The separately measured fresh
setup/key/input16/output-record verification after prover drop takes
49,578.1817 ms in aggregate.

The output-only union estimate is 150.501960222601 bits, recomputed from
115 NTT terms, two Relin terms and the already-composed arithmetic17 report
counted once. Input proofs retain their separate 128-bit policies. This does not prove
whole128 or whole144 security, evaluation-key same-secret provenance or complete
noise bounds. `sql_grant`, `fresh_agreed_head` and `whole128_claim` remain false.

## Evidence handling and limitations

A first partial arithmetic run was deliberately stopped before the inherited
ignored WHIR fixture writer could run. Its 205,520.9586 ms and partial cases receive
no PASS credit. A continuation later reached cached WHIR executables with the
old compile-time manifest directory, so its resource test failed after relocation.
That failed invocation also receives no credit. Completed, successful groups from
these runs retain their original command results, stdout/stderr, memory samples,
source/runner identities, executable hashes and actual test discovery.

The file-resource tests were then compiled afresh after an SDK-scoped clean in a
second independent copied target. Actual Cargo artifacts are fresh, embed the
vendor manifest directory and omit the old directory. Both WHIR modes and the two
read-only backend cases pass there. No fixture is regenerated. T1 is hash-verified
unchanged across copy and the T2-scoped clean; later Cargo stages may update this
stage's cache. Selected executable hashes and all 52,274
historical artifacts, 1,027 SDK anchors and 5 tool hashes
remain checked through closure. Original caches and old targets are preserved.

The runner samples target-owned processes and descendants nominally every 100 ms,
with a sampled 1792 MiB per-PID soft fuse and 1200-second command stop. Actual sample
gaps and OS peak working sets are retained. These are observations, not a hard
whole-peer RAM bound; commands without a live sample establish no RAM fit. The
times above include instrumented owning test work and are not SQL latency claims.

The full integration captured 2,531 samples: maximum sampled working set
1,285,951,488 bytes, private bytes 1,281,052,672 and OS peak working set
1,293,111,296. Its maximum observed interval was 501.9846 ms; the atomic NTT
suite reached 1,440.9608 ms. The nominal 100 ms sampler is not an interval bound.
The four fast SDK resource commands captured no live samples.

This change creates reusable proof ownership. It does not enable network SQL,
authorize mutations or implement PostgreSQL locking. A private query still needs
an explicit composition between certified stored encrypted input and a separately
proved hidden query, independently pinned to the actual objects and fresh agreed
head. The WHERE condition and its constants must remain hidden. Source ingest
and per-query proof origins must remain distinct; owner row
inspection or fixture answers cannot replace peer FHE computation. Full SQL,
distributed transaction/lock fences, completeness across stored rows, recovery,
compact durable storage and the complete resource/security guarantees remain open.
