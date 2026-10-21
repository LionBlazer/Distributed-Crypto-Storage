# QueryMaskEncoding native validation

Executed on2026-10-21 with Rust1.99.0, the pinned Cargo.lock/P3 0.8.0 suite and
the same release/native CPU configuration as the earlier Word measurements.
This is the fixed Stmt96/Mask256/Cw4112 mathematical component. No network SQL
operation or fresh lock/QC was accepted.

## Executed gates

Strict all-target Clippy passed. Release test compilation took61.906s. The owning
filter passed all13 tests in1.36s, including two honest private proofs with
distinct nonce values and a third genuine false-input proof. The standalone
held process lived1391.1659ms and consumed2.1875 CPU-seconds. Six unchanged Word
metadata/complete-IR/PP checks then passed in0.13s on the same binary.

The original QueryMask AIR, layout, Expected implementation, mathematical
profile, security calculation, full ordered symbolic tuple and PP goldens remain
unchanged. The original Word statement serializer changed only private visibility.
The module registration has a doc correction and additive private declarations.
No old Word proof/codec/runtime behavior changed.

The new tests check complete native BASE equations for all96 statement fields,
all256 reversed mask bits and all3840 high zero coefficients, including padding.
Repaired hash/root paths cannot hide bad packed mask words, non-Boolean bits,
bank reset failure or an omitted final absorb. Honest receiving constructs its
own public PP and runs the actual native verifier. Repaired foreign-nonce headers
and damaged OOD openings must fail with native Verification. A fresh false-W256
proof, with all hash/checkpoint/root/PUBLIC paths repaired, must also fail with
native Verification. Local BASE diagnostics are separate assertions.

Canonical EOF and legacy-magic rejection passed. A4097-element sequence fails
the sequence limit. The total-budget test uses240x128x16 canonical Gold values
after clearing unrelated heavy vectors: every individual length fits4096, but
the subtree alone charges4454640 decoded slots, exceeding4194304. Its complete
frame is asserted within4MiB before receiving, so the Resource rejection comes
from decoding rather than the frame cap or an earlier topology check. This
replaces an incorrectly sized empty-vector input found during source review;
no proof or resource limit was relaxed and no extra proving site was added.

## Measured complete encoding component

Each interval includes opening checks, actual native proof and canonical frame.
Cold production includes public setup. Cold receiving includes its own public
setup, decoding, shape validation and native verification. Warm calls retain
only independently constructed PUBLIC setups; the second nonce requires a new
proof with fresh private randomness.

| Rayon threads | Setup policy | Production ms | Receiving ms | Sum ms |
| --- | --- | ---: | ---: | ---: |
| 2 | cold |306.644|76.510|383.154|
| 2 | warm, distinct nonce |265.224|45.402|310.626|
| 16 | cold |143.884|69.026|212.910|
| 16 | warm, distinct nonce |112.987|53.252|166.239|

The16-thread observation reruns only the single honest/native-rejection test,
with two actual fresh proofs, on the exact same executable and sources. It
passed in0.54s; process lifetime was556.5678ms and CPU time2.859375s. This is a
comparison setting, not a production thread-policy change. Background load was
not controlled, proof coins/nonce differ, and this is one observation per case,
not a latency bound or statistical benchmark. Concurrent producer/validator
oversubscription and composed peer memory remain unmeasured.

At two threads, the first honest native prove took270.151ms; cold PP construction
took17.063ms for the producer and17.358ms for its receiver. At16 threads, those
values were110.462ms,8.072ms and7.836ms. The warm16-thread native prove took
107.030ms and actual native verify46.340ms. Faster proving did not improve all
receiving phases: the two-thread warm native verify was40.807ms.

Honest frames were1732944/1734640 bytes at two threads and1727728/1732912 bytes
at16 threads. The static envelope is a bound, not an observed fixed proof size.

## Resources and provenance

Both native observers retained the original120-second/1792MiB whole-process
fuses and20ms sampling. They checked held process/image/creation identity,
successful terminal state and no surviving direct child. No fuse, forced cleanup
or observation fault occurred. System memory was diagnostic only.

| Gate | Sampled peak private bytes | OS peak working-set bytes |
| --- | ---: | ---: |
| all13 tests,2 threads |131457024|140587008|
| exact honest test,16 threads |133844992|142528512|

These are standalone test-process observations, not a universal peer, owner,
concurrent-workload or recovery memory bound. The separate770957312-byte
analytical workspace ledger is unchanged and has explicit policy reserves.

Local records are release build44, held native receipts44/45/46 and their archived
72-file source image,1171248 bytes, aggregate SHA256
79C4F4A8409F51CBE90ACF2A7B418ACAF32B34C32BF0888272B86EFB020B7CCE.
The executed binary was11058688 bytes with SHA256
4FB4F354F7E03A4AA7C062422F58ABBF9221EDA2BD2FBE314AD443D3F1CBC194.
The archive precedes this documentation-only update. Generated records and
private proof artifacts are not repository fixtures.

The independently reconstructed public PP commitment had SHA512
cab829adaa948211c7b0a2dcd65d26764dfeb3c43451e9633c739d0c4422aa32f2167b81646be79a352a92bc3be6a328bf8f41afc1cb31c87e3eb314ba495b3b.
Its equality alone is not proof acceptance; full AIR/PP goldens and actual native
receiving remain mandatory.

## Unfinished system obligations

This component binds a complete original statement opening to a complete scaled
vector commitment. It does not prove that the original QueryCt encrypts this
same vector under the installed Cs, nor install/authenticate DATA/Source/Word
history. Full request/context/nonce association, authorization, current weighted
finality, locks, WAL, decryption of the completed peer product and SQL completion
still need their own real joined implementation. Ordinary SQL capability guards
remain closed. No composed-system/lattice security or complete-query500ms claim
follows from these measurements.

## Original QueryCt Formation join

The added closed `formation` component reuses the original mask AIR/backend and
the existing complete single-Ct Formation prover/verifier. One protected mask
opening constructs both inputs. The exact original pair, nonce, retained DATA
binding and complete original Stmt96 root derive an acyclic Cw context; the Cw
root is excluded from its own context. The lower Formation expectation uses
that same Cw, the literal original QueryCt and the DATA expectation's exact Cs
context/root. Retained DATA metadata is not an accepted Source or key token.

On 2026-10-21 all 16 owning tests passed in 9.27 seconds on the final release
image, including the unchanged 13 mask tests and three new join cases. Strict
all-target release Clippy and the dependency-free requirements-sync test passed;
the four changed Rust files passed rustfmt. The final release test build took
58.843 seconds. Earlier compilation had a missing explicit fixture array type;
only the corrected final image supplies the results here.

| Measured joined component | Milliseconds |
| --- | ---: |
| Opening checks, both cold public preparations, real private proving and canonical frames | 4814.279 |
| Independent cold preparations, bounded decoding and both native verifications | 1066.115 |
| Sum | 5880.394 |

This uses the existing two-thread Rayon configuration and CPU/native release
flags. Fixture SDK key generation, original input encryption, DATA/Word admission,
product computation/certificate, client completion, freshness, quorum, network,
durable locks and SQL are outside the interval. It is one component observation,
not a full-query measurement or latency bound. No speedup is claimed. The honest
mask and Formation frames were 1,736,400 and 2,521,395 bytes respectively.

Each native argument is independently corrupted at an OOD opening while keeping
its canonical shape and repairing frame lengths. The joined receiver must return
the corresponding native `Verification` error; a valid argument on the other
side cannot substitute for it. A changed original nonce is rejected, and swapping
the pair fails binding. Changes to the complete DATA expectation or Stmt root
change the derived context. A canonical, genuinely SDK-encrypted QueryCt under
the SAME key but with nonzero high plaintext coefficient 256 is rejected by the
complete Formation equations with `Arithmetic`, despite its honest mask proof.

The held test process lived 9276.1045 ms and consumed 16.984375 CPU-seconds.
Sampled peak private bytes were 1,333,276,672 and OS peak working set was
1,344,495,616 bytes. The original 120-second/1792 MiB fuses, 20 ms sampling,
held image/creation identity, terminal exit-zero and no-direct-child checks all
passed without faults or forced cleanup. This is one standalone test process,
not a concurrent peer memory bound.

Local build/held receipt r73 retains the exact source hashes, complete stdout/
stderr and memory samples. Its release image had 11,153,408 bytes, SHA256
9AAB7047D6531ACE88424F7368FE5144AAC0ACCB00203F76A71F154DE63509A2.
Generated artifacts and private proofs remain ignored, not checked-in fixtures.
The source snapshot precedes this documentation-only validation update.

```sh
cargo test --release --locked -p registry200-proof registry_progress::word_inventory::query_mask_inventory:: -- --nocapture --test-threads=1
cargo clippy --release --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --locked -p repository-contracts --test requirements_sync
```

The new relation remains test-private with no runtime registration, admission
token, shared proof challenge or composite wire codec. Independent proof calls
do not themselves establish composed cryptographic or lattice security. The
full-query target is still unmet. The measured Formation cost must be reduced
while preserving its all-coefficient, same-secret and bounded-error constraints;
removing this proof or relying on successful decryption would violate admission.

## Dense QueryCt proof selection and paired observations

The v2 join uses the explicit `gold::data::prove_dense`/`verify_dense` API and
includes its distinct protocol digest in the join profile. The lower library
now compiles the fixed dense backend in ordinary builds; fixture factories and
test/attack code remain test-only. It reuses the SAME guarded equation derivation
and original Expected, not a query-specific plaintext answer. There are no new
dependencies, runtime registration or automatic proof fallback. Both directions
between old `DCSGFD01` and dense `DCSGDD01` frames reject with `Encoding`.

The final 16-test join gate passed in 10.78 seconds. Six lower dense cases passed
in 4.33 seconds, including honest public-facade receiving and actual false-wire
proof rejection. Two complete original Pair/DATA symbolic/PP golden regressions
passed in 0.06 seconds. Both libraries passed strict all-target release Clippy;
four compile-fail ownership checks and the dependency-free requirements-sync
test passed. No AIR equation, native packing/security parameter, resource limit
or original proof profile was changed. Normal builds also validate the complete
inventory's numerical summary before preparing the proof.

After all of this task's builds had completed, the exact joined honest/hostile
case ran once at two threads and once at sixteen threads, sequentially on the
SAME release image and source. Within each process both backends use the exact
same original pair, original statement, secret/Cs and scaled W. Each creates
fresh private proofs and independently reconstructs its own PUBLIC setup.
Dense runs first; the old backend is a test-only baseline, not a receiving path.
Keys/proof randomness differ across the two process runs. Background load was
uncontrolled; one observation per setting is not a bound or statistical benchmark.

| Rayon threads | Backend | Produce ms | Cold receive ms | Sum ms | Mask bytes | Formation bytes |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 2 | Dense H2048 |1500.884|522.540|2023.424|1737968|3278709|
| 2 | Original H8192 |4762.917|1033.965|5796.882|1730576|2512179|
| 16 | Dense H2048 |521.833|252.442|774.275|1733392|3283125|
| 16 | Original H8192 |1122.453|292.479|1414.933|1730672|2529587|

Both intervals include opening checks, actual private proving, canonical frames,
independent cold PP, bounded decoding and full native verification of both
arguments. Fixture encryption, Word/Source/DATA admission, FHE product and result,
client completion, current weighted finality, transport, durable locks and SQL
remain outside them. The sixteen-thread configuration is an observation setting;
no production thread policy changed. Larger dense frames remain a network cost.
The 774.275 ms component does not meet the complete-query 500 ms target.

All final observers retained the 120-second/1792 MiB fuses, 20 ms sampling, held
process/image/creation identity, successful terminal state and no direct child.
There were no faults, fuses or forced cleanup. The exact two/sixteen-thread
processes lived 8604.6797/2518.6236 ms and used 15.890625/22.421875 CPU-seconds.
Their OS peak working sets were 1357795328/1363021824 bytes. These peaks include
the OLD baseline, so they do not measure the dense chain alone. The standalone
lower six-test dense process peaked at 526409728 working-set and 519372800 sampled
private bytes; it is also not a concurrent peer memory bound.

The final registry release image was 11333632 bytes, SHA256
F351E15C89FEABF2E126900DF0EDD8CE90F9D71DF7B123142F0C324F21157D72.
Lower release image: 5975552 bytes, SHA256
BC6100B58A18456A9C4C2D6362E7B80C208F80FDF802ACF0BD1719913D957CA9.
Ignored local build/held records r82-r84 retain sources, exact command contracts,
complete output and memory samples. The first r81 functional run overlapped a
lower build and is not the paired performance evidence above. These snapshots
precede this documentation-only validation update. Generated proofs stay ignored.

For comparison set `RAYON_NUM_THREADS` to 2 and then 16 and execute the SAME
release image with the fully qualified owning test above, `--exact --nocapture
--test-threads=1`. The existing all16 command continues to run that test plus the
other required mask/association/hostile cases. Never interpret test duration as
query latency.

The two independent proofs still both process the complete Cw stream. A future
joint relation could eliminate that duplicated work, but must explicitly retain
the original statement/mask, every high-zero coefficient, same Cs, bounded noise
and original-query association. Omitting a proof from the existing Expected is
not such an optimization. Word/state admission, composed security and the real
peer SQL/finality path remain unfinished.
