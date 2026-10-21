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
