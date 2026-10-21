# Joined immutable-version read validation

Historical private-boundary measurements follow. The normal library successor
now lives in [word::read](../../word/read/README.md), with its own
[validation](../../word/read/VALIDATION.md). Its owning example consumes guarded
public Word and Gold Query inputs; the public receiver replaces the private probe.

The private `read` boundary joins six unverified frames: StateCertificate,
VersionSource Role3, dense DATA Formation, original Word, fused original Query
Formation and the conditional unrelinearized-product certificate. It does not
install data, accept SQL, finalize a lock or establish composed cryptographic
security. Complete independently retained expectations and the actual receiving
operations are described in [README](README.md).

The bounded PUBLIC fixture uses the original SkipBeforeOffset Word example,
including its complete encrypted source images, C_state, private mask and full
Stmt96. Real SDK DATA encryption consumes coefficients from that exact Role3
witness; its original QueryCt uses the same key and original Word mask. The
public evaluator receives only ciphertexts/parameters and performs actual FHE
multiplication. The owner decrypts only the closed receiver's checked Ct3, then
compares all4096 coefficients with a separate public ring oracle and checks all
four packed row endpoints. That oracle never supplies the encrypted computation
or receiving result. This is not SQL projection/lock completion.

The fixed workload contains four public(age,amount) rows: (0,1), (1,2), (128,3)
and (255,4), in the existing12-byte DATA/2336-byte index schema. The Word mask
matches the256-value age domain. This is one N4096/Q2 ciphertext multiplication,
not a general SQL workload or a scalable table-volume benchmark.

The first executed r108 owning case passed on2026-10-21. A successor adds a
repaired child argument, same-version-tag/different-C_state and swapped-pair
rejections and fixes the timing endpoint to exclude the post-verification public
oracle. Final execution and measured boundaries are recorded below after gates.

## Executed receiving and failure gates

The final17-case mask/composition filter passed in24.49s, including the original
16 cases and the new joined read. The unchanged original H8192 State/Role3/DATA
case passed in15.29s after factoring common prerequisite handling for the new
explicit dense API. Two compile-fail private-construction/clone checks passed;
strict release all-target Clippy and dependency-free requirements_sync passed.
No native equations, parameter/security assessment, lower profile, noise/range
bound, codec cap, production timeout, SQL refusal or freshness rule changed.

The new case checks the actual closed receiver and only then permits client
decryption. Each of the five native arguments is independently decoded, its
actual OOD opening changed and its canonical frame/length repaired. Receiving
must report the concrete corresponding native Verification error, including
SourceVersionProof(Verification) for State and Proof(Verification) for Role3.
These are not malformed-frame or panic substitutes. The conditional product
certificate's binding mutation fails before expensive native work. Each of the
six missing frames fails the bounded Resource check.

The constructor also rejects an original ordered-pair swap. A more subtle
negative preserves the complete original encrypted images and version tag while
changing C_state; complete retained source comparison must reject it. This
protects the distinction between an image/key version tag and a full proved
version claim. The original H8192 receiver rejects a genuine dense DATA frame
even when its separate State/Role3 prerequisites are genuine. No frame fallback,
accepted flag or supplied lower verification token is introduced.

All proof and owner fixtures remain under the existing test-private Word
inventory. The normal new production surface is only
`two_lane_encoding::data_formation::{prove_dense,verify_dense,dense_profile_digest}`.
It consumes the same guarded source witness/W/salts/SDK key and verifies the
same complete State/Role3 prerequisites at both producer and receiver. The
original public functions retain their fixed H8192 behavior. Distinct lower
frames are enforced by the two actual native receivers.

## Measured complete local mathematics

After builds, Clippy and documentation tests completed, the exact joined owning
case ran once at16 Rayon threads and then once at2 on the SAME final release
image. Runs were sequential. Fresh SDK keys, DATA/Query ciphertexts and proof
randomness differ between processes; original compact encrypted source images,
fixture/schema/Word command and workload are unchanged.
Background load is uncontrolled. These individual observations establish no
statistical bound or production thread policy.

| Measured phase | 2 threads, ms | 16 threads, ms |
| --- | ---: | ---: |
| Genuine immutable State proving |1984.841|942.078|
| Role3 proving, including fresh State prerequisite |1422.802|1083.887|
| Dense DATA proving, including fresh State/Role3 prerequisites |2494.840|1149.079|
| Original cold Word producing |405.192|129.879|
| Fused original Query producing |1667.600|390.819|
| Actual FHE multiplication and product certificate |30.992|31.572|
| Complete cold receiving of all six arguments |2253.644|1311.042|
| Client decryption/decoding |0.709|0.721|
| Owner setup through completed local read |10270.433|5048.899|
| Six frame bytes, excluding ciphertext endpoints |26930981|26928581|

The final owner interval begins before the bounded Word fixture and includes SDK
parameters/key generation, source/mask compilation, actual DATA/Query encryption,
all expectation/opening preparation, all six proofs/certificates, complete cold
receiving and client decryption. Its endpoint is captured before the independent
PUBLIC full-ring oracle and before any hostile test work. Individual phase timers
exclude the initial owner/fixture setup; the first two immutable-version phases
are deliberately NOT presented as per-query-only work. The DATA producing phase
retains mandatory prerequisite reverification rather than treating producer
output as trusted.

All receiving calls independently verify State, Role3, DATA, Word, fused Query
and conditional product under complete retained expectations. No prepared
verdict/cache or callback is supplied. The proof frames alone total about26.9MB,
which is also an unmeasured real-network cost. Original Source/Word/data binding
is now exercised together rather than assumed from independently generated
fixtures. The old537ms query-only component is not this complete boundary.

These numbers still exclude authorized key/lattice and product-security
assessment, independently established bootstrap/history/OldRoot, fresh weighted
QC and lock finality, peer transport, durable result installation and actual SQL
projection/completion. Word proves its constrained transition relative to the
retained old claim; this test does not establish the old claim's history. The
full-ring decoded values are not claimed as PostgreSQL returned rows. Neither
the500ms complete-query target nor live SQL functionality is established.

## Resources and retained evidence

Every native observation used the120s/1792MiB whole-PID fuses,20ms samples,
held image/creation identity and final exit0/no-direct-child checks. There were
no faults, fuse hits or forced cleanup. The17-case functional process lived
24500.4008ms, used38.890625 CPU-seconds and peaked at569098240 OS working-set
bytes and561487872 sampled private bytes. It overlapped Clippy; the original
DATA regression overlapped a documentation build. Their durations are test
feedback, not performance evidence.

The exact16/2-thread processes lived10451.3616/17287.2033ms and used
34.03125/25.546875 CPU-seconds. Their OS peaks were592994304/560791552 bytes and
sampled private peaks588357632/555302912. Those processes include the honest read,
all repaired hostile checks and oracle assertions; these are not per-proof or
concurrent-peer memory bounds. The original H8192 regression peaked at1371721728
OS working-set bytes, remaining inside its unchanged fuse.

Final release test image:11814400 bytes, SHA256
22D9E893A3C02DD91F8FD5B32E20C05537F77088E2F8476ADE5F447BA53919FE.
Ignored local build/check/held records r109-r112 retain complete source hashes,
commands, output and memory samples. The earlier successful r108 gate is
preliminary and is not the final timing evidence. This result update follows
those source snapshots and changes no executable code. No private key or
generated proof/ciphertext output is committed.

Reproduce using the pinned Rust1.99.0 MSVC/native release build, Cargo.lock,
one harness thread and `RAYON_NUM_THREADS=16`, then2:

```sh
cargo test --release --locked -p registry200-proof registry_progress::word_inventory::query_mask_inventory::read::tests::original_version_word_data_query_and_real_product_are_all_required_before_client_completion -- --exact --nocapture --test-threads=1
```

The next receiving design must distinguish immutable DATA admission from fresh
query/Word/finality checks. Reusing immutable admission can only use a privately
constructed, bound result from actual verification of that exact complete
version; a serialized flag, matching version tag alone or unverified DATA
metadata cannot replace any proof. It must still reject a different C_state,
image, key, operand pair, query or current agreed head.

## Retaining verified immutable DATA

The next stage uses the already existing move-only `VerifiedDataFormation`, whose
only constructors are actual full State/Role3/DATA receiving. The additive
public `require_expected` method compares complete Source metadata/images, the
literal original DATA request/nonce/ciphertext and full Cw/Cs/key contexts/roots.
It cannot verify a new proof, produce a result from raw metadata or assert
currentness. Existing H8192 and dense verification functions and their proof
requirements are unchanged.

The new private `verify_retained` requires that actual bound result plus three
unverified per-query frames. Only the earlier immutable theorem is retained:
conditional product checking, original Word native receiving and fused Query
native receiving still run on every call with independently retained complete
expectations and cold public setups. No per-query verdict is reused. Retention
has no serialized representation, accepting flag or new native frame. The old
six-frame cold receiver still checks all its proofs on every invocation.

The owning case installs DATA with a fresh independent native verification and
compares cold six-frame and retained three-frame receiving on the SAME original
query/proof bytes. It then produces an actual different query against that SAME
DATA/key: age255 no longer matches; call, invocation, SQL identity, QueryCt and
query nonce also change. Fresh complete Word and fused Query arguments and an
actual public FHE product/certificate are produced. Only successful receiving
allows owner decryption, and a separate full-ring oracle checks all4096 values.
The age255 row becomes zero while the first three row endpoints remain correct.
The oracle never supplies an answer to either evaluator or receiver.

After successful receiving, canonical OOD mutations of the new Word/Query proof
must still fail their actual native verifiers; product binding and all three
missing per-query frames must reject. Full DATA installation with a damaged
native argument must fail too. Retained comparison rejects a new C_state under
the SAME version tag/images, a changed installation nonce, actual re-encryption
of the SAME data, changed Cw or changed original Cs. A complete read expectation
with the foreign C_state also fails at retained DATA binding. The original
six-frame hostile cases are kept. Original H8192 receiving additionally exercises
the same public retained-comparison method.

The initial r113 two-thread case passed before documentation edits. Final
execution, comparison timings and exact boundaries follow after the stage gates.

### Executed retention gates and observations

The exact joined owning case passed at both16 and2 threads on the final release
image after build/Clippy/documentation gates completed. It covers original cold
receiving, independent DATA installation, paired receiving of the same query,
a genuinely different query and all retained/raw hostile checks above. The
unchanged H8192 owning case also passed in14.52s, including the new method on its
actual verified result. Two compile-fail private-construction/clone checks,
strict all-target release Clippy and requirements_sync passed. Other native
equations, profiles, security parameters and unchanged standalone mask cases
were not modified or claimed as newly executed coverage.

Runs were sequential at16 then2 threads on the SAME final image. There was no
overlapping task build or native test during these exact observations. Each
process uses its own fresh SDK key/ciphertexts/proof randomness; schema and
scenario are unchanged. Within a process the paired cold/retained receiver uses
the SAME original query and proof bytes. Cold receiving runs first. Background
load and cache effects are uncontrolled; one observation is not a latency bound
or statistical benchmark. Public Word setups remain cold and independent on
every receiving call; production thread policy is unchanged.

| Same original query | 2 threads, ms | 16 threads, ms |
| --- | ---: | ---: |
| Complete six-frame cold receiving |2045.190|1289.531|
| Separate independent DATA verification/retention |1361.705|915.042|
| Three-frame receiving with bound retained DATA |825.823|340.069|

The16-thread paired receiving observation is73.6% shorter; the2-thread one is
59.6% shorter. This comparison concerns receiving only. Installation includes
actual independent State/Role3/dense DATA verification, rather than a supplied
acceptance flag. Its proof generation and initial source/key/DATA preparation
are paid separately in the original complete owner cycle below; no part of them
is hidden inside a claimed full-query500ms result.

| Actual different query, SAME installed DATA | 2 threads, ms | 16 threads, ms |
| --- | ---: | ---: |
| Owner Word/statement/mask/QueryCt/opening/expectation preparation |2.708|2.797|
| Complete cold Word proving |403.806|130.752|
| Complete fused Query proving |1639.742|397.948|
| Actual FHE product and certificate |32.020|30.596|
| Cold retained-DATA receiving, all per-query checks |825.035|338.005|
| Client decryption/decoding |0.701|0.735|
| Whole new-query local cycle |2904.013|900.834|
| Three per-query frame bytes |8032778|8029450|

The new-query timer starts before the second owner Word fixture/statement and
actual mask encryption. It ends immediately after owner decryption/decoding,
before the public full-ring oracle and before hostile tests. It includes every
new per-query proof, actual ciphertext multiplication, certificate, independent
Word/Query setups and native receiving. It excludes initial source/DATA/key
preparation and the independent DATA installation, which are version work.
No Word proof, Query proof, FHE computation or per-query verdict is reused.
The retained object contains public metadata only, not proof buffers, keys,
setup, a current head or an unbounded cache.

For context the same processes' original complete owner setup through six-frame
read/decryption took9933.347/4979.493ms at2/16 threads and generated
26921541/26920229 proof-frame bytes. That boundary includes initial
key/parameter/source preparation, DATA/Query encryption and all immutable and
per-query proofs. Moving immutable verification out of each query does not make
that first setup free. Three new-query frames still total about8.03MB, a real
network cost not measured here. Even the900.834ms local query cycle exceeds500ms.

Both exact processes retained the120s/1792MiB whole-PID fuses,20ms samples,
held image/creation identity, exit0/no-direct-child checks and no faults or forced
cleanup. The16/2-thread complete test processes lived13532.9756/24465.2919ms,
used51.015625/37.265625 CPU-seconds and peaked at593555456/561508352 OS working-set
bytes and587927552/568209408 sampled private bytes. These processes include both
query scenarios, full original verification/installation, all hostile checks and
oracle assertions. They are not individual-operation or concurrent-peer memory
bounds. The original H8192 regression peaked at1371275264 OS working-set bytes.

Final release test image:11773952 bytes, SHA256
F6E40FBBA674519137E151AA7609538FB1B19088C67CCC859E7970D9FC5B90E7.
Ignored local records r114-r116 retain exact source hashes, commands, output and
memory samples; the r113 run is preliminary. The result update follows those
snapshots and changes no executable code. Private material and generated
proof/ciphertext outputs remain ignored. The exact reproduction command above
still runs this strengthened owning case with one harness thread and the
selected Rayon setting.

This is still test-private mathematical composition. The only new normal public
API is `VerifiedDataFormation::require_expected`. Full source/Word/key/product
cryptographic assessment, authoritative bootstrap/history/OldRoot, independently
fresh weighted QC, real peer transport, SQL projection and durable lock/result
completion remain required. In particular, the historical
`registry200_finality::progress::VerifiedParent` explicitly does not establish
a current lock lease and is not adopted here as freshness. No production
storage-client/runtime admission or refusal guard changed. The complete-query
<=500ms goal remains unmet.
