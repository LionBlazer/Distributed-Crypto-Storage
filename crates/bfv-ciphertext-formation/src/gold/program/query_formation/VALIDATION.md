# Fused query Formation validation

The first metadata-only gate ran on2026-10-21 before any new private proof. It
passed in0.04s; the held process lived62.5741ms and reported9740288 OS-peak
working-set bytes, without faults or cleanup under the120s/1792MiB fuses.
This is metadata cost, not query latency. That r93 capture has unconditional
successor source pins for the complete ordered tuple and every public field:

| Captured object | SHA256 |
| --- | --- |
| Ordered native constraints/lookups,572381 bytes |8195b92cafa2121eb7da4232d18b6a90ed9868a57136a297bd3424882b8065f1|
| Domain-prefixed full PP,1449984 fields |d37135fbf16749c8cb08669b109fec4af772cf5fe6906c5ae4394c6fb3bd1932|
| Mathematical profile digest |ec46bf5679719336a842e4790887f1c8c3eb88fcee1ebf69ca893dfd4492737e|
| Frame profile digest |6a59432b675bda962f240a1c5a5447f2f4e850c62ebb5913b2e79161ae37e354|

The final two table rows are SHA256 of the respective profile bytes, matching
the explicit test convention. They are not proof acceptance labels. Numerical
geometry and workspace/model limits are in the module README. Private/native
execution must be recorded separately; metadata success proves none of it.

## Executed native and regression gates

The final seven-case owning filter passed in7.33s. It produces one genuine
honest native proof and two genuine false-input proofs, on actual SDK-generated
keys/ciphertexts. The public patterned mask exercises mixed bits in all eight
words; every4096 range coefficient and every emitted word is checked. An altered
header with its entire hash path/root repaired still violates actual equations.

The false high-coefficient case uses a real SDK QueryCt, correct same-key DATA
equations and honest complete Cw/Cs/Stmt hashes, but W[256]!=0. It must fail full
native verification. The second false proof changes a packed statement-mask word
and repairs every statement hash/root/public association while keeping the FHE
input. All local equations pass, but the native verifier returns the actual
Lookup(TerminalSumNonZero). Replacing only that terminal with zero then fails the
independent native opening/OOD verification. No metadata, decryption or local
diagnostic is used as an accepting proof oracle. The honest writer independently
refuses a wrong high coefficient before constructing its MAIN.

Six unchanged dense DATA cases passed in4.48s, including actual facade proofs,
hostile receiving and the unconditional original wire-profile literal
02da94943cc4525796b506c168276e91be771cd5269a75469d4c59eef002c68f.
Two complete original Pair/DATA symbolic and PP regressions passed in0.07s.
The existing sixteen-case registry QueryMask/join filter passed in11.23s against
the ordinary non-test lower library. Both affected libraries passed strict
all-target release Clippy; all four compile-fail ownership cases and the
dependency-free requirements-sync guard passed. These31 owning cases and their
supporting checks do not constitute a green full SQL suite.

The shared native implementation is instantiated into two closed namespaces;
Expected/Prepared types, AIR, geometry and wire identity remain fixed per host.
The original profile, complete PP and equations are preserved. There is no
runtime protocol selector, accepting verifier callback, compatibility fallback
or lint suppression. The fused namespace remains test-only. Whole-source
snapshots precede this documentation-only final record.

## Complete native component observations

After this task's builds completed, the same exact honest/hostile owning case ran
once at16 Rayon threads and once at2, sequentially on the same release image.
Only the independently prepared honest proof/receive intervals are timed below.
Ciphertexts, fresh keys and proof randomness differ between processes; the mask
fixture algorithm and fixed mathematical workload are the same. Background load
was uncontrolled. These are individual observations, not a latency bound, a
paired old/new comparison or a production thread-policy change.

| Phase | 2 threads, ms | 16 threads, ms |
| --- | ---: | ---: |
| Producer public PP |380.434|74.024|
| Complete private MAIN |8.916|8.391|
| Native proving |876.686|233.364|
| Complete producing/framing |1296.176|355.991|
| Independent receiver public PP |371.695|73.879|
| Native verification |73.968|70.792|
| Complete cold receiving |475.615|177.418|
| Producing plus receiving |1771.791|533.409|
| Frame bytes |3362741|3358549|

Timers include actual public setup, guarded private graph/range/hash writing,
fresh native proving, canonical framing, independent cold public setup, bounded
decode/topology and native verification. Fixture key generation/encryption and
opening-constructor preparation are outside the intervals. Source/Word/DATA/key
admission, original ordered-pair join, FHE product/result, client completion,
fresh weighted finality, network and durable SQL locks are also outside them.
Even this standalone component exceeds500ms. No complete-query result follows.

Public PP construction accounts for147.903ms of the16-thread observation. The
matrix and public setup still depend on the exact request; they cannot simply
be reused for a different query. Any further static-part reuse must preserve
the complete independently reconstructed commitment and native verification.

## Resources and retained records

The same120s/1792MiB whole-PID fuses,20ms sampling, held image/creation identity,
successful terminal state and no-direct-child checks applied to every final
observation. No final gate hit a fuse, fault or forced cleanup. The full seven
cases lived7336.7019ms, used13.546875 CPU-seconds, peaked at505131008 sampled
private bytes and516096000 OS working-set bytes. The two exact observations
lived2636.0176/813.7924ms at2/16 threads and used4.625/6.59375 CPU-seconds, with
OS peaks514560000/515776512 bytes. These standalone processes are not concurrent
peer or complete-operation memory bounds.

Final lower release image:6385664 bytes, SHA256
588FB41A1754F3B92AAE1B6AAB95B33534114E4BFB9C26DFE769616434249088.
The ordinary registry regression image:11349504 bytes, SHA256
038BBCAA51D4BFA6032E39CC929740F0E5CCFE4B180ED6AC58FFA13ED1E96ECE.
Ignored local builds/held records r96-r100 retain the exact source hashes,
commands, complete output and memory samples. The earlier r92 metadata attempt
failed before private proving because the shared wire guard still required the
old PP width; it is preserved and not counted as a passing gate. The successful
r93 capture preceded private proofs and is the source of the unconditional pins.
Generated proof outputs and private material are not checked-in fixtures.

## Remaining system boundary

The live owner progress preparation still uses the separate Source/Input16 and
Control815/Predicate896 chain; see its
[actual preparation](../../../../../storage-client/src/private_predicate/source/locking/joint/progress/prepare.rs).
This candidate cannot be relabeled into that protocol or substituted for its
Word/Source/fresh-head admission. The original exact statement/header, retained
DATA/key, original ordered pair and actual product/result must be joined before
an upper receiver can admit SQL. The
[SQL capability guard](../../../../../storage-client/SQL-CAPABILITY-VALIDATION.md)
remains closed. No mutation/lock can be committed from this component alone.
