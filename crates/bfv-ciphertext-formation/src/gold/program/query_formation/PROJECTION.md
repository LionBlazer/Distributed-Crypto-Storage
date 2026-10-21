# Exact structured-Query range projection

The v2 DCSGQF02 backend keeps the complete original Query relation: all81920
Formation gates,4096 coefficients, literal original QueryCt/nonce/association,
original Cw4112 and Cs528 hashes, Stmt96/header13/zero95, reversed mask lookup,
shared bounded S/E and exact symmetric K equations. It changes no FHE parameter,
noise bound, primitive, private randomness, finality or SQL-admission policy.

## Projection argument

For each of the low256 coefficients, the existing active-mask equation is
W*(W-16389)=0 over the Gold prime field. Therefore W is exactly0 or16389. For
all3840 remaining coefficients, the existing high-mask equation is W=0. These
constraints are kept for EVERY coefficient, including the range-only tail rows.
Both possible canonical representatives lie in[0,65536].

The original additional range witness consisted of17 boolean bits for W and17
for65536-W. Since their integer sum is65536 and their possible integer values
are below2^17, their field equations cannot wrap the Gold modulus. Given any new
satisfying witness, inserting the unique ordinary binary expansions of those
two integers satisfies every omitted old constraint. Conversely, deleting those
bits from an old satisfying witness preserves every new constraint. The same
W values enter the full Cw hash, mask lookup and exact Formation equations.
All other columns/relations stay identical under the fixed offset remapping.
Thus this is existential witness projection, not omission of a required range.

Every coefficient keeps all64 S/E/K range bits. Only its34 implied W/slack bits
are removed:68 bits per two-coefficient row. Removing28 obsolete padding cells
then reduces MAIN512 to416,18.75%, or1572864 raw bytes at H2048. Public PP708,
PV32, all248 original/83 packed lookups, AUX420, eight quotient chunks, GoldEF5,
192 queries, blowup3, salt4, random5 and the128-bit assessment floor are retained.
The native assessor derives the changed constraints and resource budget afresh.

## Independent old-relation check

The test-only FullWordRangeAir evaluates the old complete equations and512-column
layout. It has no legacy native producer, receiver, wire format or negotiation.
A compact genuine private trace is expanded by reconstructing exactly the omitted
bits from each actual W coefficient; it must satisfy ALL original full native
constraints. Flipping one reconstructed bit must fail that original checker.
The normal fixed backend accepts only the416-column MetadataAir type.

The actual old Pair/DATA range emitter remains unchanged in its false generic
instantiation, and its existing ordered-symbolic/full-PP pins remain mandatory.
The Query projection case also retains the original literal full-PP digest using
the original v1 hash prefix. All1449984 preprocessed cells and their order must
still match that original digest. No new expected digest replaces that old test.

Before any new native proof, r189 passed both metadata and old-relation projection
checks. The native assessment derived1098 BASE/86 EXT constraints, degree4,
83 packed lookups, AUX420,8 chunks and2490 batched openings. Its checked workspace
estimate is657719296 bytes versus687603712 for v1. Its UDR/LDR terms both retain
the128-bit floor and the actual LogUp estimate is297.045803689613 bits. These
are conditional proof-component assessments, not BFV/composed/SQL assurances.

The independent public metadata capture pins the564835-byte ordered tuple to
`c134fc6a96e685ef0a0db909020de6ee08954dae2ddbdda7c0cfaa3fbb59a96b`.
The new domain-prefixed full-PP digest is
`c37659509244a5efd78996007d6ad60e9d7e96a0ce5093f0797af85c0c0f4406`;
the original v1 prefix still yields
`d37135fbf16749c8cb08669b109fec4af772cf5fe6906c5ae4394c6fb3bd1932`.
New mathematical/profile and frame-profile digest hashes are respectively
`c3ca285d0da35b3036dc1482fc1f453490da3e1d07da4c1af6dfec8341649bcd` and
`7349f4d8f2864e980cb46702511cbe864fcfa163557c1b1ed61d1c58d26cc125`.
Old DCSGQF01 bytes are rejected; no format fallback or accepting flag is added.
Complete native proving, hostile proofs and upper read measurements follow this
metadata gate. The complete-query <=500ms goal is not established by projection.


## Executed v2 native and consumer validation

All35 Gold cases passed in32.00s (r191), including genuine native Query proofs,
repaired header/statement/hash/terminal/OOD arguments, false high-W witnesses,
all original Pair/DATA full preprocessing/ordered-symbolic snapshots and the
unchanged separate two-AIR candidate snapshot. Old frame bytes reject at both
cold and prepared Query receivers. The first full r190 attempt passed34 cases
and failed only the topology test's obsolete literal DCSGQF01 expectation; that
assertion now strictly requires DCSGQF02. No cap or native check was waived.
The final35-case image is6450688 bytes, SHA256
`90B5E5327848D844DD14E4F3F48A4D3B8EDA3690013ECC17013F655A9F0D3A30`.
That process lived32028.6663ms, used59.90625 CPU-seconds, reached1351012352
OS peak working-set bytes and1345019904 sampled private bytes across1570 samples.
This suite includes the larger original Pair; its peak is not Query-only memory.

For comparison with the old r181 filter, r192 reran the same7 Query owning cases
on that exact new image. All7 passed in8.81s. The process lived8827.71ms,
used15.828125 CPU-seconds and reached488521728 OS peak working-set bytes and
482746368 sampled private bytes across430 samples. The old7-case r181 OS peak
was516104192 bytes. The honest v2 proof is3201237 bytes versus3354005 in that
old v1 observation. Its producer/cold receiver measured1415.400/608.581ms;
preparing an independent receiver took490.385ms plus96.078ms successful receiving.
The old producer/cold receiver were1389.528/545.554ms. The smaller matrix/proof
and measured memory reduction do NOT establish a latency improvement.

The normal protected-owner Source/Role3/DATA/Word/Query/product read passed in
31.29s including hostile examples (r193). A generated/sealed/destroyed/restored
Owner retains its secret throughout. All five repaired native proof families,
exact complete immutable-DATA checks, genuine product arithmetic, original
request binding and post-check full-ring oracle remain. The independently
prepared public receiver overlaps production through the same bounded local
channel and shared Rayon pool as r184. The second actual query against the same
verified immutable DATA measured:

| Phase | Milliseconds |
| --- | ---: |
| Original owner query preparation | 3.772 |
| Actual public FHE product and certificate | 44.279 |
| Public receiving preparation, overlapping | 832.401 |
| Word proof, sharing the CPU pool | 886.548 |
| Query proof | 1502.857 |
| Prepared Word/Query/product receiving | 226.132 |
| Protected client completion | 1.419 |
| Entire local query interval, including all setup | 2666.541 |

Three query frames total7886026 bytes. The earlier v1 pipeline measured2679.455ms;
these sparse observations show no confirmed full-operation speedup. They are
local conditional mathematics, with no actual peer transport, fresh weighted
head, SQL completion or durable finalized lock. The <=500ms goal is not achieved.

The same upper image passed all16 standalone-mask/Formation-adapter cases in7.00s
(r194), including its strict new frame literal, all original scope binding,
genuine ciphertext/proof and repaired native failure checks. Its image is
12326400 bytes, SHA256
`596BC75D3FCC48E78E847D48AC427DC63936F2B941DDEE4F3726416FA89CEC23`.
The full read process lived31305.2345ms, used42.921875 CPU-seconds and reached
561950720 OS peak working-set bytes and556068864 sampled private bytes across
1533 samples. The16-case process lived7005.366ms, used12.25 CPU-seconds and
reached511328256 OS peak working-set bytes. These are test processes, not
complete-peer RAM guarantees.

All successful observers confirmed exact source/image/creation identity,
terminal exit0, no faults, no remaining direct child and no forced cleanup.
The pinned Rust1.99/native/release/locked/offline environment, shared Rayon2,
one harness thread and120s/1792MiB whole-process research fuses were retained.
No other build/test was intentionally run during an observation. The composed
read adds one public receiving thread; Rayon2 is not a total thread count.
Strict release/all-target Clippy passed for both libraries. All6 Gold and8 Word
compile-fail contracts and the dependency-free requirements mirror guard passed.
Code identities were compared against those actual successful captures before
writing this final documentation. No generated proof, private input or key is
committed. Current application acceptance/finality/security guards stay closed.
