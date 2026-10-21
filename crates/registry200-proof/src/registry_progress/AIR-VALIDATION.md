# Progress AIR factoring and feasibility validation

Executed on 2026-10-21, Windows x86_64/MSVC Rust 1.99 release, opt3,
`-C target-cpu=native`, two Cargo jobs/two Rayon threads. This stage factors
private equations and provides fast structural feedback; it does not implement
the new Cmd relation or establish a faster complete SQL query.

## Actual old contract comparison

Two `registry_progress::air_snapshot_tests` cases run the actual native
`get_all_symbolic_constraints` and Postcard representation. Fixed inputs are
explicitly public/nonsecret metadata from the existing published test authority.
No Source/Encoding proof, FHE fixture, MAIN/LDE or private witness is created.
All temporary capture builders and optional golden branches were removed.

Each role has four unconditional digests: its actual math/wire profile, complete
Statement identity/public values, ordered BASE/EXT constraints with full BaseAir
metadata, and every native periodic column/cell. The complete 512x512 periodic
table is checked, including its 262144 fields; it is not sampled.

| Role | Public values | BASE constraints | EXT | Symbolic stream bytes |
| --- | ---: | ---: | ---: | ---: |
| Control |815|31823|0|2891677|
| Predicate |896|31123|0|2942576|

Both retain MAIN width 8266, H512 and the complete original next-column lists.
The eight hashes passed before and after the exact private extraction into
`equations::predicate`. Every assertion remains in its original order; the
original wrapper supplies the same SQL identity. All profiles, periodic cells,
public builders, proof/prerequisite verifiers and codecs are unchanged.

The final pair, after removing the temporary inventory, ran in 0.14s
(154.402ms process lifetime,0.125 CPU seconds), with peak sampled private bytes
26963968 and OS peak working set 31985664 bytes. Its release executable was
9407488 bytes, SHA256
`4947E4A0209211889E0A63F5F598D71B7536083D8971846E3CDFB2D6EACA99BD`.
These structural checks do not
substitute for cryptographic or behavioral validation when the relation changes.

The existing relation proves a transition relative to an independently proved
previous root. It opens the selected actor's old Progress48 on resume and its
new Progress48 when parked. For the other slot it checks presence/root shape and
exact carry or End compaction; its full semantic validity follows from bootstrap
and the verified transition history. This is not standalone validation of an
arbitrary private State supplied with public metadata. A new relation must retain
that explicit inductive contract or additionally open/check both full preimages;
an owner model or stored success flag cannot replace the required chain evidence.

## Rejected mechanical bit-level lowering

A temporary test-private compiler collected a genuine logical SymbolicExpr DAG,
shared identical ordered subtrees, and counted every producer/read/assertion
event, including repeated operands. Three cases passed in 0.09s: both-role
inventory, duplicate-read multiplicity and refusal of nonlocal symbolic leaves.
No accepting AIR, verifier, proof, trace or SQL authority was implemented.

| Role | Logical assertions | Input wires | Binary gates | Total wires | Port events | Minimum rows at64 ports |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Control |19338|7638|54215|63354|183848|2873|
| Predicate |18541|7622|57824|66942|193587|3025|

Greedy rows were 2912/3066; maximum fanout 1940/1931. Source hashing, serializers,
four authenticated mask lookups and padding were still excluded. Consequently
this specific lowering cannot fit H512 even before those missing obligations.
It is not a lower bound on word-level relations or cryptography in general.
The rejected compiler and its complete source/results remain local research
artifacts; no partial relation or guessed admissibility flag is retained in Core.

## Checks and remaining work

Strict all-target Clippy passed after the extraction. The metadata tests use the
real release test target, Cargo offline/locked and a held-process 120s/1792MiB
observer; no fuse, cleanup kill or unexpected direct child occurred.

A new relation must implement a complete typed word-level inventory, exact
canonicality and u64 limb/carry checks, authorization, physical row order,
conflict-before-OFFSET, WAIT/resume, NOWAIT, SKIP, progress, writes and Result160.
It must bind the real source/DATA and originating request and pass actual native
security/resource/proof rejection gates before runtime composition. Full FHE
computation, fresh weighted QC, durable tickets and complete SQL response remain
separate required work. No full-query speedup or <=500ms result is claimed here.

## Complete word-level candidate, first layout

The subsequent temporary inspector implements the full relative word relation,
with two ranged u32 limbs per u64, exact equality, canonical banks, all control
writes, physical predicate scan and continuation. The complete streams contain
1672 fields: Source680, Enrollment64, old208, Cmd160, new208, Result160,
Statement96 and two Progress48 preimages. Their 209 native Poseidon2 permutations
are included, alongside all ranges, mode policies, four mask reads and padding.
No legacy Encoding Cmd48 is relabeled: this candidate is a separate research
family requiring the protected owner/request composition described above.

Root and the independent reviewer removed a circular context dependency before
native inspection. The final context contains only independent source/version,
profile, genesis, parent, enrollment and scope data. It excludes the Cmd and
Result roots that consume it. The public sample has arbitrary unproved output
roots and supplies no honest witness, accepted DATA or SQL result.

Four owning inventory cases passed in 0.05 s. They check both complete roles,
refusal of missing real hash/serialization routes, duplicate reads, padding and
the actual P3 symbolic/LogUp construction. The phase-exclusive layout measured:

| Rows by phase | Control | Predicate |
| --- | ---: | ---: |
| Input providers |16|18|
| Arithmetic |161|158|
| Assertions |15|17|
| Ranges |107|113|
| Full hash permutations |209|209|
| Policy reads |104|118|
| Policy providers |25|25|
| Mask providers |32|32|
| Mask reads |4|4|
| Total |673|694|

Consequently this layout exceeds H512 and would pad to H1024. MAIN width is 568,
PP width 695; all 1672 fields and 209 absorbs are counted. Control/Predicate have
7763/7853 values, 9820/9863 wire reads, 918/1057 assertions and 853/903 ranges;
maximum fanout is 182. Actual native BASE counts are 1315/1314 with EXT33,
degree 4, 87 original messages, 30 default packed groups, eight committed quotient
chunks against rate 8 and AUX155. These metadata results do not assess security,
resources or proving time, and do not establish a complete-query speedup.

The inventory process took 65.531 ms/0.0625 CPU seconds, sampled peak private bytes
5,120,000 and OS peak working set 14,528,512. Its 9,924,608-byte image SHA256 was
`97F67DF7C748B195F89EA597B58907081A0056B4D2ACE1161D72E13327446E47`.
No PP/MAIN/LDE/PCS/proof was created; the process measurements cover inspection
only. Strict Clippy passed. The old two snapshot cases also passed in 0.15 s on
that image, preserving all eight unconditional hashes.

The exact executed inspector, including its temporary dev edges, was archived
under `.local/word-cmd-native-overlay-r1`; only the experiment's own files were
removed and its guarded original manifest, lock and registration restored.
No rejected or partial backend remains in Core. Receipts use
`.local/word-cmd-native-r2-` and `r3-`. The next layout can reuse otherwise idle
hash-row space for ranges/input providers and batch policy reads; it must retain
the identical full semantic graph and pass a new native inventory. Fit alone
still precedes actual security/resource, honest-proof and hostile-wire gates.

## Packed complete word-level layout

The second temporary layout retains the same complete semantic factory. It puts
eight range values and their 256 decomposition bits into spare hash-row cells,
then places Input providers in the remaining ports. Twelve mode-policy queries
share a row, each enabled by a separate verifier-owned PP flag. Short groups have
fixed zero padding; no private route or multiplicity selector was introduced.

Both complete roles measured 455 rows and fit H512. Control phases are
`[0,161,15,0,209,9,25,32,4]`; Predicate phases are
`[0,158,17,0,209,10,25,32,4]`, in the order of the preceding table. MAIN568,
all values, assertions, ranges, wire reads, stream fields and hash absorbs remain
unchanged. PP is 708. Actual SDK counts are BASE 1315/1314, EXT 37, degree 4,
98 original messages, 34 default packed groups, eight committed chunks against
rate 8 and AUX 175. Q192, EF5, five random codewords and four salt elements remain.
This is measured layout fit, not a security/resource assessment or proving time.

Five owning cases passed in 0.06 s. The added case compares the entire explicit
semantic Pool byte vector before and after layout, checks all fixed placements
and partial policy groups, then requires rejection after removing a range flag.
Control has 282032 serialized bytes and Predicate 287395; all eight semantic Rust
files and both Cargo images stayed RAW identical to the executed first layout.
The same image passed the old two snapshot cases in 0.13 s with all eight hashes.
Strict all-target Clippy passed. The 9,948,160-byte image SHA256 is
`703ACC02BEC40BF53FCCBC940D6BB4769E9103842E3EB352D021DC4688619BFE`.
The five-case process lasted 90.742 ms/0.078125 CPU seconds, with sampled peak
private bytes 6,995,968 and OS peak working set 13,856,768; no fuse or cleanup kill.

Receipts are `.local/word-cmd-native-r4-` and `r5-`; the exact executed 14-file
overlay is archived at `.local/word-cmd-native-overlay-r2`. Its own temporary
files and three guarded Core edits were removed/restored after checking. No
accepting word backend remains in Core. No private witness, committed PP/MAIN,
LDE, PCS or proof was allocated. A typed honest witness recipe, actual complete
native proofs and hostile cold verification, full resource/soundness assessment
and the independently admitted Source/DATA/Owner/current-head composition remain
required. The complete DCS query has not met the <=500ms target.

## Native parameter and workspace assessment

A separate private inspector assessed the actual packed AIR with the pinned SDK.
It derives all BASE and EXT constraints, default LogUp packing and weighted
degree, both MAIN/PP rotations, eight ZK quotient chunks and 3012 opening powers.
The hiding reserve is 404 rows against H512. Original lookup counts remain 98
with widest tuple 5; signed count-height weights are 7158272/7165440.

Both independent SDK baselines and the reports with the lookup term reached
128 bits for UDR and LDR. Every reported term was finite and at least 128 bits;
the lookup fingerprint term was 299.577935 bits. These are conditional SDK model
results for this standalone AIR. They do not establish the confidentiality of
the BFV profile, the soundness of the complete DCS operation or an accepted proof.

The arithmetic workspace envelope is 155095040 bytes. Explicit additional
reserves for IR/Plan, future recipes and SSA values, symbolic/native runtime,
codec buffers, owner prerequisites, threads and allocator raise the policy
ledger to 712764925/713022687 bytes. Future code must enforce its actual bounds;
these reserves are not measurements or a whole-process memory theorem. The
external 1792 MiB held-process cap stays unchanged.

All six owning cases passed in 0.11 s; strict all-target Clippy passed. The
process lasted 122.7371 ms with 0.078125 CPU seconds and OS peak working set
14307328 bytes, without a fuse, cleanup kill or unexpected direct child. It
built no PP/MAIN, PCS or proof. Its 10001408-byte image SHA256 is
`E3630724040BDAE606AF4490B3CF0CCF52C6DA0E7CCFA21DA39FD06920471D80`.
The complete per-term reports are in `.local/word-cmd-native-r6-`; the exact
15-file inspector is archived at `.local/word-cmd-assessment-native-overlay-r1`.
Only its own temporary files and guarded Core edits were removed/restored.
This assessment creates neither an honest witness nor a native proof.

## Complete private witness and direct diagnostics

The closed factory now has a private typed origin/recipe sidecar for every Input.
It retains operands and gates for inverses, equality, u64 borrow/carry and
principal selectors, with cycle/depth/count guards. Evaluation memoizes the
actual 209 Poseidon2 permutations and writes the whole MAIN, including unused
cells and all 57 padding rows. The semantic Pool bytes and their two recorded
SHA512 values remain exact unconditional goldens; the AIR and plan are unchanged.

Both bounded public examples, Control Begin and Predicate Start/Done, produced
honest 512-by-568 traces accepted by the SDK BASE diagnostics and every original
native lookup expression. The Predicate example locks the OFFSET row and selects
the next two physical rows. These owner examples supply no peer SQL answer,
Source/DATA admission, verified prior-state history or current quorum certificate.

An actual Add input/output mutation preserves its local BASE equation but fails
the wire multiset. A repaired mask-frequency mutation similarly passes BASE and
fails the original lookup. Damaged permutation/range cells fail BASE; missing
origins, cycles, private u32 overflow and a foreign Result claim fail at their
respective producer boundaries. These are direct diagnostics, not native proof
rejections. Private buffers use best-effort fills without a total erasure claim.

All ten owning cases, including the preceding parameter assessment, passed in
0.18 s. Strict all-target Clippy passed. Process lifetime was 210.5647 ms with
0.171875 CPU seconds, sampled peak private bytes 7962624 and OS peak working set
17473536, without a fuse, cleanup kill or unexpected child. The 10113024-byte
image SHA256 is
`7677C335811F84DAAAC3C8A3D59FB9E9A91FE3E7D6FFF4A26D4CFE35C10553D9`.
The exact 21-file overlay is archived at `.local/word-witness-native-overlay-r1`;
receipts use `.local/word-cmd-native-r9-`. Its own temporary Core edits were
removed/restored. AUX, PCS, proofs and SQL authority were never created. Genuine
honest and hostile hiding proofs, bounded cold verification and complete DCS
composition remain required; these timings do not establish a <=500ms query.

## Actual complete word hiding proofs and cold receiver

The complete private candidate now has a genuine native hiding prover and cold
receiver, not just trace diagnostics. PUBLIC preprocessing uses its own sealed
deterministic setup, which is dropped before any private commitment. The producer
checks the same complete schedule and uses fresh OS randomness for actual native
proving. The receiver rebuilds its own AIR and trusted PUBLIC CommonData; no
sender-selected preprocessing, cached verdict or admission token is accepted.

The separate canonical frame binds the complete independently retained public
expectation, role and profile. Its 4MiB byte limit, 4096 per-sequence limit and
4Mi shared-slot limit precede native verification. All five PCS rounds and full
MAIN2/PP2/AUX2/FRI topology are checked. The scalar field's binary representation
is strict canonical LE[8]; all five extension coordinates, EOF and re-encoding
are also checked. The original complete semantic Pool goldens remain unchanged.

All 13 owning cases passed in 2.32 s, including both actual honest role proofs
and cold verification. A repaired Add passes every local BASE equation but has
an unbalanced wire multiset. Release proving created its actual proof, and
native verification rejected it with exact `Lookup(TerminalSumNonZero)`.
Forging its terminal to zero passes fixed topology but still fails actual native
opening/OOD verification. Wrong MAIN/PP/AUX openings and a FRI leaf also fail
native verification. Header/scope, canonicality, EOF, sequence/global/frontier
limits and a final restored honest cold verification passed their owning gates.

One optimized CPU/Rayon2 sample measured these phases in milliseconds:

| Phase | Control | Predicate |
| --- | ---: | ---: |
| Producer assessment | 11.444 | 12.374 |
| Producer PUBLIC preprocessing | 91.234 | 94.423 |
| Private MAIN preparation | 4.255 | 4.490 |
| Native proving | 180.101 | 183.430 |
| Canonical encoding | 3.611 | 3.467 |
| Producer total, including cleanup/gaps | 296.452 | 303.881 |
| Cold assessment | 11.411 | 12.109 |
| Cold canonical decode | 6.426 | 6.482 |
| Cold PUBLIC preprocessing | 94.576 | 90.858 |
| Native verification | 60.881 | 60.429 |
| Cold total, including cleanup/gaps | 178.022 | 174.624 |

Frames were 2926794/2925098 bytes. Totals overlap their component phases and must
not be added to them. Later fast hostile rejections are excluded from honest
verification measurements. Unrelated compiler processes were active; these are
diagnostic single samples, without a controlled comparative speedup claim.

The supervised 13-case process lasted 2331.6882 ms with 3.609375 CPU seconds,
114 memory samples, sampled peak private bytes 118890496 and OS peak working set
129662976. It exited zero with no fuse, cleanup kill or unexpected direct child.
Strict all-target Clippy passed. The 10474496-byte image SHA256 is
`FA7B717B3FCFCAEEFC530AF8298B1E9016F38588DB549B9616A5D6CECD3DA40F`.

Receipts use `.local/word-cmd-native-r12-`; the exact executed 24-file overlay is
archived at `.local/word-probe-native-overlay-r1`, aggregate SHA256
`772DD5EB2CB9AFE7E5170EB5CF71814CFD73190CABBD8878AB0BA2B6AEF17C5D`.
After validation the private module is retained in source under `cfg(test)`;
only documentation/comments were updated afterwards. No production receiving
API, feature escape or accepted-state capability was added.

These samples exclude Source/DATA proofs, the original FHE request/product,
independently proved bootstrap/history, fresh weighted quorum certificates,
transport and durable completion. Honest fixtures exercise only Begin and
Start/Done; the remaining business branches need their own witness/proof gates.
Standalone SDK parameter reports do not establish BFV confidentiality or
complete-system security. The complete DCS query has not met <=500ms. Rebuilding
request-specific PUBLIC preprocessing on each side is a measured next target;
it cannot be cached across different requests without a new constrained-input
profile and independent native security/binding checks.

## Structural public preprocessing with constrained request values

The new explicit private profile
`word208-v2-structuralPP-direct309PUBLIC` moves 309 public metadata words into
ordinary AIR constraints. Addresses are allocated independently of their values;
private Source openings, banks, mask/WHERE and salts stay private. All 1672 hash
fields and 209 Poseidon2 absorbs remain. The complete role-only factory accepts
no Metadata or sample fixture. Public setup depends only on role/profile/label.
The existing production profiles and receiving APIs are unchanged.

The first actual stage measured Control/Predicate at 462/460 rows, H512, MAIN568,
PP714, BASE1624/1623, EXT37 and degree4. There are 98 original messages, 34 default
packed groups, AUX175, eight committed chunks, 3024 opening powers and 404 hiding
rows. The two full IR hashes, every PP cell and native public commitment were
captured before proving and are now mandatory literal guards with no fallback.
Thirteen inventory, witness and preprocessing-invariance cases passed in 0.68s.
That stage produced no private proof; receipts use `.local/word-cmd-native-r15-`
and the source archive is `.local/word-public-native-overlay-r1`.

The subsequent proof stage independently constructs producer ProverData and
receiver CommonData from those fixed role factories. The receiver discards
recipes and prover-only data. Each call derives its current Expected309 and
performs fresh native verification; private proving uses fresh OS randomness.
Public setup holds no private input, trace, RNG or verification-status cache.
The workspace policy explicitly charges another independent public setup and
totals 789257618/789652334 bytes. Its ledger is not an RSS theorem.

All 16 cases passed in 3.94s, including genuine Control m0 and Predicate m0/m1
proofs. The same immutable predicate producer setup and independently constructed
receiver accept distinct valid expectations. An m0 proof with its plain header
repaired for valid m1 passes full canonical shape and fails exact native
`Verification`; a genuine new m1 proof succeeds. The actual release false-wire
proof fails `Lookup(TerminalSumNonZero)`; repairing its terminal to zero still
fails native opening/OOD. Existing canonicality, malformed MAIN/PP/AUX/FRI,
per-sequence/global/frontier limits and restored honest verification gates pass.
Private v2 `DCSWCW02` rejects the old frame. Its byte, sequence, slot and external
120s/1792MiB process caps are unchanged; MAIN2/PP2/AUX2 rotations remain intact.

One CPU/Rayon2 sample recorded these milliseconds:

| Phase | Control m0 | Predicate m0 | Predicate m1, prepared setup |
| --- | ---: | ---: | ---: |
| Producer setup, including assessment and PUBLIC PP | 112.817 | 113.052 | already prepared |
| Private MAIN | 2.231 | 2.312 | 2.442 |
| Native proving | 176.917 | 171.776 | 177.852 |
| Canonical encoding | 3.152 | 3.212 | 3.248 |
| Producer wall, including setup for m0 | 298.990 | 291.350 | 184.436 |
| Independent receiver setup | 110.082 | 111.608 | 113.873, measured separately |
| Canonical decoding | 5.682 | 5.769 | 5.761 |
| Native verification | 61.619 | 62.733 | 61.152 |
| Receiving wall, including setup for m0 | 178.822 | 181.672 | 67.525 |
| Creation plus independent receiving | 477.811 | 473.021 | 251.961 |

The warm receiver also freshly verified the genuine m0 proof in 67.484ms. Cold
frames were 2934954/2935946 bytes; the distinct m1 frame was 2941770 bytes.
RAII totals overlap their phases and must not be added again. Fast hostile
rejections do not count as honest verification timings. These are diagnostic
single samples, not a controlled comparative or complete-query benchmark.

The supervised process lasted 3957.4137ms with 6.265625 CPU seconds and 194 memory
samples. Sampled peak private bytes were 165621760; OS peak working set was
168398848. It exited zero, without a fuse, cleanup kill or unexpected direct
child. The optimized test image was 10573824 bytes, SHA256
`85EF2F143D0CE833F2234BFFDEB80951255B6C07DEE4905382E6D061B8F15E5C`.
Strict all-target release Clippy passed. Actual receipts use
`.local/word-cmd-native-r17-`; the exact executed 28-file source is archived at
`.local/word-public-proof-native-overlay-r1`, aggregate SHA256
`8C7F47FA7D91FA9DEA06ACED5D0A590F8D5080629E77C9FE66F1830115B01888`.
Only documentation/comments were changed after this native gate.

This remains a test-private mathematical candidate. Honest fixtures cover Begin
and Start/Done; other business branches require their own witness/proof cases.
Standalone SDK security reports do not settle BFV confidentiality or full-system
soundness. Source/DATA admission, originating FHE/product, bootstrap/history,
fresh weighted QC, network I/O and durable owner completion are not included.
The <=500ms complete DCS query target remains unmet.
