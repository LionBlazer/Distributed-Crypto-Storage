# Private locking relation validation

The distinct `locking-selection` experiment now has genuine canonical-source
and private locking proofs. It covers a closed four-row/two-transaction
snapshot and remains nonaccepting. Live PostgreSQL locks, peer-only FHE
execution and agreed freshness are not established. Practical end-to-end
query latency remains an open goal; no fixed latency cutoff is claimed.
All fixture keys, rows, identifiers and controllers are PUBLIC NONSECRET.

## Contract and implementation

The [owning module](src/opening/locking/README.md) separates exact statement
encodings, AIR, bounded witness construction, composition and owning tests.
The complete genuine canonical source proof is verified before the lock
proof. Independently supplied Expected fixes that source, genesis, parent,
old registry and client plan/C_plan. Controller authorization is external
and unimplemented; pinning Expected does not authorize the client. Expected
is not derived from submitted witness outputs. Parent binding alone does
not establish finality.

The complete registry represents both transactions and every one of the
four source RowIds. All four PostgreSQL row-lock modes use the exact OTHER
holder conflict table. Own locks can upgrade without self-conflict; Failed
other transactions retain locks. The actor must be Active. SKIP conflicts
consume neither OFFSET nor LIMIT; nonconflicting OFFSET rows acquire locks.
A late WAIT/NOWAIT conflict discards earlier tentative effects and counters,
produces empty outputs and retains the exact old root and salt. It grants
nothing. LIMIT zero still opens the whole source and advances successful
command counters without acquiring OFFSET rows. Counters are admitted in
a strict u32 subset of the metadata oracle's u64 domain before conflicts.

The closed `Blocked` result is an atomic snapshot with no grant. It does not
implement PostgreSQL waiting/wakeup, deadlock handling or MVCC rechecks. The
selected row-conflict and OFFSET/SKIP rules follow the
[row-lock table](https://www.postgresql.org/docs/18/explicit-locking.html#ROW-LOCK-COMPATIBILITY)
and [SELECT rules](https://www.postgresql.org/docs/18/sql-select.html#SQL-FOR-UPDATE-SHARE)
only. Table-level `ROW SHARE`, `OF`/joins, cursor behavior and multiple locking
clauses are outside this candidate.

Stable Registry112 is query independent. Plan144 and the two distinct
output168 encodings bind the fresh query and exact old/new roots. Returned
and command-owned rows are distinct stable compacted commitments; the latter
is not an independent write capability. No plaintext SQL answer is used
as a substitute for encrypted peer computation. Root equality reveals an
unchanged outcome; no hidden-outcome or access-leakage policy is claimed.

Shared integration adds the distinct relation dispatch/profile and admits
the two new fixed commitment lengths in the existing digest helper.
Old profiles and existing relation behavior remain unchanged. In the new AIR,
42 duplicate presence assertions were hoisted to one identical constraint
loop before native analysis; no prior relation constraints were removed.

## Build, dependency and numerical gates

Offline workspace-only resolution added the dev-only transaction-state
oracle closure to this standalone lockfile. Of 126 old package records,
125 remained exact and only the experiment root gained the dev edge;
15 records were added, with registry identities/checksums already present
in the unchanged root Cargo.lock. Optional lock/metadata entries are not
evidence of compiled features. The oracle is actual State::transition in
tests; it is not a live acceptance path or a replacement for proof checks.

The first release build and test compilation passed, but strict Clippy
rejected one unused import. That first failure, all logs, source snapshots
and both executables were retained. Removing only that import left the AIR
and test bodies unchanged. A fresh isolated target then passed release
build, test compilation, strict all-target Clippy and exact discovery of
146 unique tests. Neither compilation stage executed test bodies.

The first full suite then passed 145 cases and failed the positive Bytes
proof verification in one foreign-profile test. That fixture changed the
relation but retained the canonical profile-bound opening commitment.
Its failure, 831.52 s harness interval, original process facts, logs, CSV
and both executables remain preserved. The only four-line test repair
recomputes the Bytes opening commitment before genuine positive verification
and the unchanged negative canonical-substitution assertion. No AIR,
production acceptance rule, key, witness or assertion was relaxed.

A third fresh target then repeated release build, test compilation, strict
Clippy, discovery and all sixteen field-exact numerical reports. Its
corrected genuine test passed separately before the final full suite.

The corrected build used Rust/Cargo 1.99.0 MSVC, release/locked/offline,
native CPU flags, two build jobs and two Rayon workers. Frozen inputs are
18 task paths, 77 controls and 24 SDK anchors. Six previously validated
executables, both first-Clippy-failure executables and both first-full-suite
executables remain independently pinned: ten retained prior PEs plus the
two final-build PEs. Only the first Clippy-failure executables are excluded
from proof baselines; the R2 CLI already produced the verified composites.
All 16 actual trace-free security reports passed before new trace allocation;
the previous 15 remain field-exact. The new relation has 7,092 constraints,
actual degree 4, conservative declared bound 5, 16 quotient chunks and
4,076 batched functions. Both model floors are 128 bits; this is not
production security certification or an end-to-end composition proof.

T512/W1948/PV116 retains two complete row openings, 512 public periodic
columns, q192, five random codewords, extension degree five and post-hiding
degree bits ten. Counted trace/masked/main-LDE arrays are respectively
7,979,008 / 15,998,976 / 127,991,808 B. They omit symbolic AIR, periodics,
quotients, trees, DFT scratch, proofs, stack and allocator overhead.

## Genuine composite observations

Before the test-only fixture repair, each of three R2 CLI processes
genuinely proved and verified its complete
canonical source and private locking relation. These are fixed public
fixtures, with no paired speed comparison or whole-query SLA inference.
The final R3 build changes only that test fixture; all production SOURCE
files and sixteen numerical reports remain identical. Physical executables
differ and each is separately pinned. These R2 observations are
retained evidence, not freshly repeated R3 timings.

The proving timer includes canonical source Backend construction, genuine
source proving and verification, then private-locking Backend construction
and proving. The verification timer constructs fresh public Backends and
verifies both genuine proofs plus their expected bindings. Neither is an
isolated locking-verifier time. Fixture construction and the initial
trace-free security report precede those timers; the outer interval
includes the complete child process.

| Process | Proving ms | Verification ms | Outer ms | Sampled working set B | Sampled private bytes B | Sampled OS peak working set B |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 4611.021 | 1120.469 | 5810.248 | 843902976 | 855982080 | 843907072 |
| 2 | 4711.500 | 1271.859 | 6057.273 | 842633216 | 839307264 | 842633216 |
| 3 | 4836.624 | 1231.473 | 6371.172 | 843522048 | 850440192 | 843522048 |

Medians are 4711.500 ms proving, 1231.473 ms verification and
6057.273 ms outer. The 167 observations had actual within-process sampling gaps
102.7000–111.4887 ms. Timers, sampled counters and OS peak counters
have different scopes. The observer samples only its own child PID, uses
nominal 100 ms waits and a 1,792 MiB soft stop; this is not a hard RAM cap.

## Owning tests

The separate shape gate passed one test with 145 intentionally filtered
tests in 162.736 ms outer under R2. After the fixture repair,
the corrected genuine test passed in 13895.396 ms outer with 145
intentionally filtered tests. The final complete serial suite passed all
146 unique expected tests in 860.40 s (860549.144 ms outer),
with zero failed, ignored, measured or filtered tests. This includes all
122 previous cases and 24 new locking cases. Default test capture was used.

New cases compare actual metadata transitions across mode pairs, actor
positions, Failed ownership, upgrades, SKIP/window selection and atomic late
WAIT/NOWAIT outcomes. Genuine source/profile/context rejections and rebuilt
malicious traces cover omitted holders, false skip, forged identities,
controllers, counters and unsigned wrap, incompatible registries, missing
outputs and blocked reblinding. Coherent false-skip and blocked-wrap attacks
recompute downstream commitments rather than merely changing stale hashes.
The 24 cases combine native/AIR checks, raw-SDK rebuilt rejections and
genuine composites; they are not 24 independent complete SQL proofs.

The suite had 7920 memory observations, with actual gaps
100.0146–225.6079 ms (mean 108.663240 ms).
Maximum sampled working set/private bytes/OS peak working set were
1002680320 / 1022902272 / 1002680320 B.
No observer abort occurred; stderr was empty and every source/artifact
postflight matched. Suite memory includes historical profiles and cannot
be assigned solely to private locking. Sampling does not establish the
whole-process 1–2 GB target under production workload.

## Reproduction and provenance

Use the experiment manifest for release/locked/offline build, test
compilation and strict all-target Clippy, followed by the built executable:

```text
hiding-fri-source-primitives.exe security locking-selection
hiding-fri-source-primitives.exe prove locking-selection
hiding_fri_source_primitives-<hash>.exe --exact opening::locking::tests::genuine_byte_opening_proof_cannot_substitute_for_canonical_source --test-threads=1
hiding_fri_source_primitives-<hash>.exe --test-threads=1
```

Review actual geometry/security before constructing traces. The observed
native executables, source snapshots, log hashes, original process facts,
separate checked facts and memory CSVs remain immutable ignored evidence.
No generated proof, key, database or native output is committed.

| Evidence | SHA-256 |
| --- | --- |
| .local/private-lock-validation-r3/source.json | `A7686C6B7FA4C187A5ADE90948AC5ACADF8769CD567A95A620782A7CBA9470AF` |
| .local/private-lock-validation-r2/source.json | `3C0A05619440E11704EA305D49B3F827214F8ADDEF0AAFD4AC86A032BFBD812D` |
| .local/private-lock-validation-r2/compile-success.json | `B727F3E0497B2430B1F981FDFED6E3F3F8BF16C555112006ECD531D9C3B909E6` |
| .local/private-lock-validation-r2/numeric-success.json | `2FD397C26EE8485999CF3ED5B7B3B5AA212016860F91F96FB32F9D0110BD1D92` |
| .local/private-lock-observations/20261016-235631-618-ShapeGate/success.json | `DCB86703A997B285688F0BFE637ACC4AF67EF66E8093556BD83344C83CA6C2D9` |
| .local/private-lock-observations/20261016-235638-956-CompositeProofs/success.json | `1878B517AD88A4D5FE490EB7741AFF6B00E7C65D2FE43B051714B5C79692541B` |
| .local/private-lock-observations/20261016-235706-475-FullSuite/result.json | `8D1AEF2DE5055FC61772140822977CE4AB94DA4CC2AD06F45022811D147F98E3` |
| .local/observe-private-lock-r2.py | `6B1136EF168FBC77B84C4C1D84982416C653809E43C5712550A009BBAD38224E` |
| .local/observe-private-lock-fixture-r2.py | `7995D9154808C3198BCA4EA3245387D938233FE86CC0BEDBA1696ABACB739764` |
| .local/private-lock-validation-r3/compile-success.json | `B4F76BD9B4D0FD182B93646EFB318D2301E6F34623BD1844457BB0EA3F161CFE` |
| .local/private-lock-validation-r3/numeric-success.json | `54D1732458D86B14986FB524C18CE04086EF967565B74BF5935A092594D628DF` |
| .local/private-lock-fixture-observations/20261017-002131-322-CorrectedGate/success.json | `F2FE3154F52A42A0D85912D5EB76457E9DD5BC099BE549B56ED32F1FE17A9185` |
| .local/private-lock-fixture-observations/20261017-002158-376-FullSuite/success.json | `2755C521FEDA08CD149A106344BA2B3E90267C56191CB7F73707353A4D556B23` |
| hiding-fri-source-primitives.exe | `4DC8CC5EE30A015196F971512B2AC8A1E06C9AB49633C4DF317C071339FEB9A0` |
| hiding_fri_source_primitives-58cfc84b5b1c9656.exe | `397D79CA299754EC13DD0681C830A16D54D5E70B7AA4B05C12A1BF168F2E6712` |

## Remaining acceptance obligations

Registry genesis/lifecycle and controller authorization, authenticated
same-parent control/data transitions, agreed finality/freshness, stable
cross-version RowId history, writer fencing, complete BFV key/noise and
ciphertext formation, proved output re-encryption, MVCC/rollback and
cross-shard scheduling remain open. C_key here anchors source AEAD, not
a BFV secret key. The complete two-holder registry is a fixed experimental
bound, not permission to omit other holders in production. The live
Session, JobVerifier and MetadataVerifier are unchanged and cannot accept
this proof as a SQL grant. A cached certificate optimization is separate
future work; this measurement always includes a genuine source proof.
