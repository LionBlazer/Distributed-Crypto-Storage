# Version-bound private locking validation

This distinct `version-locking-selection` experiment reuses a genuinely admitted
StateCertificate for two fresh private locking proofs over one unchanged version.
It remains a closed N4/two-transaction experiment and cannot grant live SQL locks.
All fixture keys, rows, controllers, salts and identifiers are PUBLIC NONSECRET.
Practical end-to-end latency remains to establish; no fixed latency cutoff applies.

## Statement, authority and lifecycle

The [owning module](src/opening/state/locking/README.md) separates a typed
StateStatement from independently supplied query/control Expected. Both the
submitted source and independent expected source must exactly match the admitted
lease before public-word conversion, Backend construction or a trace factory.
Complete heads, packets, C_key, C_state, source profile and version tag are compared;
a tag or root alone cannot credit a query. Source version tags remain distinct
from fresh query requests and parents. Mutating a generic source relation cannot
relabel a canonical locking contract as certificate authority.

Actual source proof verification constructs the sealed certificate. One exclusive
borrowed lease prevents replacement while in use. Restart/miss requires genuine
admission; no trusted flag, prefix, signature or metadata shortcut supplies it.
The existing single-entry 64 MiB retained-owned accountant charges nested Vec
capacities and old plus prospective entries before publication. It retains no
Backend, FFT/prover data, key or witness. That local budget excludes already
allocated candidates, allocator overhead, query witnesses/proofs and verifier work.

The new profile/domains reuse the same complete canonical-source/locking AIR and
stable Registry112. It checks all four original RowIds and the complete two-holder
registry, membership, ordered SKIP/OFFSET/LIMIT, ownership versus returned slots,
bounded counters and closed Blocked atomic outcomes. The
[canonical locking contract](src/opening/locking/README.md#walk-and-atomic-outcomes)
limits these PostgreSQL-aligned rules: this is no WAIT/wakeup/deadlock/MVCC-recheck
protocol, table-level ROW SHARE, OF/join/cursor or multiple-clause implementation.
Expected plan/root pins do not establish controller authorization, genesis,
control consensus, fresh agreed heads or common-parent finality.

## Build and numerical gate

From published parent `fe5b2c4dd32502f920390651e68e66373e4b862f`, the narrow donor
integration preserves the corrected canonical locking fixture and published
PrivateLock report/sections. Both validated PrivateLock parent README byte prefixes
remain intact. The pre-existing State README text is retained with the recorded
line-ending normalization. No dependency, lockfile, SDK or production consumer changes.
Fourteen changed Rust files, four task READMEs, 81 controls and 24 SDK anchors were
frozen. Twelve prior executables and both new executables remain independently
pinned; the old failed-compiler pair is retained evidence, not a proof baseline.
Earlier PrivateLock failures and corrected successful gates remain unchanged.

Release build, test compilation, strict all-target Clippy and discovery of all
158 unique tests passed under Rust/Cargo 1.99.0 MSVC, native CPU flags, locked/offline,
two build jobs and two Rayon workers. Compilation/discovery execute no test bodies.
All 17 actual trace-free numerical reports passed before new traces: the previous
16 reports and complete JSON objects remain exact. VersionLockingSelection has
7,092 constraints, actual degree 4 under declared bound 5, 16 quotient chunks and
4,076 batched functions, with both model estimates 128 per proof. These are neither
production security certification nor a composition-wide 128-bit claim.

T512/W1948/PV116, 512 public periodics, two full row openings, q192, five random
codewords, extension degree five and post-hiding degree bits ten remain unchanged.
Counted trace/masked/main-LDE arrays are 7,979,008 /15,998,976 /127,991,808 B;
these omit symbolic AIR, periodics, FFT/tree/proof/cache/allocator and stack costs.

## One observed cold/two-warm chain

One new CLI process genuinely proved the source, admitted the certificate, then
proved and verified two distinct warm locking queries. Query 2 independently pins
query 1's successful C_new as C_old and uses LIMIT zero. This fixture chain is not
agreement, scheduling, a production grant or evidence of controller authorization.
There is one fixed observation, no paired speed comparison or comparative median.

| Stage | Proving ms | Verification/admission ms |
| --- | ---: | ---: |
| Cold source certificate | 2163.8341 | 736.9497 |
| Warm locking query 1 | 801.5260 | 190.8551 |
| Warm locking query 2 | 800.4063 | 185.2060 |

Cold proving includes the real SDK prover/trace factory after public source
Backend setup. Cold admission times cache.admit, including actual source
verification, the joint old-plus-candidate arithmetic budget check and publication.
Candidate::new and its deep capacity traversal precede the admission timer.
Warm cache.lease acquisition and fixture/witness/Statement construction precede
the warm timers. Exact Expected/Statement full-state matching guards and fresh
Backend setup are inside both warm proving and verification timers. Warm calls
do not repeat the admitted source proof. They still require local original private
bytes, registry, plan and salts for their query witnesses; this is not peer-only
FHE execution or a BFV formation proof.

The whole child took 5286.2155 ms including fixture/security setup and all
three stages. Retained cache accounting reported 12,899,548 B, below
its 64 MiB policy. The 49 CSV observations have 48 actual gaps
105.3407–126.6619 ms (mean 109.537896 ms).
Maximum sampled working set/private bytes/OS peak working set were
553521152 / 549638144 / 553521152 B.
Nominal 100 ms owned-PID sampling and a 1,792 MiB soft fuse are not a hard process
RAM cap, device-wide measurement or workload guarantee. No abort occurred.

## Owning tests

The typed shape/contract test passed once with 157 intentionally filtered tests
in 103.9279 ms outer. It constructs a genuine constraint trace; it is not a
trace-free test. Its one memory sample cannot describe its lifetime peak.

The complete serial suite passed all 158 unique expected cases: 146 previous
cases plus twelve new VersionLockingSelection cases, with zero failures, ignored,
measured or filtered tests. Default capture was used. The harness took 815.25 s;
the externally observed child took 815307.0737 ms.

The twelve new cases cover typed state/query separation, genuine cold admission
and two warm proofs, independent expected inputs before trace factories, real SDK
context rejection, every full-source alias/malformed pairing, miss/restart/foreign
profiles, unchanged stable registry encodings, relabeling, rebuilt false source
words/salts and failed joint replacement retaining a usable certificate. They
combine native/AIR and genuine/rebuilt proof tests, not twelve complete SQL proofs.

The full suite recorded 7519 samples and 7518 gaps of
99.9707–159.9597 ms (mean 108.440607 ms). Sampled working set/private/OS peak
maxima were 1007558656 / 1029718016 / 1007558656 B.
No observer abort occurred; stderr was empty and every input postflight matched.
The fixed 1,800 s suite fuse provides headroom for the new genuine proof cases;
it is not a query-latency target. Suite resources include historical profiles.

## Reproduction and evidence

Use release/locked/offline build, test --no-run and strict all-target Clippy for
`experiments/hiding-fri-sha256-gate/Cargo.toml` under a fresh native target. Review
all seventeen security reports before trace allocation, then use the built CLI:

```text
hiding-fri-source-primitives.exe security version-locking-selection
hiding_fri_source_primitives-<hash>.exe --exact opening::state::locking::tests::typed_state_context_keeps_version_tag_and_fresh_query_in_separate_commitments --test-threads=1
hiding-fri-source-primitives.exe prove version-locking-selection
hiding_fri_source_primitives-<hash>.exe --test-threads=1
```

Use an external owned-child lifecycle/resource guard; the immutable local observer
is not published as a product API. Keep original process facts, separately checked
outputs, raw logs, CSVs, source/tool snapshots and each physical executable hash.
The old 146 names remain and twelve names are added; historical reports retain
historical scope. No generated proof, key, database or native output is committed.

| Evidence | SHA-256 |
| --- | --- |
| .local/version-lock-validation-r1/source.json | `56E33EE8DE3ABB0C6D3178016FD6DBCE29BE940521A81F5244B159BF9581DE96` |
| .local/version-lock-validation-r1/compile-success.json | `A08771B04E2FDD3B12DB9FC5BE6109D3AF9CD63453443076FEA9D4A51B434487` |
| .local/version-lock-validation-r1/numeric-success.json | `67165659D9D7BC91B11C49E888E7E9771DC69A2E1AFA291E33042231CE9EE4E8` |
| .local/observe-version-lock-r1.py | `AD8978C8C5F6924849E87FB2DF202289E3973C8CE2DBB72950A7A16A5C53F0FA` |
| .local/VERSION-LOCKING-VALIDATION-draft-r2.md | `636808626341B6874BCCD54B65CFFDD8A58B281211D81E13C5CF035B3BDA8025` |
| .local/version-lock-observations/20261017-005900-548-ShapeGate/success.json | `B2774A8E606C5B97F51AED0C80C600BB61C8F3E13EE102E884C60C3D13381617` |
| .local/version-lock-observations/20261017-005912-646-VersionProve/success.json | `F0EDED49837AFC52CADB2BAEC7548FC3CAD3D32D3C7797282F46B19E6B1D926A` |
| .local/version-lock-observations/20261017-005928-236-FullSuite/success.json | `F704B64D57F6BA4A1B3CBB0A90A822E517482584902B472B38DC02185E3F9897` |
| hiding-fri-source-primitives.exe | `B60EB866AFAA81E38659576429F5198E5EA29B8AF189B9F37DFC5EC3384B32A3` |
| hiding_fri_source_primitives-58cfc84b5b1c9656.exe | `1DE378209F4935DD3451C4185CCC50D78B43B6ECE33A3F47153436D38A4D0019` |

## Remaining obligations

Independent controller authentication/control lifecycle, fresh agreed heads,
writer fencing, durable control transitions/finality, row-identity history,
PostgreSQL wait/MVCC/rollback and cross-shard behavior remain separate. C_key
anchors source AEAD, not a BFV secret key. BFV key/noise/ciphertext formation,
proved encrypted result completion and peer-only execution are not established.
The live Session/JobVerifier/MetadataVerifier cannot accept this experimental
proof as FOR UPDATE/SKIP LOCKED. Complete private PostgreSQL, practical query
latency and whole-process resource targets remain open.
