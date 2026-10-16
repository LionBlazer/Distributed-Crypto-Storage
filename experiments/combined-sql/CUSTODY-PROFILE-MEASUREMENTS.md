# Randomized object-profile comparison

This record compares the complete accepted million-row UPDATE and subsequent
SELECT on `57a334aff81b2d5c8991bcf6627450b4e66e25a6` and
`edb486d68659fd24fb37798bdc71eaa602173a37`. The latter integrates
`e81f2b5e7fa553ae9e020758814c4a36ee11476f` and the final malformed-version
holder fallback fix. Both use the full initial source for UPDATE. The subsequent
static-source network UPDATE is not included.

The new [object profile](../../docs/salted-custody-objects.md) derives a randomized
ID from both canonical heads instead of hashing all ciphertext again. The binding
to ciphertext still requires complete validation of both physical images. Every
custody RPC, Delta reconstruction and final agreed-head owner restore retains
its complete audit. The changed profile, envelopes, factories and duplicate-check
ownership form one comparison; these timings cannot isolate the hash change.

## Operation and configuration

The existing real-process test is
`million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore`
in `apps/dcs-peer/tests/proved_sql.rs`. One independent TLS peer stores one million
public fixture rows with 256 rows per data page. All amounts start at 1; the first
999,999 ages are 7 and the last age is 42. It executes:

```sql
UPDATE records SET amount = amount + 1 WHERE age = 42;
SELECT * FROM records WHERE age = 42;
```

The test asserts one matched update, changed object/head revision, preserved table
geometry and exactly `[[42, 2]]` from the actual encrypted operation. Startup, keys,
creation and initial Status inspection are outside each timer. Source retrieval,
real BFV computation/STARK, proof verification, staged ciphertext, physical Delta
admission, journal publication/confirmation and complete final FetchVersion restore
are inside UPDATE. SELECT includes source preparation, proof and final freshness.
The easy fixture work target and one descendant confirmation are not a production
attack budget or decentralized-finality guarantee.

The host is Windows x64, AMD Ryzen 9 9950X3D2. Rust 1.99.0/MSVC release builds use
`-C target-cpu=native`, build jobs 2 and unchanged dependencies for BFV/STARK. The
after build spells out `--target x86_64-pc-windows-msvc`, also the before host target.
Measured owner and peer each use eight Rayon threads. Each peer reports AVX-512.
Both sources use N8192/Q218 proof profile v3, all 81,920 residues, FRI blowup 8,
192 queries and extension degree 5. The arithmetic profile and 128-bit floor are
unchanged; they do not prove the security of the complete storage protocol.
The custody/application namespace changes from RPC v1/application v3 to RPC
v2/application v4, with ObjectProfileID included in the new application domain.

## Uninstrumented accepted operations

The corrected window at
`.local/salted-custody-runs/20261016-090047-062/` ran three fresh alternating
before/after pairs. All six scenarios and twelve accepted-operation timers passed.
All presence-gated diagnostic variables were removed using the Env provider,
checked absent before launch, and all logs checked for RPC/PID markers afterwards.
No development build, other proof test or memory monitor ran during this window.
Unrelated host background load was not controlled.

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 995.271 / 1044.832 / 1078.205 | 825.081 / 923.944 / 947.830 |
| SELECT | 354.677 / 360.116 / 361.865 | 312.612 / 318.748 / 356.933 |

The differences between variant medians are -11.6% and -11.5%, respectively.
These are not medians of paired percentages. Three samples on one healthy peer
cannot establish causation or tail latency. UPDATE remains above 500 ms in every
sample. SELECT meets 500 ms in this fixture; this is not a general SQL guarantee.
The later [static UPDATE comparison](STATIC-UPDATE-MEASUREMENTS.md) uses its own
adjacent before/after window and must not be combined with this one to infer a
cumulative speedup.

## Instrumented diagnostic window

All three alternating before/after pairs in
`.local/salted-custody-runs/20261016-085040-476/` passed. This first window is
**instrumented** and is excluded from the uninstrumented distribution. An initial
harness call to `System.Environment.SetEnvironmentVariable(name, null, Process)`
created present empty variables on this PowerShell/.NET runtime. Presence-gated
RPC and PID hooks therefore ran. The original logs, script and manifest are
preserved; `instrumentation-correction.json` explicitly corrects the original
manifest's erroneous `instrumentation=false` field. No sample was silently removed.

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 1045.818 / 1063.088 / 1096.390 | 874.328 / 890.528 / 969.328 |
| SELECT | 355.448 / 362.688 / 414.284 | 333.000 / 333.945 / 333.960 |

In these diagnostic logs the after initial full Fetch takes 161.249–172.414 ms,
StoreDelta 202.575–279.463 ms, and final FetchVersion 162.549–171.957 ms. These
are instrumented complete-RPC observations, including their client processing,
not isolated disk or hashing costs; they must not be added to infer a full critical
path or treated as the clean timing distribution. Final full custody verification
remains material and is not replaced by prefix membership or a storage ACK.

## Frozen artifacts and reproduction

Each ignored window contains `artifacts.json`, `timers.json`, six logs and copies
of each exact owner, peer and both kernels. The corrected script is archived with
the clean window. The owners embed different absolute peer paths; running a
copied owner alone does not pin its peer.

| Variant | Exact owner path under repository root | Exact baked peer directory |
| --- | --- | --- |
| Before | `.local/target-mutation-cancellation/release/deps/proved_sql-b77c1dcb3169d113.exe` | `.local/target-mutation-cancellation/release/` |
| After | `.local/target-salted-custody-objects/x86_64-pc-windows-msvc/release/deps/proved_sql-501f76c956e504af.exe` | `.local/target-salted-custody-objects/x86_64-pc-windows-msvc/release/` |

| Artifact | SHA256 |
| --- | --- |
| Before owner | `C705A969159DC2BDD689B071CAE84A003D975731E95BBAC9A43BC0EA63214512` |
| Before peer | `E762EDF063F1ED4910CA6A348F08D9B9BAF17EEF7D4BB988089E03938BEAF203` |
| After owner | `D21873170B9D2F92ED9597F4C6EF40F42DCDDDE8282579B416B1602BD4370C36` |
| After peer | `7EC7B4E4E7B319C96B65DFC00A597D723A5A2CB6ECF7B6CCBB938CEF734BE335` |
| AVX2 kernel, both variants | `EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C` |
| AVX-512 kernel, both variants | `6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975` |

Restore the matching peer and kernels at the owner's baked path before running,
outside the timer; never overwrite an active consumer's artifacts. Use the actual
Cargo-reported owner executable, not an unverified wildcard match. Build with the
same pinned source, native flags and locked dependencies. For a clean run:

```powershell
$env:RAYON_NUM_THREADS = '8'
$env:DCS_TEST_PEER_THREADS = '8'
foreach ($name in 'DCS_TEST_RPC_PROFILE','DCS_TEST_FIXED_PIDS','DCS_TEST_TYPED_PIDS') {
    Remove-Item -LiteralPath ('Env:' + $name) -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath ('Env:' + $name)) { throw 'Diagnostic hook remains' }
}
<compiled-owner.exe> --exact million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore --nocapture --test-threads=1
```

Reject logs containing `rpc_observation=`, `owned_fixed_process=` or
`owned_typed_process=` for an uninstrumented distribution. Setting a hook to `0`
or an empty string still enables it. Genuine failures or interrupted runs are not
successful latency samples and must be reported separately.

Before timing, the combined namespace passed 281 distinct native behavioral tests
and two compile-fail contracts, with strict seven-package Clippy. The final holder
guard fix reran all affected client, SQL and fault tests. Portable GUI passed 195
default tests, seven launcher tests and three separately selected actual-process
GUI scenarios, plus strict Clippy. These checks do not establish production
finality, public source-completeness proofs, complete PostgreSQL, private SQL locks,
a whole-process RAM bound or general 500-ms latency.
