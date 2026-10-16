# Bounded bulk custody decoding comparison

On 2026-10-16, complete accepted million-row UPDATE and SELECT ran on
`28703e3606952063cbaef9a4f59e4a53bcaa2f4a` and its direct child
`dbf034204fc45d549b5517884c6bc029187425c5`. Both include Boolean fixed-schema
predicates, bulk serialization, static initial UPDATE sources, custody profile 2,
RPC v2 and application v4. The [previous serialization record](BULK-SERIALIZATION-MEASUREMENTS.md)
describes the unchanged fixture and operation boundaries.

The child changes decoding of full-object disk envelopes, Store requests and
successful RawBundle replies. A private serde view borrows all four byte fields
from the immutable input; every length and the trailing-byte check must succeed
before copying any payload into the ordinary untrusted RawBundle. Public generic
Deserialize and its existing bounded sequence visitors remain unchanged. This
slice-only path is never applied to an arbitrary IoReader.

Pinned bincode's slice deserializer replaces its configured size limit with
Infinite. Explicit actual-size checks therefore cap the whole existing envelope
at 64 MiB, including disk/Store/reply headers of 40/14/18 bytes. The existing v2
tags and bytes are unchanged; malformed specialized bodies reject without another
codec. Other RPC variants retain their ordinary decoders. In particular, this
does not replace the outer per-byte decoder of ReadImage replies.

Inner version, nonce, heads and ciphertext remain untrusted until admission. Owner
authorization still precedes custody admission; all complete physical image
audits, quota checks, nonce/head binding, proof verification, final freshness and
pending recovery remain. No new format, FHE operator, parameter, kernel ABI,
unchecked object, trust flag or cross-RPC cache is introduced.

## Full accepted operations

Three fresh alternating before/after pairs ran in
`.local/bulk-decoding-measurements/20261016-101822-043/`. All six actual-process
scenarios and twelve accepted-operation timers passed their result/head checks.
The fixture stores 1,000,000 public rows on one independently running TLS peer;
only the final age is 42. UPDATE adds 1 to its amount and SELECT returns
`[[42, 2]]` from the genuine encrypted result.

Startup, keys, table creation and initial Status inspection are outside the
timers. UPDATE includes source preparation, real BFV/STARK, local verification,
complete Delta admission, journal publication/confirmation and final full agreed
object validation. SELECT includes source preparation, genuine proof and final
freshness before decryption. The prototype work/confirmation settings establish
neither production finality nor attack resistance.

| Complete operation | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| UPDATE | 811.084 / 820.726 / 852.761 | 623.026 / 644.717 / 668.199 |
| SELECT | 330.243 / 337.932 / 338.450 | 255.426 / 257.475 / 265.576 |

Differences between variant medians are **-21.45%** for UPDATE and **-23.81%**
for SELECT, not medians of paired percentages. Each after sample is below every
before sample for its operation in this window. Three pairs do not establish
causation, tail latency or general performance across PostgreSQL workloads.
Every UPDATE still exceeds 500 ms. Keep this window separate from earlier
baselines; do not infer cumulative speedup. WAN and memory were not measured.

No development build, other proof test or memory monitor ran in this window.
Owner and peer each use eight Rayon threads. All three presence-gated diagnostic
variables were removed and checked absent before launch; every clean log has no
RPC/PID markers and reports AVX-512. Unrelated host background load was not
controlled.

## Artifacts and reproduction

The host is AMD Ryzen 9 9950X3D2, Windows x64. Both builds use Rust 1.99.0/MSVC,
release, implicit host target `x86_64-pc-windows-msvc`, native CPU flags and locked
dependencies. The N8192/Q218 arithmetic proof profile v3 and its 128-bit floor
remain unchanged; this is not a security proof of the complete storage protocol.

| Variant | Exact owner under repository root | Baked peer directory |
| --- | --- | --- |
| Before | `.local/target-boolean-record-predicates/release/deps/proved_sql-18a2eaec0e34c184.exe` | `.local/target-boolean-record-predicates/release/` |
| After | `.local/target-bounded-bulk-custody-decoding/release/deps/proved_sql-18a2eaec0e34c184.exe` | `.local/target-bounded-bulk-custody-decoding/release/` |

| Artifact | SHA256 |
| --- | --- |
| Before owner | `3A73ABDEC7C71875DAB4575C95C1C8A782C9B0E7B048767515EB9BA7654DA90C` |
| Before peer | `DA2390258EF684EE6DB69B46C9348B8745129D865842776A465E16CF4DA015B4` |
| After owner | `315140190972B7E6E5FD00E52E01B473FF2B0B65BECA8A4A7B71DA1D89C6BF5B` |
| After peer | `63F18EE1288AACC740AD11D7F446F8811F03D3AEE81A1F5C5DEA93C6FECB06A7` |

Kernel hashes and the exact eight-thread/no-hook fixture command are in the
[object-profile record](CUSTODY-PROFILE-MEASUREMENTS.md#frozen-artifacts-and-reproduction).
The ignored window retains six logs, twelve timers, eight exact executable/kernel
copies, source/hash/path metadata and `driver.ps1`. Original and archived hashes
were independently rechecked. Preserve the matching peer and kernels at the
owner's baked path; a copied owner alone does not pin the peer. Generated outputs
and ciphertext are not committed.

## Separate diagnostic and validation

One subsequent instrumented run in
`.local/bulk-decoding-diagnostics/20261016-101939-554/` passed with the RPC hook
explicitly present. Its UPDATE was 604.985 ms and SELECT 256.266 ms; these are
excluded from the clean samples. Owner-observed complete RPCs included ReadImage
57.081 ms, FHE proof 87.391 ms, StoreDelta 199.278 ms and final FetchVersion
96.101 ms. These include transport and processing; they do not isolate hashing,
copying, disk writes or proving. Client work and journal RPCs also contribute.
This single observation guides investigation, not an additional speed claim.

The child passed 155 owning native behavioral tests: transport 15, faults 4,
SQL 43, runtime 60, client 23 and relational TLS 10; one aggregate measurement
fixture remained ignored. Strict three-package all-target Clippy, formatting
and exact requirements-section/mirror comparison passed. Logs are retained in
`.local/bounded-bulk-custody-decoding-runs/20261016-101152-162/`. No GUI source/API
changed, so the portable GUI suite was not rerun for this decoder-only child.
Codec tests include actual 64-MiB envelope boundaries, malformed late fields,
plain-Vec compatibility, unchanged IoReader limits and real authorization/custody
failures. Two source reviews and an independent measurement audit found no issue.
This establishes neither full PostgreSQL/private SQL locks, public source proofs,
production finality nor whole-process resource bounds.
