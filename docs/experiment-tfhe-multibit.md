# Official TFHE 1.8.1 multi-bit CPU source probe

Status: **bounded real classic/grouping4 comparison completed**. Grouping4 was
correct and faster than the matched local controls, but 4/16-row queries still
exceeded 500 ms. This is an isolated research result, not a promoted backend.

The goal ledger and project docs at the experiment's baseline revision
9c4ad836c8a581455bfb4a7a9d395a9e87507675 contained no multi-bit measurement.
A text search for multi-bit/multibit/grouping-factor covered docs and
compact-query; existing measured kernels all specify the classic
PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 parameter set.

## Official parameters and security boundary

The official [parameter contract](https://docs.zama.org/tfhe-rs/fhe-computation/compute/parameters)
states that supplied parameter sets target at least 128 bits according to the
Lattice Estimator. The official [multi-bit API guide](https://docs.zama.org/tfhe-rs/configuration/parallelized-pbs)
describes parallel PBS and its larger-key tradeoff. This source probe selects
only official CPU TUniform 2M128 constants. It does not tune dimensions, noise,
decomposition or failure targets.

All technical parameter/source facts below were read directly from the locked
official tfhe=1.8.1 crate, checksum
0d60dcde24115624e62a9a8dc627daa8d3dad40e8de69975957d12ee9ab70a2b.
Its .cargo_vcs_info.json records source commit
187fc0b95ab35352422deec6c027d0bd8743b6db. The pinned source references are:

- [V1_8 CPU aliases](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/shortint/parameters/v1_8/multi_bit/tuniform/p_fail_2_minus_128/ks_pbs.rs)
  select the V1_1 constants, rather than new hand-chosen parameters.
- [Official constant definitions](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/shortint/parameters/v1_1/multi_bit/tuniform/p_fail_2_minus_128/ks_pbs.rs)
  specify all fields. The inspected local file SHA-256 is
  70BE7628DE4CFB691FFAC309C839C8B2614114824A52B5FD71445EC6974294EA.
- [Classic V1_4 definition used by V1_8](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/shortint/parameters/v1_4/classic/tuniform/p_fail_2_minus_128/ks_pbs.rs)
  is the exact existing baseline.

The network browser could not fetch those pinned GitHub pages; the matching
locked installed crate was inspected locally. The external documentation is
supporting context, not a substitute for the pinned package source.

All four sets use native u64 modulus, binary secrets, 2 message bits, 2 carry
bits, maximum noise level 5 and Big/KS-PBS encryption order. TUniform columns
are the source distribution-bound parameters, not Gaussian standard deviations.

| CPU set | LWE n | GLWE k | N | LWE / GLWE TUniform | PBS base log / levels | KS base log / levels | log2 p-fail | Native PBS producer threads |
| --- | ---: | ---: | ---: | --- | --- | --- | ---: | ---: |
| Current classic | 918 | 1 | 2048 | 45 / 17 | 23 / 1 | 4 / 4 | -129.581 | None of the multi-bit producers |
| Multi-bit grouping2 | 918 | 1 | 4096 | 45 / 3 | 21 / 1 | 3 / 5 | -140.341 | 5 |
| Multi-bit grouping3 | 918 | 1 | 2048 | 45 / 17 | 15 / 2 | 3 / 6 | -128.235 | 7 |
| **Multi-bit grouping4 candidate** | **920** | **1** | **2048** | **45 / 17** | **22 / 1** | **3 / 5** | **-134.345** | **9** |

All multi-bit entries satisfy per-PBS p-fail <= 2^-128. This is not a whole-query failure bound for an arbitrary number of bootstraps. Grouping3 has less failure margin
than the current classic set despite meeting that threshold. It is not the first
candidate. Grouping4 has greater published failure margin, the same GLWE
dimension/N/noise and two more LWE dimensions at the same LWE noise. The
official security floor is retained; this report does not independently rerun
the estimator or assert an exact bit-security value for either set.

Multi-bit deterministic_execution remains the official false default. Different
ciphertext bytes across repeated evaluations can be normal with this setting;
correct plaintext results, fresh request randomness and metadata/version checks
are the correctness contracts. No smaller-security 2M64 examples are used.

## Exact API and copied-source changes

The candidate import is:

    tfhe::shortint::parameters::current_params::V1_8_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128

The copied Owner::generate retains ConfigBuilder::with_custom_parameters(...).build()
and generate_keys. Only its existing imported constant is aliased to this
official multi-bit value. No conditional predicate, compact-XOR conversion,
COUNT/SUM reduction, overflow work, update validation or owner/peer role is
removed or replaced. No persistent FHE row cache or precomputed answer is used.

Both generated classic and candidate evaluator copies receive the same
**workbench-only 512 MiB -> 1 GiB evaluation-key decoder cap**. This is necessary
framing accommodation: even the smallest estimated complete official multi-bit
key exceeds the current cap. The experiment therefore consists of a
parameter-only difference between two equally accommodated copied backends,
not a claim that the unmodified production key-restore API already accepts it.
Request/output bounds, canonical data/index formats and all other core source
remain unchanged. The runner records original/prepared source hashes.

The shared high-level configuration keeps dedicated_oprf_key=true.
[Config/inner source](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/high_level_api/keys/inner.rs)
and [OPRF construction](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/shortint/oprf.rs)
show a second independent Fourier BSK in the public high-level server key.
Omitting it from estimates or disabling it in just the candidate would confound
the comparison. Neither profile enables extra compression/noise-squashing/
transciphering configuration.

## Source-derived key and peak-memory estimates

Let g be grouping factor, n input LWE dimension, k GLWE dimension, N polynomial
size, L PBS decomposition levels and K KS decomposition levels. The official
[entity sizing code](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/core_crypto/entities/lwe_multi_bit_bootstrap_key/mod.rs)
uses (n/g)*2^g GGSW ciphertexts. The
[GGSW formula](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/core_crypto/entities/ggsw_ciphertext.rs)
gives L*(k+1)^2*N u64 coefficients or half as many complex Fourier coefficients.
At 8 bytes/u64 and 16 bytes/complex, both representations have equal payload:

    One Fourier or standard BSK = (n/g)*2^g*L*(k+1)^2*N*8 bytes.
    Compute KSK = (k*N)*(n+1)*K*8 bytes.
    Default high-level full key payload = 2*BSK + KSK.

The second BSK is the retained dedicated OPRF key. The
[KSK entity](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/core_crypto/entities/lwe_keyswitch_key.rs)
stores one output LWE ciphertext per level per input secret coefficient.

| Official multi-bit set | Compute BSK payload | Compute KSK payload | Dedicated OPRF BSK | Full key payload lower estimate | Key plus serialized payload |
| --- | ---: | ---: | ---: | ---: | ---: |
| Grouping2 | 240,648,192 | 150,568,960 | 240,648,192 | 631,865,344 | 1,263,730,688 |
| Grouping3 | 320,864,256 | 90,341,376 | 320,864,256 | 732,069,888 | 1,464,139,776 |
| **Grouping4** | **241,172,480** | **75,448,320** | **241,172,480** | **557,793,280** | **1,115,586,560** |

These are arithmetic source estimates, not generated keys, serialized-byte
measurements or OS allocation peaks. Container/serialization metadata, any
additional parameters, allocation slack, stacks and temporary cryptographic
buffers are excluded. The classic two-BSK+KSK payload is 180,551,680 bytes;
the measured current high-level wire key including its domain is 180,610,708 bytes,
illustrating why payload arithmetic is not the final wire count.

The official
[key-generation implementation](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/shortint/engine/server_side.rs)
holds standard and Fourier representations during conversion. While the first
compute key remains live and the OPRF BSK is built, grouping4's corresponding
three-BSK+KSK payload is 798,965,760 bytes. The benchmark preserves the current
safe order: serialize the public key, drop the original evaluator, restore the
new evaluator, drop the wire buffer. A grouping4 key plus its wire buffer is
therefore plausibly below the 2 GB whole-process target before other costs;
actual native peak RSS/private commit and active concurrency must decide.

## Native thread proliferation

The same engine source hard-codes grouping2/3/4 producer counts 5/7/9 based on
m6i.metal tuning. These counts are not derived from the caller's Rayon size.
[The actual PBS algorithm](https://github.com/zama-ai/tfhe-rs/blob/187fc0b95ab35352422deec6c027d0bd8743b6db/tfhe/src/core_crypto/algorithms/lwe_multi_bit_programmable_bootstrapping.rs)
uses std::thread::scope/spawn to create those producer threads for each PBS.
Radix-level Rayon tasks can invoke several PBS operations concurrently, and
additional scoped row initiators can multiply the active calls. Nine producers
per PBS does not mean nine process threads or nine cores in the complete query.

Compute ShortintBootstrappingKey serialization omits its runtime thread_count
and recomputes the official count when deserialized; deterministic_execution
is retained. The dedicated OPRF multi-bit enum additionally serializes its
thread_count. The prototype does not modify either runtime thread setting.

The initial paired run should use one row initiator and two Rayon workers,
then four/eight Rayon workers if resource-safe. Compare the classic control
under identical external budgets. Eight row initiators are a later optional
stress point, not the default matrix. Sample actual process thread counts;
do not advertise an eight-thread total from a Rayon8 setting.

The same 25 ms process sampler runs in both profiles. It captures Windows'
OS-maintained peak working set and peak private commit from
[PROCESS_MEMORY_COUNTERS_EX](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex).
Toolhelp enumeration records current own-process threads and a sampled maximum,
including the sampler itself. Brief peaks may be missed. Polling overhead is
part of both measured process runs and has not yet been quantified. A current
working-set or commit value above 2,000,000,000 bytes exits the probe with code 3,
preserving the partial raw report. Polling cannot enforce a hard allocation cap.

## Full operation, checks and larger-key accounting

The new [probe/runner](../experiments/tfhe-multibit/README.md) uses current-main
compact-query's actual million-row fixture, 256 data rows/page, encrypted
PaddedV2 index, fresh serialized requests and serialized outputs. It preserves
1/4/16/absent aggregates, encrypted range selection, genuine FHE point/multirow
AddAmount, owner-validated writeback, both canonical image roundtrips and stale
output rejection. Setup/key generation/serialize/restore are separated from
warm full operations. A small separate three-row public fixture under the same
keys checks global overflow rejection without mutation, an actual encrypted
zero amount, duplicate-age selection and wrong-query rejection.

All storage factors will use the same 3,000,000-byte logical denominator.
Baseline/candidate canonical images should retain the same lengths, but
nonces/ciphertexts are freshly generated. Larger keys, owner state, trusted heads,
rebuilt Merkle hashes, all retained copies, native peak RSS/commit, sampled
threads and serialized request/answer traffic must be measured again. This
comparison does not inherit the previous 210-table 1.996193x joint result.

A source-only amortization illustration: each current million-row table has
5,229,212 canonical data/index bytes, leaving 770,788 bytes/table before the
2x logical cap. The grouping4 key payload alone requires at least 724 such
tables before fixed-key amortization could approach 2x, ignoring other state.
Retaining 724 canonical tables alone uses more than 3.78 GB before this larger
key or Merkle caches, outside the current RAM target. Paging immutable snapshots
from disk could change the memory policy, but is not implemented here. This is
a retained-table control limitation, not a proof that larger-key amortization
is impossible in another storage lifecycle.

No concealed index/PIR, distribution, network latency or computation proof is
added by changing PBS parameters. Current compact-query exposes candidate
counts and page addresses. The owner continues to validate updates locally;
retrieval/version checks still do not prove a malicious peer's FHE COUNT/SUM.

## Initial source preparation

Completed without Cargo invocation: current-main source/parameter inspection,
absence-of-existing-ledger-entry search, source-derived arithmetic, official
documentation check, exact pinned source export for both profiles, Rust source
formatting, and PowerShell parser validation. The 103-package lock was selected
as the recursive closure of the current-main lock without resolving new
versions. At that source-preparation stage, Cargo locked metadata, build, key
generation and timings were pending the CPU lease; actual results follow.

The initially planned paired commands from the repository root were:

    ./experiments/tfhe-multibit/run-multibit.ps1 -Preset classic -Threads 2 -RowWorkers 1 -Rounds 2 -PointUpdates 4 -Offline
    ./experiments/tfhe-multibit/run-multibit.ps1 -Preset group4 -Threads 2 -RowWorkers 1 -Rounds 2 -PointUpdates 4 -Offline

Use project-local CargoHome/TargetDirectory overrides where the shared runtime
is already available. No global tool or environment installation is required.

## Actual bounded comparison

The official grouping4 candidate ran correctly and improved the matched local
controls, but did **not** close the multirow 500 ms target. With Rayon4 and four
scoped row initiators, complete 4-row queries took 572.138–599.319 ms and 16-row
queries 2040.596–2059.491 ms. These settings produced a sampled maximum of 49
process threads, versus 13 for the classic control. The actual grouping4
evaluation-key wire is 558,029,098 bytes. No core API is promoted on this evidence.

Five independent native processes completed with exit status zero:
two matched classic/grouping4 pairs (R2/W1 and R4/W4), plus one supplemental
classic R4/W1 control already in flight before the final concurrency choice.
All 89 complete encrypted operations passed their result and lifecycle checks.
No TFHE dependency source was changed. Both copied examples passed strict
release Clippy with --no-deps -- -D warnings.

R means global Rayon workers; W means scoped row initiators. The machine
reported 32 available logical processors. Native PBS producer threads are in
addition to these caller settings. The same 25 ms monitor ran in every process.
There was no concurrent heavy root/agent workload under the exclusive CPU lease.

### Paired aggregate evidence

All cells below are complete fresh serialized owner/peer operations in milliseconds,
with **two samples per exact parameter/concurrency/cardinality case**.
Median is the arithmetic average of those two samples. The samples are too few
to estimate tail latency or assert a universal speedup. Controls precede
candidates; run-order, thermal and sampling effects were not separately isolated.

| R/W | Rows | Classic minimum / median / maximum ms | Grouping4 minimum / median / maximum ms |
| --- | ---: | --- | --- |
| 2/1 | 1 | 160.487 / 163.288 / 166.089 | 124.005 / 127.942 / 131.880 |
| 2/1 | 4 | 875.012 / 877.005 / 878.999 | 760.949 / 770.104 / 779.258 |
| 2/1 | 16 | 3311.803 / 3589.113 / 3866.423 | 2789.162 / 2989.685 / 3190.208 |
| 2/1 | 0 | 0.450 / 0.570 / 0.691 | 0.322 / 0.408 / 0.495 |
| 4/4 | 1 | 136.707 / 147.805 / 158.903 | 96.016 / 98.968 / 101.919 |
| 4/4 | 4 | 859.043 / 875.880 / 892.717 | 572.138 / 585.729 / 599.319 |
| 4/4 | 16 | 2686.746 / 2854.096 / 3021.446 | 2040.596 / 2050.043 / 2059.491 |
| 4/4 | 0 | 0.705 / 0.820 / 0.935 | 0.288 / 0.371 / 0.453 |

Absent selection has no candidate predicate/conversion work; the current
backend returns encrypted empty aggregate identities. Its sub-millisecond time
does not demonstrate nonempty FHE query performance or concealed cardinality.
The same actual authenticated encrypted index still determines completeness.

The supplemental classic R4/W1 run had 1/4/16-row ranges
145.950–159.158 / 893.439–919.520 / 3142.056–3180.185 ms and a sampled maximum
of 9 process threads. It is not paired with a grouping4 R4/W1 candidate and is
not used to claim a candidate speedup.

No R8/W8 sweep was run: R2/W1 already sampled 25 threads with grouping4, and
the bounded next R4/W4 pair sampled 49 on 32 logical processors. R4/W4 establishes
the additional concurrency point without treating Rayon4 as a four-thread total.
These results do not establish that the candidate beats the previously published
classic R8/W8 integration control under a different scheduling/measurement setup.

### Genuine FHE updates and rejection

Every update included actual encrypted predicate/conversion/overflow arithmetic,
request/output serialization, owner result validation, compact writeback, both
canonical encode/decode/rebuild operations and stale-result checks.

| R/W | Operation | Samples per profile | Classic complete ms | Grouping4 complete ms |
| --- | --- | ---: | ---: | ---: |
| 2/1 | 1-row AddAmount + restore | 4 | 481.081–491.426 | 391.406–417.031 |
| 2/1 | 4-row AddAmount + restore | 1 | 2175.085 | 1743.064 |
| 2/1 | 16-row AddAmount + restore | 1 | 7799.648 | 6600.148 |
| 2/1 | Empty AddAmount + restore | 1 | 5.244 | 5.205 |
| 4/4 | 1-row AddAmount + restore | 1 | 492.913 | 325.471 |
| 4/4 | 4-row AddAmount + restore | 1 | 2073.053 | 1435.180 |
| 4/4 | 16-row AddAmount + restore | 1 | 7422.967 | 5073.219 |
| 4/4 | Empty AddAmount + restore | 1 | 11.131 | 6.240 |

Every nonempty successful update was followed by a fresh canonical restore and
rejected the previous output at the new head. Every process retained exactly
5,229,212 canonical data/index bytes; final revisions were 6 for the four-point
update runs and 3 for the single-point runs. Empty updates preserved the head.
No key/database file was written.

A separate real encrypted three-row fixture, under the same owner/evaluator keys,
selected two duplicate-age rows with amounts 65535 and 1. AddAmount(1) returned
COUNT=2/SUM=65536 and overflow=true, and owner application rejected the entire
update with canonical data and index byte-identical. This is a small corner
contract, not a million-row overflow latency class. All five processes also
evaluated an encrypted zero amount correctly and rejected a new-query/old-output
pair before owner result decryption. This owner validation is not a succinct
malicious-peer computation proof.

Range 250..252 selected all 21 rows, COUNT=21/SUM=5910. Full classic/grouping4
range latencies were 6032.051/4505.486 ms at R2/W1 and
4273.581/3055.263 ms at R4/W4 (one sample each).

### Actual key, storage, wire and native resources

Primary expansion factors use **3,000,000 logical plaintext bytes**, consistently.

| Fixed or canonical material | Classic bytes | Grouping4 bytes |
| --- | ---: | ---: |
| Canonical data, one million rows | 3,187,648 | 3,187,648 |
| Canonical encrypted PaddedV2 index | 2,041,564 | 2,041,564 |
| Combined canonical data/index | 5,229,212 | 5,229,212 |
| Rebuildable Merkle hashes | 281,824 | 281,824 |
| Serialized public evaluator material, including domain | 180,610,708 | **558,029,098** |
| Owner FHE key serialized byte count | 31,268 | 31,305 |
| Owner symmetric key/domain state | 80 | 80 |
| Independently trusted data/index heads | 224 | 224 |
| Joint known canonical + fixed material | 185,871,492 | **563,289,919** |
| Joint known / logical plaintext | 61.957164x | **187.7633063x** |
| Joint known including hashes / logical plaintext | 62.0511053x | **187.8572477x** |
| Persistent FHE row cache / peer plaintext or pads | 0 / 0 | 0 / 0 |

Canonical data/index remain 1.7430707x logical plaintext. The public evaluator
wire grows by 3.08968x. The generated grouping4 wire exceeds the source-derived
payload estimate by 235,818 bytes, confirming why estimates are not final
serialized counts. These fixed-key numbers replace, rather than inherit, the
earlier amortization evidence.

Using the actual grouping4 public wire, owner key/state and per-table trusted
heads gives a source-arithmetic minimum of 725 retained million-row tables to
approach 2x before hashes, or 1142 including the actual per-table hashes. These
are **not actual retained-table experiments**. They exclude any unlisted system
material, replicas and routing. Holding those canonical tables in memory already
exceeds the 2 GB budget, so the earlier 210-table 1.996193x configuration cannot
be carried over to this larger-key backend.

| Matched run | Native peak working set bytes | Native peak private commit bytes | Maximum sampled process threads |
| --- | ---: | ---: | ---: |
| Classic R2/W1 | 390,361,088 | 386,924,544 | 7 |
| Grouping4 R2/W1 | 1,145,872,384 | 1,187,422,208 | 25 |
| Classic R4/W4 | 391,802,880 | 388,857,856 | 13 |
| Grouping4 R4/W4 | 1,145,303,040 | 1,189,122,048 | 49 |

All native memory peaks remained below 2,000,000,000 bytes. Grouping4 R4/W4 is
1092.246 MiB peak working set and 1134.035 MiB peak private commit. These are
actual whole-process owner+peer/key+wire peaks, not a sum of subsystem estimates.
They are not a peer-only allocation trace. Maximum threads are sampled and may
miss brief peaks; memory peaks are OS-maintained. The sampler itself is included.

| Matched setup stage | Classic R2/W1 ms | Grouping4 R2/W1 ms | Classic R4/W4 ms | Grouping4 R4/W4 ms |
| --- | ---: | ---: | ---: | ---: |
| Key generation | 1082.070 | 3405.464 | 1057.905 | 1852.711 |
| Public key serialization | 41.109 | 146.406 | 147.871 | 135.089 |
| Full cold key/image restore + first query | 227.989 | 298.495 | 307.347 | 309.242 |

Cold timing excludes generation, and includes the actual serialized key restore,
both canonical image encode/decode/rebuilds and first complete query. There is
no disk or network I/O measurement.

Because grouping4 retains N2048/Big encryption, its request/output ciphertext
dimensions match the classic control. Exact serialized FHE aggregate wire:

| Selected rows | Request bytes | Response bytes |
| ---: | ---: | ---: |
| 1 | 263,669 | 148,497 |
| 4 | 856,541 | 280,217 |
| 16 | 3,228,029 | 280,217 |
| 0 | 66,045 | 280,217 |

FHE AddAmount request/response bytes are 395,405/296,721 for one row,
988,277/823,673 for four, 3,359,765/2,404,601 for sixteen, and 197,781/296,697
for empty. These counts are identical across matched parameter profiles.
The owner additionally receives index membership-response payloads of 8896
bytes for nonempty groups or 4448 for absent, plus 1216 data-response bytes for
nonempty groups. The peer's local proof/conversion path handles another 1216-byte
data response; it is not claimed as a separately measured network transfer.
Transport framing, network propagation and distributed execution remain excluded.

### Reproduction, evidence and validation

The real commands used the exact pinned source, locked offline dependencies and
project-local caches:

    ./experiments/tfhe-multibit/run-multibit.ps1 -Preset classic -Threads 2 -RowWorkers 1 -Rounds 2 -PointUpdates 4 -Offline
    ./experiments/tfhe-multibit/run-multibit.ps1 -Preset group4 -Threads 2 -RowWorkers 1 -Rounds 2 -PointUpdates 4 -Offline
    ./experiments/tfhe-multibit/run-multibit.ps1 -Preset classic -Threads 4 -RowWorkers 4 -Rounds 2 -PointUpdates 1 -Offline
    ./experiments/tfhe-multibit/run-multibit.ps1 -Preset group4 -Threads 4 -RowWorkers 4 -Rounds 2 -PointUpdates 1 -Offline

The supplemental classic R4/W1 used two rounds and four point updates. The
actual Windows invocation also set -Cargo to the existing explicit cargo.exe
and CargoHome/TargetDirectory to the shared project-local runtime directories;
no global environment was changed.

Strict checks actually run for each generated profile:

    cargo clippy --release --locked --offline --no-deps --manifest-path .local/tfhe-multibit/probe-classic/Cargo.toml -p compact-query --example multibit_query -- -D warnings
    cargo clippy --release --locked --offline --no-deps --manifest-path .local/tfhe-multibit/probe-group4/Cargo.toml -p compact-query --example multibit_query -- -D warnings

The broad original library unit suite was not rerun; the candidate's observable
full-operation and failure cases were checked through the 89 real runtime
operations described above. Source formatting and runner AST passed. The first
manually selected 103-package lock closure retained workspace-unified optional
dependency edges; --locked rejected that feature graph. Full offline Cargo
metadata pruned four unused packages and their feature edges, changing no
retained package version or checksum. The resulting 99-package lock built both
profiles under --locked. This preparation failure preceded key generation and
is not hidden as an application-test success.

All raw ignored reports are under .local/tfhe-multibit/:

- multibit-classic-r2-w1-20261014-221309-095.jsonl
- multibit-group4-r2-w1-20261014-221402-402.jsonl
- multibit-classic-r4-w1-20261014-221455-292.jsonl (supplemental unpaired)
- multibit-classic-r4-w4-20261014-221603-797.jsonl
- multibit-group4-r4-w4-20261014-221655-639.jsonl

The shared probe source SHA-256 is
AE63099569D5B6ED25A57A0CAC3481E6889631B7C08A5F16044F3E2E846CE9EB.
The generated original/classic owner source hash is
325DCE3A09595C7B03776BD672A30091230E85E8553E38DED445304DF4725EC6;
grouping4 owner hash is
1B74D0F5428E09661846AC3477D5BE6949B24833CE65EFA6C626E2B67F26B7D3.
The common prepared evaluator hash is
A6020790327D7310905FDC1CC60002662321273AFA8CE79CB7007130F3B5493A.
Generated source-provenance.json records the baseline revision and original
evaluator hash, plus the explicitly shared key-decoder allowance.

This official parameter alternative is feasible inside the measured 2 GB memory
bound for one loaded table, with materially larger fixed keys and many native
threads. It does not demonstrate the overall 2x/500 ms SQL goal, concealed
access, durable/distributed write publication, or verifiable malicious-peer
computation. It remains an isolated research result.
