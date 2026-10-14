# Parallel preparation of native PIR caches

Status 2026-10-15: five owning contract tests and strict authored Clippy pass.
Three fresh processes per implementation measure preparation of two actual native
PIR caches at 214.838–228.315 ms using the original serial loader, versus
49.665–51.638 ms using disjoint trial scheduling. Both full output buffers match
the original loader exactly. This is a cache-preparation measurement, not a full
indexed query result or a smaller representation.

The reusable [spiral-cache-core](../experiments/spiral-cache-core/README.md) owns
only conversion of exact fixed-profile record images. It uses public SDK APIs,
with no storage, BFV, owner-key, SQL, catalog, cache replacement or GUI dependency.
Callers retain their resource policy and Rayon pool. No SDK source is modified.

## Schedule and unchanged mathematical operation

The pinned native Spiral loader traverses instance, trial and item serially.
Its output layout is [instance,trial,z,ii,j]. For the existing profile there is
one instance and four trials; each trial owns a disjoint 8 MiB output slab.
The helper uses par_chunks_mut over those slabs and a separate Cursor over shared
immutable records per task. Each item still calls the SDK load_item_from_seek,
recenter_mod and native polynomial NTT, then preserves the exact two-residue
packing and destination index. load_pair uses Rayon join in the same caller pool
for the independent data and index images. It creates no extra pool or output copy.

All dimensions, derived parameters and exact record lengths are checked before
any output allocation. The only accepted profile is N2048, CRT primes268369921/
249561089, Gaussian width6.4, n2, p256, q2_bits20, t_conv4, t_exp_left8,
t_exp_right56, t_gsw8, expanded queries, nu1=7/nu2=2, one instance,8192-byte
records and SDK version0. The same full Params equality also catches mutated
NTT/scratch parameters. Each input must contain exactly512 records:4194304 bytes.
Short data is rejected rather than silently padded by a partial-read API.

Source authority is the clean SDK revision fdb7206517c249603b0c91b65f1f29f95272107c,
server.rs:320-356. Its MIT-licensed scheduling is the comparison control; no
cryptographic primitive, reduction, distribution or parameter has been replaced.
The active native output remains33554432 bytes per cache,67108864 bytes per pair.
The two28-bit residues occupy32-bit slots in each u64; changing packing would
require a different native consumer. This scheduler makes no compression claim.

## Reproducible measurements

Windows x86_64, Rust1.99/MSVC, release/offline/locked, one dedicated target and
an8-worker caller Rayon pool in both variants. No other FHE benchmark or build
ran concurrently. Each observation starts a fresh process, builds two distinct
public non-secret4194304-byte record images, then times only actual conversion
through returned native buffers. Pool initialization, fixture construction and
report output are outside the conversion timer.

| Process sample | Original serial pair ms | Parallel pair ms |
| --- | ---: | ---: |
| 0, serial then parallel | 222.9835 | 50.1009 |
| 1, parallel then serial | 228.3152 | 49.6652 |
| 2, serial then parallel | 214.8380 | 51.6382 |

Median222.9835→50.1009 ms (4.45x). Maximum observed native process RSS is
81203200/81805312 bytes for serial/parallel; peak commit77443072/77991936 bytes.
The unchanged output allocation dominates both. The example uses current and
OS-maintained peak counters with an admission reserve, not a hard allocator cap.
Native total process threads were not sampled by this small conversion example;
the configured worker budget is eight. No keys, caches or record images are saved.

A cold request must additionally read/decode/authenticate actual snapshots,
materialize proof records and run real PIR/BFV. No sum of this microbenchmark
and prior query timings is accepted as that full request measurement. The
bounded disk-cache experiment must measure those costs together, including
misses, hits, eviction, stale versions and actual native process memory.

## Owning checks and evidence

Five tests cover unsupported profile rejection, short/extended records,
validation of the second pair input before conversion, exhaustive equality of
all4194304 u64 words in each of two distinct caches, and three genuine native
PIR reads recovering complete first/middle/last8192-byte records with32 zero
SDK guard bytes. Query serialization, server query decoding, native evaluation
and client recovery are real. Generated keys are ephemeral and never printed.
The tests supply no response authentication or malicious-peer arithmetic proof.

The independent source review checked slab disjointness, full profile validation
and exact residue packing. It also caught an initial use of a missing aligned
buffer iterator; the compiled version uses the public as_mut_slice API. All five
tests and authored strict Clippy pass after that correction. Four existing
SDK lifetime/static-mut warnings remain; CLIENT_TEST is never populated.

Use the module runner with the pinned SDK and dedicated target:

    ./experiments/spiral-cache-core/run.ps1 -Mode check -SdkDirectory <sdk> -Cargo <cargo> -CargoHome <cache> -TargetDirectory <dedicated-target>
    ./experiments/spiral-cache-core/run.ps1 -Mode bench -SdkDirectory <sdk> -Cargo <cargo> -CargoHome <cache> -TargetDirectory <dedicated-target>

The package lock pins the actual native SDK dependency graph. Raw JSONL is
retained in the compact-playground worktree's ignored directory:
.local/spiral-cache-core/cache-setup-20261014-232113-980.jsonl.

| Frozen artifact | SHA256 |
| --- | --- |
| lib.rs | 4DA15C08050DD6F55FA2B0811088513DF8A31540848A91B56F4E9B059A5E6DCE |
| Cargo.lock | 5BD1C8FB9E6118B929C9071E95D449171E769195E06027011BC700D8C2931181 |
| Raw six-process JSONL | A4881E8EC5A076364C95350216AB16EEF83A38558A3918C407F950B422641E30 |
| cache_setup.exe | 95882480CD3F050FE264A3204098EDFBA1243825189B26E2E6DFF1F5BBF4A96C |

The executable is archived beside the raw evidence under
.local/spiral-cache-core/frozen-20261014-232113-980/. No generated output is committed.