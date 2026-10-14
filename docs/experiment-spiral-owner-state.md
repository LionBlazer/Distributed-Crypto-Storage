# Spiral owner-state recovery and accounting

Status: **validated** with seven focused owner contract tests and one genuine
restored-client private-PIR integration test. Strict Clippy passes for this package.
The pinned SDK retains four upstream compiler warnings; SDK source is unchanged.
This is a correctness/accounting result, with no benchmark timing or security-level
claim.

## Supported recovery boundary

The pinned SDK is `blyssprivacy/sdk`
`fdb7206517c249603b0c91b65f1f29f95272107c` (`spiral-rs 0.2.1-alpha.2`). Its public
`Client::generate_secret_keys_from_seed([u8;32])` reconstructs both secret matrices
and their identity-extended forms. Use a fresh `Client::init` on restoration.
`generate_keys_from_seed` first reconstructs these keys, then deliberately creates
a new independent entropy RNG for the public setup. Seed plus exact parameters
therefore does **not** reconstruct the same public setup.
[Key and seed implementation](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/client.rs#L504-L550).

The reusable [experimental module](../experiments/spiral-owner-state/README.md)
stores an opaque, zeroizing owner seed envelope. On recovery it validates all
metadata and the hash of the original public wire, calls the supported secret-only
seed method, and decodes that original public wire. It does not regenerate public
keys, export private key coefficients, access private SDK fields, or modify SDK
source. Query creation keeps the SDK's fresh entropy on every call; restoring a
seed never resets or determinizes query randomness.

The exact current private-BFV profile is degree 2048, CRT primes 268369921 and
249561089, Gaussian width 6.4, `n=2`, plaintext modulus 256, `q2_bits=20`,
`t_conv=4`, `t_exp_left=8`, `t_exp_right=56`, `t_gsw=8`, query expansion enabled,
`nu_1=7`, `nu_2=2`, one instance, record size 8192, SDK version 0. SDK JSON parsing
uses width 6.4 regardless of the descriptive `s_e` field.
[Profile construction](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/util.rs#L224-L275).

## Canonical retained bytes

| Owner envelope field | Offset | Bytes |
| --- | ---: | ---: |
| Magic, version, little-endian marker, 64-bit word marker | 0 | 12 |
| Exact SDK revision | 12 | 20 |
| Fixed RNG/secret-sampler contract SHA-256 | 32 | 32 |
| Expected owner/session domain | 64 | 32 |
| 18 exact primitive parameter words, including f64 width bits | 96 | 144 |
| Original public setup SHA-256 | 240 | 32 |
| Secret seed | 272 | 32 |
| Corruption checksum of all preceding fields | 304 | 32 |
| **Owner image** | | **336** |
| **Retained original public setup, already counted by pipeline** | | **6,029,344** |
| **Owner image plus public setup** | | **6,029,680** |

This is one owner/session shared across compatible table handles, not a seed per
page or table. The domain is explicitly supplied and checked against trusted caller
context. It is an identity binding, not a KDF: unrelated owners must use independent
OS-random seeds. Existing data/index trusted heads, cached index-header state,
storage owner key and BFV owner/public material remain separate counted state.

The owner image contains a real secret. The module provides no confidential or
authenticated durable backup storage. Its unkeyed checksum detects corruption and
cannot prevent malicious replacement of the whole trusted image. The original
public setup may come from untrusted storage only after its length and SHA-256
match the trusted owner image. Losing the original public wire loses the ability
to recover that identical public setup with the supported API.

Public setup serialization uses `u64::to_ne_bytes` and decoding `from_ne_bytes`;
this is not a portable public format across byte orders. The wrapper explicitly
accepts little-endian 64-bit processes and pins `rand=0.8.5`,
`rand_chacha=0.3.1`, the SDK revision and its reviewed package lock. It does not
promise recovery after a dependency upgrade or on another architecture. The
runner checks a clean pinned SDK checkout before preparing an isolated ignored
package. No secret images or key files are written by the probe.

## Reconstructed RAM and remaining boundaries

Secrets are fixed-weight ternary, not sampled from the Gaussian CDF. Each of the
three secret polynomials has 256 coefficients `+1`, 256 coefficients `-1`, and the
remaining 1536 coefficients zero, shuffled from ChaCha20 through pinned
`SliceRandom`. The supported method reconstructs GSW and Regev keys in the same
order. [Ternary sampler](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/client.rs#L130-L144).

The 49,152-byte base payload plus 131,072-byte identity-extended payload
(**180,224 bytes**) is live client RAM, not a required canonical secret backup.
No persistent key coefficient blob is necessary for this supported recovery path.
SDK internal private allocations and temporary seed/RNG copies are not zeroized by
the wrapper; only wrapper-owned seed/envelope buffers are zeroizing. This is a
research ownership/accounting boundary, not a production key-handling audit.

The public Gaussian CDF is regenerated by `Client::init` from width 6.4: 53 u64
entries (424 payload bytes), its vector capacity and struct headers. Floating-point
CDF generation is not required for deterministic ternary secret recovery; it
continues to supply fresh encryption/query errors. Public `Params` contains
reconstructible NTT tables, Barrett constants and scratch. The probe separately
reports public table capacities/headers, CDF length/capacity and inline sizes.
Allocator metadata, alignment, TLS, thread stacks, SDK temporary matrices and
whole-process resident/commit memory are not inferred from these payload counts;
the larger composed experiment must retain its native process monitor.

## Executed validation and claims

Seven passing focused contract tests cover byte-identical public setup restoration,
wrong domain/profile, changed/truncated/extended public setup, corrupted/length
mismatched owner image, different SDK/RNG/profile markers, fresh query randomness,
and the fact that the same secret seed produces a new public setup. One passing integration
test invokes a genuine server query on 512 generated public records of 8192 bytes:
original client reads a record; original client is dropped; restored client reads
first/middle/last using serialized query decode and retained public setup. A
controlled wrong seed must fail the exact public fixture oracle. Expected records
are generated independently of server evaluation, with distinct encoded slot IDs.

A wrong-key oracle mismatch does not authenticate a PIR response. The composed
pipeline still needs its Merkle/root/AEAD validation and independently held heads.
No private-index completeness, malicious-server proof, durability, security level
or global SQL routing claim follows from owner seed recovery. No benchmark timing
claim is made by this small correctness probe.


The standalone raw probe returned one original read and three restored reads,
`identical_original_public_wire_restored=true`, `owner_image_roundtrip=true`, and
`wrong_seed_oracle_mismatch=true`. The original client was dropped before recovery.
The additional deliberately wrong client uses a different explicitly public fixture
seed and the same original public setup; it returns a record unequal to the oracle.
No seed, secret matrix, owner image or participant data is printed or written.

The initial harness compared the SDK's whole 8,224-byte decode buffer with an
8,192-byte record, so the original-client check failed before restoration. The
pinned `PolyMatrixRaw::to_vec` explicitly appends 32 guard bytes. The corrected
harness requires exactly 8,224 decoded bytes and all 32 guard bytes zero, then
compares the entire 8,192-byte canonical record. The eight tests and standalone
probe reported here all use the corrected harness. No SDK parameter or circuit
change was involved.

Observed public-field/inline accounting on `x86_64-pc-windows-msvc`, Rust
`1.99.0 (b940084d7 2026-09-28)`, LLVM 23.1.1:

| Reconstructed state | Bytes |
| --- | ---: |
| Base secret matrix payload | 49,152 |
| Identity-extended secret matrix payload | 131,072 |
| `Client` inline object, including four matrix handles and CDF handle | 264 |
| CDF live allocated capacity (53 entries = 424 payload bytes) | 512 |
| **Client payload/capacity/inline model** | **181,000** |
| `Params` inline object | 328 |
| NTT coefficient table capacity | 131,072 |
| Nested NTT vector headers/capacity | 240 |
| `Params` scratch capacity | 32,768 |
| **Params payload/capacity/inline model** | **164,408** |
| Wrapper's inline canonical owner image | 336 |

The table is an allocation model for retained objects, not a native process peak.
It excludes allocator bookkeeping, process/TLS/thread memory, public setup RAM,
PIR database caches and temporaries. The fixture's database NTT payload is
33,554,432 bytes. Existing composed native RSS/commit accounting must continue;
canonical seed recovery does not remove these live allocations.

Exact commands used after the prepare-only runner verified the clean pinned SDK:

```powershell
$env:CARGO_HOME = 'E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home'
$env:CARGO_TARGET_DIR = 'E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target/spiral-owner-state'
$env:RAYON_NUM_THREADS = '8'
# Worktree-local package prepared by experiments/spiral-owner-state/run.ps1:
$manifest = 'E:/Users/white/.codex/worktrees/compact-fhe-query/DistributedCryptoStorage/.local/spiral-owner-state/package/Cargo.toml'
& 'E:/Users/white/.cargo/bin/cargo.exe' test --release --locked --offline --jobs 2 --manifest-path $manifest -- --test-threads=1
& 'E:/Users/white/.cargo/bin/cargo.exe' clippy --release --all-targets --locked --offline --jobs 2 --manifest-path $manifest -- -D warnings
& "$env:CARGO_TARGET_DIR/release/spiral-owner-state.exe"
```

Reproduction uses the retained module `Cargo.lock`; the supported owner seed path
is pinned to `rand 0.8.5` and `rand_chacha 0.3.1`. Test result: **7 + 1 passed,
0 failed**; strict package Clippy passes. Four existing warnings belong to pinned
`spiral-rs` (three elided lifetime spellings and its untouched `CLIENT_TEST` static
reference). The experiment never reads or writes `CLIENT_TEST`.

Frozen validation artifacts are below the task worktree's ignored
`.local/spiral-owner-state/`: `tests.txt`, `clippy.txt`, `recovery.jsonl`, and
`validation.json`. The executable is copied to `spiral-owner-state.exe` there to
avoid a later shared target build replacing its provenance.

| Artifact/source | SHA-256 |
| --- | --- |
| `src/lib.rs` | `32CF886EEAD6D14CA887E13B8A595FFAA5049E3ACB17844919A5B31F4AE25E3B` |
| `src/main.rs` | `DCBD446A8AF949E41204414119F2EF6C51F5A3C9A3B9CE4F11811ECC395D51CE` |
| `Cargo.lock` | `AB3C61031AEDECB506DBBE3117ED68FDAE2EFEBE644838354CB8576654D6A34D` |
| Tested executable | `A0EAB5E50A06DEBD04BA86321A533B71406D0D7E0F1EF88C09DD00AAB2EF892B` |
