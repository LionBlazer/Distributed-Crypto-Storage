# BFV query arithmetic proofs

Reusable Plonky3 0.8.0 STARK generation and verification for the complete canonical
BFV addition and ciphertext-by-public-polynomial product. The unchanged N8192/Q218
BFV profile contains 81,920 NTT residues in each result; no coefficient, modulus or
ciphertext component is omitted. This crate handles arithmetic evidence. The caller
owns authenticated SQL-plan coverage, authorization and a fresh agreed database head.

| Direct project dependency | Responsibility |
| --- | --- |
| [bfv-linear-circuit](../bfv-linear-circuit/README.md) | Fixed BFV profile and exact canonical addition input/output |
| [bfv-product-circuit](../bfv-product-circuit/README.md) | Exact canonical ciphertext/public-polynomial product input/output |
| [proof-acceleration](../proof-acceleration/README.md) | Shared fixed-profile ABI and optional startup-only trusted kernel loader |
| [bfv-query-core](../bfv-query-core/README.md), tests only | Genuine FHE owner/evaluator adapters and explicitly public fixtures |

`prove(input)` executes the canonical encrypted operation, constructs the witness
and returns `GeneratedOperation` owning the complete encrypted output, serialized
proof and complete phase timings. `verify(trusted_input, claimed_output, proof)`
returns `CheckedOperation` only after successful proof verification. Its private
fields prevent callers from constructing unchecked evidence, and its digests bind
the exact input and result byte arrays. `CheckedOperation::matches_statement` rechecks
the operation and both exact SHA-256 identities without repeating proof verification
or arithmetic. Consumers must perform that binding check before using a checked marker
with a separately supplied pending request or result. No API exposes Plonky3 implementation types,
secret keys, GUI state, process ownership or fixture policies.

The caller must independently derive the canonical input from its authenticated
pending request. Accepting a peer's chosen input would prove a different statement.
The verifier checks input/output shapes and canonical residue bounds, derives its
own full public preprocessing commitment (or reuses its exact local derivation),
and verifies the STARK. It never evaluates
the addition/product, calculates a quotient, trusts a prover-supplied key or compares
several peers' answers. Exact SHA-256 digests of the input and output enter the public
transcript; the canonical header also binds the original opaque request digest.
Binding head bytes does not establish their agreement or freshness.

Each linked engine or loaded kernel image keeps its own private FIFO cache of at
most 128 locally derived SDK `PreprocessedVerifierKey` values: only public width, degree and commitment, never
trace, LDE, prover data or keys for decrypting ciphertext. Its domain-separated
SHA-256 key binds `PROOF_PROFILE_ID`, the operation frame magic and the exact
SHA-256 input/output/certificate identities already computed for the statement.
The empty addition certificate has an explicit SHA-256 identity in this cache key;
the existing two-hash addition proof transcript is unchanged.

A prover may seed this cache from its own preprocessing setup before generating
a proof. This records no accepted result. Verification always repeats canonical
frame/degree/shape/range and security checks, validates cached width/degree against
the operation, and runs genuine `verify_with_preprocessed`, including FRI, on every
call. A miss or poisoned optional cache derives the key independently. Only short
clone/insert operations hold the cache mutex; no SDK work runs under that lock.
No peer can supply a preprocessing key. This cache is separate from the runtime's
bounded cache of already verified exact proof bytes and creates no checked marker.
Wire format, arithmetic relation, security parameters, profile and ABI are unchanged.
The fixed zero-height Merkle cap retains one 32-byte root per verifier key, so all 128
roots occupy 4 KiB per image, plus bounded width/degree, SHA-256/FIFO identities,
container and allocator metadata. Public matrices, traces, LDEs and SDK prover
storage are not retained. This cache bound is separate from whole-process memory.

A matched 2026-10-16 evaluation from base `bc5aafbc` used native owner builds,
v3 AVX512 kernels and eight Rayon threads for each owner/peer process. Three
unmonitored full accepted-query runs produced these small-fixture observations:

| Full operation | Before min / median / max (ms) | Cache min / median / max (ms) |
| --- | --- | --- |
| UPDATE, three matching rows across two shards | 567 / 610 / 651 | 547 / 615 / 634 |
| Single INSERT | 393 / 435 / 437 | 352 / 415 / 448 |
| COUNT + SUM, 512 asymmetric rows across two shards | 217.21 / 217.72 / 217.98 | 216.90 / 217.23 / 217.31 |

These observations do not establish a full UPDATE median improvement or a 500 ms
bound. The cache remains an evaluated branch experiment, pending evidence for
integration. Both sides used the same v3 relation, one outer peer proof permit,
worker settings and actual completion/freshness checks. The cache side rebuilt
both private SIMD kernels; no acceptance marker or cached owner result supplied
any measured answer. Build before measurement and avoid other builds or monitors.
For reproduction, use `RUSTFLAGS=-C target-cpu=native`, `RAYON_NUM_THREADS=8`,
`DCS_TEST_PEER_THREADS=8` and run each exact `dcs-peer --test proved_sql` scenario
three times with `--exact --nocapture --test-threads=1`:
`proved_select_insert_update_survive_a_process_loss_and_journal_restart` and
`real_peers_prove_count_sum_and_empty_sql_null_over_complete_shards`.

Separate successful owned-process memory runs sampled live working sets every
100 ms and also read OS per-process peak working-set counters. Mutation: owner
169.9 MiB, peers 174.0 / 173.7 / restarted 172.7 MiB; observed simultaneous sum
363.3 MiB across 73 samples. Aggregate512: owner 170.5 MiB, peers 168.0 / 168.4 MiB;
observed simultaneous sum 353.4 MiB across 21 samples. Individual peaks are not
summed. `DCS_TEST_REPORT_PIDS=1` reports only owned test peer PIDs for observation.
These small-fixture whole-process observations do not establish a general RAM
bound, and monitored runs are separate from latency samples.

## Exact arithmetic and field-wrap protection

Addition uses a Boolean carry and `a + b - c - q*k = 0`, with `a,b,c < q < 2^44`.
Each lane holds one complete 8,192-coefficient NTT polynomial. Its fixed modulus
is an AIR constant. Ten residues share a row: ten witness and 30 public columns in
exactly 8,192 rows. Every row is used; all 81,920 residues remain constrained.

Product requires more than `a*b - c - q*k = 0` in the Goldilocks field: an 88-bit
integer product could wrap its 64-bit characteristic. For `B = 2^22`, the AIR uses
two-limb canonical public values `a,b,c`, fixed modulus limbs `q0,q1`, a 44-bit
public quotient and two signed public carries. The fixed auxiliary certificate stores each quotient `k` in six
little-endian bytes, followed by shifted carries `s1,s2` in three bytes each. Before
field conversion the verifier requires `k < 2^44`, `s1 < 2^23`, `s2 < 2^24`.
Let `k = k0 + B*k1`, `r1 = s1 - B`, and `r2 = s2 - 2B`. Every residue enforces:

```text
a0*b0 - c0 - q0*k0                           = B*r1
a0*b1 + a1*b0 - c1 - q0*k1 - q1*k0 + r1     = B*r2
a1*b1 - q1*k1 + r2                          = 0
```

Every constrained expression has absolute integer value below `2^47`, far below
the Goldilocks characteristic. Therefore field zero implies integer zero. Multiplying
the equations by `1,B,B^2` and adding yields exactly `a*b - c - q*k = 0` over the
integers. Since the verifier independently requires `0 <= c < q`, this proves the
unique correct modular product. The genuine quotient is below `q < B^2`; genuine
carries lie in `(-B,B)` and `(-2B,2B)`, so all valid operations have a witness. This
uses ten independent residues per row: ten zero-constrained dummy main columns
and 100 public columns in exactly 8,192 rows. The quotient/carry certificate is exactly 983,040 bytes;
all its values are functions of already public ciphertext operands and disclose no
additional plaintext. The verifier commits it with the trusted input and claimed
output; it never calculates these quotients/carries. A third SHA-256 transcript hash
binds the exact certificate. Range checks alone cannot accept a result: all three
limb equations still require a valid STARK proof. Frame magics `BFVP3A03` and
`BFVP3M04` reject all earlier trace layouts.

Moving ciphertext-derived auxiliary values into the independently committed public
certificate avoids 91 Boolean witness columns per residue. This reduces prover
work without reducing the number of covered coefficients, arithmetic constraints,
FRI queries, extension degree or security-model threshold.

Packing ten residues per row removes the old eight-lane layout's 37.5% padding.
It halves trace height while increasing width by 25%, reducing the total trace
cells and public preprocessing work without skipping any arithmetic. The shared
backend profile identifies the layout; hosts reject a stale installed kernel.
Rebuild both SIMD kernels with the launcher when updating this proof format.

The canonical order remains component/modulus/coefficient, including the product
certificate. Only the AIR matrices transpose it: coefficient index is the row and
component/modulus selects the lane. Constant lane moduli remove 25% of addition
and 16.7% of product public matrix cells without reducing coverage or the number of
arithmetic constraints. Direct AIR tests rebuild preprocessing around forged
coefficients at both ends of every polynomial; their rejection depends on actual
arithmetic constraints, separately from serialized-proof transcript binding.

`PROOF_PROFILE_ID` identifies the complete accepted arithmetic/proof/security
profile. Application/genesis commitments must bind it alongside FHE parameters;
identical encryption parameters alone do not identify compatible proof formats.

Both relations use Goldilocks degree-five extension, standard Poseidon2 width 12,
FRI blowup eight, 192 queries, binary folding and no grinding. The SDK's security
model must report at least 128 bits in both decoding regimes for the actual AIR
shape before proving or verification. This is an implementation and model check,
not an independent production cryptographic audit.

## Serialized and resource boundary

Proof frames are capped at two MiB before decoding. The recursive Serde adapter
requires every sequence to declare at most 4,096 elements before its consumer can
reserve storage. A shared budget of 1,048,576 slots also charges nested sequences,
tuples, fixed arrays and map keys/values. The fixed public certificate is parsed separately without attacker-controlled
length fields. Unknown sequence lengths, trailing bytes
and noncanonical Postcard encodings are rejected. SDK verification panics from an
invalid decoded proof shape are converted to rejection. These are bounded decoder
structures; whole-process peak RAM and full query latency need separate measurement.

```powershell
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
cargo test --release --locked -p bfv-query-proof -- --test-threads=1
```

Tests use fresh in-memory keys and explicitly public rows. Both real full-profile
proofs cross the serialized verifier boundary before restoring and decrypting the
FHE result. Rejection cases include the final coefficient, a changed trusted operand,
request rebinding in both headers, changed public quotients/carries, out-of-range or
truncated certificates, omitted result coefficients, noncanonical residues,
missing/corrupt/truncated/oversized/trailing frames and proof-operation substitution.
The same security parameters apply to tests and consumers. Decoder tests cover
malicious nested lengths and budget exhaustion before allocation.

An arithmetic marker alone must never authorize network SQL acceptance or mutation:
the storage-client/SQL layer must additionally establish complete authenticated
selection and the version-journal/freshness layer must certify the requested head.

Default builds remain portable. The default `runtime-dispatch` feature permits
`initialize_backend(trusted_directory)` to select a compatible installed SIMD kernel
once at application startup. The caller supplies the installation directory; this
library performs no application-path discovery. Before explicit initialization,
ordinary library consumers use the linked engine. Missing optional kernels retain
that engine; an invalid present selected kernel makes initialization and subsequent
proof calls fail with `BackendUnavailable`. The first initialization result is
retained, so later callers cannot change a running process's backend. Applications
must initialize before accepting jobs. `backend_kind()` reports the selected ISA;
`compiled_kind()` reports the linked engine's compile-time packing.

The dispatcher makes one backend call per operation, with no CPU detection inside
the arithmetic loops. The trusted kernel executes the same genuine engine and
fixed security profile. Only after successful generation/verification does the
host privately construct `GeneratedOperation`/`CheckedOperation`; checked markers
retain exact SHA-256 input/output binding. Complete host timings include the ABI
call, buffer handling and marker binding. Disable default features when building
the [proof-kernel](../../apps/proof-kernel/README.md), so a kernel cannot recursively
load another kernel. Native libraries are part of the trusted application install;
an ABI/profile descriptor detects incompatible builds, not a malicious replacement.

Complete
proving includes the public certificate and preprocessing; complete verification
includes certificate parsing, bounded SDK decoding, checked locally derived or
exactly reused public preprocessing and full cryptographic verification. Reporting
only the final SDK call omits most work.

## Local phase measurements

The following historical observations precede the polynomial-lane layout. One
full-profile fixture run per build on the current Windows x86-64 computer,
using two Rayon threads and identical cryptographic parameters. Fresh owner keys
stay in memory. These are single observations under concurrent development load,
not tail-latency guarantees or full network-query measurements.

| Operation | Portable prove | Portable full verify | CPU-native prove | CPU-native full verify |
| --- | ---: | ---: | ---: | ---: |
| Addition | 973 ms | 488 ms | 227 ms | 106 ms |
| Public-polynomial product | 1,679 ms | 1,386 ms | 365 ms | 239 ms |

The portable serialized product frame was 1,633,309 bytes, including its 983,040-byte
public certificate. The native run used a separately generated fixture and a
1,635,581-byte frame. The whole nine-test process, including fixture generation,
repeated valid verification and rejection cases, peaked at 259,125,248 bytes RSS
(portable) and 260,444,160 bytes RSS (native), monitored under a 1.75-GiB guard.
This measurement excludes a live peer's transport, storage and version journal.
The earlier witness-only product baseline required 19.059 s to prove and peaked
at 1,386,188,800 bytes RSS; public auxiliary values reduced that cost without
changing proof soundness settings. Full query latency is still above 100 ms.
