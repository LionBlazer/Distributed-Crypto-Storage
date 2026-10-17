# Actual Owner Key and five Basis validation

The reusable `bfv-basis-convolution` library owns the original fixed one-basis
H512/W9452/PV62 relation. The optional Core `basis-proofs` feature now provides a
borrowing, opaque `OwnerBasisJob`: one actual Owner Key proof followed by five
ordered convolution proofs sharing its fresh hidden transform opening. This is
a mathematical prerequisite for ciphertext formation; live SQL admission remains open.

## Ownership and verification

The original complete setup identity, geometry and fixed parameters, then the
complete canonical ciphertext, are checked before the SDK secret coefficient copy.
One private Shat is derived outside the trace; the real Key trace still proves
its NTT transitions. Guarded coefficients drop after successful Key emission.
Only one public Key frame, public ciphertext, a private 64 KiB Shat and tiny salts
remain in the job. Each subsequent call emits one Basis component. Cancellation
is terminal between synchronous calls; no interruption, persistence or recovery
of native work is promised. Explicit guarded buffers are cleared; native field,
FFT, trace, LDE, PCS and SDK scratch are not guaranteed securely erased.

Actual Key verification precedes child claim/AIR/trace work. All 33 verified Key
public values, including CsHat, must match the explicit Basis expectation. Two
genuine jobs of the same Owner can share Cs while having different CsHat; they
cannot exchange components. The compound public verifier verifies the Key once
under independent pins and derives the complete Basis expectation privately.

The complete setup label is an independent Owner association outside the unchanged
parameter-only descriptor. A canonical ciphertext carries no authenticated keyset
identity: newly proving A*s for another canonical ciphertext is possible. Replaying
an existing proof with changed full ciphertext, including only B, is rejected.
These relations do not establish short-noise encryption, B/plaintext formation,
evaluation-key same-secret consistency, Registry200/Source linkage, authority or
fresh agreed state. Six individual 128-bit floors imply only a 125.415-bit union
floor; composed 128-bit security is not claimed.

## Decoder and component boundaries

A borrowed exact protobuf/residue preflight rejects malformed amplification
envelopes before SDK polynomial allocation/NTT. It requires two unseeded polynomials
or one polynomial and seed32, exact Ntt/degree8192/packed223232 geometry, all packed
residues below their modulus, and canonical omitted-false or true variable-time
metadata. Unknown, duplicate, nonminimal, wrong-level/degree/seed/representation,
extra and trailing fields reject. Original SDK checks and exact roundtrip follow.
Parameter/ciphertext limits remain 1024 bytes/512 KiB.

The component has a 308-byte header binding the original full public input,
request, basis, full Key statement, profile and independent setup label. Genuine
components fit the 20 MiB payload, 16384 sequence and 24 Mi nested element limits.
Verifier-derived topology, canonical Gold values and nested shape checks precede
cryptographic verification. Existing experiment allowlists/caps are unchanged.
Mandatory main openings alone total 87,892,992 bytes for Key plus five Basis,
already exceeding the existing 64 MiB transport-message and 32 MiB total signed
Journal Body limits.
No aggregate frame, transport registration or quota increase is added.

## Executed checks

Rust 1.99.0/MSVC, release, locked/offline, `-C target-cpu=native`, Cargo jobs 2 and
Rayon threads 2 were used on the same local Windows host as the previous Owner
validation. Default core check, strict selected-library/experiment Clippy and
format checks passed. All 449 compiler-discovered runtime tests passed: 337 old
experiment scenarios, 103 old library/integration scenarios and nine new owning
scenarios (Basis5/Core3/Key1). All 11 compile-fail examples, including four new
opaque-job contracts, and both requirements/architecture contract tests passed.
All 33 historical security invocations retained their complete ordered JSON lists.

The main Owner test checks every one of 8192 coefficients in each of five bases
against independent native-prime NTT/centered-CRT arithmetic and separate salted
Poseidon streams. Public component files are spooled sequentially; Owner and job
are dropped before a fresh setup/frame decode and public verification. Genuine
same-Owner/different-CsHat and foreign-Owner controls, coherent header rebindings,
full-ciphertext/B-only changes, malformed nested proofs, resource limits and
sequence/error/cancellation behavior are exercised. Incorrect explicit Key claims
cannot produce accepted proofs. Old test bodies, profiles and numerical reports
were preserved.

Reproduce the owning boundaries with `CARGO_BUILD_JOBS=2`, `RAYON_NUM_THREADS=2`
and `RUSTFLAGS=-C target-cpu=native` in the environment. `--nocapture` retains the
phase JSON from passing tests:

```sh
cargo test --release --offline --locked -p bfv-basis-convolution -p bfv-key-transform -p bfv-hiding-stark -p bfv-query-core --features bfv-query-core/basis-proofs --all-targets -- --test-threads=1 --nocapture
cargo test --release --offline --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- --test-threads=1 --nocapture
cargo test --release --offline --locked -p bfv-query-core --features basis-proofs --doc
```

## Observed phases

One actual invocation measured Owner/ciphertext generation 230.9309 ms,
anchor/job construction 97.0417 ms and Key production,
self-verification/serialization plus its public-file write 5089.4120 ms. The complete Key
frame was 16,735,583 bytes. These are separate phase observations,
not a cold application or SQL benchmark; independent test-oracle work is excluded.
Each Basis generation phase includes mandatory actual Key verification, proof
generation, self-verification and serialization; its public-file write is excluded.
Fresh component verification reuses an independently decoded setup. The timed
call checks fixed parameters, validates the complete setup identity and public input,
and performs both actual Key and Basis verification. Reconstruction of
`PublicSetup` and public file reads are outside this timer.

| Basis | Complete frame bytes | Generation/self-verification/serialization ms | Fresh component verification ms |
| --- | ---: | ---: | ---: |
| 0 | 15,956,547 | 6530.1260 | 2834.2742 |
| 1 | 15,961,667 | 6480.2002 | 2934.9656 |
| 2 | 15,958,467 | 6335.5061 | 2885.3141 |
| 3 | 15,960,163 | 6505.8075 | 2997.1797 |
| 4 | 15,959,459 | 6755.2849 | 2813.9848 |

Across 138 owned CLI/test processes, 36112
samples and 35974 actual intervals, maximum sampled working set was
1,331,634,176 B, private usage 1,329,623,040 B
and sampled OS peak working set 1,331,634,176 B. The maximum
observed interval was 247.3042 ms (nominal 100 ms). No sampled
1792 MiB soft fuse or 1200 s per-child validation timeout fired. Compilers and child
processes were not observed. These samples do not establish a hard RAM bound,
whole-peer resource guarantee or global concurrency permit. There is no fixed
application query latency requirement; reasonable performance remains a goal.

## Source and retained preparation checks

Root/standalone locks add exactly one local library (554→555 and 215→216 packages);
all previous third-party package dictionaries, versions, checksums and edges are
exact. The optional Core feature is inactive in the standalone dependency, so its
lock entry gains no Basis edge there. Four published README prefixes are RAW-exact.
The Russian requirements and mirror are unchanged.

Independent source review found a missing Digest import and an unchecked recursive
test-directory cleanup target; both narrow fixes were applied before native source
freeze. The R1 preparation helper stopped after successful formatting/metadata on
an incorrect expectation about that inactive optional lock edge. Its R2 read-only
replay stopped on stdin-LF versus file-CRLF formatting. R3 independently replays the
exact formatted code with explicit uniform line endings, validates local-only lock
deltas and preserves both earlier attempts. No requirement/profile was weakened.

The first native default-core check passed; strict Clippy rejected three redundant
singleton Vec clones in new tests. R2 uses borrowed singleton slices with unchanged
test behavior. Its correction helper's byte-for-byte unformatted expectation stopped
on normal formatter line wrapping; a read-only exact formatting replay completed
the R2 freeze. The failed run, logs and compiled artifacts remain preserved. The R2 native
Core checks passed; standalone Clippy then found obsolete adapter imports and a helper
now needed only in tests. R3 removes those imports and marks the exact legacy
contexts helper test-only, retaining all old test bodies and mathematical code.

* Original author source: `B58B2CB9A4475B0C1C79FD60258226111EA10071F249FB3DF594A9DF44765819`.
* Exact native source: `B744A837197A6C1F52FDE03D25AAC09742122D7A38509AE9E90B998199137C9D`.
* Complete gate closure: `6B823536168975278EAA3443DD1B3095B83D7DC4AE7084CE27D6E908EB18168A`.
* Compiler gates: `93B4B77DAC458DC0F353E67FF99E644FBA0044127A197624AB544B99D58B06D0`.
* Ordered numeric reports: `BB92D58A0A9CCCD67A65E7003F5097F2338CDCEA2C6AD6B83B02A8584BBFDDDB`.
* Runtime scenarios: `9C864B757C56FA1B0E21B4E3F637083900C0D83B6C68CE76FA70B2DB954AA262`.

Raw generated proofs, keys and logs remain outside tracked project content.
The PostgreSQL/full SQL/locking/decentralized storage goal remains active.
