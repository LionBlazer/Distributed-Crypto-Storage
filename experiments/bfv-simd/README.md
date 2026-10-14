# BFV SIMD probe

A standalone, public-fixture experiment for an online owner and one local peer.
The owner retrieves authenticated compact pages, decrypts and packs the input
rows, then freshly encrypts them with BFV. The peer computes encrypted age
predicates, COUNT and SUM. The owner decrypts its result. Plaintext expected
answers are used only as an untimed public-fixture test oracle.

This package has its own Cargo workspace and lock file. It depends directly on
`compact-store`; it has no `compact-query`, TFHE, GUI or protocol dependency.
It changes no backend selection. See
[the research and security gates](../../docs/experiment-bfv-simd.md).

Native Windows output includes peak working set, peak commit and private
commit. Optional --noise-diagnostic adds an owner-only, untimed diagnostic
on public fixtures. It uses the ciphertext's own decoded plaintext; it cannot
assign the cause of a wrong answer or establish a worst-case noise bound.

## Boundaries

- `main.rs` owns the public fixture, page-owner authority, BFV secret key and
  timings. `Peer` contains public parameters, relinearization/rotation keys and
  an encrypted snapshot. Its request contains three ciphertexts, or four for a
  range, plus public shape/current-head/request-ID metadata.
- Eight MSB-first age-bit blocks fit within each SIMD row. Only block zero of
  the predicate is consumed. All non-value blocks and padded COUNT positions
  are zero. The first SIMD row holds amounts and the second holds COUNT weights.
- `metrics.rs` measures the whole process high-water resident set. It includes
  owner and peer setup, temporary public-key serialization/restoration and
  allocator retention. It is not a separate peer-RAM measurement.
- Exact input bounds are 16 or 256 u8-age/u16-amount rows. Unsigned output
  decoding supports the full 16,776,960 SUM. There is no UPDATE implementation,
  index/PIR lookup, network transport, arithmetic proof or production decoder.

## Reproduction

The Windows optimized build, strict authored Clippy and bounded real-FHE
checks passed for the complete official 16384 profile. Official 8192 failed
exactness. EQ16 reached 508.16 ms maximum over 5 samples; other tested cases
were slower. Actual transport/proofs are additional. See the research document
for the measured table and exact source/binary hashes.

Use the host's explicit Cargo path and shared configured Cargo cache, after
obtaining the root agent's CPU lease. Build once:

```powershell
$env:CARGO_HOME='E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home'
$env:CARGO_TARGET_DIR='E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target'
& 'E:/Users/white/.cargo/bin/cargo.exe' build --release --locked --manifest-path experiments/bfv-simd/Cargo.toml --jobs 2
```

Run the release executable in a fresh process for each row-count/profile pair:

```powershell
& "$env:CARGO_TARGET_DIR/release/compact-bfv-simd-probe.exe" --degree 8192 --rows 16 --samples 5 --predicate ge --lower 18
& "$env:CARGO_TARGET_DIR/release/compact-bfv-simd-probe.exe" --degree 8192 --rows 256 --samples 3 --predicate range --lower 18 --upper 128
```

First validate each EQ at 0, 19 (miss), 255; GE at 0, 255; ranges [0,255],
[18,128], [19,19]; and `--rows 256 --fixture allmax --predicate ge --lower 0`
which must give COUNT=256, SUM=16,776,960. The fixture contains ages 0 and 255.
Use one sample for these boundary invocations. If the official 8192 profile
fails exactness, repeat with the unmodified official 16384 profile. Never shrink
the ring, expand its modulus budget, change distributions or accept modular wrap
to obtain a fast number.

JSONL goes to stdout; no keys, rows or generated outputs are written by the
program. Save reports only under ignored `.local/`. Setup reports complete
serialized public keys, parameters, owner secret-key byte count, canonical
data and rebuildable hash payload. Query reports include authenticated page
responses, all request/output wire, cold versus warm samples, operation counts,
owner work, peer work and whole local wall time. There is no measured network
delay; attach a separately measured transport before an end-to-end claim.

Security remains **upstream claimed about 128 classical bits**, not independently
validated. The exact `fhe=0.1.1` profile uses CBD variance 10 for secret/error.
The source never substitutes a SEAL ternary-secret security claim for that
distribution. Positive exact-fixture checks are not a worst-case noise bound.
Results remain unverified against a malicious evaluator.
