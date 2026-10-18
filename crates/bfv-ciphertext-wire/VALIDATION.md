# Borrowed PowerBasis view validation

Executed on Windows with Rust 1.99.0 MSVC, release, locked and offline dependencies,
`RUSTFLAGS="-C target-cpu=native"`, one Cargo job and two Rayon threads. The source
parent was `fb7fa8406ca4407be98cc6b2a25bea0b9b3280c2`. Two independent, initially
empty target directories preserved the first run while a Core SDK-oracle test was
added. No earlier executable or target cache was reused or overwritten.

## Executed scope

| Boundary | First run | Focused second run |
| --- | ---: | ---: |
| Wire library, complete owning suite | 10 | unchanged |
| Basis library, complete owning suite | 5 | unchanged |
| Core ciphertext preflight tests | 2 | 3 |
| Separate peer process over actual TLS | 1 | unchanged |
| Compile-fail borrowing examples | 2 | unchanged |

All selected cases passed with zero failures or ignored cases. There were **21
runtime invocations covering 19 distinct cases**: the second run repeats the two
original Core cases and adds one independent coefficient oracle. The compile-fail
examples are separate from runtime counts. Strict Clippy passed with `-D warnings`
for wire `--all-targets` and Core `--lib --tests`.

The orchestrator compiled explicit library/integration test targets, discovered
their actual executables and test names, then ran those executables with
`--include-ignored --test-threads=1 --nocapture`. The peer case used its exact full
test name. Reproducible Cargo equivalents for the executed runtime scope are:

```sh
cargo test --release --locked --offline -p bfv-ciphertext-wire --lib
cargo test --release --locked --offline -p bfv-basis-convolution --lib
cargo test --release --locked --offline -p bfv-query-core --lib ciphertext_preflight_tests::
cargo test --release --locked --offline -p dcs-peer --test process_transport ciphertext_preflight::ciphertext_preflight_rejects_amplification_with_valid_custody_and_keeps_peer_usable -- --exact
cargo test --release --locked --offline -p bfv-ciphertext-wire --doc
cargo clippy --release --locked --offline -p bfv-ciphertext-wire --all-targets -- -D warnings
cargo clippy --release --locked --offline -p bfv-query-core --lib --tests -- -D warnings
```

Wire cases check every coefficient at all five Q indices, both stored components,
mixed boolean flags, borrowed original seed, exact iterator length and fusion,
short-lived view handles, invalid indices, noncanonical final residues and complete
EOF rejection. Both earlier test-file byte prefixes remain intact.

Core's new oracle generates an actual SDK encryption and its unseeded form. For
two seeded and four unseeded flag combinations, it compares all 8192 coefficients
of each stored component at every Q index against independent SDK decoding followed
by conversion to PowerBasis. Expected rows do not use the new packed-bit reader.
The existing Core case separately checks full plaintext decryption, including the
zero tail. Seeded c1 remains a borrowed public seed; the parser does not expand it.

The actual TLS case observes a separately running `dcs-peer` executable. Under valid
stored heads, setup and custody metadata it rejects the tiny-polynomial allocation
amplification input and verifies that the peer remains usable. Basis cases retain
their actual SDK and genuine proof rejection checks.

## Evidence and limits

Frozen source manifests, SHA-256:

- First run: `9DF66108AA0B7EB7FD20FEFA054149D411E59565921FCFDB7DBAC121BF80F5F4`.
- Focused test-only revision: `19DF9A24D8C73749CBA3026CD019F2EC9468EF85D7DF0B0B4E473EAF021D4436`.
- Final source/executable/control review: `0C1D536EAE4F0BA8EB215525EB11B7196271F2373DF6E60BB811BAFA3C033339`.

The final review checks current sources, 953 inherited external SDK files, both
runs' executables and receipts, and all 16,266 previous control artifacts. The
historical preflight validation text is retained verbatim after its heading in
[PREFLIGHT-VALIDATION.md](PREFLIGHT-VALIDATION.md). Requirements and their mirrored
copy match, including hidden WHERE and constants. Manifests, dependency locks and
the default build graph are unchanged.

This gate executes selected owning boundaries; it does not run the entire Core or
historical SQL suite. No query latency or whole-peer RAM claim follows. The native
sampler was observational, with nominal 100 ms sampling, a sampled 1792 MiB per-PID
soft fuse and a 1200 s per-command limit. Short tests can finish without a memory
sample; these are not hard resource guarantees.

The view validates canonical syntax and supplies stored public ciphertext rows.
It does not establish input provenance, encryption, key consistency, linked
MulRelin computation, hidden-predicate completeness, fresh decentralized agreement
or SQL admission. The overall goal remains incomplete.
