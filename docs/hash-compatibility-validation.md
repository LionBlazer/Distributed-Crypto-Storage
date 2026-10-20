# Fast hash compatibility checks and measured candidate

The retained change adds three short canonical SHA512 adapter tests and one
explicitly selected genuine N8192 NTT compatibility gate. The production hash
writers, cryptographic profiles, configuration, APIs, proof acceptance, threads
and timeouts are unchanged. The only dependency change is an already-existing
pinned `p3-commit` dev edge for the test's actual PCS commitment trait.

The original seven library tests and thirteen NTT tests remain unchanged. The
new ordinary library tests compare all adapter outputs with independent one-shot
SHA512 of complete canonical domain+LE64/byte messages. They cover all domain
prefix offsets, padding/block edges, empty input, high bits and long single-pass
iterators. All ten library tests passed together with no skip or ignored case
in 0.02 seconds; the whole command including its 37.30-second rebuild took
37.675 seconds. Final strict all-target Clippy for both packages passed in
1.746 seconds.

## Genuine proof boundary

The ignored NTT gate calls production prove and verify for the existing public
nonsecret forward/basis0 fixture. It compares every one of the 8192 output
coefficients with the native SDK. A semantic sumcheck mutation is decoded and
canonically reencoded, passes frame decode, then fails actual verification with
`Error::Verification`. It supplies no SQL, finality or full-product capability.

Test-only capture independently rebuilds the same ordered public preprocessing
tables and actual PCS commitment, dropping the extra codeword before direct
verification. A named actual verifier challenger produces its final 64-byte
state digest; this is not a transcript event log. The same gate compares seven
complete artifacts by length and every byte, with bounded reads and EOF checks:

| Artifact | Bytes |
| --- | ---: |
| Canonical request | 65616 |
| Canonical output | 65648 |
| Complete serialized proof | 1969937 |
| Profile | 64 |
| Preprocessing root, all eight LE64 words | 64 |
| Final verifier challenger digest | 64 |
| Actual SDK security report | 574 |

All seven matched between original and buffered implementations. The proof's
SHA256 is `A5E6395FBDB6D8BC5A4461CFE60C6FF1594CF1E904BB42C668A77F1F5E1E4799`.
The actual assessment still requires at least 144 bits with no unassessed term.
No checksum, successful decryption or fixture-computed answer replaces a proof.
Exports require an explicit new path under ignored `.local`, use CreateNew and
contain only the public fixture. Generated proof artifacts are not committed.

## Buffering candidate was not retained

The candidate batched the same bytes through a fixed 128-byte stack buffer. Its
first genuine NTT observation showed prove 2676.108 versus 2599.596 ms and verify
193.642 versus 182.398 ms. This one ordered observation did not establish a win.

To avoid rebuilding between repetitions, two exact-source test executables were
retained locally and run in ABBAAB order: three original and three buffered fresh
processes. Every repetition verifies the genuine claim, semantic rejection and
all seven complete baseline artifacts; no prior checked result is reused.

| Interval, median of three | Original | Buffered |
| --- | ---: | ---: |
| Production prove | 2823.769 ms | 2794.847 ms |
| Production verify, including public setup | 228.272 ms | 193.713 ms |
| Per-run prove + verify | 3059.901 ms | 2988.962 ms |
| Complete test body, including extra capture and rejection | 3.65 s | 3.65 s |
| Outer process observation | 3.705 s | 3.839 s |

Test-body samples were original `[3.80,3.65,3.43]` and buffered
`[3.75,3.46,3.65]` seconds. Samples overlap; no confidence interval or general
speedup is claimed. Outer observations also include process launch and observer
polling, so their 3.6% difference is not a measured test-body regression. Writer
micro observations were mixed and cannot establish query or complete-test speed.
The production hash was restored byte-exact, SHA256
`9F7853DCFE2F63710B93F21D2B19C00470B124AB240442EBC18FD605AC3B6E07`.
The experimental implementation and writer-only benchmark are excluded.

All runs used Rust 1.99 MSVC release/offline/locked, native CPU codegen, two
Cargo jobs and two requested Rayon threads. The existing 1792 MiB per-process
soft fuse and 1800-second command budget remained. Neither fired. The nine
genuine cases, including initial parity, one old-code rebuild and six alternating
executions, passed. The largest observed OS peak among them was 869056512 bytes;
these local observations do not establish a formal resource bound.

## Reproduction and scope

```sh
cargo test --release --offline --locked -p bfv-multilinear-stark --lib -- --test-threads=1
cargo clippy --release --offline --locked -p bfv-multilinear-stark -p bfv-ntt-witness-proof --all-targets -- -D warnings
cargo test --release --offline --locked -p bfv-ntt-witness-proof --lib tests::hash_parity::one_public_ntt_preserves_complete_proof_preprocessing_and_transcript -- --exact --ignored --test-threads=1 --nocapture
```

The NTT [README](../crates/bfv-ntt-witness-proof/README.md) documents the optional
artifact environment. The final 1649-file source receipt is
`3606265306EE7F76E865E52B586D8C330AF5623DF3D50835DC78C399232298B5`;
the unchanged after receipt is
`1E61915094199BEFBE43DCF54D96999B713150E55CCF36C58B71BAA1AE4B18B0`.
Only execution documentation changed afterwards. Baseline and buffered after
receipts are `32BCC1D087E22E216EF580A80751B48098D1686390F798DB2018576DAD7AD0A4`
and `F2821E5D58ABED50877220922B5E7D4B76CD52D4873C17CA9F918AF00F49A32B`.
The six-repetition receipt is
`52FCA6F6352CC707E70CEF840624626840C8129609A31256DCC3600532C67985`.
The local detailed profile, including all seven artifact hashes and body samples,
is `.local/ntt-sha512-repeat-r1/profile-with-body.json`, SHA256
`C1EAC91D611D77AC8F2EC3DE628422533A2ACEB7A46D21EAC834D7E117874A62`.
Generated observations, executables and rejected source images stay under `.local`.

This small owning boundary gives useful fast feedback for future byte-exact
hash changes. It does not replace relevant network, recovery or failure-model
gates when those boundaries change. The separately
[validated seven-process improvement](joint-query-fast-path-validation.md) and
new [FHE application](progress-application-validation.md) have different scopes;
this change claims no further end-to-end DCS speedup.
