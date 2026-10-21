# Executed private witness arithmetic gate

This records a native arithmetic prerequisite, not a Formation proof or a DCS
query. No peer receives the secret, plaintext buffers, transformed secret,
products, errors or quotients. The owner fixture supplies its own ephemeral SDK
key and the same original plaintext buffers used for encryption. The witness
producer and its local checker both consume secrets; neither is a peer verifier.

## Owning checks

Rust1.99.0/MSVC release, the existing locked dependencies, the same two build
jobs and two Rayon workers, and the existing private-peer target were used.
Ambient Rust/Cargo/DCS overrides were removed before applying the pinned native
environment. No dependency, production timeout, old proof profile or requirement
was changed. Commands were serial:

```sh
cargo clippy --release --offline --locked -p bfv-unrelinearized-certificate --all-targets -- -D warnings
cargo test --release --offline --locked -p bfv-unrelinearized-certificate -- --nocapture --test-threads=1
cargo build --release --offline --locked -p bfv-unrelinearized-certificate
```

Strict all-target Clippy passed in0.734s. All19 tests passed in0.63s; the test
command took6.703s including5.98s of compilation. Three new tests cover:

- All4096 coefficients of dense and sparse negacyclic products against an
  independent integer double-loop reference, including negative wrap and tail.
- Two genuine SDK ciphertexts under one actual random SDK key, all four complete
  Gold products against independent SDK Poly multiplication, and the bounded
  shared-secret/shared-error/exact-quotient equations. The same fixture rejects
  a range-valid wrong key, a basis-local error mismatch even with freshly derived
  quotients, a re-canonicalized wrong basis, final c0/A/W changes, equation/range
  changes to K, and changed full requests with the same or a different nonce.
- Strict canonical fixed key-codec failures at the header, first/last value,
  truncated and trailing bytes.

The16 existing tests also passed, including genuine SDK product completion and
repaired false public certificate/scaler/last-coefficient attacks. Failure
assertions do not print random private coefficients. Full network and recovery
gates were not repeated: their protocols and consumers are unchanged.

## One explicit native observation

The freshly built executable was run directly with
`--private-formation-fixture`. This is one observation, not a latency distribution:

| Owner-local phase | Milliseconds |
| --- | ---: |
| SDK input preparation |5.8691|
| Genuine SDK three-component product |1.6607|
| Witness construction |2.9332|
| Complete private witness arithmetic check |1.5706|
| Whole local diagnostic, including product and cleanup |13.7364|

The total additionally includes statement/key serialization and other local
bookkeeping. It excludes a cryptographic Formation proof, Source/Key admission,
FHE-result certificate, network, agreed head, lock finalization and SQL client
completion. The command's wall time was0.031s. Counts are S4096, shared E8192
and signed K16384; no witness is exported. The output keeps proof, security,
Source, SQL, freshness and network flags false. Logical vector counts are not
measured process RSS or a whole-peer resource theorem.

A separate `--public-fixture` run still produced/checked the complete
1737899-byte arithmetic certificate and decrypted the actual SDK output, matching
all4096 public oracle coefficients. Its local total was78.6598ms, including
35.0606ms certificate construction and34.2794ms checking. The public profile
remains exactly
`9d97f6eede741c9a179fc359d8b33f299720ab54576fbfe955f6192af65a5724fecbfad31bf8b4f7ba1d88c2d9aebcdcd2a2c925b0f9b838b71be1806b343bed`.
Neither observation establishes a speedup for an equivalent complete proven
query. **The500ms complete-query requirement remains unmet.**

## Reproduction receipts

Ignored local receipts retain exact command arrays, stdout/stderr and before/
after source hashes with no source drift during native checks:

| Receipt | SHA256 of result.json |
| --- | --- |
| `.local/gold-formation-native-r2-clippy` |`9AE50405305B8E0E4F32EDFFD6CEF9E87F89D381A95107A254E2995DBF6DF485`|
| `.local/gold-formation-native-r1-tests` |`85344B209F6ED4F1AA8F7EA07EE269048C6D3C0164711D442A3E95941E0E5C2C`|
| `.local/gold-formation-native-r1-fixture` |`5F9C776F1C260D168E1025FD2A275EE00B5B8A757E7630F01789E5252A6C87B6`|
| `.local/gold-formation-native-r1-public` |`63A40174E317BCF41236D0DFCE18D89490EED310FF890C86E695BF88DBC867A4`|

The normal executable is1085952 bytes, post-run SHA256
`7D43475595DB7387EF39EAD69385492DA016FB6F9FF6637E0A72643139143A33`;
the test executable is1731072 bytes, post-run SHA256
`1CBA6640C8780285A3C8D65C95843B202004DA2F93013EE83AB78B945CC351D4`.
These are post-run identities, not held-process image or resource observations.
No native performance, privacy or proof claim follows from source review alone.

Independent source review covered the SDK sign/scaling, u128 overflow bounds,
twist/order/normalization, strict codec, all-coefficient shared S/E/K relations,
fixture ownership, hostile cases and unchanged public protocol. Its exact final
five-Rust-file aggregate is
`CB324FE6BACDFC33E0775A1EF4B8DE9E4188EA83AFB648E319BEAC10F234B970`
(33267 bytes; sorted POSIX path UTF8, NUL, then exact raw bytes for each file).
The original seven-file source packet manifest SHA256 is
`5EC7181C7BE2B92EC5CED37D6CD2A277442604D982BB5C1C86EDBD6C10ECE520`.
This source acknowledgment supplies no proof or admission authority.
