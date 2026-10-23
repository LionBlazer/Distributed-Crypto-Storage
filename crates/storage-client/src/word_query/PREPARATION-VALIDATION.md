# Public preparation and native proving overlap

## Change and verified boundary

The former combined `prove_public` returned the public Query expectation only
when both native proofs had finished. Independent receiving preprocessing was
therefore serialized after proving in the ordinary client example.

`PendingQuery::prepare_public` now consumes the same guarded original inputs and
captures their fresh public Query expectation. The move-only `PreparedPublicQuery`
exposes only the public request and that expectation; consuming `prove` produces
the same SHA Word/Query arguments. The existing `prove_public` convenience method
still performs those two steps sequentially. No proof profile, sampler, equation,
accepted result, verifier or native verification decision changed.

The genuine public example obtains the actual SDK FHE product/certificate first,
constructs its complete independent read expectation, then runs public receiving
setup in a scoped thread beside native proving. Native Word/Query/product checks
remain fresh. Setup is dropped after checking so later hostile cases do not
retain an extra heavy copy. The complete existing 4096-coefficient oracle,
packet/frame corruption, mixed-suite, foreign endpoint/owner, replay, entropy
and public/private single-use cases remain. Dropping a prepared query additionally
checks that neither public nor private retry can recover its witnesses.

Four independent compile-fail cases prohibit cloning, constructing and extracting
either private witness from the prepared type. All ten client compile-fail cases,
five owning runtime scenarios, strict all-target release Clippy and the
requirements mirror guard passed. This is conditional arithmetic verification;
Predicate still grants no Journal admission, current head or lock.

## Alternating local measurements, 2026-10-23

Each interval begins before `prepare_public` (or its former combined equivalent)
and includes private Query preparation, the actual SDK product/certificate,
complete read-expectation construction, independent public setup, both native
proofs, retained-DATA receiving and bound owner completion/decryption. It excludes
prior SQL compilation/current-state witness synthesis, original query encryption,
role-only producer setup and immutable Source/Role3/DATA installation. It has no
network, fresh weighted agreement or final lock grant.

The runs alternated the known sequential executable and the new split API. Each
process ran the same five owning `word_query::` scenarios, one at a time, with
configured `RAYON_NUM_THREADS=8`; no other build or heavy test ran during capture.

| Capture | Scheduling | Local prepared-query milliseconds |
| --- | --- | ---: |
| 609 | overlap | 501.829 |
| 610 | sequential | 507.519 |
| 611 | overlap | 467.242 |
| 612 | sequential | 527.130 |
| 613 | overlap | 485.992 |
| 614 | sequential | 560.914 |

Sequential min/median/max were 507.519 / 527.130 / 560.914 ms; the split example
measured 467.242 / 485.992 / 501.829 ms. The observed median reduction was
41.138 ms (7.8%) in this short series. It is not a stable latency guarantee.
The measured setup/proving overlap lower bound was 97.793--117.316 ms; total
proof duration also changed under concurrent public work, so that overlap must
not be presented as an equal end-to-end saving.

Even this local component exceeded 500 ms in one run. The complete SQL/FOR UPDATE
500 ms target is not achieved by these observations. Both the old and new cases
perform real ciphertext computation and full native checking; none is a network
SQL timing or a composed cryptographic security assessment.

## Environment and provenance

Windows/MSVC Rust 1.99.0, release opt-level3, native CPU, locked/offline dependencies
and Cargo jobs2 were retained. The machine reports AMD Ryzen 9 9950X3D2,16 physical
cores/32 logical processors; no affinity was imposed. The sequential baseline is
the historical r595 executable already validated at r596, archived before the
new build. It was not relabelled as a current source build. Its frozen receipt
and original build hash map accompany the local archive. Current observer
workspace hashes and historical executable source hashes are recorded separately.

| Image | Bytes | SHA256 |
| --- | ---: | --- |
| r595 sequential | 28,616,704 | `809EE6451E24BD426831055006D65845D3E07D4BAF842C1EB4262D29A1414718` |
| r608 prepared | 28,627,456 | `504598163FE577022A02B17821C7DC7F54487EB59DC6C2CD564FC3D63466FABB` |

Every capture pinned its image, exact five-case contract and source provenance,
held the directly launched process handle/image/creation identity, and retained
120 s /1792 MiB whole-process fuses with 20 ms sampling. All six exited0 without
faults, forced cleanup or surviving task children. Sequential/new maximum OS
working sets were 709,046,272 /708,259,840 bytes; sampled private-byte peaks were
723,795,968 /721,313,792 bytes. These are isolated test-process observations.

Generated receipts under `.local/word-cmd-native-rNNN-storage-client-observe-tests/result.json`
are not committed, nor are proofs or executable archives:

| Capture | Receipt SHA256 |
| --- | --- |
| r609 | `276127C567E18F7B0A91D8ACA0FC23C5AE50728915B1CDE532B1AEF1AE38F82C` |
| r610 | `0FAF878277C421F933E52522DD6341077026CB260033C8712743DDD7BE34DD71` |
| r611 | `09674B75272D0548EC5EC96B90510643BB787CC9DBE9175A99279C8ABB3E4129` |
| r612 | `3677703CE022444AA5D0A4BFCF29A789579076F43C8F8C988E1656E59772B963` |
| r613 | `D1FB33FC9CB5EF8C2F519D915FEABEE424617ED02F073DDCADF7B3D0F8EEA35D` |
| r614 | `6815A10104774536C9F77DC4448DFB97C9CC78E7763BACD6FFFD283D266DD4FD` |

Reproduce the affected behavior with the stated environment:

```powershell
cargo test --release --locked -p storage-client --features word-query --lib word_query:: -- --nocapture --test-threads=1
cargo test --release --locked -p storage-client --features word-query --doc word_query -- --test-threads=1
cargo clippy --release --locked -p storage-client --features word-query --all-targets -- -D warnings
cargo test --release --locked -p repository-contracts --test requirements_sync
```
