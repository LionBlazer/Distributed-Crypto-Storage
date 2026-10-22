# Product extraction and composed receiving validation

Later [four-field scheduling and complete-read measurements](../registry200-proof/src/registry_progress/word/read/CPU-SCALING.md)
retain the original profile/frame and all integer/PIT checks. All19 current
library cases, actual read/owner consumers and the real daemon/TLS/product route
passed. The record distinguishes fixed-kernel evidence from mixed full-interval
observations; the500ms complete SQL goal remains unmet.

Executed on 2026-10-21 UTC. This change moves the actual public product
implementation into a reusable core library and makes the experiment and a
Source/encoding/Formation consumer use it. The former ten implementation files
are deleted from the experiment; no compatibility implementation remains.

The unchanged historical SHA512 profile is
`9d97f6eede741c9a179fc359d8b33f299720ab54576fbfe955f6192af65a5724fecbfad31bf8b4f7ba1d88c2d9aebcdcd2a2c925b0f9b838b71be1806b343bed`.
It retains eighteen points per basis and the complete 1,737,899-byte frame.
Its UNASSESSED label and all experiment security/SQL/freshness flags remain
unchanged. A mathematical checked value is not a DCS admission capability.

## Checks performed

Root alone ran native commands serially, with Rust 1.99.0 MSVC, release
optimization, `-C target-cpu=native`, two Cargo jobs and two Rayon workers.
Cargo used the existing locked offline dependency cache. Ambient `DCS_`
controls were excluded. Independent agents reviewed source packets and
mathematical arguments without running native commands.

```sh
cargo clippy --release --offline --locked -p bfv-unrelinearized-product --all-targets -- -D warnings
cargo clippy --release --offline --locked -p bfv-unrelinearized-certificate --all-targets -- -D warnings
cargo clippy --release --offline --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --offline --locked -p bfv-unrelinearized-product --lib -- --test-threads=1
cargo test --release --offline --locked -p bfv-unrelinearized-certificate --bin bfv-unrelinearized-certificate -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib two_lane_encoding::formation -- --nocapture --test-threads=1
cargo test --release --offline --locked -p bfv-unrelinearized-product --doc ArithmeticCheckedProduct -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof --doc two_lane_encoding::product -- --test-threads=1
cargo run --release --offline --locked -p bfv-unrelinearized-certificate -- --show-profile
cargo run --release --offline --locked -p bfv-unrelinearized-certificate -- --public-fixture
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

For process measurements, Cargo first built the test or CLI image with JSON
artifact output. Root then invoked that exact image directly with the shown
arguments. Its release profile, SHA256, source snapshots, process creation
identity and held Windows handle were checked. Source and image hashes were
unchanged through every observation. Runtime gates used the unchanged
120-second/1792-MiB limits with 20 ms samples; the CLI used its existing
30-second/1792-MiB limits with 5 ms samples. All exited zero with no child,
fuse violation, fault or cleanup termination. System memory was diagnostic.

| Gate | Passed | Process lifetime | CPU time | Sampled peak private bytes | OS peak working set bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Core arithmetic | 18 tests | 455.449 ms | 0.453125 s | 23,179,264 | 23,248,896 |
| Experimental private diagnostics | 9 tests | 140.590 ms | 0.156250 s | 12,849,152 | 20,688,896 |
| Complete upper receiving chain | 1 test | 19,224.970 ms | 26.656250 s | 1,377,038,336 | 1,371,897,856 |
| Actual CLI public product | 1 operation | 86.985 ms | 0.078125 s | 11,849,728 | 16,203,776 |

Four public compile-fail examples passed: neither lower nor upper checked
result permits private-field construction or cloning. The three strict
all-target Clippy commands and requirements mirror check passed.

The eighteen core tests preserve complete codec/scaler/PIT rejection, repaired
false-output rejection, all-coefficient SDK conformance and the exact historical
profile. A new concrete midpoint case checks that the real SDK scaler and its
valid integer certificate can differ from ideal CRT rounding on arbitrary QP
input. It is a contrast assertion, not permission to weaken product verification.
The experiment's nine remaining tests cover its private Gold diagnostics.

## Actual complete mathematical chain

The existing single Formation test now computes a genuine public SDK product,
produces its full arithmetic frame and calls the new closed product receiver.
That receiver first checks arithmetic, then freshly verifies Source, both
encoding children and the actual cold native Formation argument. Only afterward
does the owner test decrypt the result and compare all 4096 coefficients with
its independently retained oracle. Neither the oracle nor secret key reaches
the keyless public evaluator or receiving checker.

One genuine Source, two children, one Formation and one product frame serve
positive and hostile cases. Existing direct Formation failures remain. The new
wrapper must also reject a corrupted Formation header and repaired OOD argument
with the exact nested Binding/Verification errors; skipping Formation cannot
pass the gate. Foreign output, final scaler quotient corruption and frame caps
reject on those same original proofs. There is no second heavy fixture.

| Phase | Observed time | Evidence/output bytes |
| --- | ---: | ---: |
| Public SDK encrypted product | 2.486 ms | 92,205 |
| Original Source proving | 3497.247 ms | 19,301,471 |
| Two encoding children proving | 2812.897 ms | 5,723,726 combined |
| Public arithmetic production | 32.360 ms | 1,737,899 |
| Consuming Formation production, including fresh prerequisites | 4365.455 ms | 2,531,603 |
| Fresh complete product receiving | 1730.017 ms | all five original frames |
| Client completion after receiving | 1.070 ms | all 4096 coefficients checked |
| Whole fixture and hostile cases | 19,204.844 ms | one full chain |

The whole test includes fixture preparation and multiple rejection checks; it
is not one deployed query latency. Phases are single observations with fresh
randomness, not percentiles or a comparable speedup against a different profile.

The actual CLI independently measured SDK preparation/product, certificate
production, complete arithmetic checking and client completion. Its total was
75.604 ms: preparation 6.038 ms (including 1.647 ms SDK product), production
33.978 ms, checking 31.956 ms and completion 0.680 ms. All 4096 decrypted
coefficients matched. This smaller operation excludes Source/Formation, hidden
program binding, fresh head, authorization, SQL locks and network agreement.

## Scope and remaining work

The new upper profile is an explicit mathematical composition label; no old
proof is relabeled. The raw endpoint accessor preserves the Gold request bytes,
nonce, parser and profile. The complete arithmetic checker has no SDK query
replay, caller challenge, callback, serialized verdict or cached proof result.

These gates do not assess concrete lattice security, the RNG, the full
Fiat-Shamir composition or installed-key authority. They do not install this
candidate into DCS Result/Session/WAL/SQL, prove a fresh weighted QC, or establish
FOR UPDATE/SKIP LOCKED behavior on this new profile. The 500 ms complete-query
requirement remains unmet: fresh mathematical receiving alone took 1730.017 ms.
No production timeout, proof, resource fuse or meaningful assertion was relaxed.

Ignored local receipts use the prefixes
`.local/product-composition-native-r1-` and include exact commands, source/image
hashes, stdout/stderr, process counters and memory CSVs. Those generated files
are not committed. The recorded test-image SHA256 values are
`04D6BF8904AE82A21B901E100A824AA4EF39D27F65FA11C626127E3757D57CFC`
(core), `197313EAFCD1F59DDF25ED819AFFFBC7B9EFEC44EBA27424461ADD88747E865A`
(experiment), and `2BCF3AC63372115B7840AA63A3E220DBB59665A64F2A940D9E835E0284D62B43`
(upper). CLI SHA256:
`125826437EF6FE9D34E19322748BC81C8EFA56987C93B66A5CE3A8070B7AB8DC`.

## Producer NTT optimization

Also executed on 2026-10-21 with the same release, worker and held-process
observation settings. The producer now shares the private Montgomery field
implementation with the verifier. Public NTT coefficients stay ordinary;
twiddles are encoded once per stage, updated in Montgomery form, and applied
with REDC. Inverse normalization encodes its common factor once. Canonical
input validation, primitive-root checks, convolution geometry, all seven
integer certificates, eighteen challenge points, cold verification, frame
bytes and the UNASSESSED profile are unchanged.

Before changing the transform, a native test recorded SHA512 of EVERY product
and quotient coefficient for fixed public dense inputs in all four bases.
Boundary values include zero, p-1 and p/2. The final test unconditionally pins
`94120219463f2115c811c87e1cc6ff83c533f6ec15b8bf94dbc7dcee48be38bd5158f7a93534781576068593641888aefd5fa36f003abc6ecf43c4a10d672b51`;
no capture fallback remains. The existing independent sparse convolution
oracle, actual SDK full 4096-coefficient checks and repaired false-output/quotient/codec
rejections also passed. No SDK computation or verifier is replaced by this hash.

| Same measured scope | Before | After |
| --- | ---: | ---: |
| Actual SDK example: complete public certificate production |34.685 ms|27.408 ms|
| Same example boundary: complete cold arithmetic checking |32.330 ms|32.595 ms|
| Nineteen owning cases, test-reported total |0.46 s|0.43 s|

These are individual observations with freshly generated public test examples,
not percentiles. The old/new complete coefficient identity supplies the exact
deterministic comparison; elapsed times alone do not establish equivalence.
The final core process took 435.842 ms/0.4375 CPU seconds, with sampled peak private
bytes 23,191,552 and OS peak working set 23,461,888. Its 1,652,224-byte test image SHA256
was `C08CC4FF5B3DF2B8A7EBDE6165ECD9418F8FAA177F5F96BF6585A0D8B4671C2A`.

All four protected Gold owner cases passed in 0.24 s. The same local
originate->wire decode->actual SDK product/certificate->complete check->full4096
client decryption scope took 69.102 ms (encryption 0.900, worker 34.012,
receive 34.063), versus its prior 76.316 ms observation. This includes neither
DATA/Source admission nor SQL compilation/locks, fresh weighted agreement,
transport or durable completion. Cold import/restore took 12.775 ms. That process
took 259.411 ms/0.234375 CPU seconds, peak private bytes 21,786,624 and OS peak working
set 25,976,832; no fuse, cleanup kill or unexpected child occurred in either run.
The exact 1,737,899-byte certificate remains unchanged.

Strict all-target Clippy, the owning consumer's all-feature Clippy, formatting
and the dependency-free requirements mirror gate passed. No heavy Source or
network recovery gate was repeated for this producer-only implementation
change. Receipts use `.local/product-ntt-native-r1-` and `r2-`; generated receipts
are not committed. Complete-query 500 ms, concrete security and live SQL remain
unestablished.

## Compact wire with the original logical transcript

Executed on 2026-10-22, based on `04f19711fe4ef841212b277c9d3f73e2872cba90`.
The public certificate now has one canonical `UCPITC02` encoding of 1,081,595
bytes instead of 1,737,899: exactly 656,304 bytes (37.7642%) less per product.
This is a measured byte reduction, not an established latency improvement.
The [codec contract](src/certificate/README.md) records the layout and unique
expansion to the original full logical transcript. All seven original integer
checks, all eighteen PIT points per basis, the mathematical profile, actual SDK
product and strict claimed-CT3 equality remain. No old-wire fallback exists.

The mathematical profile SHA512 remains
`9d97f6eede741c9a179fc359d8b33f299720ab54576fbfe955f6192af65a5724fecbfad31bf8b4f7ba1d88c2d9aebcdcd2a2c925b0f9b838b71be1806b343bed`.
The separate wire-profile SHA256 is
`640191d5fd1e4324df163e6ec2602c812ebfeb03f1dd5feec9ccf61036f3898a`.
Both are literal test contracts; an independent Python construction also
reproduced the latter from its fixed domains, old profile and exact lengths.
CLI profile and public-fixture observations report both identities.

Twenty owning tests passed, including genuine compact expansion equal to EVERY
original division-producer logical byte; actual SDK and full4096 scalar
boundary examples; malformed shape, bindings and reserved bytes; and repaired
false products that still fail the original PIT. Final coverage additionally
checks both K words in every last scalar row, the first and highest forbidden
bits, empty/header-short frames and trailing data. Two independent read-only
agent audits found no new soundness/consumer defect; their documentation and
test-coverage observations were incorporated. This is not an independent
cryptographic security assessment.

Source-pinned native runs used the existing release/MSVC/native-CPU environment,
locked/offline dependencies, held exact executable/creation identities, 20ms
sampling sleeps, 120s and 1792MiB process/aggregate fuses. No build or other heavy
test ran concurrently. The actual peer capture used the existing corrected
parent/image ownership guard, with no forced cleanup or faults. The observations
below preceded only final documentation, profile-golden and rejection-test
additions; the executable arithmetic implementation is the same.

| Complete measured scope | Observation |
| --- | ---: |
| Genuine daemon/TLS RPC: connection through received product and compact certificate | 60.152 ms |
| Owner's original-pair arithmetic checking and client decryption | 70.041 ms |
| Complete mathematical RPC interval | **130.194 ms** |
| Different public query, installed DATA, fresh Word/Query/product generation, receiving setup/check and completion, 16 workers | **1089.447 ms** |
| Second originating-owner query, own private input premise, fresh Word/product and completion | 369.124 ms |
| Third originating-owner query, same scope | 337.120 ms |

TLS inner request/output/certificate lengths were 123,572 / 92,199 / 1,081,595
bytes. The runtime response cap follows `CERTIFICATE_BYTES` and is now
34+131072+1081595=1,212,701 bytes; oversized old replies reject. The actual TLS
test retains changed-certificate, wrong-original-call, foreign-owner,
cancellation/retry, observed-I/O, storage-unchanged and full4096 decrypted-oracle
checks. It omits Source, Word, SQL, fresh head and locks.

The complete public query carried 7,224,762 per-query proof bytes; its cold setup
and first read took 8443.439ms and 26,114,741 bytes. The two owner-specific calls
carried 4,105,132 / 4,107,084 bytes and omitted a public Query proof by relying on
their originating owner's own private input premise. That premise is
nontransferable and cannot admit a public validator Predicate. These local
reads omit transport, current agreed head, SQL admission, consensus and locks.
Compared with the [prior individual observations](../registry200-proof/src/registry_progress/word/read/CPU-SCALING.md),
these runs were slower despite smaller certificates. Fresh proof randomness,
scheduling and the additional reconstruction cost prevent a speedup claim.

The read process's sampled working set/private peaks were 592,986,112 /
587,071,488 bytes, OS peak working set 594,219,008. TLS aggregate sampled working
set/private peaks were 49,692,672 / 22,036,480 bytes. These scoped observations
do not establish whole production-peer resource use. The complete SQL500ms
target remains unmet; all SQL/Predicate admission and security guards stay
closed and no production timeout was relaxed.

Generated local receipts are not committed:

- Core20 r420: `.local/word-cmd-native-r420-bfv-unrelinearized-product-observe-tests/result.json`,
  SHA256 `0CE778A00FAFCC9D6CD58C14A8988D686AAAC420A905061B4488247D5CDF8A67`.
- Real TLS r426: `.local/gold-process-native-r426-gold/result.json`, SHA256
  `BCF2498FE3DA0CB0BC5B256DC8FE9880AF3698105CD7165DEB8ACBB9CB68E3A4`.
  Peer image23,874,048 bytes SHA256
  `CE7399ACAD7C061BCD0A04A297DEF3B9F2D6DCC78F65D18A18A942562FD27632`.
- Complete read r427: `.local/word-cmd-native-r427-registry200-proof-observe-tests/result.json`,
  SHA256 `1F192C866016DF96133C7A33D88D4787C1F21FB26C0516CB32E5AF94D9A8DDB7`.
  Image12,466,688 bytes SHA256
  `51D9FC34417B830CB9FF2C167EF3F52F89E2C78F084FAC5477A84B68E7301E33`.

The owning Clippy checks and consumer builds passed before these captures.
Reproduce the owning boundaries with release locked Cargo tests for
`bfv-unrelinearized-product`, `registry200-proof --features owner-read --lib
registry_progress::word::read::tests::`, and `dcs-peer --test gold_product
real_peer_returns_only_bounded_unverified_gold_math_and_owner_checks_originals`.
Use `RAYON_NUM_THREADS=16` for the recorded complete-read worker budget; the
TLS and core20 captures used2. Ordinary `cargo test` output alone does not
replace the pinned-resource observer records.

After the final profile-golden and failure-coverage edits, fresh matched native
artifacts passed20 product cases (r436),12 protected-owner cases (r437) and the
bounded runtime codec case (r438), with no faults or forced cleanup. The two
private-result compile-fail examples, strict all-target Clippy for the product,
experiment and runtime, rustfmt, local documentation links and actual
`requirements_sync` test also passed. The owning Core Clippy and complete
registry/daemon/experiment consumer builds had already passed for this same
arithmetic implementation. Final unit receipt SHA256 values are:

- `.local/word-cmd-native-r436-bfv-unrelinearized-product-observe-tests/result.json`:
  `E7BA10DF5927286DE3C7307645BEE73B34ED73BB995C3D0F53A4E2BF0775EF43`.
- `.local/word-cmd-native-r437-bfv-query-core-observe-tests/result.json`:
  `3ED5C95125D5B939EBE00B62BF3D3424F4C853211522FB1E07FA760A838F6936`.
- `.local/word-cmd-native-r438-peer-runtime-observe-tests/result.json`:
  `295D3A2392988426773E99AFF5558F7F230B2C5F42DD1FF7C3B1B1004701C44C`.
