# Gold product over real peer transport

`GoldProductRequest` contains only the bounded existing public N4096/Q2 Gold
request. `GoldProductReply` contains a Ct3 and the actual conditional arithmetic
certificate. No mask, SQL, secret key, source opening, witness, accepted flag or
plaintext row crosses the wire. The worker performs genuine SDK multiplication
and certificate production from the literal input pair and original nonce.

## Boundary and lifecycle

`RemotePeer::gold_product(&PublicRequest)` uses the existing pinned TLS endpoint,
request identity, cancellation scope, framing, traces and observed I/O. The
client rejects unrelated response variants before their payload deserialization.
It returns only `bfv_query_core::gold::UnverifiedProduct`. The originating owner
must independently verify the certificate against its full original nonce/pair,
then complete the required DATA/Word/version/authorization/finality composition
before any SQL result or lock is accepted. TLS authentication and a successful
RPC are not computation or completeness proofs.

Only the daemon's independently configured TLS owner can invoke this heavy job.
Unauthorized calls reject before acquiring CPU resources or decoding SDK inputs.
The daemon uses its ONE existing `ProofGate` shared with other heavy services;
Busy remains a resource failure. It holds no store lock during SDK computation
or network I/O and writes no object, journal, setup, proof verdict or SQL state.
The worker owns only public fixed SDK parameters. `gold-evaluator` compiles no
Gold Owner, private mask, encryption, custody or decryption implementation.

SDK computation is synchronous; cancellation closes client sockets and prevents
client acceptance. It does not claim to preempt an already running native product
or release SQL locks. Ordinary transport budgets are unchanged. The process
connection cap, owner authorization and shared heavy gate bound concurrent work.

## Fixed wire and bounds

RPC version 2 is retained. The appended request tag 22 and success response tag 14
preserve all existing tags. These are untrusted messages, without a protocol
upgrade, migration or relabeling of the earlier private-product stream.

The request has the original Gold 640-byte header and two 128KiB ciphertext caps.
Its bounded serde visitor checks the announced sequence length before allocating.
The output is capped at 128KiB and its certificate must have exactly 1,737,899
bytes. The total narrow response cap is 34 + 131072 + 1737899 = 1,869,005 bytes,
including the actual fixed bincode envelope/vector lengths. Error strings are
also bounded by that complete response cap. The ordinary incoming outer-frame
cap remains owned by peer-transport. Canonical inner Gold decoding happens
before SDK computation; malformed, truncated and trailing requests reject.

The response tag is selected before any unrelated vector decoder can allocate.
Bounds never establish arithmetic validity: genuine full original-input checking
is still necessary on the owner side. Shape-correct damaged certificates and
prior-call replies remain untrusted and must fail that check.

## Verification and remaining scope

`gold_product` owns codec/tag/hostile-length tests. The actual `dcs-peer` process
integration test starts an independent daemon, sends only public ciphertexts
over real TLS, receives its actual product/certificate and runs full original
arithmetic checking before decryption and an independent full-ring oracle. It
also checks foreign-owner rejection, changed certificate and original-call
binding, cancellation, retry and unchanged physical storage. Shared process
lifecycle helpers launch a hidden Windows child and reap it on all paths.

This primitive has no SQL, agreed-head, Source/Word or finalized-lock acceptance
route. Its certificate retains the lower conditional/unassessed security model.
It does not establish the 500ms complete SQL target. The existing public voter
Predicate gate and client SQL admission guards remain closed.

## Executed validation

The working tree based on `9185478cc10fb98f1ff0c2d10db0585a387d6b7d` passed
fifteen distinct owning runtime cases: twelve existing Gold owner cases, the
new bounded codec case, one genuine daemon/TLS product case and the existing
private-product foreign-owner rejection case after extracting their shared
process helper. Seven protected Gold compile-fail examples also passed. Strict
all-target Clippy passed for the public-only core feature, the owner core
feature, peer-runtime and dcs-peer. The requirements mirror guard passed.

Actual process tests ran directly from matched prebuilt release artifacts, with
Rust 1.99.0/MSVC, opt-level 3, native CPU, Cargo jobs 2, Rayon threads 2 and the
existing locked/offline dependency set. No other build/test ran during captures.
The ordinary dependency feature tree independently confirms `gold-evaluator`
and absence of `gold-owner` in peer-runtime's normal dependency edges. Cargo
test binary feature unification can additionally compile owner support for the
integration test; the worker receives no private owner input in either build.

The accepted Gold r236 capture starts its interval with the actual originating
public request already prepared. On loopback TLS it measured:

| Actual component | Milliseconds |
| --- | ---: |
| Connection, request, remote SDK product/certificate and received reply | 41.793 |
| Independent original-pair arithmetic check and client decryption | 33.867 |
| Complete measured mathematical RPC interval | **75.661** |

Request bytes were 123,572, output 92,199 and certificate 1,737,899. These are inner
payload lengths; the actual transport adds its canonical RPC/TLS envelopes.
An earlier accepted capture of the same binaries measured 88.338ms. Neither is
a full-query deadline or a controlled speedup over the earlier local pipeline.
Origination/encryption, Source/Word proofs, SQL compilation, current agreed head,
consensus and locks are outside these intervals. The same test checks changed
certificate, different original call, actual foreign TLS owner, cancellation,
retry, observed I/O and unchanged disk objects; its independent full 4096 oracle
runs only after native arithmetic verification and decryption.

The final capture holds the test and actual daemon handles with exact image
and creation identities, plus two separately identified Windows console hosts.
All exited 0 naturally, with no faults, forced cleanup or surviving task children.
The daemon's OS lifetime peak working set was 20,160,512 bytes; the test parent's
was 22,401,024. Aggregate sampled working-set peak was 42,172,416 bytes, with a
20ms sampling sleep between full process-tree scans. This is a short primitive
test, not a production-peer or full-proof memory bound. Its 120s and 1792MiB
aggregate fuses are observation limits, not changed production timeouts.

Before accepting a discovered descendant for cleanup, the observer checks its
creation time against its held parent and its exact pinned executable. Windows
can retain a stale numerical parent PID from a process that exited before our
test. Such unrelated processes are excluded; unknown images are never stopped.
Known console hosts are included in accounting and allowed to exit with their
attached processes. Five pure ancestry-classification cases check the concrete
pre-existing/PID-reuse failure mode separately from the native cryptographic gate.

Earlier r225/226/227 captures were rejected during socket/Windows-console
observer setup. The r233 observer also wrongly registered a pre-existing process
under a reused numerical parent PID and terminated it. That process was restarted;
the ancestry/image guard and repository cleanup convention were corrected before
accepted r235/r236 reruns. Those failed reports establish no native PASS or
performance claim. No cryptographic assertion, resource fuse or production
timeout was weakened to obtain the accepted results.

Accepted local evidence is generated output and is not committed:

- `.local/gold-process-native-r236-gold/result.json`, SHA256
  `95074AD0CAB5CA2054E72B7C35AAAF5DCFC57CDDF00C7D30444E7E7A95452DB8`.
- `.local/gold-process-native-r235-private/result.json`, SHA256
  `A9F0B1F01C29FBECD8E493CAEAB81D9A8B37AD543E7210F2D792F97EE3FD84CB`.
- `.local/gold-owner-native-r234-bfv-query-core-observe-tests/result.json`, SHA256
  `E6C862C4356C96C659D9FA62607347AAAAAD9CBE77DC871D66AF66C829858BE5`.
- Matched daemon image 23,783,424 bytes, SHA256
  `C2C0B531D84D1D4B594920094EB41A0CD1A3D2960EE3B3E5482D2A4556E5AA09`;
  Gold test image 3,687,424 bytes, SHA256
  `D543F5964B501DF61F9EAF44A889D361659C9E821496E3ED9743CC093DDEB5ED`.
- The accepted process observer source SHA256 is
  `ADE66D423F84E8E167D2BB53130FD8B9A4B3C97C38EF92A9AEDA96954751E5BE`.
  Pure public dependency-tree output SHA256 is
  `21774D81F35B3B046C374549E99558C0E830FF44B386FACC92047DD1B83383BD`.

Reproduce with the stated native environment and an isolated target directory:

```powershell
cargo test --release --locked -p dcs-peer --test gold_product -- --nocapture --test-threads=1
cargo test --release --locked -p dcs-peer --test private_product foreign_tls_identity_cannot_start_a_private_product_stream -- --exact --nocapture --test-threads=1
cargo test --release --locked -p peer-runtime --lib gold_product:: -- --test-threads=1
cargo test --release --locked -p bfv-query-core --features gold-owner --lib gold:: -- --test-threads=1
cargo clippy --release --locked -p bfv-query-core --features gold-evaluator --all-targets -- -D warnings
cargo clippy --release --locked -p bfv-query-core --features gold-owner --all-targets -- -D warnings
cargo clippy --release --locked -p peer-runtime --all-targets -- -D warnings
cargo clippy --release --locked -p dcs-peer --all-targets -- -D warnings
cargo test --release --locked -p bfv-query-core --features gold-owner --doc gold:: -- --test-threads=1
cargo test --release --locked -p repository-contracts --test requirements_sync
```
