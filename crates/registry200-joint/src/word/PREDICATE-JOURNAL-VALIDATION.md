# Closed Predicate journal validation

Date: 2026-10-22. Base: `7b7e3ae407d7517c3e568e6e6a655e9df8465440`.

The complete original [Predicate packet](PREDICATE-PACKET.md) now reaches the
same fixed Joint verifier used by owner-authorized journal imports and durable
voting. This is a reject-only integration. No Predicate operation, SQL result,
lock, current-head assertion or quorum certificate is admitted by this change.

## Actual receiving boundary

The new unverified lane has request/evidence tag 2. Its statement root must be
nonzero; Bootstrap/Control retain their original zero-statement shape. All
canonical field, evidence size, external-source and complete-EOF checks remain
mandatory. `OperationId` still binds the full application, request and evidence.

`Verifier::check` derives the Word Predicate expectation from its own genuinely
verified immutable Source, application Genesis, actual journal parent and actual
active enrollment/old registry. It reconstructs the complete DATA/Query/product
endpoints from the original packet, then invokes the original six-proof public
receiver. The move-only mathematical result is discarded. Even success returns
`RejectedComputationProof` before any `Proof`, `VerifiedOperation` or pending
import exists. There is no caller-selected verifier or public successful helper.

The actual Journal checks the owner signature before that callback. The new
native case first commits genuine Bootstrap and BEGIN operations, prepares the
Predicate from that real BEGIN bank through `prepare_transition`, and generates
the original Role3, DATA, Word, fused Query and actual SDK product evidence.
The source certificate is the original genuine fixture proof. No selected answer,
Next bank or Result is supplied as a substitute for the owner transition recipe.

The genuine private mathematical check succeeds. Both `check_block` and
`prepare_import` reject the same genuinely signed candidate without changing
header count or ancestry floor. Further cases reject a foreign owner, independent
operation pin, request parent and old registry. Each of the six proof payloads is
separately damaged while metadata remains structurally valid; actual native
verification rejects each. A damaged Query also traverses the real signed journal
path. The stale inner-parent case retains the actual outer journal parent and
old heads, requiring the common verifier to reject that foreign association.

## Executed checks and scoped observations

All three owning Word Joint cases passed in 28.71s. The new case took 22023.042ms;
its separate complete six-proof receiving interval took 2069.288ms. Those times
exclude a successful network SQL/consensus/locking operation. The full 500ms
query target remains unmet, and composed cryptographic security remains
unassessed. Existing Bootstrap/Control accepted semantics are unchanged.

The release/MSVC Rust 1.99.0 capture used native CPU, locked/offline dependencies,
Cargo jobs 2, Rayon budget 2, unchanged 120s/1792MiB fuses and 20ms sampling. No build
or other heavy test overlapped the capture. Process lifetime was 28734.0896ms;
sampled working-set/private peaks were 575,397,888 / 570,003,456 bytes; OS peak
working set was 580,349,952 bytes. No observer fault, forced cleanup or surviving
task child occurred. These observations are not production-peer resource bounds.

Generated receipt, not committed:
`.local/word-cmd-native-r457-registry200-joint-observe-tests/result.json`, SHA256
`C01698EA54C3477B8A5EEA7B214577849E6B253C92F8F90337413582CDAD3FA0`.
The 26,162,688-byte test image SHA256 is
`9B499FB0C61D81F2DD44488223BF380368462955E146D90DCC561E71B78516DE`.
Earlier failed captures are not accepted evidence: they exposed a test-only
scale-inverse constant and a stale-parent candidate-builder mismatch, both fixed
without changing production cryptography or journal validation.

Strict all-target Clippy passed for Joint and its finality consumer. Both Word
external compile-fail examples and the dependency-free requirements mirror guard
passed. The normal dependency graph includes `gold-evaluator` and excludes
`gold-owner` and `storage-client`; owner functionality is enabled only by the
new test dependency. No lockfile or dependency version changed.

```powershell
cargo test --release --offline --locked -p registry200-joint --lib word::tests:: -- --nocapture --test-threads=1
cargo clippy --release --offline --locked -p registry200-joint --all-targets -- -D warnings
cargo clippy --release --offline --locked -p registry200-finality --all-targets -- -D warnings
cargo test --release --offline --locked -p registry200-joint --doc word:: -- --test-threads=1
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

The application contract identity remains unchanged because Predicate still
cannot succeed and the accepted Bootstrap/Control bytes and relations are
unchanged. A future accepting policy needs a new contract identity covering the
complete read/packet/security policy. Static consumer review found no early lane
rejection or bypass in Word finality/peer framing: journal verification precedes
control extraction and durable acceptance. No transport, consensus, WAL or
recovery behavior changed; the expensive four-peer recovery gate was not repeated.
Fresh agreement, assessed composition and actual SQL/locking admission remain
required work. No proof, resource fuse or production timeout was relaxed.
