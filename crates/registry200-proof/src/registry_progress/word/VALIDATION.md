# Public Word API validation

On2026-10-21 the existing fixed Word mathematical backend became available in
ordinary library builds through `registry_progress::word`. This is a public
mathematical API, not SQL/Source/OldRoot/finality admission. The internal graph,
hash domains, all309 public constraints, complete public preprocessing and
canonical DCSWCW02 frame are unchanged. [API ownership](README.md) describes the
required independent claims and remaining system boundaries.

## Normal implementation boundary

`Expected::checked` reaudits the sealed SourceVersion metadata and derives the
original registry/enrollment headers, scope16 and context100 from the complete
source images/claims and independent genesis/parent/enrollment. It retains all
transition claims. Control requires a zero statement root. Public header/context
accessors expose only existing PUBLIC data, not owner openings or proof status.

The exact original command/walk types and their Drop implementations moved into
the public input contract. Source/registry openings and the consumed preparation
have no raw getter, Clone or serialization. Inputs and MAIN are cleared best
effort on success/error; no stack/compiler/allocator erasure claim is added.
No producer setup retains private inputs, proof randomness or verdicts.

The original exhaustive semantic serializer moved byte-for-byte from the test
module into `inventory_encoding`, because normal goldens must not depend on test
sources. Existing literal full-IR/PP/native-commitment pins remain mandatory.
Normal assessment additionally checks that independently counted original
weights/weighted height agree with the SDK accounting; it does not change any
AIR equation, security parameter, packing choice or resource cap. Diagnostic
report storage/logging and test-only helpers are excluded from normal builds;
the actual security calculations, checked arithmetic and resource gates remain.

Public Prover/Verifier objects independently construct the existing immutable
ROLE-only preprocessing. Every private proof uses the original fresh OS config.
Every receiving call binds full metadata, performs bounded canonical decode and
actual native verification before constructing `VerifiedWord`. Cold receiving
checks original frame bounds/header before allocating preprocessing. It cannot
adopt producer CommonData, an AIR callback or a serialized accepting flag.

Existing exact-pinned P3 batch/FRI/lookup/commit/security/DFT, bounded-postcard,
Postcard and PUBLIC-only RNG dependencies moved from dev to normal dependencies.
No package version or Cargo.lock entry changed. FHE SDK test fixtures remain
dev-only. Existing production Source/Input16, Control815/Predicate896,
storage-client/finality routes and SQL refusal guards were not changed.

## Executed gates

The final owning release filter passed all38 Word cases in40.26s, including
three new public-API cases. Metadata derivation matches the COMPLETE original
binding for each of the six independent branch examples. Both mathematical and
frame profiles match the original constants. Invalid source lengths and
noncanonical source salts fail before private preparation.

The honest public prover/receiver case runs all six original owner examples:
conflict-before-offset, skip-before-offset, limit-zero, resumed prefix,
NOWAIT/latest-savepoint and End/stable-compaction. Separate receiving setups
are constructed for both roles. Each actual proof receives successfully through
the PUBLIC API; wrong-role objects reject. A genuine native OOD opening is then
changed, canonically reframed and required to fail with exact Verification.
Changing the independently expected result root and repairing only the complete
frame binding also reaches native Verification failure. Cold empty/oversized
frames and producer role mismatch reject at their actual API boundary.

The same38-case filter also executes all original full symbolic/PP/commitment
goldens, complete witness/SSA/lookup refusals, repaired false native arguments,
the source/mask/original-QueryCt join and the full genuine State/Role3/DATA/Word/
Query/FHE product/client-decryption case with retained immutable DATA and a second
different query. Those original gates were not weakened or replaced by shape
checks. The unchanged tests still distinguish BASE diagnostics from native
global lookup and OOD verification.

Normal and test targets compiled. Strict release/all-target Clippy passed
without lint suppressions. Three external compile-fail examples passed: the
verified result's private constructor, its Clone refusal and PrivateInputs Clone
refusal. The dependency-free requirements_sync gate passed. The first normal
r117 check exposed test-only constant/diagnostic references; these were repaired,
and subsequent normal/all-target compilation and strict Clippy are clean.

## Resources, records and scope

The final38-case process lived40264.5826ms, used65.640625 CPU-seconds, peaked at
571703296 OS working-set bytes and574611456 sampled private bytes. It retained
the120s/1792MiB whole-PID fuses,20ms samples, held image/creation identity and
final exit0/no-direct-child checks. No fault, fuse or forced cleanup occurred.
Its functional run overlapped a documentation build; the duration is test
feedback, not query latency or a throughput benchmark.

Final full-gate release image:11806720 bytes, SHA256
B34D2D6F8ED46EC5E3D6B7E0D66958BFB756353D05047BB0DEEC825163475E2D.
Ignored local records r120-r123 retain exact source hashes, commands, full output
and samples. The initial r120 public-only3-case gate passed before the final
numeric-coherence check. This final record and the private module's first-line
documentation correction follow the full-gate snapshot; they change no executable
behavior. Generated proof/key/ciphertext outputs are not committed.

Reproduce the owning boundary with the pinned Rust1.99.0 MSVC/native release
environment, Cargo.lock, Rayon2 and one harness thread:

```sh
cargo test --release --locked -p registry200-proof registry_progress::word_inventory:: -- --nocapture --test-threads=1
cargo test --release --locked -p registry200-proof --doc registry_progress::word -- --test-threads=1
cargo clippy --release --locked -p registry200-proof --all-targets -- -D warnings
```

The public backend still proves its fixed transition relative to independently
retained Source and OldRoot claims. Their authentication, authorized historical
bootstrap, original data/query/product association, composed/key/lattice security,
fresh weighted quorum, peer transport, SQL projection and durable lock/result
completion require the higher receiving composition. No complete-query or500ms
claim follows from this API or its test duration.
