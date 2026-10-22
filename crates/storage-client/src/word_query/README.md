# Private Word SQL preparation and public evidence

Optional `storage-client/word-query` owns private SQL compilation and original
Word/Gold input binding, with distinct owner-private and public-proof preparation
paths. It does not open Session/PGwire/GUI SQL admission or
return an accepted SQL result, fresh head or lock lease.

`CompiledLockingSelect::compile` uses the existing `sql-plan` parser for the fixed
nonnullable age domain. It accepts locking SELECT on the current four-record
schema, projections age, amount or age/amount, and OFFSET/LIMIT within 0..4.
It preserves KEY SHARE/SHARE/NO KEY UPDATE/UPDATE and WAIT/NOWAIT/SKIP LOCKED.
Three-valued WHERE compilation keeps only SQL TRUE values. Unsupported projection
order, plain nonlocking SELECT, aggregates, writes, unsupported predicates and
out-of-profile windows reject instead of being rewritten to another query.

Fresh fallible OS entropy supplies a secret 32-byte exact-SQL blind and four
canonical Goldilocks statement-salt words. Rejection sampling has eight attempts
per word and fails closed. The original SQL string is not retained. The compiled
truth table, policy and salt remain in private scoped guards; there is no public
mask getter, Clone, Debug, serialization or caller-selected RNG. `blinded_sql`
exposes only the intended 32-byte blinded commitment as eight public field words.

## Ownership and public contracts

1. The owner independently obtains complete Source/current registry material,
   caller/actor identity, call/invocation and fresh enrollment/command/result
   salts. `Actor` and `Material` are claims and private witness material; they
   authenticate neither a client nor its rights. `CurrentMaterial` supplies only
   the old bank; `prepare_current` produces the proposed transition through the
   original Word witness recipes. Durable owner state and fresh quorum admission
   are still required before application SQL acceptance. The lower `Material`
   entry also permits independently implemented old/new witness producers.
2. `compile(...).prepare(domain, Material)` consumes those guarded inputs. This
   start-only route rejects nonzero prior progress, prior SQL/statement openings
   and invalid actor/field bounds. It sets the exact compiled mask, lock/window/
   projection policy, blinded SQL and fresh statement salt. The normal Word
   encoder creates the original Stmt96 from those SAME private inputs, including
   the exact actor snapshot/controller. No source row is read to calculate a
   query answer. Resume requires its original durable statement lifecycle; this
   constructor is not an alternate WAIT-resume route.
3. `PreparedQuery` exposes its statement root and blinded SQL for independently
   building the full Word expectation. Its consuming `originate` checks full
   Source equality and the exact statement, command, profile, rules, database,
   genesis/parent, actor/call, client/controller/snapshot/invocation, version and
   DATA pins. It creates the actual original Gold ciphertext using the owner's
   opaque key, without exporting a private mask or SDK key.
4. `PendingQuery::prove` and `prove_public` are alternatives sharing one-use
   private Word/statement material. The owner-private `prove` checks the retained
   complete expected binding before consuming it. A wrong expectation leaves
   the original available. After the guard, an attempt consumes the material
   even on failure. It checks actual private original-input equations and
   produces the genuine native Word argument. `ProvedQuery` borrows the original
   encrypted input and contains the UNVERIFIED Word frame; it is not a proof
   verdict or SQL receipt.
5. The caller can send `proved.input().public_request()` through the actual
   `RemotePeer::gold_product`. The fixed `word::read::owner::Verifier` must still
   independently check the actual installed DATA theorem, Word argument and
   original-pair product certificate before owner completion. Current agreed
   head, authorization, whole Result160 opening, weighted finality, durable owner
   state and final SQL projection/locking acceptance remain mandatory outside
   this preparation boundary.
6. The separate `prove_public(owner, prover, word_expected, data_expected)` path
   produces both UNVERIFIED Word and fused Query frames from the same original
   compiled input. `ProvedPublicQuery` exports bounded public evidence suitable
   for independent receiving. It supplies no owner-private premise in place of
   a public Query proof. Actual full public `word::read` verification is required
   before its protected `complete` method can decrypt the original product.

No accepted flag, mutable owner getter, alternate verifier, model evaluator or
fixture dependency enters normal builds. All private objects are move-only with
scoped clearing. This is best effort, not complete stack/allocator erasure.

Direct dependencies are [sql-plan](../../../sql-plan/README.md) for parsing,
[Word](../../../registry200-proof/src/registry_progress/word/README.md) for
original canonical serialization and native proofs, its DATA composition,
[Gold owner inputs](../../../bfv-query-core/src/gold/README.md), the optional
direct [Gold Formation](../../../bfv-ciphertext-formation/src/gold/README.md)
dependency for original fused Query preparation/proving, OS entropy,
SHA2 and zeroize. Peer transport and finality policy remain with their existing
owners. The root feature enables the existing owner-read mathematical composition;
it does not enable the historical private-input-proofs pipeline by aliasing it.

## Public proof preparation and completion

`PendingQuery::prove_public` first compares the complete retained Word expectation
and DATA expectation against the original query. Neither a different Word
binding nor another DATA endpoint consumes the original private material. Once
those guards pass, it consumes that same one-use material, obtains a fresh
fallible OS Cw salt internally, and derives the Query expectation and commitment
from the original ordered request, Stmt96 root and original DATA. A later entropy,
binding, preparation or proving failure still consumes the attempt. Calling
either proving alternative afterwards cannot reuse its private witness.

The protected Gold owner's existing `query_commitment` and `prepare_query`
constructors keep the original mask, complete Stmt96 and SDK secret private.
The client then invokes the existing fused Query native prover and the original
Word native prover. It accepts no caller-selected mask, salt, RNG, alternate
verifier or cached proof verdict. Preparing a native witness or producing its
bytes establishes no successful public verification.

`ProvedPublicQuery` borrows the original input and exposes only:

- `public_request()`: the same original bounded ciphertext request for the public
  evaluator, including its original nonce and ordered inputs.
- `word()` and `query()`: the actual UNVERIFIED native evidence bytes.
- `query_expected()`: the complete public fused Query expectation, which is
  metadata rather than a proof result.
- `complete(owner, checked_read)`: protected decryption requiring an actual
  `word::read::ArithmeticCheckedRead` from full public receiving, with the same
  complete Word, fused Query, DATA and original ciphertext-pair bindings.

A caller can send `public_request()` through the real `RemotePeer::gold_product`,
then independently construct the full read expectation from its original Word,
DATA, query commitment and the received candidate Ct3. The existing public
`word::read` receiver must check the real product certificate, Word and fused
Query proof, plus Source/Role3/DATA or the exact retained immutable DATA theorem.
An owner-specific checked input or `word::read::owner` result cannot satisfy the
public completion contract. No private getter or conversion from that premise
to transferable proof authority is introduced.

These frames can travel to another receiver, but remain unverified until that
receiver performs the original native checks against its independently retained
expectations. This path supplies the public evidence needed for eventual
Predicate composition. Current-state authorization, fresh weighted finality,
durable Result160/registry completion, composed security and final SQL/lock
admission remain separate requirements; their guards stay closed.

## Validation and remaining scope

### Normal public producer validation, 2026-10-22

Based on `2b1d6e7c14ae450bfd1888299067da37dacd7488`, all five owning
`word_query::` cases passed. The additional native case uses the normal SQL
compiler and protected Owner to create two genuine Word/fused Query packages,
actual SDK products and full public read results. The receiver helper accepts
only public endpoints, unverified evidence and its actually verified immutable
DATA theorem. Every decrypted coefficient is compared against an independent
4096-coefficient oracle after genuine public checking.

The case rejects changed original Word claims, a different full DATA binding
with the same literal ciphertext, damaged/missing Query evidence and a genuine
sealed read result belonging to another call. It checks shared one-use behavior
in both proving orders, foreign-owner failure and fallible entropy. All-zero
salt and repeated noncanonical draws reject after bounded4/8 draws and consume
the attempt. Neither method substitutes private owner knowledge for the public
Query proof. The prior owner-private native case and all SQL/mask/entropy
contract cases also passed.

One two-worker observation from an already prepared original encrypted request:

| Measured component | Milliseconds |
| --- | ---: |
| Original native Word and fused Query production, including guarded Cw preparation | 1828.952 |
| Actual SDK product and complete arithmetic certificate production | 38.333 |
| Fresh public receiving setup and complete Word/Query/product checking | 911.198 |
| Bound owner decryption | 1.445 |
| Whole interval, including public expected construction | **2780.725** |

Word/Query/product frames were 2,937,642 / 3,204,661 / 1,081,595 bytes. This is
one freshly randomized fixture observation, not a latency percentile or speedup
comparison. SQL compilation/origination, cold Source/DATA installation and
prover setup precede this interval. It excludes transport, fresh weighted QC,
durable Predicate/Result160 completion and SQL/lock admission. All five tests,
including preparation and hostile cases, took27.45s; that is not a query time.
The complete500ms requirement remains unmet.

Release/MSVC Rust1.99.0, native CPU, Cargo jobs2, Rayon budget2, locked/offline
dependencies and the existing source/image-pinned native observer were used.
The held exact process/creation identity exited0 with no faults, forced cleanup
or surviving task children. Sampled/OS peak working set was573,558,784 bytes;
sampled private peak was563,175,424. The unchanged120s/1792MiB fuses and20ms
sampling sleep are observation bounds, not production-peer memory/latency
guarantees. No build or other heavy test ran during the capture.

The native report is generated local output, not committed:
`.local/word-cmd-native-r442-storage-client-observe-tests/result.json`, SHA256
`66BE42517C8CDF7020AFF7CA87DC06BF755BF5ACBDEB8842DAC734600364DD03`.
Its27,154,432-byte test image SHA256 is
`6E2BD4C81A21026695F24860CC0AD7E2C803924EFDF64AFC22CAAE7BD4AB6EBA`.
Strict all-target Clippy with `word-query`, all five compile-fail examples,
formatting and local documentation links also passed. The new compile-fail
example rejects the actual owner-private `OwnerCheckedRead` type at the public
completion signature. Reproduce the owning cases with
`cargo test --release --locked -p storage-client --features word-query --lib word_query:: -- --test-threads=1`;
the source-pinned observer additionally records exact artifacts and resources.

The public producer is now a normal library path. Assessed composed security,
the actual Predicate journal/voter path, owner recovery/WAIT and a current-head
barrier remain required before SQL or row-lock acceptance. This stage changes
none of those guards.

`compile(...).prepare_current(draft, CurrentMaterial)` pins the actual immutable
source, enrollment, parent, independently retained old root and this compiled
blinded SQL. It uses [Word current-state preparation](../../../registry200-proof/src/registry_progress/word/README.md)
to produce original private next-bank/result openings and all transition roots.
`PreparedCurrentQuery::into_parts` returns the normal prepared query, proposed
expectation and move-only guarded candidate opening. Neither output authorizes
installing a bank or returning rows. This client entry remains fresh-start-only;
the Word producer separately supports the original WAIT continuation. A persisted
client continuation lifecycle and fresh consensus integration are unfinished.

The actual native client example now supplies only the old bank. Independent
hand-written next-bank/result words are used solely as assertions after normal
production, then the actual installed DATA, Word proof and original SDK product
must pass independent receiving before mathematical completion. Fresh candidate
progress entropy is cleared automatically on Done. The recorded preparation
interval is only owner witness construction, not a complete SQL measurement.

```text
cargo test --release --locked -p storage-client --features word-query word_query:: -- --test-threads=1
```

Compiler cases cover all twelve lock strength/wait combinations, exact original
mask/window/projection words, NULL three-valued cases, unsupported SQL, stale
start inputs, noncanonical bounds, fresh blinding and entropy failure. One actual
native chain uses genuinely sealed source pages, fresh Source/Role3/DATA proofs,
the compiled original input, genuine Word proof, actual SDK product/certificate
and independent owner receiving before a full 4096 oracle. The test supplies an
explicit expected private bank transition; it does not implement a live owner
state/witness producer or accept an SQL answer from a fixture.

The Word encoder also compares every word and root of all five existing Predicate
examples, including WAIT resume, SKIP-before-OFFSET and NOWAIT with a savepoint.
Actual public read receiving still requires its fused Query proof. Current voter
Predicate admission and client SQL guards remain closed. Composed cryptographic
assurance remains unassessed, and no 500ms full-query result follows here.

## Executed evidence

The working tree based on `387763875490c7a56e68b22cc4dfc8766da80ea5` passed
six owning runtime cases: four compiler/native-chain cases, one encoder case
covering all five original Predicate examples, and the existing complete public
read scenario using the new normal encoder. Fourteen compile-fail examples
passed across this client module and Word. Strict Clippy passed for word-query,
all storage-client features together, and registry200-proof. Default client
compilation and the dependency-free requirements mirror guard also passed.

The genuine client chain proves/verifies the sealed Source, Role3 version encoding
and DATA, then compiles the exact SQL, creates its original input and produces
Word. It checks the actual public SDK product/certificate independently before
decryption and a full-ring oracle. Altered complete expectations, damaged Word
evidence and repeated private-witness consumption reject. The original source,
data, output and Word rejections in the full public read scenario also pass.

The four client cases finished in 8.71s, including all cold Source/encoding/DATA/
Word setup and hostile examples. This is TEST time, not a measured SQL request.
The direct process lived 8729.747ms, used 12.859375 CPU-seconds, and had 428 memory
samples. OS peak working set was 560,787,456 bytes; sampled private-byte peak was
567,259,136. The unchanged full read scenario took 30.71s including its original
public fused-Query path and hostile cases. Its process OS peak was 561,606,656
bytes. No network/current-head/finality/SQL/lock grant or whole-peer memory bound
follows from these isolated mathematical/library runs.

Windows/MSVC Rust 1.99.0, release opt-level 3, native CPU, Cargo jobs 2 and Rayon
threads 2 were retained with locked/offline dependencies. Captures ran separately
without concurrent builds/tests, pinned sources and images before/after, and held
the exact directly launched test handle/creation identity. The existing 120s and
1792MiB process fuses remained. All accepted captures exited 0, without faults,
forced cleanup or surviving task children; pre-existing processes under stale
parent PIDs cannot enter cleanup.

Local accepted reports are generated output outside Git:

- `.local/word-cmd-native-r260-storage-client-observe-tests/result.json`, SHA256
  `B2B902DDE8E58658017A3D835D6AFFE8AD409F2A23D4215C61FBE22327DE5191`.
  Matched image 26,686,976 bytes, SHA256
  `9D3DFECF4CC11F6812D705D1A32E47A0C0A38D886A6896DF08C454F49342D04E`.
- `.local/word-cmd-native-r261-registry200-proof-observe-tests/result.json`, SHA256
  `504900AC5A32B011BCF79413C3EFB1A6EE7FE3D5BA00DF9F9706C97F0323EF27`.
- `.local/word-cmd-native-r262-registry200-proof-observe-tests/result.json`, SHA256
  `2A0D38C03348C9F9AD7C4F3AEF50D6622D72E5DBE2F904572C94806BB2D78CCF`.
  Both registry runs used image 12,367,360 bytes, SHA256
  `295B7C49A2CAC339E11BFD43E89563B44DE7EE85D54135FDFABA8B4DBD9C35F5`.

The first client native capture r255 correctly rejected a supplied Done witness
with a nonzero salt reserved for Parked progress. The public test witness was
corrected to the original zero-Done-salt rule; no producer/verifier equation,
proof check or timeout was relaxed. Accepted r260 repeats the complete chain and
the new stale-start guards. Earlier compiler-only failures supplied no native
PASS and are not used as behavioral evidence.

Reproduce using the stated native environment and an isolated target directory:

```powershell
cargo test --release --locked -p storage-client --features word-query --lib word_query:: -- --nocapture --test-threads=1
cargo test --release --locked -p registry200-proof --features owner-read --lib registry_progress::word::statement:: -- --test-threads=1
cargo test --release --locked -p registry200-proof --features owner-read --lib registry_progress::word::read::tests:: -- --test-threads=1
cargo clippy --release --locked -p storage-client --features word-query --all-targets -- -D warnings
cargo clippy --release --locked -p storage-client --all-features --all-targets -- -D warnings
cargo clippy --release --locked -p registry200-proof --features owner-read --all-targets -- -D warnings
cargo test --release --locked -p storage-client --features word-query --doc word_query -- --test-threads=1
cargo test --release --locked -p registry200-proof --features owner-read --doc registry_progress::word -- --test-threads=1
cargo check --release --locked -p storage-client --all-targets
cargo test --release --locked -p repository-contracts --test requirements_sync
```
