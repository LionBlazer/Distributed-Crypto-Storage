# CoreGold full Formation native validation

On 2026-10-21 the new reusable N4096/Q2 full Formation family passed genuine
release proving, independent cold receiving verification and hostile native
proof rejection. This advances the mathematical proof boundary only. It does
not enable a new SQL/network path or meet the 500ms complete-query requirement.

The owning upper fixture constructs real random SDK BFV ciphertexts, Source and
both encoding proofs; the final original Source/mask Witnesses are consumed into
Formation with their same full W4096 openings and salts. The relation proves all
four full 4096-coefficient negacyclic equations, shared S/E, exact bounds and full
Cw/Cs commitments. No selected database answer is calculated by this fixture.
The receiver freshly verifies Source/children and the actual native Formation
argument. It cannot accept a serialized success flag or a terminal numeral alone.

## Environment and commands

Windows/MSVC, Rust 1.99.0, release opt-level 3, debug assertions off,
`RUSTFLAGS=-C target-cpu=native`, Cargo jobs 2 and Rayon threads 2. Dependencies
were resolved offline from the existing lockfile; no existing package version,
checksum, workspace/default member or old proof profile changed. The new edges
use already pinned Plonky3 0.8, bounded Postcard and Rand versions. Public PP
uses Rand 0.10 under the explicit `rand-public-pp` alias; old SDK fixtures retain
Rand 0.9. Native work ran serially; no other agent ran native work.

```text
cargo clippy --release --offline --locked -p bfv-ciphertext-formation --all-targets -- -D warnings
cargo clippy --release --offline --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --offline --locked -p bfv-ciphertext-formation --lib --no-run --message-format=json
cargo test --release --offline --locked -p registry200-proof --lib --no-run --message-format=json
<lower-release-test-executable> gold:: --nocapture --test-threads=1
<upper-release-test-executable> two_lane_encoding::formation --nocapture --test-threads=1
<upper-release-test-executable> two_lane_encoding::tests::sdk_scaling_matches_independently_built_full_two_lane_plaintext_and_all_private_mask_patterns --exact --test-threads=1
cargo test --release --offline --locked -p bfv-ciphertext-formation --doc gold -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof --doc two_lane_encoding::formation -- --test-threads=1
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

Each crypto executable was selected from its actual successful Cargo artifact
record, pinned by bytes/SHA256, and observed through one held Windows process
handle. Source/binary hashes, process image/creation identity, terminal exit 0 and
absence of children were checked. Memory was sampled every 20ms with unchanged
120second and 1792MiB whole-process fuses. No fuse fired or cleanup termination
occurred. These limits apply to the complete test process, including setup.
Generated native evidence remains ignored under `.local/`; no secret key,
private data, generated proof, binary or process log is committed.

## Actual observations

| Owning gate | Result | Held process lifetime | Total CPU | Sampled peak private bytes | OS peak working-set bytes |
| --- | --- | --- | --- | --- | --- |
| Lower full relation, codec and false-wire tests |9 passed, 0 ignored|3406.231ms|6.1875s|1,329,807,360|1,339,424,768|
| Upper genuine full-chain proof and receiving attacks |1 passed, 0 ignored|16948.7335ms|23.78125s|1,370,087,424|1,365,590,016|

The lower run collected 167 memory samples; the upper 829. The original modeled
workspace estimate 1,819,017,216bytes is a preallocation policy, not an RSS
theorem. Actual observation under the external fuse remains required when this
boundary changes. Primary private integer inputs use Zeroizing; scoped MAIN/field
buffers overwrite on drop on a best-effort basis. No volatile wipe, constant-time
execution or whole-SDK/OS erasure guarantee is established.

The upper single honest argument was reused for receiving mutations:

| Actual upper phase | Elapsed | Evidence bytes |
| --- | --- | --- |
| Original Source proving |3662.427ms|19,304,319|
| Both encoding children proving |3141.798ms|5,721,998 combined|
| Consuming Formation proving, including its fresh prerequisite verification |4364.587ms|2,524,819|
| Successful independent fresh receiving, including fresh prerequisite verification |1800.541ms|same arguments|
| Whole owning scenario, including fixture and attacks |16930.239ms|one honest Formation argument|

These are disjoint measured phase intervals; they are not a full SQL request or
a comparable repeat of the old multi-process DCS query. Source/child producers
also perform their existing required prerequisite checks. The lower hostile
actual native `prove_batch` alone took 2631.780ms; it proves a deliberately false
wire relation and must not be reported as an honest complete query benchmark.
The two release executable hashes were respectively
`B0C7E54F8510E44F33CF69F2EEE3FA6D050636AF3A4E5B671BC3E49AC2ED8662`
and`44CFC6E1DD73F1C9F44BC87F4708B6E72008076A832DD53E95E3164442A4D503`.

## Meaningful rejection and API gates

- The lower false-wire case changes one real graph input and its two outputs
  while preserving its local equations, all final products, range banks and hash
  inputs. Release genuinely produces the argument. Direct native verification
  returns exact `Lookup(TerminalSumNonZero)`. Repairing only the terminal to 0
  then passes wire shape but fails the actual native opening/OOD check.
- The upper honest proof verifies against the independently retained complete
  request/Source/key/context/root expectation. Foreign role/q/nonce/Cw/header,
  invalid secret or full tail range, wrong Cs and trailing bytes reject. A genuine
  bounded proof with one changed OOD opening is canonically reencoded and must
  return exact `Formation(Verification)`. Both receiving panic catches return
  Backend, so panic cannot satisfy that assertion.
- Empty/oversized Formation frames reject before prerequisite crypto, tested
  with deliberately invalid prerequisite bytes. Canonical Gold and every EF
  coordinate reject representatives>=p. Fixed native geometry/topology and the
  unchanged resource/security prescreen are checked before private MAIN/PP.
- The existing independent full Source/mask SDK-scaling regression passes in
  16ms. It checks the shared compiler against separately constructed polynomials
  and all private mask patterns. Four compile-fail examples pass: actual private
  result construction and cloning are prohibited in both lower and upper APIs.
- Strict Clippy for both crates and the actual requirements mirror test pass.
  After native observation only documentation and the upper compile-fail examples
  changed; no proven math, parser, producer, verifier or fixture behavior changed.

## Remaining work and next optimization boundary

Successful fresh receiving alone is 3.6 times the 500ms complete-query budget.
FHE product/completeness proof, fresh agreed-head validation, actual network/QC,
durable lock transition and client result are outside this gate. No SQL result,
installed-key, authorization, freshness, cache lease or consensus capability is
minted by either mathematical result. N4096/Q2 lattice/noise assurance and composed
protocol security are still separate requirements.

Current Source and SourceAllOriginal encoding include request q. CoreGold PP
contains request-specific ciphertext coefficients and contexts; its public seed
also includes the complete Expected binding. It cannot be reused for another
request by shape. A faster design needs an explicit immutable version/data
admission contract, separate fresh hidden-query inputs and real product proof,
plus fixed structural preprocessing independent of those inputs. An existing
SourceVersion tag cannot be cast into this request-bound Source relation. A
previous mathematical result cannot replace fresh head, authorization or quorum
checks. Cold admission must be measured separately and still counted when the
complete operation requires it. No 500ms claim follows from amortization alone.
