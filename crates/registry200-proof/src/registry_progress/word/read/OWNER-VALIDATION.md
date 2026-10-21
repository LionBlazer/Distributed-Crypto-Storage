# Originating-owner validation

The optional owner-private composition was executed on the working tree based on
`3aa5876575c8fb7d9e08236171fb45d96f7afb24`. The final owning run checks both the
unchanged public fused-Query path and two new genuine originating-owner queries.
These are local mathematical components, without real network SQL or locks.

## Executed scope

The original generated/sealed/destroyed/restored opaque owner, actual Source
certificate, Role3 version encoding and actual dense DATA theorem are retained.
The new receiver uses the sealed originating statement premise and actual
Word/product verification. It never creates a public Query-proof result. Each
new call changes the mask, call, invocation and complete statement/root. The
full 4096 independent ring oracle runs only after checked completion.

Both new calls reject damaged native Word arguments, the previous call's Word
and product evidence, changed certificate/output, DATA nonce, original statement,
Control, missing frames and oversize Ct3. A separate adversarial case keeps the
same Source and Stmt96 root while changing NextRoot: the full original Word
context pin still rejects it. Honest receiving is repeated after those failures;
setup retains no verification verdict. Existing full public Source/Role3/DATA/
Word/Query/product and complete immutable-version mismatch cases still pass.

Core tests additionally check all canonical statement/mask/header/padding pins,
foreign-owner rejection, and a deliberately repaired well-formed encryption of
another mask. Its correct public metadata is insufficient: the actual private
input equations reject it with Arithmetic. Genuine product checking/completion
and the original custody, entropy and private-equation failure cases also pass.

## Final local measurement

Windows/MSVC, Rust 1.99.0, release opt-level 3, `-C target-cpu=native`, locked/offline,
Cargo jobs 2 and Rayon threads 2. No other build/test ran during either capture.
The held process handle pins image and creation identity, samples memory every
20ms, and enforces the existing 120s/1792MiB process fuses. Source and executable
hashes are checked before and after. Both captures exited 0, with no faults,
surviving children or cleanup actions.

| Per-call work, milliseconds | Query 2 | Query 3 |
| --- | ---: | ---: |
| Actual private input equations and statement binding | 8.349 | 10.919 |
| Actual FHE product plus certificate production | 35.892 | 45.713 |
| Fresh Word proof production, with role-public setup retained | 245.645 | 242.128 |
| Fresh independent Word/product receiving and complete DATA equality | 125.639 | 120.436 |
| Original-pair client completion/decryption | 0.976 | 0.924 |
| Complete measured local call, including fixture/statement/origination overhead | **418.536** | **422.672** |
| Word + actual Ct3 + product certificate bytes | 4,769,052 | 4,770,492 |

Independent role-only public Prover and Verifier initialization together cost
**251.645 ms**, separately from those calls. The immutable DATA installation is
also outside the per-query intervals. Neither cost disappeared; their lifetime
is explicit. The same run's ordinary public retained-DATA read still requires
its genuine fused Query proof and took 2874.653 ms, including 925.065 ms independent
receiving setup overlapped with proof production. Different verifier premises
and setup lifetimes prevent treating these numbers as a general public-proof
speedup. The earlier r202 run measured 395.335/431.212 ms with 299.362 ms role setup;
r205 repeats after adding the same-statement/different-NextRoot rejection.

The whole upper test process, including original public paths, Source proving,
hostile cases and both new calls, lived 31045.9111 ms with 44.359375 CPU-seconds,
1522 memory samples, OS peak working set 561,664,000 bytes and peak private bytes
555,728,896. This is NOT an isolated owner-call or whole production-peer peak.
Core's twelve Gold cases passed in 4.87 s; its process peak was 501,714,944 bytes.

## Reproduction and evidence pins

Use the stated native environment and an isolated Cargo target directory:

```powershell
cargo test --release --offline --locked -p bfv-query-core --features gold-owner --lib gold:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-proof --features owner-read --lib registry_progress::word::read::tests:: -- --nocapture --test-threads=1
cargo clippy --release --offline --locked -p bfv-query-core --features gold-owner --all-targets -- -D warnings
cargo clippy --release --offline --locked -p registry200-proof --features owner-read --all-targets -- -D warnings
cargo test --release --offline --locked -p bfv-query-core --features gold-owner --doc gold:: -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof --features owner-read --doc registry_progress::word -- --test-threads=1
cargo check --release --offline --locked -p registry200-proof --all-targets
cargo test --release --locked -p repository-contracts --test requirements_sync
```

All passed: twelve core runtime cases, one full owning read scenario, seventeen
compile-fail examples, both strict Clippy gates, normal default compilation and
the dependency-free requirements mirror guard. Runtime-case counts exclude the
repeat captures. Generated artifacts remain local, outside Git.

- Core accepted report `.local/gold-owner-native-r203-bfv-query-core-observe-tests/result.json`:
  SHA256 `7F50396974FBC67DF34EAA1A6A0A243B5E5AF2D7E541DEED314108559731E1BA`.
  Matched release image 5,761,536 bytes, SHA256
  `9C7354941A27E3B41642A7D6DC3A04162EE95B1AB65D102402B595A0EA3FFF14`.
- Upper accepted report `.local/word-cmd-native-r205-registry200-proof-observe-tests/result.json`:
  SHA256 `BDA80328EACB555634A04641EAF26140D74EA2BCD81D13F14B745C49B43DBCBE`.
  Matched release image 12,322,816 bytes, SHA256
  `835AA4E62F0C2A87A9335AD6BD497E4F86669288881230FE99539046725F69FD`.
- Successful command records: build200/204, Clippy206/207, docs208/209,
  default-check210 and requirements211 under `.local/word-cmd-native-r*`.
- The first core capture r200 executed all twelve cases successfully but its
  observer envelope rejected a missing `scope` field in the capture contract.
  No accepted measurement is taken from that envelope; r203 reran successfully
  with the explicit non-SQL/non-security scope. No test assertion was weakened.

## Remaining full-query obligations

The 500ms complete SQL target is still unachieved. These calls omit SQL compilation,
real peer transport, authenticated prior root/rights, current agreed version,
weighted decentralized lock finality, failure/recovery, and FOR UPDATE/SKIP LOCKED
runtime integration. Approximately 4.77MB of per-call evidence/output remains a
material transport cost. The unchanged public voter path cannot use this private
owner premise as a fused Query proof. Predicate admission stays closed. Composed
BFV/PRG/ring/security, product Fiat–Shamir and noise assumptions remain explicitly
unassessed; see the [composition contract](OWNER.md). No production capability or
full-query deadline follows from this measured component.
