# Public Poly1305 primitive validation

On 2026-10-16 the standalone raw and separately padded Poly1305 candidate passed
release build, test compilation without execution, strict all-target Clippy,
seven security-only analyses, five observed public-fixture proof/verify processes
and all 33 serial tests. Fourteen tests exercise the new Poly1305 relation; the
nineteen SHA/ChaCha/shared-backend tests remain. There were no ignored tests.

This is a PUBLIC NONSECRET primitive gate, limited to three 16-byte blocks,
48 original bytes and three segment descriptors, including empty descriptors.
It does not establish private-witness secrecy/ZK composition, CSTORE opening or
AEAD composition, BFV input formation, SQL completeness, private locks, finality,
production cryptographic certification, 500-ms SQL, or a process RAM limit.
The [module contract](src/poly1305/README.md) specifies the exact relation.
Historical [SHA-only validation](VALIDATION.md),
[SHA/ChaCha validation](PRIMITIVES-VALIDATION.md) and
[unimplemented source relation](SOURCE-RELATION.md) remain unchanged.

## Reproduction and exact revision

All compilation, security analyses and observed executions recorded the related
parent `128a7f1d415d3c97d72544ca526727d55fc2814d`, with the uncommitted reviewed R6
source identified below. The build parent alone does not identify these changes.
The R6 manifest contains eleven Rust source files, one standalone Cargo manifest
and two README files, plus thirteen unchanged nonlock controls. The resolved
standalone lock is pinned separately. This report and updates to the two READMEs
were prepared only after the evidence audit; no compiled Rust, Cargo manifest or
lock bytes changed and no rebuild followed those documentation edits. The
publication manifest records that explicit documentation-only delta.

`MAIN` denotes `E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage`.
The separate target was `MAIN/.local/target-hiding-poly1305-primitives-r6`.
Host/toolchain: Windows x86_64 MSVC, Rust `1.99.0 (b940084d7 2026-09-28)`,
`RUSTFLAGS=-C target-cpu=native`, Cargo jobs 2 and Rayon threads 2. The driver
removed build-target, encoded-flags, compiler-wrapper and inherited profile/hook
overrides; `RUSTC` and `RUSTDOC` used the exact Rust 1.99 toolchain executables.

| Frozen identity | SHA-256 |
| --- | --- |
| R6 source manifest, fourteen task files | `B0EFA60EE3D97E6A69A13EC40D0AA52835674A6E68EE471C07943439A8415557` |
| Resolved standalone Cargo.lock | `6593BDC042EDD3B47935BB058AEF1EDE4AD639C5B4C568F28ED8ACA9937E9281` |
| CLI `release/hiding-fri-source-primitives.exe` | `F21BC3E37A5BEDF611F12022D3DFF53434F690FBC69B99CC5B9B2BEF62CBDD57` |
| Tests `release/deps/hiding_fri_source_primitives-e8bf6045d36c4aef.exe` | `0545933F578ABB675C6384708310A9798DB3BEC1B9D6F43B6F0BAD7965D42C13` |
| R6 phased driver | `B0E72A10023C41F2612E469A2D8D4D08A0C381CFCC58F7EA1561CF63454F4190` |
| External observer | `65D6BF3FA6549EAD9FE6B3C20F66AF55D00C01D3CD4334E0B30CDF411A4AB2AB` |
| Successful Compile metadata | `26D0773041310E41F5E81E87775C64AFDCB7EF6E51746FC5DC6BE41B4901876A` |
| Successful Security metadata | `AB8124FF872BD80EA6A4D86AC0B5E32019A3F6A3A4D437FB340A33C3F31C7B9B` |
| Independent six-observation audit | `23BF6C1B7FE5E1182096A976E1CD86D7CF920533AF4332352CBD9141D711E83B` |

Exact compiled Rust and standalone manifest hashes:

| Path relative to this experiment | SHA-256 |
| --- | --- |
| `Cargo.toml` | `9C414811719B42EDF4E3E310B3C4DF51AD8FC6061900A0F1CE344B1C562A5047` |
| `src/backend.rs` | `6AC4ED87E4E4541EEA1BA7DB89DF2D5EF5E8362B4F1E760EEE77CC53FB48600C` |
| `src/chacha/air.rs` | `B9E38CC123EB8D0CE434621B08AE7B750FD306EE8595F70DD1AE0FDCF8FDC993` |
| `src/chacha/statement.rs` | `6DCDD4813632B746807018D7313A0C3B99E8CAA84B2E172E84E3340601576437` |
| `src/chacha/tests.rs` | `BE3B6A1A5D84A7C71B94535B954D8FEE5E7E815B10EF729F187C33A56D3D71DD` |
| `src/main.rs` | `793D5C9A23CF2F8944C7F105892CED4B103A7EA7A00D55C0E05420F3AB55BA1F` |
| `src/primitive.rs` | `DF0A7AD7DAA9DB68673ACE6411D95E3407D026EDA03CF420E8CAB32F1A855415` |
| `src/poly1305/mod.rs` | `CFC34EDDB4C153FCBC9A9D2649F5BBF6177928D66E4C47A43AD198A7C7AEF9D0` |
| `src/poly1305/air.rs` | `1F6B98A2D80EDC594788B7F0B4171D7318C1EB1BE6ECB2B89A565210CEBD0CBC` |
| `src/poly1305/statement.rs` | `458DF5EBC7168DEF7A602458EBF4CFD596E99A9F1847EDB1E8916CDAA5112034` |
| `src/poly1305/tests.rs` | `844DDFC00AB0626E7827B2DA00DDA567C2440D3204FBB3BBC0D52C1255A96C49` |
| `src/tests.rs` | `ED0778265A95E9E37C5FB37E46C7331ACBF32125CD14193B4D2FAF9C52DB59B9` |

The standalone lock contains 76 packages: all 71 previous registry package
records (including versions, checksums and dependency lists) remain exact,
with four root-pinned additions: `opaque-debug 0.3.1`, `poly1305 0.8.0`,
`subtle 2.6.1`, `universal-hash 0.5.1`. Only the local package gained the two
oracle dependencies. Poly1305's explicitly requested `zeroize` feature uses the
already present `zeroize 1.9.1`; that active dependency edge was checked rather
than copied from a root manifest with different enabled features. All nineteen
P3 packages remain at 0.8.0, VCS `a21e3ed42905040ad49c519e402f018381c12d0c`.
The independent oracle pin is RustCrypto Poly1305 0.8.0, VCS
`47a72962e8898fc70ab79d4ab40949efe61a23d2`, with UniversalHash 0.5.1.

## Separated phases and preserved failures

One offline Lock invocation generated and audited the isolated lock, then
stopped. Its original R4 source/driver receipt was preserved across two reviewed
source-only repairs; the dependency graph was not regenerated. The old lock is
retained with raw hash
`3AFA0B51AA53E8B3CDEB4E27A05B35EC42A71C5C04A26E3468D3A5558DA7086A`
and canonical-LF hash
`34AF9D761D4D8BD52D7FEFE47303AE7E4EDD4D8542876D492E13424021689CBC`.

The first Compile stopped at three generic `PublicVar` arithmetic type errors.
Only three explicit `AB::Expr` conversions were then changed. The R5 Compile
passed release build and test `--no-run`, then stopped at Clippy's large enum
variant lint. Only the private Poly1305 AIR enum payload and its construction
were boxed for R6. No lint allowance, equation, profile, geometry, RNG, PCS or
security formula changed in either repair. Both failed logs/targets and R5's
first linked artifacts remain preserved; they were not used for validation.
R3 had separately corrected the unexecuted source assumption that `Some(3)`
overrides the SDK's inferred degree; R4 bound each private Backend to its exact
public statement and retained fresh-backend SDK negative-replay coverage.

The R6 Compile then returned zero for all three commands:

```powershell
cargo build --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
cargo test --release --locked --offline --no-run --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
cargo clippy --release --locked --offline --all-targets --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- -D warnings
```

Security was a separate invocation with exactly these seven CLI analyses:

```powershell
& $binary security sha256
& $binary security hchacha20
& $binary security chacha20
& $binary security poly1305-raw
& $binary security poly1305-padded
& $binary security poly1305-raw empty
& $binary security poly1305-padded empty
```

Each produced one actual JSON report and exit zero. No Security invocation
created a witness trace, proof or test process. After independent numerical
review, the observer ran `prove <kind>` once for each of the five fixture modes,
then the exact test executable with `--test-threads=1 --nocapture`. Empty is a
security-only selector; `prove ... empty` is rejected before trace creation.
There were no observation reruns or excluded CSV rows.

## Actual analytical reports

All reports used 512 rows, post-ZK degree bits 10, 192 queries, five random
codewords, Goldilocks/degree-five extension and the unchanged hiding backend.
Both unique- and list-decoding bounds were finite and exactly 128 for every row
of the table below. These are the pinned SDK's analytical model, not empirical
ZK evidence or production certification.

| Actual statement case | Width | Opening points | Periodic columns | Constraints | Inferred degree | Quotient chunks | Batched functions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SHA-256 fixture | 7,728 | 1 | 0 | 8,136 | 3 | 8 | 7,823 |
| HChaCha20 fixture | 788 | 2 | 8 | 1,492 | 3 | 8 | 1,676 |
| ChaCha20 fixture | 788 | 2 | 8 | 1,492 | 3 | 8 | 1,676 |
| Poly1305 raw fixture | 813 | 2 | 3 | 1,361 | 3 | 8 | 1,726 |
| Poly1305 padded fixture | 813 | 2 | 3 | 1,361 | 3 | 8 | 1,726 |
| Poly1305 raw empty | 813 | 2 | 3 | 1,361 | 2 | 8 | 1,726 |
| Poly1305 padded empty | 813 | 2 | 3 | 1,361 | 2 | 8 | 1,726 |

Empty Poly1305 has actual inferred degree two; the declared degree-three bound
still fixes eight committed hiding quotient chunks. Constant-zero assertions
remain counted. Although only 130 Poly1305 state columns use next-row access,
SDK 0.8 opens both complete 813-column rows. Accounting therefore uses two
full-width openings (`max_combo=2`), satisfying the masking budget
`512 >= 2*(192+5*2)=404`, rather than counting only the state columns.

| Separate array payload | SHA-256 bytes | ChaCha bytes | Poly1305 bytes |
| --- | ---: | ---: | ---: |
| Original trace | 31,653,888 | 3,227,648 | 3,330,048 |
| Masked trace | 63,348,736 | 6,496,256 | 6,701,056 |
| Main LDE | 506,789,888 | 51,970,048 | 53,608,448 |

These are individual array payloads, not an additive process peak. Quotient work,
DFT scratch, trees, salts, copies, proof, stacks and allocator overhead are not
included. The complete profile and arithmetic bounds are in the module README.

## Genuine proofs and observable tests

Each following value is one public-fixture process under an external observer,
not a latency benchmark or repeated statistical estimate. The CLI constructed a
genuine proof from its trace, invoked the SDK verifier, and printed the verified
stage only on success. Every process exited zero with no stderr output.

| Public fixture | Proving ms | Verification ms |
| --- | ---: | ---: |
| Poly1305 raw | 155.0344 | 41.4993 |
| Poly1305 separately padded | 153.3013 | 40.0853 |
| HChaCha20 | 151.8505 | 39.8355 |
| ChaCha20 | 154.8632 | 41.0133 |
| SHA-256 | 1,292.7856 | 266.8808 |

The exact 33 named tests passed, zero ignored, in the test harness's reported
21.06 seconds. Ten SHA/shared tests and nine ChaCha tests remained; fourteen
Poly1305 tests cover independent raw/padded RustCrypto oracles and RFC vectors,
empty/partial/full/three-block boundaries, independently bounded descriptors,
raw-key clamping and statement binding, canonical p-1/p/p+1 boundaries, low-128
little-endian final tags with real carries, and complete opening/security shapes.
Rebuilt malicious proofs cover noncanonical H=p with matching false tag/carries,
wrong fold factor or hibit/tail mode, omitted/reordered/extra blocks, forbidden
clamp contribution, inactive/nonboolean/negative carry witnesses and finalization.
Changed-statement replay tests use a fresh Backend as well as the bound wrapper,
so they retain actual SDK rejection coverage. The only stderr panic was the
expected caught single-opening guard in
`cloned_private_prover_data_cannot_reuse_the_single_opening_budget`; that test
and the entire process succeeded. These adversarial cases are not a full audit.

## External observation limits

The observer owned only its hidden child, requested 100-ms waits, checked sampled
RSS, private bytes and the OS peak-working-set counter against 1,792 MiB, and
used a ten-minute timeout plus finally kill/join. This is an external abort guard,
not an OS-enforced allocation limit. All six children exited zero without an
abort; all CSV rows were populated and retained.

| Observed process | Valid samples | Max sampled RSS bytes | Max sampled private bytes | Max sampled OS peak bytes | Actual inter-sample gaps ms |
| --- | ---: | ---: | ---: | ---: | --- |
| Poly1305 raw | 2 | 10,178,560 | 11,304,960 | 75,165,696 | 179.713 |
| Poly1305 padded | 1 | 61,329,408 | 57,163,776 | 61,444,096 | not measurable |
| HChaCha20 | 1 | 57,921,536 | 54,132,736 | 57,921,536 | not measurable |
| ChaCha20 | 1 | 58,241,024 | 54,935,552 | 58,241,024 | not measurable |
| SHA-256 | 9 | 525,742,080 | 522,649,600 | 539,140,096 | 164.528–192.653 |
| All serial tests | 108 | 551,313,408 | 547,315,712 | 551,714,816 | 162.422–324.736 |

A single sample gives no interval estimate; two raw samples are also sparse.
Observed OS peak values can exceed every sampled instantaneous RSS, but their
maximum sampled value is not the final lifetime peak. Startup, teardown, gaps
and transients can be missed and an abort can overshoot. No hard/full-process
RAM, private-witness memory handling, clean timing or SQL performance claim
follows from these observations.

## Retained local evidence

The following ignored directories under `MAIN/.local` retain raw commands,
receipts, logs, source/control copies, reports, CSV and archived artifacts:

- `hiding-poly1305-runs/20261016-135627-140-lock`
- `hiding-poly1305-runs/20261016-140353-155-compile` (first failed build)
- `hiding-poly1305-runs/20261016-140843-600-compile` (R5 failed Clippy)
- `hiding-poly1305-runs/20261016-141927-901-compile` (R6 success)
- `hiding-poly1305-runs/20261016-142224-467-security`
- `hiding-poly1305-observations/20261016-142719-049-prove-poly1305-raw`
- `hiding-poly1305-observations/20261016-142757-951-prove-poly1305-padded`
- `hiding-poly1305-observations/20261016-142758-415-prove-hchacha20`
- `hiding-poly1305-observations/20261016-142759-029-prove-chacha20`
- `hiding-poly1305-observations/20261016-142759-605-prove-sha256`
- `hiding-poly1305-observations/20261016-142801-716-tests-serial`

Each observation binds 65 original/archived input records, fourteen compiled-source
freeze entries, thirteen nonlock controls, the resolved lock, its exact observer,
and both original/archived executable identities. Independent audits checked the
complete six-run evidence join. Generated logs, binaries, keys and local database
contents are not committed. This gate imports or exports no Owner keys and is
not connected to production SQL acceptance.
