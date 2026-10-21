# Immutable-version DATA encoding validation

Executed on 2026-10-21 UTC. The new `VersionSourceAllOriginal` role establishes
a genuine StateCertificate-to-full-4096 DATA encoding relation. Its fixed tag 3
and profile are separate from the existing query-bound Source and mask roles.
This supplies the input encoding needed for future version-scoped ciphertext
admission; it does not yet prove that a DATA ciphertext encrypts that encoding.

`Expected::source_version` accepts the immutable `SourceVersionExpected`,
retaining both complete encrypted images, exact heads, AEAD key commitment,
derived version ID and independently retained C_state. A private enum seals the
prerequisite family. Producer and receiver both call the actual SourceVersion
verifier before the actual encoding backend. No caller verdict, callback,
profile conversion or serialized capability can replace either verification.

The shared AIR opens the real STATE-domain 680-field preimage and constrains
the same full DATA coefficients, scale, salt/context and final vector flush.
Old Source/mask producers retain self-verification. Only the new producer omits
redundant self-verification and returns explicitly UNVERIFIED `Evidence`;
receiving remains a fresh native check. There is no retained verification cache.

## Executed gates

Rust 1.99.0/MSVC, release optimization, `-C target-cpu=native`, two Cargo jobs
and two Rayon workers were used with the existing locked offline dependency
cache. Ambient `DCS_` controls were excluded. Root alone ran native commands;
independent source reviewers ran no native work.

```sh
cargo clippy --release --offline --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --offline --locked -p registry200-proof --lib two_lane_encoding::tests -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib two_lane_encoding::formation -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-proof --doc two_lane_encoding::wire::VerifiedEncoding -- --test-threads=1
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

Cargo first built the test image with JSON artifact output. Root then directly
ran that exact release image with the listed filters. Its source snapshot,
SHA256, release profile, held Windows process handle, creation identity and
terminal exit were checked. The unchanged 120-second/1792-MiB limits and 20 ms
sampling applied to both runtime gates. Neither process spawned a child, tripped
a fuse, required termination or reported a fault. Source and image hashes were
unchanged throughout. Memory readings cover the whole measured test process;
sampled private memory is distinguished from the OS peak working set.

| Gate | Passed | Process lifetime | CPU time | Sampled peak private bytes | OS peak working set bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Encoding roles, including four new version cases | 14 tests | 33,340.249 ms | 39.140625 s | 856,702,976 | 846,356,480 |
| Existing full Formation/product/client chain | 1 test | 18,926.584 ms | 26.031250 s | 1,378,361,344 | 1,372,024,832 |

The test runner reported 33.32 s and 18.91 s respectively. The two public
compile-fail examples passed in 0.17 s and prevent actual private-field
construction or cloning of `VerifiedEncoding`. Strict Clippy, formatting and
the requirements mirror check passed. Test compilation took 32.828 s; the
separate non-test/doc command took 29.485 s including its build. Build time is
not query latency. No network/recovery gate was repeated because this change
does not install a new application, protocol, WAL or SQL admission path.

## Genuine and hostile evidence

The four new cases reuse one explicitly public source fixture, one separately
produced genuine StateCertificate and one genuine new encoding child. The
original canonical Source proof is never relabeled. The cases cover:

- Fresh receiving of the actual State certificate and all-4096 encoding.
- Missing or foreign-family prerequisite bytes, wrong witness role and the
  unchanged old pair boundary.
- Changed C_state with the same version ID, changed BFV key epoch, and repaired
  child headers that cannot turn a version proof into the canonical family.
- A genuine State proof with a canonically repaired OOD corruption. Both new
  producer and receiver must return exactly
  `SourceVersionProof(BackendError::Verification)`, which excludes wrapper
  panic, shape, resource and proving failures.
- A changed final W coefficient with a repaired complete vector root. Its
  false trace reaches real release proving, produces a native argument and
  must fail receiving with exactly `Proof(BackendError::Verification)`.
- A final honest fresh receive after failures and four exact historical
  profile digests captured from the pre-change compiled library.

The ten original tests remain intact. The separate existing full chain also
passed: actual keyless SDK multiplication, full arithmetic certificate,
Source/children/cold Formation verification, all-4096 owner decryption and
the original/upper repaired-header and OOD rejection cases. Old pair and
Formation remain closed to the version role; no old codec/profile is cast.

| New version boundary | Observed time | Evidence bytes |
| --- | ---: | ---: |
| Genuine StateCertificate production | 1843.181 ms | 12,255,935 |
| New unverified encoding production, including fresh State verification | 1250.573 ms | 3,359,271 |
| Fresh State plus encoding receiving | 712.602 ms | both original frames |

These are single local observations, not percentiles or a full query benchmark.
The old full-chain regression independently measured fresh complete receiving
at 1736.649 ms and post-check client completion at 1.055 ms. Its whole fixture
with hostile checks took 18,913.273 ms. It is not a comparable speedup against
the new version-only encoding operation.

## Remaining obligations

The 500 ms complete-query requirement remains unmet. Even the observed cold
State-plus-encoding receive exceeded it. A future immutable DATA admission must
still prove actual same-secret ciphertext Formation and independently bind the
BFV key identity. AEAD C_key and BFV Cs are different commitments. An encoding
proof or version ID establishes neither authorized/current heads nor freshness.

No DCS Result/Session/Joint/WAL/SQL capability, hidden-query ciphertext linkage,
delegated rights, mutation or lock-finality path is admitted by this change.
Lattice/noise/concrete composition assessment remains separate. Existing
proofs, freshness policy, production timeouts and resource fuses were retained.

Ignored receipts use `.local/version-encoding-native-r1-` and
`.local/version-encoding-native-r2-`; the successful strict Clippy is revision 2.
They retain commands, source/image hashes, stdout/stderr, process counters and
memory CSVs. Generated outputs are not committed. Both runtime gates used the
same test-image SHA256:
`C81665A88B01D2E999F04C81A150E2AF17F36173DAC68EACCE729223B10C72E7`.
