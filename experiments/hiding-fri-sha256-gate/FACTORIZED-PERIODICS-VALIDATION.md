# Factorized public periodic source profile

The separate `factorized-packed-canonical-index-opening` experiment represents
the packed source's 512 public row selectors with 32 low-row columns of period 32
and 16 high-band columns of period 512. Selector r is
`low[r % 32] * high[r / 32]`. Exhaustive comparison covers every selector at every
original trace row. These are verifier-owned public constants, never witnesses.

The source table payload is 73,728 bytes instead of 2,097,152. The periodic LDE's
element payload at the existing 8192-row geometry is 3,145,728 instead of 33,554,432
bytes. These exact array counts exclude allocator overhead. Main trace, masked
trace and main LDE payloads remain 29,331,456, 58,703,872 and 469,630,976 bytes.
They are not measured process peaks or disk-storage expansion factors.

## Relation and security boundary

All packed ChaCha/Poly1305/Poseidon2, canonical-index, private AEAD-key, capture/reset,
identity and whole-source constraints are shared with the old evaluator. The
per-instance OnceLock retains only the public schedule. The original profiles,
State/VersionSelection and SelectedEncoding do not opt into the new basis.
The new Kind and profile bind its periods, declaration order and selector formula;
its C_open context differs from the old profile. This is no proof migration.

The low and high public polynomials have degrees 496 and 511 on the original
domain. Their product at an out-of-domain point has degree 1007 and must not be
replaced by the old one-hot polynomial. Therefore row equivalence alone is not
enough: actual SDK weighted inference and fresh genuine verification are gates.
The declared degree bound 5 is the existing quotient-sizing floor.

All fifteen trace-free SDK reports passed before new trace/proof allocation.
The old fourteen reports remained field-exact. New actual inference is degree
5 (old packed: 3), 16,133 constraints, 16 quotient chunks and 14,502 batched
functions. Both security-model reports are 128 bits. T512, masked degree bits 10,
W7161, PV691, q192, extension degree 5, random codewords 5, salt 4 and complete
two-point openings remain. The new periodic count is 48; no old profile changed.

This remains a nonaccepting fixed N4 source experiment over two encrypted pages
and explicitly PUBLIC NONSECRET fixture keys/plaintexts. Framework security
reports are conditional model analyses for the exact wrapper. They do not certify
the complete composition, production ZK/key custody, encrypted SQL semantics,
BFV ciphertext formation, private locks, finality or the 500 ms full-query target.

## Native verification and measurements

Rust/Cargo 1.99.0 MSVC, release, locked/offline, native CPU flags, two Cargo
jobs and two Rayon workers: release build, test compilation and strict
all-target Clippy all passed. The fresh isolated target preserves earlier
measured binaries. The frozen inputs comprise 13 task paths, 74 controls and
24 SDK anchors. The lockfile and dependencies are unchanged.

All six observed processes generated and genuinely verified their own proof.

| Profile | Proving ms, min / median / max | Verification ms, min / median / max | Outer ms, min / median / max |
| --- | --- | --- | --- |
| packed-canonical-index-opening | 1898.272 / 1912.499 / 1932.950 | 426.301 / 430.647 / 447.476 | 2817.763 / 2842.124 / 2897.399 |
| factorized-packed-canonical-index-opening | 1831.365 / 1897.091 / 1926.466 | 469.375 / 502.626 / 503.813 | 3010.077 / 3076.901 / 3171.405 |

The new profile did not accelerate the measured operation: its outer median
increased by 8.2606%, and its verification median increased by 16.7144%.
Proving medians were within 0.81%. No speedup or 500-ms achievement is claimed.
The existing profiles remain selected by their existing consumers.

| Profile | Sampled working set range B | Sampled private bytes range B | Largest sampled OS peak working set B |
| --- | --- | --- | --- |
| packed-canonical-index-opening | 553414656–553590784 | 549588992–549814272 | 554762240 |
| factorized-packed-canonical-index-opening | 499273728–499548160 | 496406528–499838976 | 522371072 |

There were 166 samples across the six processes (79 old, 87 new). Actual
within-process gaps span 99.2892–112.5905 ms. Sampled working-set maxima and
the OS-maintained peak counter are distinct observations. The lower memory
observations do not imply lower full-query latency.

The six comparison processes alternate old/new, new/old, old/new in the SAME new
binary. Each is cold and uses the same environment and two Rayon workers.
`proving_ms` includes private trace construction and genuine proving after backend
setup; `verification_ms` is genuine verification. The external interval also
includes fixture preparation, security analysis, backend setup and process
overhead. This compares source profiles only; unchanged composites are not a
factorized-query measurement. Three observations per profile do not establish a
tail-latency or production SLA.

The complete serial suite passed all 121 tests with no failures, ignored or
filtered tests in 696.41 s (observed outer interval 696489.235 ms).
It retained every prior 114 test and executed all seven new cases. The owned
process produced 6403 memory samples; actual gaps were
101.0192–125.4497 ms, mean 108.782899 ms.
Sampled working-set/private/OS-peak maxima were respectively
1004781568/1024544768/1004781568 B.
These full-suite peaks include historical profiles and cannot be attributed
solely to the new profile. The observer reported no abort and empty stderr.

The new cases exercise every row selector, actual security/geometry, complete
plaintext parity, independently verified genuine proofs under both profiles,
fresh cross-profile rejection and hostile rebuilt witnesses. Tampering includes
capture predecessors, resets/stale buffers, out-of-range key words, changed
polykey views, zero/duplicate IDs and forged identity bits. Previous tests remain.
An explicit selector-equivalence prerequisite runs before the observed proofs;
its intentional exact filter is separate from the full suite.

An owned-child observer records working set, private bytes and the OS peak working
set with actual sample intervals. The 1792 MiB observed-counter stop threshold is
a soft experimental guard; missed private-memory peaks remain possible. Scope is
one native process, not a network deployment or total host memory. Source, SDK,
lock and artifact hashes are checked around each run. No external proof kernels,
SDK modifications, security-parameter reduction or private witness cache is used.

## Provenance and reproduction

The original donor remains frozen. Its changes were contextually merged with the
later State/Version/SelectedEncoding work in a separate worktree; all current
branches and lock/dev-dependency changes were preserved. The one additional test
assertion verifies the old genuine proof under its own verifier before checking
cross-profile rejection. ROOT integration from 6dbc9f1 changed thirteen task
paths, with one declared disjoint PostgreSQL-document control transition and
23 control files differing only in line endings. No executable integration delta
was introduced.

Generated logs/CSV/PEs and fixture state remain ignored. Immutable local
evidence identifies this exact run; independent reproduction remains useful.

| Evidence | SHA-256 |
| --- | --- |
| .local\factorized-periodics-validation-r1\source.json | `BDDD069EDC6DA3A0B48343AD2634C18E7C2D1BFCF00F147ED232295D6D9FDFD2` |
| .local\factorized-periodics-validation-r1\compile-success.json | `2FE7E01C597476E05A0ECCE44E53AF6E65F445B8F1C658DFCE176EC529B88F46` |
| .local\factorized-periodics-validation-r1\numeric-success.json | `F0C04564355CA6362697055F2DD906A35651B7294916D3DB21534463B5E61638` |
| .local\factorized-periodics-observations\20261016-224334-371-SelectorGate\success.json | `E0E9123A33F829066F95DFD7044255D3A00514E633ED3D64373E9DD5D670A5B6` |
| .local\factorized-periodics-observations\20261016-224340-725-PairedProofs\success.json | `8338E1BD3BE5E2FB423B13F85E4751A231A6B51DFD1C928CD7942C75736FC5CB` |
| .local\factorized-periodics-observations\20261016-224935-935-FullSuite\success.json | `51A885FBA727E90C18F64D89786BB2F58E368EDD2B74A0498262CB3568DC4FD2` |
| hiding-fri-source-primitives.exe | `C9A9C3B99DA6A5B7021ABB21558A5FAD75A50E2388B8F82977EEC2B64B58335F` |
| hiding_fri_source_primitives-27bcc2b47206c364.exe | `DE4A2B50C50DF040143043A8F089B390B4E0891CDC60D02B6EBB93E52336F1BE` |
| R2 owned-process observer | `7B318BCBBAB68DBF9B731903C2E03F931BE2136B5B853EE3F751E6443A1EF55B` |

From the root with Rust 1.99 MSVC, `RUSTFLAGS=-C target-cpu=native`, two Cargo jobs,
two Rayon workers, the same locked/offline dependency cache and an isolated target:

```powershell
cargo build --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
cargo test --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --no-run
cargo clippy --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --all-targets -- -D warnings
```

The fifteen built-native CLI security cases are:

```text
security sha256
security hchacha20
security chacha20
security poly1305-raw
security poly1305-padded
security poly1305-raw empty
security poly1305-padded empty
security pair-opening
security canonical-index-opening
security selection-opening
security packed-canonical-index-opening
security state-certificate
security version-selection
security selected-encoding
security factorized-packed-canonical-index-opening
```

Then run `prove packed-canonical-index-opening` and
`prove factorized-packed-canonical-index-opening`. Run the built test binary with
`--test-threads=1`. The normal source module and
[previous validation](SELECTED-ENCODING-VALIDATION.md) retain their own scope.
