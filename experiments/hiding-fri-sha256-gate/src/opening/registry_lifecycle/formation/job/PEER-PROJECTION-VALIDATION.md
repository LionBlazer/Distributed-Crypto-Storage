# Registry200 peer projection: executed validation

This records the narrow experiment implemented beside this report, on parent
`c7e4d3b4cb5d9485af6fe6ed1ad5862afdac1dec`. Fixtures are explicitly public and nonsecret.
The peer performs the real public-polynomial FHE projection; private predicate,
selection completeness and lock-witness construction are still owner-side.
No live SQL grant, writer fence, agreed finality or composed 128-bit security is established.

## Execution and verification

Windows x86-64, Rust 1.99.0 MSVC, release, locked/offline dependencies,
`RUSTFLAGS="-C target-cpu=native"`, two Cargo jobs and two Rayon threads.
The exact prepared source manifest SHA-256 was `DF6D8726D47FB38D821EA521BF4815F68257A501098C999DE4CBE70FF7A51950`.
The experiment has no new AIR, proof profile or production acceptance path.

```powershell
$env:RUSTUP_TOOLCHAIN = '1.99.0-x86_64-pc-windows-msvc'
$env:RUSTFLAGS = '-C target-cpu=native'
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
$env:CARGO_TARGET_DIR = Join-Path (Get-Location).Path '.local/target-registry200-projection-reproduction'
cargo build --release --offline --locked -p dcs-peer
cargo build --release --offline --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
$peerExecutable = (Resolve-Path "$env:CARGO_TARGET_DIR/release/dcs-peer.exe").Path
& "$env:CARGO_TARGET_DIR/release/hiding-fri-source-primitives.exe" prove registry200-peer-projection $peerExecutable
```

Offline reproduction requires the pinned dependencies to be cached locally.
The measured daemon reported the `avx512` proof backend; timings vary with hardware.

The actual CLI reported `verified_registry200_peer_projection`, a distinct owner
PID 467344 and daemon PID 466172, and actual request ID 4.
The daemon received public setup and encrypted input through the existing
Probe/Store/InstallSetup/Prove RPCs. Verification used the genuine
`PublicPolynomialProduct` proof, the complete independently pinned prerequisites
and both current Journal paths. The original Owner decrypted all 8192 slots;
the separate public oracle matched all of them. The daemon exited with code 0
through sole-stdin EOF. This was an independently running process, not the
test-only TLS server-thread fixture.

One run measured 122.977537 s from signed history/proof generation
through original-Owner decryption and EOF cleanup. Input generation/admission was
122.391564 s; the subsequent process startup,
TLS/Store, setup, actual FHE/proof, client verification/control reread, restore,
decrypt and EOF interval was 585.9828 ms.
The shorter interval is not whole SQL latency. No fixed latency threshold is claimed.

| Retained/input component | Bytes |
| --- | ---: |
| Public setup | 8,930,306 |
| Encoding | 38,078,113 |
| Key | 16,731,871 |
| Basis 0 | 15,953,571 |
| Basis 1 | 15,956,163 |
| Basis 2 | 15,956,835 |
| Basis 3 | 15,960,579 |
| Basis 4 | 15,961,443 |
| Formation | 21,291,515 |
| Encrypted response | 446,812 |

The ten logical proof components are checked and dropped before CLI network I/O;
they are not serialized into one oversized network frame. The existing 64 MiB
peer/transport, 32 MiB Body and 256 MiB Journal limits remain unchanged.

## Owning behavioral checks

Fresh compiled binaries executed 30 selected runtime tests: 19 affected Core
projection tests, all five new Registry200 job tests, the five existing certified
job tests and the existing actual state-lease job test. Six of these are new
tests (one Core completion example and five Registry200 examples). Core doctests
passed 15 examples; requirements synchronization and core dependency architecture
each passed their actual contract test. Default core check, formatting and strict
Core/experiment Clippy with all targets also passed.

The first contract attempt stopped before compilation: its archival integrity
guard hit Python `MemoryError` while reading a large protected file as one buffer.
That failed attempt is retained. A separate runner uses bounded streaming SHA-256
and executes the same contract sources and compiler flags, with only executable
output paths moved to `contracts-r2`. Both tests then passed. Product source,
previous artifacts and already successful gates were unchanged.

New checks cover full 8192-slot decryption with the original Owner; exact metadata,
anchor/setup and statement substitutions; absent prerequisite components; a genuine
foreign product proof; missing/tampered arithmetic evidence; corrupted physical
index custody; real LIMIT 0/all-skipped histories; Empty confirmations; actual
EndCommit, release and new-ID reacquisition; same-root sibling reorganization; and
durable reopen with real proof replay and an exact retry without a second CAS.
Delayed reply tests require the precise post-arithmetic Journal `StaleHead` error.
Production `LockingSelect` remains a hard rejection.

The legacy test bodies and mathematical AIR/profile files were not rewritten to
fit this adapter. All 2300 previously protected native
artifacts, 864 SDK source anchors and 2891
previous receipts retained their hashes. The 1068 parent files outside
the 28-path adapter/refactor scope remained byte-identical.

## Observed process memory

For the full CLI, owner maximum sampled working set was 1,473,486,848 B,
maximum private bytes 1,470,181,376 B and sampled OS peak working set
1,473,486,848 B. The independent daemon's corresponding
values were 80,875,520, 75,931,648 and
168,964,096 B; only 2 daemon samples were captured.
Maximum aligned concurrent working set was 1,473,486,848 B.
Its maximum actual sample gap was 446.6089 ms.

Across this CLI and the commands running the 30 selected tests, the observer captured
5152 samples across 11 process instances.
Maximum per-process sampled working set/private/OS peak values were
1,492,115,456/1,490,010,112/1,510,871,040 B;
maximum aligned command-level concurrent working set was
1,492,115,456 B and maximum actual gap
801.0941 ms.
The nominal 100 ms observer and 1792 MiB per-process soft fuse are observations,
not a hard RAM bound; short peaks and private allocations between samples can be missed.
Test fixtures retain extra public proof frames and real Journal Bodies in-process.

## Evidence pins and remaining work

Local ignored receipts are retained under `.local/registry200-peer-projection-validation-r1`.
They are not committed and are not a portable proof receipt or authority token.
The success receipt SHA-256 values are:

| Gate | SHA-256 |
| --- | --- |
| compile | `39D6342A3E24FCA24DB616347B27E221B94AC56FC6D828E774B24C995B69719B` |
| prove | `ED28CDFC529F2F7D98867ED6168AFAD2193973B2EA4D52CFD01DA9C0F519B6EF` |
| tests | `F395CC877369D597118040A0103D1A3E3C80F2F6D5DD0E22CF92DA79384E25B1` |
| docs | `9B7629ED663BC2672CF5C7124EB0BB1ED752366CB79F227F4C1F731DBBDA94BF` |
| contracts | `0B885519C917ADC657D356F11D3BE7EF712105BB671415D6C4F6FA919A940634` |

These observations establish only this exact adapter and its local current-state
guards. Peer-side private predicate/completeness, MVCC, wait wakeup, authorized
mutation fencing, independent network admission of Registry200 proofs, production
agreement/freshness, bounded remote component streaming, safe Journal compaction
and whole-composition security remain open. A local Journal cannot establish
global PostgreSQL lock exclusion during partitions. Future evaluation-key and
ciphertext multiplication proofs must retain their own distinct contracts.
