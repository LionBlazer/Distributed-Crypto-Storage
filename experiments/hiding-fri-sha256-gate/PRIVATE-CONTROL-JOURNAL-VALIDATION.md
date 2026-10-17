# Private-control Journal validation

The [experimental adapter](src/opening/private_journal/README.md) links genuine
CanonicalIndex Source + RegistryBootstrap or cold LockingSelection SDK proofs to
the actual owner-authorized version Journal. First admission and durable reopen
verify the complete original proof pairs. An exact already accepted duplicate
uses the existing idempotent fast path. Public test keys, controllers and records
are explicitly PUBLIC NONSECRET; the verifier owns no owner signing key.

The adapter is an owner-local witness experiment. It adds no live SQL acceptance,
delegated controller possession, private Begin/End/abort, MVCC, writer fence,
atomic encrypted data installation, agreed global freshness or partition-safe
finality. Actual work and confirmation on a locally validated branch can still
reorganize. Peer-only FHE SQL remains required by [REQUIREMENTS.md](../../REQUIREMENTS.md).

## Checked transition contract

Application identity fixes the network/database, Source/C_key, two shard IDs and
the unchanged three proof profiles before genesis. Genesis installs Pending
control heads, never a precomputed Active root. After the actual genesis exists,
Bootstrap derives its acyclic query intent and enrollment; owner authorization
binds the complete request, parent, all updates and proof bytes. Acquire keeps the
original CompiledLockPlan request formula and authorizes an opaque private plan.
It does not publicly prove SQL parsing or possession of a controller signing key.

The callback takes Source, C_old, genesis and parent from actual Journal state,
accepts exactly one changed control update and preserves Source. Stable canonical
112-byte control components contain no query/nonce/parent. Genuine Blocked and
NOWAIT preserve C_old and therefore have no appendable CAS update or invented
grant. Genuine LIMIT 0 can advance counters without returning rows. The fixed
2716-byte request has canonical tags/reserved fields/Gold roots and encrypted
packets. The unchanged hard complete Body limit checks overflow-safe
`117 + request_bytes + 456*update_count + proof_bytes <= 32 MiB`.

No State replay, MetadataVerifier, StateLease, cache receipt, simulated proof or
fixture-derived answer replaces either cryptographic verification. The fixture
encrypts Source only once, reusing the same heads, encrypted packets and C_key
through all three transitions; each request rebinds C_open.

## Native validation scope

Rust 1.99.0 MSVC, CPU-native release code, two Cargo jobs and two Rayon threads
were used offline. Strict Clippy with `-D warnings`, explicit formatting,
test/normal CLI builds and actual binary discovery passed. Discovery found 275
leaf tests: all 263 old names and twelve new unignored names. This stage executed
27 leaf bodies (all twelve new plus fifteen affected old controls), not all 275.
All eighteen original version-journal contract cases and the actual requirements
mirror/architecture test files also passed. Those two files were compiled directly
with rustc against the pinned release dependencies; the GUI suite was not built.

All 26 prior numeric CLI calls preserved their complete ordered JSON arrays.
The new `security private-control-journal` call reports exactly two unchanged
profiles: Bootstrap (4996 constraints, degree 3) and Lock (7092, degree 4). It
creates no trace, proof or Journal append. The existing per-proof unique/list
floors reach 128 bits; this is not a composed-security theorem.

| Executed leaf group | Passed | Process ms | Observed OS peak working set B |
| --- | ---: | ---: | ---: |
| `private-journal-owning` | 12 | 102388.5776 | 1091416064 |
| `wire-frame-boundary` | 2 | 110.4595 | 2056192 |
| `bootstrap-wire-boundary` | 4 | 96792.4365 | 1071419392 |
| `locking-wire-boundary` | 4 | 100653.7735 | 1057529856 |
| `owning-control-0` | 1 | 15278.6147 | 845508608 |
| `owning-control-1` | 1 | 14880.0706 | 844054528 |
| `owning-control-2` | 1 | 4928.8156 | 819838976 |
| `owning-control-3` | 1 | 9443.6370 | 844111872 |
| `owning-control-4` | 1 | 9055.6702 | 844972032 |

New cases cover real owner-signed Bootstrap/Acquire/conflicting SKIP, unchanged
encrypted Source, unauthorized tampering before callback, re-signed foreign
request/opening/plan/enrollment/context/source/output, second Bootstrap/unproved
Active genesis, genuine Blocked/NOWAIT, LIMIT 0, canonical request/full-Body
boundaries and overflow, data/extra updates, stale CAS, durable reopen/lost ACK
and a valid detached fork with reparenting rejection/Reorganized freshness.
The shared test cache holds only canonical public block/body bytes and context;
it is not an acceptance cache and no private witness or proof object is retained.

## One genuine CLI observation

`prove private-control-journal` generated, encoded, signed and imported three
real proof-pair Bodies, then imported an Empty confirmation under an explicitly
easy public work fixture. All three passed actual Journal admission.

| Complete Body | Bytes |
| --- | ---: |
| Bootstrap | 21728127 |
| Acquire | 23139263 |
| Conflicting SKIP | 23133695 |

The internal `outer_lineage_ms` was 19495.8845 ms. It includes
proof production, wire encoding, signatures, mining, Journal verification and
confirmation; source/owner fixture setup is outside that timer. The full CLI
process lasted 19585.4989 ms with 195 samples; observed
OS peak working set was 958013440 B, sampled
working set 937488384 B and private bytes
933482496 B. JSON explicitly reports `owner_authorized=true`,
`live_sql_grant=false`, `finality=false`.

Across the CLI, leaf and Journal contract run processes, the observer recorded
3711 CSV samples from their owned PIDs.
The largest observed OS peak was 1091416064 B.
Sampling nominally occurs every 100 ms; the largest recorded interval was
122.6240 ms. No sampled 1792 MiB soft fuse or 1200-second per-child
cutoff fired. These observations are not hard RAM bounds, whole-peer process
measurements or application SQL latency guarantees. No 500 ms target is imposed.

## Preserved attempts and dependencies

The immutable source bundle is `5365C25D`, its narrow eleven-path patch
`1DBAC61B`; two independent full source reviews passed. Published wire and
Bootstrap README prefixes were preserved during integration; historical donor
documentation was not applied. R1 stopped before proofs/tests on two Request slice-index E0271 errors.
R2 explicitly typed the index as usize and stopped on strict Clippy's contains
suggestion plus three unused Gold-array results. R3 uses contains and explicit
`let _ = ...?`; all canonical validation/rejection paths remain. Independent
source review confirmed these corrections; old AIRs, profiles and tests are exact.
Failed receipts and targets remain preserved.

After native validation, two compressed fixture/test closures were expanded for
readability without changing literals or code. A separately compiled checker
using the exact existing proc_macro2 and syn2 libraries from the validated build
confirmed identical recursive token kinds/groups/identifiers/literals and equal
parsed Rust ASTs, including operator parsing. Candidate and Root rustfmt checks
passed. The R3 native snapshot remains the executed input; final formatting is
separately pinned by the readability receipt. No semantic change required repeating
cryptographic tests. All old 263 test bodies remain untouched.

Offline leaf resolution added only direct version-journal and ed25519-dalek edges;
all 213 package/version/source/checksum nodes and the Root workspace lock stayed
unchanged. R3 protected 963 unaffected tracked files, all 876 earlier EXE/DLL
artifacts, 904 SDK anchors and five tool binaries. No generated proof, key, database,
CSV, binary or raw execution log is committed.

| Local receipt | SHA-256 |
| --- | --- |
| `R1 source` | `5222B0BBBEB2F5A06A1DA1182E3CF2E1C3AA2047944DEE29782EC5ADAD87AC8B` |
| `R1 failed compile` | `48A06D5C509BFC3F4BFFEA414DE5D864B03310374CA1F693E20B0796C06ACE43` |
| `R2 source` | `5813EA9A42724EB0A8A804D958CBE5EFC0E6C7827EF4FFC6C408945D0F685F2A` |
| `R2 failed compile` | `BCCD0706EFC8070E9FECCCA81BF27281E11B0E8D16A51DA42762C67A80387E8F` |
| `R3 source` | `60D140FF7B670145C218BF08A376BE62CF845A7EF0F035E4846C8772A6C74C5F` |
| `compile` | `D11F7073E41C8A70875E9AEE49BDCF7F057BD0D45D29906AD9EF0C68C4A311F3` |
| `numeric` | `E10AF9BD72B74DBB8486A955DCD89266ED761DFA714645138F52C156AF9D4220` |
| `smoke` | `79997A82D239C6F8083D6C912A8D97E3481F8A3F15725A80F1EC703EF64A5F92` |
| `tests` | `FEEC96EF3512C94C5B0B3307B9A48812117DA80F3E903F061ABB21C7EC098C2C` |
| `journal-core` | `7D663533C93AFF86D597BCF9C1021C056F7F25F97699ADBBB4D108D08A104328` |
| `contracts` | `853E3B7F6E83B52E676AC1AE7EFBF5CD72561C6B0088A97A08998A3D8B4B673E` |
| `all gates` | `F8B215EAC1B4E8C0132C1A9FD6972329028636B907512630B17B20A52AC2673D` |
| `readability token/AST check` | `3DC946B4533AE0B6CD74669EBE431CE6EB99ED04AAC1BE4A5D7533AE8D054218` |

## Reproduction

```sh
cargo clippy --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --all-targets -- -D warnings
cargo run --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- security private-control-journal
cargo run --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove private-control-journal
cargo test --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::private_journal::tests:: -- --test-threads=1
cargo test --release --locked --offline -p version-journal --test journal_contract -- --test-threads=1
```
