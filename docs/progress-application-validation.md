# Closed progress application validation

The separate `registry200_joint::progress` application composes the new private
Registry208/Statement96/Progress48/Result160 relations with actual FHE evidence.
Its local owning gate passed on 2026-10-20: five tests passed, zero failed or
ignored, including the explicitly selected heavy Predicate case. This establishes
a library composition, not a real peer/finality/SQL success or a current lock.

## Closed contracts

The independently installed Descriptor binds SourceSpec, source object, both
complete original setup hashes, full anchor and ALL33. Application/Genesis,
request, manifest and setup-claim codecs have distinct domains. Legacy Joint
profiles and APIs remain unchanged. Role caps are checked before blob I/O;
setup hashes precede SDK decode.

One concrete ProgressDepot shares the actual ProductStore/typed ledger. Its
fixed verifier checks actual Source and Bootstrap803, Source and Control815,
or full input16/output118 product replay plus Predicate896. It checks the exact
current transition and independent original OperationId before native work.
The Journal authenticates the owner-signed Header/Body. Its unpublished
PendingImport captures this call's actual mathematical result; argument-free
commit publishes only the checked operation. No caller-supplied verifier or
saved checked flag supplies acceptance. This path supplies no QC/finality receipt.

## Actual positive and rejection coverage

The heavy test restores the same genuine Owner/Anchor/Ready epoch and ALL33,
including CsHat, from bounded encrypted public-fixture records. It imports
genuine Bootstrap803 and Begin815 under the new Genesis. It then creates a fresh
Source context, full Source and private-mask Encodings, ten Basis proofs and two
Formation proofs. The SDK encrypts all four original rows and the whole private
mask and performs actual ciphertext multiplication/relinearization.

The real product Prover emits all 118 records. The shared RecordingVerifier
checks every actual prerequisite and record, END and local Cursor EOF, then
publishes the catalog. The closed application freshly replays that catalog and
the actual Predicate896 proof. Only after this verification and exact import
does the owner open Result160 and decrypt the real encrypted response. Proved
selection flags select row two after OFFSET one/LIMIT one; the client performs
no second WHERE or window evaluation. All four decrypted tuples are asserted.

The other cases cover complete descriptor/setup pins, distinct legacy domains,
canonical role extents, a single shared retained charge/store lock and strict
store reopen. A genuine Control child with a hash-valid substituted non-proof
Source is rejected without Journal advancement. Wrong independent OperationId
rejects before another full replay, preserving Journal and quota. A corrupted
genuine Predicate child is rejected at the actual Core proof boundary. Public
non-proof bytes occur only in explicitly negative cases.

## Native observations

The group used release/offline/locked Rust 1.99 MSVC, host-native codegen, two
Cargo jobs and two requested Rayon threads. The existing 1792 MiB per-process
soft fuse and 1800-second whole-command budget were preserved; neither fired.
The group body took 629.02 seconds; the whole command took 644.370 seconds,
including its 15.16-second rebuild. Two privacy compile-fail examples passed in
1.16 seconds in tests, 2.602 seconds whole. Strict all-target Clippy for both
affected packages passed in 2.595 seconds.

| Heavy-case interval | Observed |
| --- | ---: |
| Restore original private material | 1.260 s |
| Bootstrap and Begin application imports | 17.610 s |
| Fresh Source and Encodings | 7.983 s |
| Predicate Core proof and corrupted-child rejection | 5.189 s |
| Original ciphertext preparation, Basis and Formation | 89.076 s |
| SDK ciphertext multiplication/relinearization | 0.096 s |
| Graph/input verification, producing/checking/recording output118 | 444.093 s |
| Fresh complete application replay, import and private completion | 38.344 s |

These intervals total 603.651 seconds for the heavy case. Its fixture timer is
zero because an earlier ordinary case initialized the shared public fixture;
that preparation is included in the complete group's 629.02 seconds. The named
output118 interval also includes graph preparation and fresh input16 checks,
so it is not an isolated prover or hash benchmark. This is one observation of
a new boundary, with no before/after performance comparison or interactive-speed
claim. The original unverified SDK method is used only after independent full
application verification; successful decryption is not the proof.

Maximum sampled working set and OS peak were 1491206144 bytes; maximum private
bytes were 1552334848. The largest sample gap was 4005.606 ms. Retained charged
bytes were 577926451. These observations cover this local fixture, not a formal
resource bound or sustainable storage-growth result.

```sh
cargo test --release --offline --locked -p registry200-joint --lib progress::tests:: -- --include-ignored --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-joint --doc progress:: -- --test-threads=1
cargo clippy --release --offline --locked -p registry200-proof -p registry200-joint --all-targets -- -D warnings
```

An initial test-only call incorrectly expected `Key::Evidence::statement()`.
Compilation rejected it before any expensive run. The corrected gate uses the
existing Ready restore's actual proof/ALL33 checks and checks all ten Basis
statements against the same pinned Key. No extra Key proof or accepting stub
was introduced. Failed attempts remain recorded as failures.

## Reproducibility and remaining work

The final test source receipt covers 1645 unchanged files:
`B6CD88240D6C943DF7C3F07AAB907317E361F85A53F034255259CCAD1D55A793`.
The unchanged after receipt is
`9B6850CDC47373D9531A872110844E64932F3EC0D5DB503C8F3D664EB78322A4`.
The local profile with complete results/phase/memory pins is
`.local/joint-progress-predicate-native-r2/profile.json`, SHA-256
`A351AF41027BA3CA6173EF070FC466EA46CE290FB6EA0FFC170A3D30553FC137`.
The heavy group stdout, stderr, CPU CSV and memory CSV hashes are respectively:

```text
769B9B70DC385E5FA75B2F0A9A2562D320DD629EE89EBEA1B3284D4616BD93E9
23140C35F31FF8711D50881486849A6E30FB22FDAB094B377ED3AE56C23C01B5
AEE3F21E046F464EF08A99A11C338888AAA79B9FB5799ACB7CD6AD767C409AA2
78EE09655618C173A9B4123849539B553BCC9DFA7C88D3560EAADAC5FC7DBD41
```

Generated observations remain uncommitted under
`.local/private-peer-native-r1/joint-progress-predicate-local-r2/`. After the
source freeze, only execution documentation and two status comments changed.
New weighted finality/Rules/Work integration, peer transport/participant mode,
atomic owner Parked/NOWAIT state, recovery, general SQL and a current freshness
policy remain required. The earlier real-peer Joint Acquire path uses its own
legacy proof profile and does not establish these new progress guarantees.
