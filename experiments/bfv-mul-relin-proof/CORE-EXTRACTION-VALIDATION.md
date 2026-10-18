# Full BFV graph Core extraction validation

## Boundary and preserved contract

At parent `23e13535e71d5cda8f49dab1a91babfcdc3557e8`, the fixed134 graph's
canonical claims, complete predecessor routing and PB/native endpoint bridges
belonged to this experiment. They now belong to
[bfv-mul-relin-circuit](../../crates/bfv-mul-relin-circuit/README.md).
The actual immutable original-setup `PreparedKey` now belongs to
[bfv-relinearization-key-source](../../crates/bfv-relinearization-key-source/README.md).
The former local `claims.rs` and complete-relinearization `key.rs` are deleted.
Consumers use the real library types rather than duplicate implementations or
forwarding wrappers.

The new default Core member depends on existing math codecs, fixed geometry,
ciphertext wire and public key source. It imports no experiment, proof backend
or SDK fork. Root has no global SDK patch. Existing primitive AIRs, configurations,
profiles, public transcript, proof frames and caps remain unchanged. All third-
party lock records in the four affected graphs are unchanged; the root lock adds
one local package and the other changes are local dependency edges.

Core claims remain unverified. Their codec receives an independently expected
profile64, while this proof consumer always supplies its own fixed profile.
Core receives an already derived binding32 for each request. The complete G,
Source/Encoding/Key33 provenance, special17 arithmetic labels, actual SDK proof
admission, output-only security union and session budgets remain here. There is
no callback, alternate verifier, checked-prefix receipt or new SQL grant.

Public key preparation retains the original full setup pin and SHA512, all50
rows,25 sequential public C0 transforms and original seeded C1 expansion. It
exposes immutable public components and a dedicated error type. It does not
establish same-secret key validity. Core graph routing performs no NTT/query
evaluation; fixed public key preprocessing and seeded input expansion retain
their separate original roles. The existing Basis input verifier still performs
its public ciphertext representation conversion/preprocessing.

## Executed native gates

Final source is `mul-relin-core-validation-r1/source.json`, SHA256
`97EE94607AA11EA13F98C94B9CCE246C8CA5B823FC6BF65BC82DC2CB87845975`.
It freezes1342 repository files, two deletions and four local ABI-replay files.
The final report/README updates follow native closure; all Rust, manifests and
lockfiles must remain byte-identical to that source.

| Owning group | Passed cases | Direct process time, ms |
| --- | ---: | ---: |
| Core full graph mathematics/codec | 6 | 2,624.1716 |
| Public key source/preparation | 12 | 2,418.0632 |
| Original complete32 proof consumer | 7 | 102,658.1155 |
| Full graph proof policy/envelope | 3 | 206.7857 |
| Requirements synchronization | 1 | 225.9287 |
| Actual input16/product134 integration | 1 | 602,228.0472 |
| Total distinct owning cases | 30 | |

All selected cases passed without ignored cases. The hiding executable's other
369 cases were filtered; this is not an all-repository result. Formatting, strict
all-target Clippy for the five affected library/consumer packages, and actual
default-core check passed. The old complete32 CLI compiled; its unchanged CLI
prove was not run again because the owning seven-case suite already executes
the genuine complete stream. Both library doctest commands passed with zero
executable cases. No SDK fixture writer ran in these selections.

The original nine key-source test bodies are unchanged. Three new cases compare
every one of all50 key rows against actual SDK relinearization impulse probes,
test complete-setup rotation/seed changes and reject malformed sources before
public transforms. The moved full claim-codec test retains its name and every
assertion, with only explicit profile arguments. Additional Core cases check the
complete134 mathematical chain against the actual encrypted SDK product, every
full edge including25 digits/all50 key rows, prefix/native/header rejection,
profile boundaries/raw-feed separation and both seeded/unseeded PB bridges.
Those mathematical tests alone produce no computation proof.

The original complete32 test still generates genuine proofs, drops its producer,
freshly verifies all32 components and compares the entire SDK endpoint. Its
genuine foreign-proof control must verify under its own statement before failing
the honest verifier. Original private-field assertions now compare the complete
immutable component slices; no coefficient/assertion was removed.

The full private-input integration retains actual Key, Source, both Encoding,
ten Basis and two Formation proofs, all118 output records containing120 SDK
proofs, canonical final-coefficient attacks, genuine repaired-header foreign NTT
rejection and terminal cancellation/attempt/byte limits. After dropping the
prover, old key, graph, expectations and verifier state, a new public verifier
actually verifies all input/output evidence and returns the exact SDK ciphertext.
Plaintext/decryption remains an independent test oracle only.

## Byte replay and composition policy

A separate local-only executable decodes the preserved PUBLIC NONSECRET R3
`product-claims` with both the exact published pre-extraction codec source and
the new Core codec. Both re-encode all16,727,920 bytes identically, compare all
native rows and134 complete child frames, and feed the identical raw coefficient
sequence to SHA512. It also rejects a changed upper-half expected profile byte.
The direct process took242.2273 ms. This is a codec/identity replay, explicitly
`cryptographic_verification:false`, not another proof test. The R3 proof run was
partial and stopped; replay does not promote it into a complete proof PASS.

The unchanged accepted profile64 is:

```text
20ccad0e98d273158d4ba4ab6f314c5ded8854f11787b0135facf65548a9ac4ad6bdac0808e7304e9710e75e396aeca2db7a2821f12c6654055e63f0ba6a1aeb
```

The proof consumer separately pins that full published profile in an executed
test. Fresh actual output reports still combine to150.50196022260138 bits:
115 NTT, two Relin and the already-combined arithmetic17 report counted once.
Input proofs retain individual128 policies. No whole128/whole144 or public
same-secret evaluation-key theorem follows.

## Full integration measurements

| Observation | Measured value |
| --- | ---: |
| Complete graph claims | 16,727,920 bytes |
| Output118 records including headers | 236,824,478 bytes |
| Largest output record, arithmetic17 | 6,501,224 bytes |
| Input15 frames including duplicate Source | 264,181,215 bytes |
| Source proof repeated in both pairs | 19,301,023 bytes |
| Complete public claims/input/output spool | 517,733,613 bytes |
| Graph preparation | 1,088.5031 ms |
| Graph input verification | 35,468.4971 ms |
| Output generation/verification/spool/negative controls | 382,453.5092 ms |
| Sum of output `prove_next` calls | 362,347.1752 ms |
| Sum of output verification calls | 17,340.2739 ms |
| Fresh public verification after prover drop | 49,361.0202 ms |
| Whole direct test process | 602,228.0472 ms |

The fresh interval includes new setup/key preparation, input16 verification,
all118 output proofs and file reads. The full test also includes owner fixture
and input proof generation, earlier input verification, adversarial controls and
repeated complete verification. These are not ordinary SQL request latencies,
isolated SDK timings or a controlled before/after speedup measurement. Fixtures
are newly generated; byte/time differences from the [preceding validation](VALIDATION.md)
are separate observations, not a wire-policy change.

Root used Rust1.99.0 MSVC, release/locked/offline, native CPU code, two Cargo jobs
and two Rayon workers in an independent copy2 target. Owned-process observation
retained the nominal100 ms sampler,1792 MiB per-PID sampled soft fuse and1200-
second command bound. No fuse fired. For full-test PID503252,2585 samples show
maximum working set/OS peak1,383,665,664 bytes (1.288639 GiB), maximum private
bytes1,382,309,888 (1.287376 GiB), and maximum actual sample gap869.0201 ms.
The two fast proof-policy/requirements commands have no live memory sample, so
no RAM fit is inferred for them. Sampling, including the short ABI process's
single sample, does not prove a hard process or whole-peer resource bound.

No Body32 MiB, transport64 MiB, history256 MiB, proof/frame/decode or session cap
was enlarged. The517,733,613-byte spool is a collection of bounded public files,
not one accepted network frame or Journal Body.

## Receipt identities and reproduction

The local immutable `mul-relin-core-validation-r1/<mode>/success.json` receipts are:

| Mode | SHA256 |
| --- | --- |
| contracts | `7943F4D7D5FAC88E581A744EFC7BF34E090862A3E8135F343EA5F3867E409E6C` |
| compile | `8727CC576931A908B05B85BFABD8D8506D5A1B75A611BBFAD2C54AAAA7FACCC8` |
| tests | `E60AC4BC53966B96C9149A1F85B2363AA0FA281E690D791650C3BF5BAA9696D0` |
| numeric | `DE1A55BB85CD0049B07CA4FF4CD4FFFEDC48CF44E848E4B13CC5189081606F01` |
| docs | `CD0206D5192DECFAAAC60171028E61EAD9436C38988C587491CF25FA274C10B3` |

Final native closure `mul-relin-core-native-closure-r1/success.json` is
`BF1C74DB3AC6D19FB69A05152055F0B9177ECD50A282B5DB8307F29331FAA3AC`.
It rechecks sources, discovered executables, logs, CSV counters,1027 original
SDK/archive anchors, five tools and40,895 protected prior artifacts. Source import
packet is `C25CE16B7BB5340FBEF889E97481AC317994CA60374786D251327DF4522EAE2C`;
independent copy2 preparation is
`48DA3B2AE5B81D4739B75B844AA59AA79BB670C4A44A514349B4E4930EE2B3F3`.
The original native runner remains
`9505DD6E4D9EA317EFF1C6C45BF86FAA4D3837E5C45D2DF41A9535048C8CFC38`.
Two independent subagents reviewed source/lock/assertion preservation; native
execution was performed only by Root.

Use the reviewed locks, a fresh target and the environment above, including the
existing `DCS_CHUNK_IO_FEASIBILITY=1` / `DCS_PACKED_IO_FEASIBILITY=1` flags:

```text
cargo check --release --locked --offline
cargo test --release --locked --offline -p bfv-mul-relin-circuit --lib -- --test-threads=1
cargo test --release --locked --offline -p bfv-relinearization-key-source --lib -- --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/bfv-complete-relinearization/Cargo.toml --lib -- --test-threads=1
cargo test --release --locked --offline --manifest-path experiments/bfv-mul-relin-proof/Cargo.toml --lib -- --test-threads=1
cargo test --release --locked --offline -p fhe-playground --test requirements_sync
cargo test --release --locked --offline --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml opening::coefficient_encoding::input_formation::input16_and_all134_product_nodes_verify_exact_ciphertext_after_private_drop -- --exact --test-threads=1 --nocapture
cargo test --release --locked --offline -p bfv-mul-relin-circuit --doc
cargo test --release --locked --offline -p bfv-relinearization-key-source --doc
```

Root used Cargo JSON discovery and invoked exact frozen test executables. The
ABI replay source and old public spool remain local immutable validation inputs;
they are not production dependencies or committed generated outputs.

## Remaining SQL integration

Full PostgreSQL, `FOR UPDATE`, `SKIP LOCKED`, live query admission and proven
writes remain incomplete. The next shared proof-library boundary must move real
verifiers/producers without bringing CLI fixtures into Core or creating a
QueryCore dependency cycle. Network completion belongs above Owner/Pending and
the proof libraries, with independently derived complete expectations and final
head/ancestry checks before client decoding.

Current coefficient and Registry200 compilers derive different preproof q labels.
A combined private intent must be defined before making fresh Source/Encoding/
Lifecycle proofs; relabelling old proofs or treating matching heads as a bridge
is invalid. Same-secret authority, full-protocol security/noise analysis,
post-SKIP/window selection, active control fences, data transitions and global
freshness remain explicit obligations. Existing live SQL/mutation rejection is
unchanged by this extraction.
