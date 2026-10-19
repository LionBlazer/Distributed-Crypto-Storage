# Locking inputs from verified Joint parents

The [owner-side Joint adapter](../crates/storage-client/src/private_predicate/source/locking/joint/README.md)
accepts a sealed historical `VerifiedJointParent` and independently pinned
installation/BFV metadata. It checks the complete descriptor, Genesis, database,
original setup, anchor, genuine Ready epoch Key proof and all 33 Key values.
No raw Journal, HeadRef or peer-nominated root can create this parent.

`SourceOwner::prepare_joint_locking` reopens the real encrypted N4 Source,
authenticates the complete image/index and checks both private control openings
before FHE. It uses the same private mathematical producer as the original
`prepare_locking`. The original public parent factory, hash domains, proof
profiles and test bodies remain unchanged. A closed private parent enum routes
the shared producer; the new request uses the fixed Joint Acquire envelope.

Output consists of actual Source/input16, Lifecycle and PredicateAcquire proofs,
the original BFV pending/request, and opaque move-only completion/staged
candidates. No state installation, completed answer, current lock grant or SQL
admission is exposed. Historical parent validity does not show that no later
finalized state exists.

## Executed behavior

Both new owning native cases passed on the first run. The main case constructs
actual signed Source/Bootstrap/Begin/ControlKind bodies and real three-of-four
Work QCs, then destroys the history, ingress and parent-proof buffers before
preparing a hidden query:

```sql
SELECT age, amount FROM records
WHERE age IN (0, 255)
LIMIT 1 OFFSET 1 FOR UPDATE SKIP LOCKED
```

The producer encrypts all original rows and proves the actual input16,
Lifecycle and private-mask Link. After the private Source/Owner/epoch/compiler
objects are dropped, independent public verifiers recheck all input evidence
and the genuine Lifecycle/Link prerequisites. Test keys, rows and openings are
explicitly public nonsecret fixtures; no peer result is calculated from them.

Negative checks reject foreign Genesis/binding, Owner/setup, an unready epoch,
wrong actor/controller/salts/Registry, foreign object and damaged index. A second
genuine Key proof from the same anchor has a fresh CsHat: its first 29 public
values match, but its remaining four do not. The full independently pinned Key33
check rejects it. The other case checks setup association without encryption,
including a foreign setup of identical geometry and correct canonical restore.

This query runs against the genuinely proved uncontended Registry. It does not
establish SKIP LOCKED behavior after a competing admitted Acquire. The previous
[locking gate](private-locking-inputs.md) retains its genuine mathematical
WAIT/NOWAIT and contention evidence; actual Joint contention needs a later full
FHE/Acquire/QC scenario.

```sh
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib private_predicate::source::locking::joint::tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --lib locking_compiler_ -- --nocapture --test-threads=1
cargo test --release --offline --locked -p storage-client --features private-input-proofs --doc -- --test-threads=1
cargo test --release --offline --locked -p fhe-playground --test requirements_sync
```

The two original compiler regressions passed, covering three-valued truth,
LIMIT/OFFSET and rejected unsupported plans. All twelve client compile-fail
contracts passed, including five new ownership contracts. Strict all-target
Clippy for `storage-client` with `private-input-proofs`, the Core default release
check, all-target `dcs-peer` check, workspace formatting and the actual
requirements synchronization test passed. The broader legacy SQL success suite
was not rerun: its previously recorded closed-capability failures remain
unresolved. These targeted gates are not evidence that general SQL works.

The lock file adds only four existing local dependency edges to `storage-client`:
optional Joint/finality and test-only storage/Work owners. No external package,
version or checksum changed. Core has no dependency on its consumers.

## Measurements and evidence

The main command took 239.291s, including 29.08s compilation and 209.23s runtime.
The Windows observer retained 1,469 samples with a maximum 839.829ms gap.
Maximum sampled working set was 1,406,939,136 bytes, sampled private bytes
1,435,090,944 and OS-peak working set 1,487,319,040. Neither the 1792MiB
per-process soft fuse nor the 1800s runner budget was reached. These observations
are for a local input/replay suite, not full SQL latency, concurrent peer memory
or an interactive performance guarantee.

The compiler command took 0.642s; the twelve ownership contracts took 15.853s
including startup/recompilation, with 2.49s test runtime. Requirements checking
took 129.043s including its dependency build.

Parent commit was `a9b9c5c309ee741d76a446fa0216cc37f2e5b4cb`. The frozen
1,516-file source manifest SHA256 was
`98EC63FD9005136E27AABE1872BA4520661C24662508A7B36A4B3FE5A8073DD8`.
All raw hashes and the complete public inventory matched after native and
completion checks, before this documentation update. The independently reviewed
eleven-file source packet aggregate was
`F62A2E2961020EEE743C2A432AE08CA02206A158160FCBB493997E1DFC6A23CC`;
Root then added the local dependency edges and applied workspace formatting.

Ignored main receipts are in
`.local/private-peer-native-r1/joint-client-tests-r1/`. Stdout/stderr SHA256:

```text
06D84CA3679E547FB813C233173DB3F2411BD347C10E0B5CFD201BDAF6AEC46F
D2B2156059B96867F3D238895BC1E134C399AAC179E5D3C14DBF3755ED87C343
```

Ownership contract stdout/stderr SHA256:

```text
91AB16B3FB48D494C818337AEDA5E361928D68D876541CAFB222F3D468B9C84B
E6D2D9A1E4F1D2B68044C46A63387784D572D9BE38B460E8B1A5F20807B32198
```

## Remaining integration

This stage performs no OS-peer FHE request, output118 replay, admitted Joint
Acquire or completion/decryption. Those complete chains still require actual
computation evidence and the exact fresh agreed operation. Owner Vault/CAS,
durable exact-byte retry and client recovery remain required before general SQL
entry guards can open. A genuine future contention test must first admit the
competing Acquire; changing a private Registry under an old parent is invalid.
Individual proof policies do not establish composed 128-bit security or an
evaluation-key same-secret theorem.
