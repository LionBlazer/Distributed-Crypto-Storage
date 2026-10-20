# Private predicate Result160 opening validation

The owner-private typed opening passed its owning release/offline/locked gates
on 2026-10-20. It consumes the genuine sealed Predicate `VerifiedStep` and all
160 canonical private fields, the independently retained original Statement,
and exact optional previous/parked progress. It verifies their commitments and
complete proof context before exposing typed private values. Control results,
modular aliases, wide integer limbs and invalid flag/status shapes are rejected.
The backing fields are zeroized on drop; there is no unchecked constructor, raw
getter, serialization, Clone or Debug. This is mathematical consistency, with no
SQL success, fresh-head receipt, QC, lock grant or bank installation.

The Witness export and original proof claim use the same extracted Result160
builder. Its field order and computation are unchanged. Relation profiles,
AIR, wire formats, proof caps, dependencies and old APIs are unchanged.

## Owning checks and cost

All nine affected cryptographic tests passed in 133.15 seconds in the test body,
177.831 seconds including its 44.13-second rebuild. Existing WAIT/prefix/End
compaction/fresh-blind resume, NOWAIT/savepoint and both SKIP LOCKED cases now
also open the actual checked result. All 160 single-word mutations and all 160
field aliases reuse one genuine verified proof, alongside original-Statement,
progress, salt, flag and integer-limb rejections. No extra proving call or fixture
setup was added for these negative cases. The unchanged model tests were not
repeated for this opening-only addition.

Five ownership/privacy compile-fail examples passed in 0.91 seconds in tests,
39.150 seconds whole including rebuild. Strict all-target Clippy for Core and
the application passed in 8.008 seconds. The same existing two Cargo jobs, two
requested Rayon threads, 1792 MiB per-process soft fuse and 1800-second command
budget were preserved. Neither limit fired. The crypto group sampled maximum
working set/OS peak of 1024131072 bytes and private bytes of 1069178880; maximum
sample gap was 782.285 ms. This is a local observation, not a formal process bound
or a before/after performance claim.

```sh
cargo clippy --release --offline --locked -p registry200-proof -p registry200-joint --all-targets -- -D warnings
cargo test --release --offline --locked -p registry200-proof --lib registry_progress:: -- --test-threads=1 --skip registry_progress::model_tests::
cargo test --release --offline --locked -p registry200-proof --doc registry_progress:: -- --test-threads=1
```

The source receipt covers 1647 unchanged files, SHA-256
`BB3E8F722A62B60FB351787E1F19D61F65E58B9CE84C0EFABEAF58F598FD3418`.
The complete after receipt is
`90DDDB84CBE3FF2A77D24561B2FB2608539CD07C5FE68DD55A58513E0C7C35DF`.
Generated observations remain uncommitted in `.local/result-opening-native-r1/`
and `.local/private-peer-native-r1/result-opening-{clippy,crypto,cf}-r1/`.
The crypto stdout/stderr/CPU hashes are respectively:

```text
3AAF83F431BFF88953DD7F4E782EEC7816C0160E507882E937F8D47B45C4D2D1
2EF318C89BA4F01686EA281795044B3C09F2BD908E70D18FB86ADCF156F33C36
CE66A3C796C7E95FE30C29893E7BDA99834C04FB3FC6A70CACDA37BDE7BBD3F6
```

After the freeze only this record and the module's execution documentation
changed. The earlier [Core](registry-progress-validation.md) and separate
[FHE application](progress-application-validation.md) gates establish their own
boundaries. Durable owner continuation, exact finality association, current
freshness and real peer admission of the new progress profile remain required.
