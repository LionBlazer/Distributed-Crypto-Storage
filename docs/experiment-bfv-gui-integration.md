# BFV integration at the SQL/GUI boundary

Validated on 2026-10-15 without opening a GUI. The prototype now uses the owning
[bfv-query-core](../crates/bfv-query-core/README.md) through the explicit
[compact-query BFV adapter](../crates/compact-query/src/bfv.rs). It does not import
PIR, disk caches, owner recovery or experiment packages into a product library.
Security/noise/CCA and malicious arithmetic proofs remain unresolved. This finite
visible-access result is not arbitrary-SQL, hidden-access or production promotion.

## Ownership and exact contract

`crates/bfv-query-core` extracts the authoritative main 62de3ad arithmetic and 37
owning tests/2 doctests. All five source files are identical except crate names in
imports/doctests. Private kernel/exact_index/indexed_update modules and public roles
remain; N8192, Q218, t114689, CBD variance10, native NTT, unfused comparator, level0
and the complete original public keyset are unchanged. Baseline lib SHA256:
`F4EC7930D306AE933142AFE7455B500B61A23D53F3DBA69454E796F33EF88CCB`.
The dependency direction is GUI → compact-query → bfv-query-core; the latter has
no storage, SQL, PIR, fixture or GUI dependency. Frozen probes retain their old
implementation and are historical reproducibility sources, not forwarding layers.

`compact-query::bfv` owns the storage contract. Its private selection constructor
reads complete authenticated index counts/postings, preflights min(budget,256),
rejects duplicates/out-of-range values, authenticates/decrypts real selected pages,
and rejects EVERY age mismatch before fresh encryption. One exact AgeRange serves
both index selection and authorized predicate; FullScan/coarse candidates cannot
enter this API. Multiple posting/data pages remain supported. Pending state binds
both current heads, query ID, operation, geometry and keyset; owner completion
consumes it. Selected fields reserve capacity before plaintext exists and live
field/page buffers are zeroized on drop, including error paths; this is no guarantee
about every compiler/stack/allocator copy.

Exact aggregate freshly encrypts low/high byte weights and COUNT ones, with inactive
slots zero, and genuinely performs eight rotation/add stages. The owner does not
substitute COUNT/SUM. Indexed UPDATE performs genuine peer ciphertext addition,
then unverified owner decode and a local checked-add comparison of EVERY selected
slot before staging any canonical change. Any selected u16 overflow leaves all
images unchanged. Storage helpers stage complete data/index replacements, preserve
index page0 after its112-byte binding, and publish the Table only after both-head
checks. Local arithmetic checking is not a succinct cryptographic computation proof.

`LabEngine` generates one BFV owner/setup; peer Evaluator clones share only public
material through Arc. Physically empty shards retain the existing skip policy;
nonempty shards with absent matches still execute fresh encrypted zero weights.
Every shard stages independently; late overflow/quota/transport cancellation
prevents all-shard publication. Inspector rows are refreshed from actual staged
compact ciphertexts. UPDATE zero/absent success still advances the manager revision,
as before, although unchanged canonical pages are not resealed. This is in-memory
local atomic publication, not a durable distributed transaction.

The optional default `tfhe-backend` retains the broader public FullScan/coarse
predicate and conditional-update contracts. GUI disables defaults and enables
`bfv-experiment`; its isolated dependency graph has no tfhe1.8.1 and no fhe/fhe-math
`tfhe-ntt` feature. The ordinary tfhe-ntt0.6.1 math dependency does not mean TFHE
integer keys are generated. GUI and owning BFV crate declare Rust 1.99, tested with
rustc/cargo1.99.0, x86_64-pc-windows-msvc; no lower MSRV claim or toolchain install.

The SQL parser is unchanged: combined COUNT(*),SUM(amount), or amount=amount+u16;
optional age=N or age>=N, omitted WHERE meaning all rows. Other projections,
operators/joins/clauses/expressions reject; empty SUM is0. No range SQL syntax or
arbitrary predicate is silently redirected to exact unconditional ADD.

## Validation

Release, locked, offline, jobs=2 and test-threads=1:

- bfv-query-core:37 runtime tests +2 compile-fail doctests.
- compact-query BFV-only:19 runtime tests (8 adapter +11 index) +1 one-use doctest.
- compact-query default TFHE:23 runtime tests, including FullScan/coarse filtering.
- Full headless GUI/SQL:80 runtime tests; one existing preview-export test ignored.
- Strict all-target Clippy: all three owning crates with all features, and separate
  BFV-only compact-query. Workspace cargo fmt --check passed.

The eight BFV storage regressions include0/1/16/128/256 exact aggregates, duplicates,
absent/all/max unsigned SUM, budget257, reversed range, authenticated wrong age,
both stale heads, foreign owner/keyset, Arc sharing, actual public in-bounds echo
rejected by the local UPDATE check, nonce/index rebinding/no growth and global
overflow. A separately labeled safe256-positive fixture updates every selected
amount0..255 by1 across31 data pages, verifies255→256, all unselected max-u16 rows,
and index page0 suffix. Headless tests retain late-shard rollback, offline/empty
shards, quota failure, repartition/stable IDs, cancellation and commit revocation.

## Actual complete SQL workload

`examples/bfv_sql_workload.rs` runs the SAME `LabEngine::execute` as the GUI, without
a window. Public 128-row fixture: row0 age42, rows1..4 age18, other ages=index%17,
amount=index*7+3. Each1/3/16-peer configuration runs all 16 cases three times:
point, duplicate, full/noWHERE, >=18, =255, >=255, >=0, age0; point/duplicate/full/
>=18/absent/zero UPDATE;65535-overflow UPDATE; full read after writes. Three additional
controls put65535 at final ordinal127 and reject all-row+1 with unchanged owner rows,
revision, BOTH heads and image sizes. There are144 unique matrix cells +3 controls,
all exact; no dropped case or >500ms result. One preceding PowerShell Tee binding
error prevented launch and produced only a provenance record; it contains no
measurement and is retained separately.

The timer includes parse, complete index/page authentication and age checks, fresh
encoding/encryption, actual request/output serialization/decode, peer BFV, owner
completion/local UPDATE oracle, inspector refresh and staged publication. Fixture
oracle comparisons and OS memory sampling occur AFTER the timer. Setup is separate;
all six setups use fresh keys in one process, not six cold-process starts. Rayon is
fixed8, shards execute serially. Host: Ryzen9 9950X3D2,16cores/32logical; release with
no RUSTFLAGS override. Virtual delivery, RTT, rendering, real network and proofs are
excluded; access is visible.

| Peers | All SELECT min–max ms (27 each) | Successful UPDATE min–max ms (18 each) | Early overflow min–max ms (3 each) | Late overflow ms (1 each) |
| --- | --- | --- | --- | --- |
|1|21.2484–22.3183|10.8671–11.8405|11.3049–11.3801|11.6974|
|3|63.8293–69.4812|32.3015–35.8772|11.3654–11.9979|23.0441|
|16|344.1347–383.8544|172.5906–197.8485|11.4530–11.7050|193.0652|

Each case has three observations. The maximum 383.8544ms is full/noWHERE128 rows,
16peers, round 0. Early overflow stops after the first overflowing shard, so its
11–12ms is not full-shard success latency. The late control exercises the later
shard after earlier staging. Point max22.3183/67.1156/353.8174ms; duplicate max
21.7250/67.6327/368.5889ms; full/noWHERE max21.7685/67.7491/383.8544ms for 1/3/16 peers.
Observed values under500ms in this finite local subset do not establish a general SLA.

Native 2,000,000,000-byte gates check current and OS peak RSS and commit. Actual peaks:
RSS 240,250,880 B; commit 246,702,080 B, including expanded BFV keys, retained setup,
transient serialization and owner inspector/trees/containers. Fresh owner+table
setup 329.7558–346.7190 ms. One shared full public setup serializes to 13,395,426 B
(parameters 46 B, relin 1,116,273 B, rotations 12,279,077 B plus framing), including keys
unused by the exact aggregate. Owner secret serialization COUNT 8195 B is not an
export/restoration image; compact AEAD key 32 B and trusted heads remain owner state.
Canonical data+index sizes are 3125/8092/40384 B for 1/3/16 peers versus 384 B logical.
These tiny tables exceed 2x even before keys; no aggregate storage-ratio achievement
is claimed. Expanded keys and rebuildable trees are in native memory, not hidden
inside the canonical byte count. No key/row/database file was written.

## Reproduction and provenance

```powershell
$env:CARGO_TARGET_DIR='target/bfv-gui-integration'
cargo test --release --locked --offline --jobs 2 -p bfv-query-core -- --test-threads=1
cargo test --release --locked --offline --jobs 2 -p compact-query --no-default-features --features bfv-experiment -- --test-threads=1
cargo test --release --locked --offline --jobs 2 -p compact-query -- --test-threads=1
cargo test --release --locked --offline --jobs 2 -p fhe-playground -- --test-threads=1
cargo clippy --release --locked --offline --jobs 2 -p bfv-query-core -p compact-query -p fhe-playground --all-targets --all-features -- -D warnings
cargo run --release --locked --offline --jobs 2 -p fhe-playground --example bfv_sql_workload -- 3
```

Raw local evidence `.local/bfv-gui-integration/headless-sql-20261015-011517-329.jsonl`
has 155 records (provenance, contract, six setups,147 operations), SHA256
`9B93BF65028922302D65D4C5A9F0221EA1768428FCBD7AC7DEC79850DDBD5790`.
Executable SHA256 `81709C55118C534AE4BF0FA8DC225BF5B0ECF21B6204D3543D96134B7FF17107`.
The raw provenance records exact 18 source/manifest hashes, including kernel and
canonical index. Final changed-path/log hashes accompany the local frozen handoff.
Results remain explicitly Unverified; owner availability, private access, arbitrary
SQL, production security, distributed consistency and arithmetic proofs remain open.
After the measured run, the only runtime-source change is a one-line root reexport
of the public diagnostic PeerHeads type. Its method/structure and every execution
path were already present during measurement; no kernel or timing path changed.
Final GUI library SHA256 is
`D7653EDD6BE8354C0AF530DCB68927F27C8E8046AFA2674651D7C84FEBD4935E`.
A locked/offline existing-target library rebuild passed its five tests and workspace
formatting after that export. The exact measured18 source/manifest files and executable
are preserved under `.local/bfv-gui-integration/measured-runtime`; its provenance
manifest SHA256 is `990071968CB52295063550FB7289815192B3CE7F06F6AD46A658CE65B5CABF41`.
All archived hashes were checked against the raw run before making the reexport.
No benchmark repeat is represented as a new measured artifact.
