# Disk-only whole-snapshot bulk scale

One fresh1000-table run completed: **54/54 exact full operations**, local
26.6722–30.3293ms, and actual files +observed native peak private **1.782226215x**
3GB logical. Every query transferred5,736,091B. This is full-snapshot bulk retrieval,
**not PIR**. The100Mbps/10msRTT serial network MODEL is505.55948–509.21658ms;
all54 modeled observations exceed500ms. No network was measured.
See the [complete measured report](../../docs/experiment-private-bfv-bulk-scale.md).

This is explicitly ONE database/compact owner/BFV keyset with1000 independently
sealed1M-row tables, not1000 independent owners or the earlier portable-restart
bundle. All2000 distinct roots and physical112B heads/lengths were checked.
No owner restart, GUI-private-backend or general SQL integration is claimed.

## Modules and dependency direction

| Module | Responsibility |
|---|---|
| roles.rs / bulk_wire.rs / resources.rs | Byte-identical hash-pinned copies of the measured bulk18 owning lifecycle,270B bounded framing and decimal2GB native guards. Original Resident APIs are retained for inherited tests; actual scale runtime always uses Disk. |
| disk_scale.rs | Actual available-disk/checked6.5GB preflight; fresh CreateNew files/public catalog; independently sealed root inventory; all-file ledger; synchronous trusted-descriptor dispatch and temporary public-only Arc peer. |
| fixture.rs | Public table-specific ordinary amounts and point4095+tableID; age255 sparse256 maximum amounts, age254 absent. Oracle construction is after the outer clock. |
| main.rs | One same-DB owner/full setup, original unused PIR material retained, finite54 operations, complete raw/network MODEL/native accounting. |
| tests.rs / scale_tests.rs | Six unchanged bulk owning tests plus three actual scale/shared-owner/disk-routing/admission tests. |

Dependencies point directly to reusable compact-query (BFV-only), compact-store,
and original Spiral owner-state/SDK. There is no product→experiment dependency,
crypto/index fork, plaintext aggregate substitution or persistent FHE overlay.
The full N8192/Q218/t114689/CBD variance10/native/level0 setup is unchanged; unused
relinearization/rotation keys and original PIR owner/client/wire/expanded public
matrices remain counted/live. Outputs remain Unverified /ProofStatus::Unavailable.

Every outer clock starts BEFORE catalog lookup/descriptor clone/public peer creation,
then calls unchanged Disk execute and drops the peer before ending. Actual held
full reads occur EVERY observation; neither observation is called a cache miss/hit.
No resident ciphertext, owner response cache or decoded Table survives calls. Both
full ciphertext roots, index/postings and selected AEAD/ages are authenticated before
fresh BFV preparation; arbitrary selected-page placement<=256 is supported. Empty
queries still transfer both images and execute genuine encrypted zero-weight COUNT/SUM.
The timer includes diagnostic full-body SHA256. Oracle/native sampling are after it.

## Validation and reproduction

Nine release tests passed3.30s; authored strict all-target Clippy, silent fmt check,
release build and unchanged locked/offline resolution passed first attempt. No
runtime failure, rebuild or benchmark retry occurred. prepare.ps1 verifies eight
owning-source hashes, four frozen module/test hashes and pinned public Spiral SDK
fdb7206517c249603b0c91b65f1f29f95272107c, creates a NEW ignored package and replaces
only dependency paths. Cargo.lock differs from bulk18 only by the package name.

The source checkout must already contain the pinned SDK and project-local Cargo
cache; [private-access setup](../private-access/README.md) describes initial source
preparation. This package's prepare.ps1 copies and verifies source only.

```powershell
./prepare.ps1 -SourceRepository /path/to/reviewed/checkout
# In the returned isolated package, without competing benchmark jobs:
$env:CARGO_HOME='/path/to/reviewed/checkout/.local/cargo-home'
$env:CARGO_TARGET_DIR='/path/to/reviewed/checkout/target/private-bfv-bulk-scale'
$env:RAYON_NUM_THREADS='8'
cargo test --release --locked --offline --jobs 2 -- --test-threads=1
cargo clippy --release --locked --offline --jobs 2 --all-targets --no-deps -- -D warnings
cargo fmt -- --check
cargo build --release --locked --offline --jobs 2
# Archive source/EXE and choose a NEW dataset directory:
& "$env:CARGO_TARGET_DIR/release/private-bfv-bulk-scale.exe" /new/.local/data 1000 6500000000
```

Full root/native/file/model/raw hashes and timings are in the measured report. The
archive README/source-basis metadata retain their prevalidation preparation stage;
this README and report describe the completed validation. Measured Rust source and
four pinned modules were not edited. No fsync/crash durability, portable checkpoint,
replication/consensus, malicious arithmetic proof, CCA safety, independently validated
numeric security/noise guarantee or WAN SLA follows. Table IDs/heads/lengths/timing/
failures remain public. This hides selected addresses through complete transfer,
not a formal traffic-analysis privacy proof. No same-fixture PIR speedup is asserted.
