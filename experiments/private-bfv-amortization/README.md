# Independent retained-table BFV/PIR amortization

The actual run retains 20 independent one-million-row data/index snapshots and
all 40 native PIR caches under one BFV Rows16 setup and one Spiral setup.
All 192 full paired EQ reads pass; maximum local time is 435.892 ms. Native
peak working/private memory is 1,710,084,096/1,717,149,696 B. Eighteen focused
tests and authored strict Clippy pass. The [report](../../docs/experiment-private-bfv-amortization.md)
contains every per-table/profile/header/age visible/private result.

Primary image+key/owner accounting is 1.93869635x (1.95969902x with hash payload)
of 60,000,000 B logical plaintext. This is not full-state 2x: retained NTT
overlays alone are 1,342,177,280 B; canonical once plus listed auxiliary copies
is 24.72990915x. Actual files plus current process working set are 1,790,645,970 B.
No expanded representation is treated as free because it resides in RAM.

## Responsibility and direct dependencies

This executable owns independent table lifecycle, guarded retention, full-query
timing, wire/resource accounting and rejection/freshness checks. Dependencies:

- compact-store: independent AEAD owners, canonical snapshots, Merkle responses,
  owner authentication/decryption and actual page replacement.
- Pinned native Spiral SDK: genuine single-server private query/recovery and
  distinct native cache allocations for every data/index snapshot.
- spiral-owner-state: 336 B pinned owner recovery image and original public
  setup binding; secret image stays owner-side.
- compact-bfv-byte-limb-core: fresh fixed16 input encryption, public-only
  peer evaluation and explicitly unverified owner output.
- serde/serde_json, getrandom, Rayon and zeroize: wire/logs, randomness,
  bounded thread configuration and owner temporary material.

No TFHE, plaintext peer index, permanent FHE row cache, answer cache, cloned
table/cache or count-only projection is used. Public synthetic fixtures vary
data pages, age distributions and amounts by table; all complete ordinals come
from authenticated encrypted postings. Fixture oracles run only after timing.

## Files and entry points

- src/main.rs: shared setup/recovery, RetainedTable ownership, admission/ledger,
  paired full operation matrix, wrong-table/stale rejection and replacement.
- src/padded_index_codec.rs plus tests: unchanged frozen PaddedV2 callback format.
- src/codec_helpers.rs: authentication/page-budget helpers and contracts.
- src/resources.rs: Windows current/native-peak working/private counters and
  thread sampler with decimal 2,000,000,000 B backstop.
- run.ps1: pinned SDK verification, ignored source preparation, source hashes,
  locked unique build, new snapshot directories and raw JSONL.
- Cargo.toml/Cargo.lock: standalone workspace and 111 locked packages.

Admission checks precede every table/cache addition: explicit expected addition
80 MiB/table or 48 MiB/cache plus 80 MiB reserve under decimal 2 GB. Reject
before the next allocation and emit incomplete accounting if capacity fails.
The actual run passes all 62 admission checks. All per-table keys/heads/headers,
canonical images, raw proof-buffer lifetime, Merkle payload, 40 NTT overlays,
expanded PIR material and actual disk/process bytes are separately reported.

## Reproduce headlessly

Use existing Rust 1.99/MSVC and project-local Cargo cache. The runner requires
the shared core and owner-state modules; -BfvCoreDirectory and
-PirOwnerStateDirectory can select their source directories explicitly during
isolated work. -PrepareOnly performs no build/cryptography. -Offline requires
the exact SDK and dependencies already present. No global installation or UI.

~~~powershell
$taskCargo = 'E:/Users/white/.cargo/bin/cargo.exe'
$taskCache = 'E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home'
$taskTarget = 'E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target/private-bfv-amortization'
./experiments/private-bfv-amortization/run.ps1 -PrepareOnly -Offline
$env:CARGO_HOME = $taskCache
$env:CARGO_TARGET_DIR = $taskTarget
& $taskCargo test --release --locked --offline --jobs 2 --manifest-path .local/private-bfv-amortization/package/Cargo.toml -- --test-threads=1
& $taskCargo clippy --release --locked --offline --jobs 2 --manifest-path .local/private-bfv-amortization/package/Cargo.toml --all-targets --no-deps -- -D warnings
./experiments/private-bfv-amortization/run.ps1 -Tables 2 -Samples 1 -TableIds '0,1' -Threads 8 -Cargo $taskCargo -CargoHome $taskCache -TargetDirectory $taskTarget -Offline
./experiments/private-bfv-amortization/run.ps1 -Tables 20 -Samples 2 -TableIds '0,9,19' -Threads 8 -Cargo $taskCargo -CargoHome $taskCache -TargetDirectory $taskTarget -Offline
~~~

Dry2 passes 64 complete reads plus a fresh read after replacement. Actual20
executes 192 matrix reads and one fresh read, retaining every other table/cache
during replacement. The actual run safely invokes that same validated binary
from main's writable checkout after one pre-launch review timeout; no process
or measurement existed for the timed-out attempt. Exact source/executable/raw
hashes and actual output paths are in the report.

## Declared limits

Both Visible and real PIR controls are measured. Table/root/version identity
is public; PIR hides page addresses inside the selected table. AddressOnly
reveals empty/nonempty by RPC schedule; Fixed16 uses real authenticated dummy
reads and fresh encrypted zero weights, with invariant public lengths/counts.
Every full timer includes actual retrieval/authentication, fresh BFV predicate,
COUNT/SUM, serialization and owner completion. Queries use retained RAM, no
query disk reads or network/RTT. Concurrent owner-head/replay distribution and
active-response feedback security remain open.

The owner is online and reads selected plaintext. EQ/Rows16 and one posting/
data page are the tested scope. BFV retains upstream ABOUT128 and unresolved
independent security/noise validation; outputs remain ProofStatus::Unavailable.
The real owner-authorized replacement/files/rebuild/header/fresh read is
644.474 ms, not BFV UPDATE. std::fs::write establishes file lengths, not fsync,
durable crash recovery or atomic distributed commits. Full owner key export/
restart, arbitrary SQL, concealed writes and computation/completeness proofs
remain open. All earlier measured experiment files remain frozen.