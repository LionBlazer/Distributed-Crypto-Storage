# Explicit participant logical-file quota

The full [private-peer proof graph](private-where-peer.md) exceeds the legacy
256 MiB file budget. `protocol-storage` now provides an explicitly NEW namespace
with one shared ledger across CONTROL, immutable evidence depot and custody.
The [module contract](../crates/protocol-storage/README.md#explicit-participant-namespace-and-quota)
documents its exact grammar and public API. It neither migrates old workspaces
nor changes the legacy Body, transport, blob or Journal caps.

`ParticipantQuota` independently pins a namespace and local decimal capacity up
to 30 GB; 10/20/30 GB remain local policy. All CONTROL files share 256 MiB,
including the 136-byte root header and lock-file slot. The other two classes
share remaining global capacity. Every descendant handle retains the same root
lock and ledger. Cloning handles cannot multiply available bytes or file slots.
The fixed profile digest identifies these rules, not a participant's chosen
capacity. A future application must explicitly bind this new profile.

Scoped file permits reserve a pending path, file slot and initial extent before
creation; promotion preserves the same charge. File growth is charged before
writing. Unknown surviving artifacts and ambiguous writes retain charges and
poison the namespace. Already staged evidence writers check the shared state
before more payload I/O. Removing an owned stage may release its bytes, but
cannot clear poison. Recovery requires releasing all descendants and strictly
inventorying all classes before any usable budget is returned. Retained blobs
are rehashed; references and their application semantics require separate proof
verification.

The multi-slot signer now uses these pre-create and existing-file checks. Its
normal record writes, Advance writes and physical-position checks mark the shared
quota failed on I/O uncertainty. The later-slot context, Advance encoding and
strict replay are preserved. A torn tail remains a hard error; a complete synced
Advance whose acknowledgement was lost replays to the actual successor.

## Executed verification

Windows/MSVC Rust 1.99.0, release/offline/locked, native CPU, Cargo/Rayon threads 2:

```text
cargo test --release --offline --locked -p protocol-storage -p work-finality -- --test-threads=1
cargo clippy --release --offline --locked -p protocol-storage -p work-finality -p registry200-finality --all-targets -- -D warnings
cargo check --release --offline --locked
cargo fmt --all -- --check
```

All 27 storage cases, 39 work-finality cases and five ownership compile-fail
examples passed. The fifteen new Windows storage cases exercise actual namespace
and CAS files, concurrent reservations, global/class caps, pending permits,
failed creation, shared poison, complete restart inventory, two-hardlink recovery
and file-slot exhaustion. Scalar reservations test GB capacities without allocating
GB payloads. The symlink-specific case is Unix-only and unexecuted here.

Three new owning signer cases cover pre-create header refusal, six combinations
of normal/Advance writes with partial-write/before-sync/lost-ACK faults, and an
actual changed file extent. The initial run passed all storage tests but failed
two new signer tests because Windows locks prohibit another descriptor's reads
and writes. The corrected tests inspect bytes after signer Drop and use a
test-only owned-descriptor append for the extent-corruption case. Metadata and
verification results are not mocked. These injected faults do not establish
operating-system power-failure durability.

The successful test command took 7.228 s including compilation; storage runtime
was 2.24 s, work-finality 0.56 s, ownership doctests 0.28 s. Strict Clippy, Core
default-member compilation, formatting and requirements mirror checks passed.
All 1436 public raw source files matched the frozen manifest after those checks
and before these documentation updates. Its ignored receipt
`.local/participant-quota-native-r2/source.json` has SHA256
`886DF25BE01238CDCB882D83FDE382694EC676044CA04B76500AF34D70A5F9CA`.
The source-only donor aggregate was
`F00CE52EC0214AC6CF22847974724CA3078A32231E061900515A8E1945DF3DE4`;
Root additionally preserved the newer multi-slot WAL and added its integration
tests. No Cargo manifest, lockfile, external dependency or version changed.

The nominal 100 ms observer captured 42 samples across Cargo and both test
processes, with a maximum 317.680 ms gap. Sampled maximum working set was
65,245,184 B, private bytes 53,735,424 B and OS-reported peak working set
66,863,104 B. No runner budget or sampled 1792 MiB fuse fired. Short-process
sampling establishes no whole-peer RAM bound. Successful stdout SHA256 is
`039BE3C4F7CD404190036623B8103BB57D092C6280355F2FD78016EC34E252E6`,
stderr `1C039DC2E0709E48ADD1D5BF7E6BCDDA140FA0F03DF6C175258CC293A45ECAD3`.
Failed-run receipts are retained separately.

## Integration limits

Accounting covers logical file bytes and reservations, excluding directories,
allocation rounding and filesystem journals. It is not an OS sandbox or a
measured physical-disk quota. Existing Windows directory-sync limitations remain;
a missing referenced file must stop recovery. The existing finality adapter's
legacy filenames and custody-v2 layout require explicit new adapters, rather
than silently admitting them into this namespace.

This change grants no SQL answer, lock, freshness receipt or cryptographic proof
validity. The new joint application must retain and genuinely reverify its full
input, Lifecycle/Link and FHE output evidence on vote, import and reopen. The
deployment of the [network finality service](network-finality.md), complete evidence graph, live participant bootstrap,
keyless client freshness barrier and four-OS partition/restart scenarios remain
separate integration work.
