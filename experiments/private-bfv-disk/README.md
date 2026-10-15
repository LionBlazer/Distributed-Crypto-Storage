# Disk-backed private BFV index probe

Measured: three independently sealed one-million-row disk tables, one shared Rows256
BFV/PIR setup and capacity 1 loaded pair. The final 288 same-table queries plus five
full controls/read operations are exact; 28 release tests and strict authored Clippy
pass. Two uncached private range misses exceed 500 ms (502.0542/513.6910); cached
private max 436.9376 ms. Both the slower baseline and final results are retained in
the [complete report](../../docs/experiment-private-bfv-disk.md). This is an isolated
research executable with an online owner and explicitly unverified BFV output.

The subsequent [actual 1,000-table run](../../docs/experiment-private-bfv-disk-scale.md)
uses the same executable and capacity. Actual dataset files plus native peak commit
are 1.816600352x of 3 GB logical data; all 288 matrix answers are exact. Six private
uncached range misses take 506–518 ms. This is measured bounded accounting, with
network, proofs and complete owner restart still outside the experiment.

`src/disk.rs` owns bounded held-handle exact reads/EOF checks, full-image commitment
gates against trusted complete heads, memory admission, capacity-one eviction and
invalidation. Unloaded tables retain only keys, trusted heads, paths, lengths and
owner-authenticated header metadata; no unloaded snapshots/native caches are held.
`src/native.rs` adapts the reviewed cache builder and exact copied public-only Spiral
server helpers. `src/main.rs` owns fixtures, roles, complete timing/serialization,
post-timing oracle and actual owner replacement/rejection lifecycle. The PaddedV2
codec owns complete authenticated posting selection, with its contract tests retained.
`src/resources.rs` separates cheap current/native-peak admission counters from actual
thread enumeration in the monitor/outside complete-query timing. The direct
`counter-diagnostic` executable argument reports eight sampler-cost pairs without
keys or datasets.

Direct project dependencies are [compact-store](../../crates/compact-store/README.md),
[BFV core](../bfv-byte-limb-core/README.md),
[PIR owner state](../spiral-owner-state/README.md) and
[PIR cache preparation](../spiral-cache-core/README.md).
Other direct libraries are pinned Blyss Spiral SDK, Rayon, Serde/JSON, SHA-256, getrandom and
zeroize. `server_schedule.rs` is exact F9B343… and `expansion_schedule.rs` exact 931FD2…;
`LICENSE-BLYSS` preserves the SDK MIT notice. Neither copied algorithm nor SDK source
is modified by this package.

Run `run.ps1 -Tables 3 -Samples 1 -Offline` with explicit tool/dependency directories
where needed. The runner copies/hashes current sources into an ignored standalone
package, checks the SDK pin and locked dependencies, and uses a dedicated target.
`-PrepareOnly` does no build/keygen/table write. Default conservative write budget is
64 MiB; count×6 MiB must fit before setup. Every supplied ID runs every case/profile/
header/access mode with a real miss then hit. The default `combined` mode schedules independent
native siblings/trials; Official/TrialsOnly/ExpansionOnly controls remain available.
Additional actual controls exercise visible miss→private native upgrade→private hit,
nine before-BFV failures and owner replacement→invalidation→fresh complete miss.

Cached headers are authenticated locally at table creation; setup does not claim
private header bootstrapping. Private PIR hides within-table page addresses; table/
root identity and load/update events stay public. Fixed256 uses real dummy fetches
and freshly encrypted zero weights; this is no constant-time/privacy proof. File I/O
uses real APIs but OS cache is not flushed, so physical disk coldness is unestablished.
No arithmetic/SQL proof, offline-owner execution, crash durability or general SQL
claim is made. Complete selections over 256 rows or one posting/data page are rejected.
