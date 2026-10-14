# Fixed-profile parallel native PIR cache conversion

Experimental reusable public-data conversion for the exact pinned Spiral SDK.
The module owns only validated record-image -> native NTT cache scheduling.
It depends directly on spiral-rs and Rayon, with no storage, owner-key, BFV,
SQL, catalog, eviction or GUI dependency. Callers own admission, the Rayon pool,
trusted roots, record framing, resource budgets and cache lifetime.

`profile_params()` returns the current 512x8192-byte native PIR profile.
`load_records(params, records)` converts one image; `load_pair(params,data,index)`
validates both images before concurrently converting them in the same caller pool.
The fixed profile and exact 4,194,304-byte record length are mandatory. The public
SDK's load_item_from_seek, recenter_mod and native NTT remain unchanged. Four
independent trial slabs own disjoint output memory. Pair conversion uses at most
the configured eight workers in the measured runner, with no dedicated child pools.

Each output still occupies exactly 33,554,432 bytes. This scheduler does not compress
NTT words, persist caches or alter crypto parameters. It provides no response
authentication, decryption, SQL completeness proof or hard allocator cap.

Owning tests compare every output word with SDK load_db_from_seek on distinct
public fixtures, reject unsupported profiles/short/extended input before conversion,
and exercise actual native serialized PIR queries for first/middle/last records.
Generated key material is never printed or persisted. The comparison benchmark
measures only pair preparation, not full query latency.

Prepare with a clean SDK checkout at fdb7206517c249603b0c91b65f1f29f95272107c:

    ./experiments/spiral-cache-core/run.ps1 -SdkDirectory <pinned-sdk> -Mode prepare
    ./experiments/spiral-cache-core/run.ps1 -SdkDirectory <pinned-sdk> -Cargo <cargo> -CargoHome <cache> -TargetDirectory <dedicated-target> -Mode check
    ./experiments/spiral-cache-core/run.ps1 -SdkDirectory <pinned-sdk> -Cargo <cargo> -CargoHome <cache> -TargetDirectory <dedicated-target> -Mode bench

Retain the reviewed package Cargo.lock before check/bench. The prepared package
lives in ignored .local/spiral-cache-core; source manifests record hashes. This
safe scheduling follows the pinned SDK's MIT-licensed server.rs:320-356; all
mathematical operations and exact native packing are compared against that control.
Five owning tests and authored strict Clippy pass. Three fresh processes per variant measure pair preparation at 214.838–228.315 ms serial versus 49.665–51.638 ms parallel; this is not full query latency. See [the measured report](../../docs/experiment-spiral-cache.md) for native memory, evidence and remaining integration work.

The upstream copyright and permission notice is retained in [LICENSE-BLYSS](LICENSE-BLYSS).
