# Core workloads

Standalone public-fixture measurement programs for the reusable storage/query
libraries. These programs were moved out of core package example targets; they
do not implement a protocol or provide a production entry point.

| Direct dependency | Role |
| --- | --- |
| [compact-store](../../crates/compact-store/README.md) | Authenticated encrypted page lifecycle |
| [compact-query](../../crates/compact-query/README.md) | TFHE selection, aggregation and checked writeback |

Rayon configures CPU workers; serde_json writes measurement reports. The examples
`compact_lookup`, `compact_query`, `index_storage`, `key_amortization` and
`disk_tables` retain their existing CLI options. Run, for example,
`cargo run --release --locked -p core-workloads --example compact_lookup` from
the repository root. Measurements and generated datasets stay in ignored `.local/`.
