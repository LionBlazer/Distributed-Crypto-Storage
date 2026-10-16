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


Current compact-query private index v3 adds encrypted stable TableId/RowId metadata.
The million-row index is now 34,416,624 encoded bytes; old index-expansion and
memory measurements predate that format. The local disk consumer retains the
expected logical TableId with its trusted heads and admits images up to the
unchanged compact-store 64 MiB bound. This API adaptation is not a rerun of the
historical TFHE workloads or evidence for their previous resource numbers.
