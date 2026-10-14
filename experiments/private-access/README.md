# Private-access research harnesses

These opt-in, headless programs compare visible and concealed retrieval using
public synthetic records. They are research executables outside the Cargo
workspace, with isolated generated manifests and pinned upstream source under
ignored .local/private-access. The programs print JSON measurements, never keys or
database files. Run CPU experiments serially.

| Direct dependency | Responsibility |
| --- | --- |
| [compact-store](../../crates/compact-store/README.md) | Existing owner AEAD sealing, Merkle proofs, bounded page decoder and snapshot replacement in the Spiral experiment |
| [Blyss SDK, exact revision](https://github.com/blyssprivacy/sdk/tree/fdb7206517c249603b0c91b65f1f29f95272107c/lib) | Unmodified DoublePIR/Spiral cryptographic primitives |
| TFHE-rs 1.8.1 | Fresh encrypted fields and real conditional COUNT/SUM/increment in the composed probe |
| Cargo and project-local dependency cache | Build only the selected standalone probe; root workspace remains unchanged |

doublepir_probe.rs measures a genuine private retrieval of one raw AES-masked
three-byte row out of a million. It uses the upstream 24-bit integer interface.
It has no page authentication or mutable database API.

spiral_page_probe.rs privately fetches a complete existing compact-store page and
its Merkle proof inside a fixed 8192-byte PIR record. The same one-million-row
fixture is grouped into 2048-row pages. It records cold RAM-cache construction,
warm fetch, a separate visible-address control, replacement/rebuild, corruption,
wrong-address, omitted-response and stale-proof rejection. The NTT database cache
is explicitly retained in RAM and never persisted by the harness. Owner AEAD and
PIR secrets are not inputs to the server function. Owner and peer roles share one
benchmark process, so memory is whole-process memory, not isolation evidence.

Use run-doublepir.ps1 or run-spiral-page.ps1. Both accept Rows, Rounds, Threads,
Cargo, CargoHome, TargetDirectory and Offline. Initial use clones the exact public
SDK revision and may download project-local Cargo dependencies. The runner checks
the pinned source and copies its committed dependency lock before building.
It restores process environment variables on exit and installs no global tools.

The page probe retains authored ring/noise/decomposition parameters while choosing
512-record database geometry. Its Gaussian width is not the standard deviation;
the JSON output records both. The upstream SDK is unaudited. Neither program
implements a network protocol, SQL index, FHE SQL computation, computation proof,
consensus freshness or hidden writes. Direct key availability, routing/timing
leakage and any visible retry policy need separate protocol work.

Read [the experiment ledger](../../docs/experiment-private-access.md) for measured
results, source references, full byte accounting and reproduction commands.

spiral_fhe_probe.rs and run-spiral-fhe.ps1 compose actual authenticated known-row
page retrieval with fresh owner-prepared TFHE inputs and real peer execution.
The separate SpiralFhe.Cargo.lock pins this opt-in build. It compares visible and
private retrieval on identical inputs and measures overflow refusal, compact
writeback and complete PIR cache rebuilding. The evaluator receives no original
stored bytes, nonce or row/page address. The owner is online and reads its own
selected plaintext; hidden SQL index navigation and computation proofs remain
absent. See the [complete pipeline measurements](../../docs/experiment-private-fhe-pipeline.md).

The [indexed private-access probe](README-index-fhe.md) additionally navigates the
real encrypted PaddedV2 age index before retrieving data. It compares visible and
private access with both exposed cardinality and a fixed sixteen-slot schedule,
including authenticated dummy reads, absent/duplicate groups, cached/uncached
headers and an actual owner-authorized compact replacement with cache rebuilding.
Its separate codec adaptation and lockfile do not change the main library APIs.
See [all 64 complete query measurements](../../docs/experiment-private-index-fhe-pipeline.md)
for the bounded workload, leakage, full byte accounting and missing query proofs.
