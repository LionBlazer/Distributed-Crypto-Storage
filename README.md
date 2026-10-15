# Distributed Crypto Storage

Research and development of distributed encrypted SQL storage on participant-owned
computers. The target system combines encrypted storage and FHE query processing,
replication and recovery, and verifiable results from untrusted peers.

[REQUIREMENTS.md](REQUIREMENTS.md) contains the target requirements, open questions,
and research references. Their joint feasibility and resource costs still need to
be validated.

The first [Rust FHE prototype](crates/fhe-prototype/README.md) uses TFHE-rs to filter
an encrypted table, compute COUNT/SUM, update encrypted amounts, and compress and
reload the table. It is a local experiment with a fixed schema, not a distributed
SQL implementation. Cryptographic query proofs and production protocols remain
open choices.

With Rust installed, run from the repository root:

```sh
cargo run --release --locked -p fhe-prototype -- --rows 4 --cycles 2 --threads 2
cargo test --workspace --release --locked -- --test-threads=1
```

The executable prints a JSON report with timings, ciphertext sizes, and process
peak memory. Synthetic data and reports go into ignored `.local/fhe-runs/` folders;
secret keys are generated in memory and are never written to disk. See the module
README for measurement assumptions, limitations, and the API.

The separate [GUI playground](crates/fhe-playground/README.md) provides an egui
client/manager, editable test data, SQL presets, up to 16 simulated peers and 8 clients.
It uses compact encrypted pages and an owner-assisted encrypted index, converting
selected rows to FHE only for the current operation. The SQL frontend supports
only the documented aggregate/update subset; peer simulation runs in one process.
SQL/data occupy the left pane, with the network and node inspector tabs on the right.
The map and dense connection matrix display the same actual links and packet events.
Presets fill the editor; execution requires Run or Ctrl+Enter.

The separate [peer-protocol](crates/peer-protocol/README.md) crate owns a bounded,
transport-independent handshake/message state machine. The playground supplies
virtual time and in-process delivery. Production networking, authentication,
consensus and automatic replication remain open work.

```sh
cargo run --release --locked -p fhe-playground
```

In Zed, use `task: spawn` and select **FHE: Open GUI playground** from
[.zed/tasks.json](.zed/tasks.json). The GUI requires Rust 1.99 or newer; the Zed task
uses the built-in Windows PowerShell and rustup.

The experimental [compact-store](crates/compact-store/README.md) crate separates
owner-only encryption keys from opaque peer pages and authenticates direct page
retrieval against an independently known version root. Its fixed-width page
replacements retain constant live encoded size. It currently exposes requested
page addresses and does not implement FHE, SQL completeness proofs, or concealed
access.

The [compact-query](crates/compact-query/README.md) crate composes those pages with
complete age-index selection, genuine FHE COUNT/SUM and overflow-safe amount
updates, followed by compact owner-assisted writeback. The GUI selects its explicit
BFV exact-index module and shares public evaluation keys across simulated peers.
The reusable [BFV core](crates/bfv-query-core/README.md) owns the arithmetic;
the legacy TFHE module retains its broader full-scan/coarse-candidate semantics.
It remains an explicitly unverified local experiment with visible addresses;
owner availability, general SQL, concealed index execution and computation proofs
remain open. See the [measurement ledger](docs/optimization-goal.md) for measured
costs, including indexes, keys and memory.

The [headless GUI/SQL measurement](docs/experiment-bfv-gui-integration.md) exercises
the actual LabEngine on 128 public fixture rows with 1, 3 and 16 peers. All 147
aggregate/update/overflow operations are exact and below 500 ms, maximum 383.8544 ms;
native peak process commit is 246,702,080 B. Setup is separate, virtual network delay
is zero, and the fixture oracle runs after the query timer. This is a visible-access
SQL subset measurement; its tiny-table metadata/key overhead is not a new 2x result.

The separate [exact-index BFV disk probe](experiments/private-bfv-exact-disk/README.md)
measures private PIR and capacity-one disk loading separately from the GUI. On 1,000
independent million-row tables (3 GB logical), actual files plus native peak process
commit total 1.816303x. Its 384 exact-index queries take at most 45.008 ms with
visible access and 351.110 ms with private PIR, including application-cache misses.
Selections are bounded to 256 rows and one posting/data page, with the owner online;
OS file cache is allowed. Network, arithmetic proofs, general SQL and complete
owner restart are outside this [paired result](docs/experiment-private-bfv-exact-disk.md).

The [BFV disk UPDATE experiment](experiments/private-bfv-update-disk/README.md)
adds genuine encrypted addition and compact writeback. Its actual 1,000-table run
retains constant file sizes after 126 positive commits; files plus native peak
process commit are 1.814285x. In 100 point cycles, UPDATE through commit/invalidation
takes at most 316.162 ms, and the compound including readiness and a separate fresh
SELECT reaches 635.367 ms. The [full report](docs/experiment-private-bfv-update-disk.md)
retains every slow mode and the same unverified, online-owner, local-transport limits.

The separate [owner recovery candidate](experiments/owner-recovery-candidate/README.md)
restores dropped original owners from a sealed checkpoint and reuses the same
encrypted files and original BFV/PIR public setups. Its 66 runtime tests and two
doctests pass; cross-process restart and durable checkpoint publication remain
separate work. The [validation report](docs/proposal-owner-recovery-candidate.md)
records external wrapping-key custody and the bounded three-table fixture.

The integration branch is `master`. [AGENTS.md](AGENTS.md) defines task branches,
automatic commit and push after each completed change, synchronization from master,
and explicitly requested promotion back to master. Project skills live in
[.agents/skills](.agents/skills).
