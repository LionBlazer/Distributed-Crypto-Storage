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
It runs actual FHE operations on local encrypted shards. The SQL frontend supports
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
[.zed/tasks.json](.zed/tasks.json). The GUI requires Rust 1.95 or newer; the Zed task
uses the built-in Windows PowerShell and rustup.

The integration branch is `master`. [AGENTS.md](AGENTS.md) defines task branches,
automatic commit and push after each completed change, synchronization from master,
and explicitly requested promotion back to master. Project skills live in
[.agents/skills](.agents/skills).
