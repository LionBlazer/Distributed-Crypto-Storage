# Experimental peer process lifecycle

This module owns one explicitly named independent `dcs-peer` child for research
consumers. It contains no SQL, Registry, BFV proof or acceptance policy. Callers
must finish their actual prerequisite verification and control checks before
`ProcessPeer::start`, which already performs Probe and encrypted-object Store I/O.

`mod.rs` owns the sole stdin writer, bounded endpoint reader, 64 KiB retained
stdout/stderr drains, remote PID check, Shutdown/EOF completion and kill/wait/reader
join on failure or Drop. `directory.rs` exclusively creates one canonical child
and checks the resolved immediate target before recursive cleanup. `identity.rs`
creates ephemeral test TLS credentials; it never receives BFV secrets. The fixed
research daemon quota remains 64 MiB. EOF completion uses the existing daemon
`--exit-on-stdin-close` contract; it is not cancellation inside an SDK proof.

Direct dependencies are [peer-runtime](../../../../../crates/peer-runtime/README.md)
for the actual process protocol, [peer-transport](../../../../../crates/peer-transport/README.md)
for bounded bootstrap framing, `rcgen` for test TLS identity and the standard process
and I/O APIs. Generic libraries do not depend on this experiment.

`testing.rs` is an explicit TLS server-thread fixture used only by owning tests.
It is never selected as a fallback by a live CLI. Both the historical
[returned-formation job](../locking/formation/job/README.md) and the new
[Registry200 job](../registry_lifecycle/formation/job/README.md) use this single
lifecycle owner. No new native result or resource guarantee is claimed by the
source-only extraction.
