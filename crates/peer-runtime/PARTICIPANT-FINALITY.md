# Original Registry participant host

This host composes the existing closed Source/Lifecycle finality actor with an
explicit participant workspace. The [native validation](../../docs/participant-finality-host.md)
passed with four independent daemon processes. It grants no SQL capability or
hidden-predicate lock. The independently pinned
bootstrap work roster is fixed; system-lane work admission, epoch activation and
freshness barriers remain separate work.

## Ownership and dependencies

| Owner | Responsibility |
| --- | --- |
| [`protocol-storage`](../protocol-storage/README.md) | Exclusive participant root, complete inventory and one global/class ledger |
| [`registry200-finality`](../registry200-finality/README.md) | Actual Journal/body/owner/Source/Lifecycle/QC verification, signer WAL and floor |
| [`finality`](src/finality/README.md) | Bounded TLS frames, sole actor, local monotonic timers and sequential catch-up |
| [`peer-transport`](../peer-transport/README.md) | Actual mutually authenticated TLS and bounded frames |
| [`dcs-peer`](../../apps/dcs-peer/README.md) | Local process bootstrap and joined stdin-EOF shutdown |

`ParticipantBootstrap::read` consumes exactly four transport frames from local
trusted IPC. It exposes no signer getter, clone or serialization API:

1. At most 64 KiB of strict JSON with version 1 and kind
   `registry200-participant-finality-v1`: TLS `identity`, `authority`, authorized
   submission `owner` fingerprint, `listen`, at most 16 unique `neighbors`,
   independent local `namespace` and total `capacity`, independent `work_genesis`,
   `journal_genesis`, `binding` digests, complete `rules` and exact 32-byte `signer`.
2. Bounded canonical WorkGenesis bytes, checked against the independent work ID.
3. Exactly 716 canonical JournalGenesis bytes for the original two-shard app,
   checked against its independent G.
4. Exactly 312 canonical application-descriptor bytes. Reconstructed rules and
   complete Binding must match the independently supplied binding ID.

`rules` contains `max_round`, `timeouts_ms` (three values), `timeout_delta_ms` and
`wal_bytes`. The seed is privately owned and guarded during JSON decode. Original
TLS `Identity` retains its existing ownership/erasure contract. No FHE/storage
secret or private proof opening belongs in this bootstrap. The local config is a
trust input, not a network evidence format; a received `ParticipantReady` is only
an observation, never independent proof or current freshness.

`ParticipantHost::bind(path, New|Existing, config)` first validates TLS material,
then creates or opens exactly the participant profile. All control/depot/custody
files are inventoried before admission. One actual `ProofGate` is allocated by
this trusted host, used during full original proof replay, and moved into the
same TLS actor. No dummy `PeerServer`, parallel verifier gate or second quota is
created. `spawn` publishes Ready only after storage initialization/replay and
listener startup; `RunningParticipant::stop` joins the actor and any current
nonpreemptible proof before releasing signer and root ownership.

Every real control-file creation has its one preflight permit, and every append
precharges its absolute extent. The metadata-last storage contract is described
by `registry200-finality`. Ambiguous creation or owned I/O poisons the shared
ledger, including depot/custody reservations. Ordinary refusal while a requested
path is still proven absent need not poison it. Reopen is strictly existing-only;
no compatibility import, silent repair or missing-file recreation exists.

This host currently activates only original Registry finality. Retained depot
and custody artifacts are inventoried and charged, but no depot/custody RPC owner
is launched here. The legacy custody-v2 service and its namespace remain separate.
Logical file accounting excludes filesystem metadata and directory overhead.

## Executed owning tests

Three bootstrap unit cases cover declared predecode bounds, private seed length
and neighbor bounds/duplicates. Three closed-adapter filesystem/QC cases cover
metadata-last reopen/deleted WAL, late quota refusal and cross-class poison.
Two compile-fail examples cover private bootstrap ownership. The new
`apps/dcs-peer/tests/participant_finality.rs` launches four actual daemon processes
with public nonsecret fixtures, builds real Source/Bootstrap/Begin/Acquire/End
proofs, and exercises competing candidates, 2+2 no quorum, heal/reopen, one offline
validator, blocked WAIT/NOWAIT and a fresh independent keyless follower. It uses
test-local bounded GetBlock decoding and sequential public Follower verification;
it does not invent a client scheduling gate. A dedicated client-only scheduling
owner is future API integration work. All seven new runtime cases, two new
ownership examples and the existing affected library cases passed. The four-OS
scenario passed in 930.97 seconds of test runtime; this is a proof-bearing
control-history scenario, not SQL latency. The native record gives source hashes,
resource observations and remaining freshness/hidden-FHE limitations.
