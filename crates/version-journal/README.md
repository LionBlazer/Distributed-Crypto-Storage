# version-journal

Bounded validation and persistence of an internal cumulative-work journal of
encrypted database commitments. No peer identity or owner signature contributes
mining weight. The module has no direct project-module dependencies; applications
provide their cryptographic proof backend through `TransitionVerifier`.

Implemented public entry points:

- `Genesis` pins network/database identity, owner Ed25519 authorization key,
  application crypto/profile commitment, initial opaque shard heads and the entire
  `ProtocolProfile`. It must be obtained independently of the responding peer.
- `Header` uses a canonical 192-byte wire and SHA256d work against the exact
  unsigned big-endian 256-bit target. `mine(attempts)` performs actual bounded work;
  applications own scheduling and cancellation between chunks.
- `Body` is either an empty confirmation block or one atomic authorized transition
  with sorted old/new shard-head pairs, exact request, proof and owner signature.
  Its canonical codec bounds lengths before allocation and rejects trailing bytes.
- `Journal` verifies work, branch-specific target transitions, timestamps,
  authorization, parent-state continuity and application proof before publishing a
  validated state. Header-only synchronization never publishes a database head.
  `validated_blocks` returns borrowed bodies in topological order for RPC adapters.
- `resolve(Exact/AtLeast/LatestConfirmed)` checks confirmations and ancestry;
  `shards(head, policy)` rechecks the condition, including after reorganizations.
  `validated_shards` is expressly unconfirmed protocol state, not a freshness gate.
- `DurableJournal` holds an exclusive OS file lock, validates before append,
  `sync_all`s before in-memory publication, and revalidates records on reopen
  against an independently pinned genesis. Incomplete or tampered tails fail closed.

## Consensus rules

Height zero is the independently pinned genesis with zero cumulative work. Each
accepted block contributes `floor(2^256 / (target+1))`; the greatest cumulative work
wins. Equal work uses the lexicographically smaller header hash as a deterministic
tie-breaker. A longer lower-work branch loses. The journal reports detached and
attached paths on reorganization; confirmation is probabilistic, never finality.

Heights `1..=I` use the initial target. At height `k*I+1`, the parent target is
multiplied by the timestamp difference between heights `k*I` and `(k-1)*I`, divided
by `I*block_spacing_secs`, with exact integer flooring. Elapsed time is clamped to
`ceil(expected/4)..=4*expected`; the resulting target is clamped to `1..=pow_limit`.
All other heights inherit their parent target. These rules are pinned, have no
compact-target rounding and use the candidate's own branch.

Every block timestamp must exceed the median of up to 11 preceding branch
timestamps and must not exceed caller-supplied UTC seconds plus the pinned future
allowance. Applications supply a trustworthy clock. Timestamp drift/grinding,
propagation delays and adversarial effective hashpower still require quantitative
analysis. There is deliberately no production default target, block time or
confirmation count. Easy test work demonstrates behavior only.

Honest partitions can continue on competing branches. Reconnection can replace a
previously confirmed branch; read-after-write tokens then return `Reorganized`.
Missing bodies on the strongest observed header branch return `BodyUnavailable`;
larger version numbers or old valid proofs never satisfy a descendant requirement.
`LatestConfirmed` means the synchronizer's validated branch under honest network
reachability assumptions. The module cannot discover an eclipse or rule out unseen
newer work during an arbitrary partition.

## Proof boundary

The owner authorizes database changes and can delegate client-side verification;
the owner is not a fixed mining committee or a peer-admission server. The signature
binds the genesis, parent, complete old/new update batch, exact request digest and
proof digest. Invalid signatures fail before calling the proof backend.

`TransitionVerifier` must verify genuine cryptographic execution proofs with exact
application, job, request and commitment bindings. The only provided adapter is
`RejectUnprovedTransitions`, which rejects all mutations. There is no accepting
placeholder or hash/signature substitute. Empty blocks require no SQL proof because
they preserve the complete database state exactly.

The journal is generic: it cannot establish a private AEAD compact-root to FHE-input
linkage by itself. In an owner-finalized application, the owner must first verify
authenticated complete selection, FHE proofs, decrypted output and compact-store
finalization before signing new roots. Public journal verification of exact FHE
jobs and owner-finalized root publication does not itself prove all private SQL
semantics. Query acceptance still needs the application's separate completeness
and freshness gates. No positive SQL transition test is fabricated in this module;
the owning application must test it with its actual proof backend.

## Bounds and persistence limits

The genesis pins header/shard/body/proof/request limits and a metadata budget up to
256 MiB. The journal stores every validated branch's state and proof body, charging
bounded state/payload/container overhead. Reaching a cap rejects additional records;
no pruning, checkpoint finality or permissionless production scalability is claimed.
RPC adapters must additionally bound aggregate responses and admission work.

Durable append flushes file contents/metadata before publication; filesystem/device
power-loss guarantees and parent-directory entry durability depend on the host.
A crash during append may leave a rejected incomplete tail; automatic crash-tail
repair, snapshots and pruning are not implemented. Journal publication is separate
from atomically installing the corresponding encrypted storage images. Applications
must retain and validate those images and handle reorganizations before serving a
new head. A valid root does not prove data availability or independent replicas.

## Verification

From the repository root:

```sh
cargo test --release --locked --offline -p version-journal -- --test-threads=1
cargo clippy --release --locked --offline -p version-journal --all-targets -- -D warnings
```

Contract tests cover exact targets/work, retargets, shorter higher-work forks,
timestamps, confirmation/ancestry, reorganizations, unavailable bodies, replay and
authorization rejection, proof rejection without publication, bounded canonical
decoding, persistence reopening/corruption and exclusive lifecycle ownership.
