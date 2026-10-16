# Finality boundary for PostgreSQL row locking

Status: source review on 2026-10-16, not an implemented or selected consensus
protocol. [REQUIREMENTS.md](../REQUIREMENTS.md) remains unchanged. Live SQL locks
are still rejected. The [PostgreSQL contract](postgresql-contract.md) records the
other missing SQL, encrypted-candidate and transaction boundaries.

## Why the current journal is insufficient

The current [journal fork choice](../crates/version-journal/src/chain.rs) permits
competing cumulative-work branches. Two branch-local valid reservations can each
reach the configured confirmation depth. A later reorganization cannot undo a
queue consumer's external action. More confirmations, a signed receipt or a
peer-local mutex therefore do not establish PostgreSQL mutual exclusion.

The existing [transaction-state](../crates/transaction-state/README.md) verifies
bounded public control transitions. `MetadataVerifier::verify_control` accepts
only its one metadata shard, authenticates the exact previous state and signed
intent, and preserves all other shards. `VerifiedControl::matches_request` binds
the receipt to the pending request. These are useful existing checks, but the
verifier intentionally cannot authorize data changes or prove the complete
encrypted candidate set. WAIT currently returns `Blocked`; it does not commit
waiters, detect deadlocks or recover a crashed SQL session.
Current `JobVerifier` proves BFV arithmetic and exact job/head binding. Private
AEAD/index-to-FHE preparation and completeness remain the designated owner's
responsibility; a public encrypted-candidate/control relation does not yet exist.

## One conditional research candidate

PoW-elected reconfigurable BFT following Solida is a candidate. The acting
committee finalizes both decisions and its replacement; longest accumulated work
does not replace finalized slots. Conditions include `n = 3f + 1`, at most `f`
Byzantine members in every committee, a known end-to-end delay bound `Delta`,
expected work interval `D` well above `Delta`, and corruption slower than committee
tenure. Slow or partitioned resource counts toward the fault budget. The paper
assumes a known, sufficiently honest genesis committee. Its committee-election
guarantee is probabilistic, requiring the effective adversarial
ratio `rho' = 1 - (1 - rho) exp(-(2 rho + 8) Delta / D) < 1/3`; population-wide
`rho < 1/3` alone is insufficient. See [Solida, sections 1.2, 3 and 4.5](https://drops.dagstuhl.de/opus/volltexte/2018/8640/pdf/LIPIcs-OPODIS-2017-25.pdf).

This leaves concrete requirements unresolved. A physical host can own several
work seats, so per-key limits do not establish survival of one host's departure.
The failure model must bound correlated unavailable weight. Ordinary Ed25519
historical keys also require a corruption model: a persisted finalized floor
protects an existing client, but a new client has no such floor against forged
old certificates after key compromise. These are engineering inferences, not
security guarantees supplied by the current repository. A trusted owner arbitration
service or invitation-only committee would not resolve the requested contract.

## Proposed repository boundary

This is a design for review, not a list of existing APIs:

- Keep a typed `FinalizedHead` and bounded finality certificates distinct from
  cumulative-work `HeadRef` and buried `Freshness`. A valid old certificate alone
  does not prove a current head; reads need an authenticated fresh barrier and a
  monotonic finalized floor.
- Reuse the exact authorization, old/new shard-set and application-verification
  checks in `Journal::prepare_state`/`apply_changes` before voting. Retain genuine
  BFV job-proof verification and add the missing complete encrypted-candidate and
  data/control relation. Certificates cannot replace computation proofs.
- Bind each decision to network/profile, configuration, lifespan, view, slot, parent,
  body hash, state root and membership root. A work ticket must bind its public
  key and the exact finalized challenge; the same paid work cannot mint extra
  seats by changing TLS identities.
- Implement the complete proposal, prepare, commit, view-change and ranked
  reconfiguration protocol. The old configuration must finalize its closing state
  and successor configuration before the successor votes. A threshold-signature
  wrapper around current fork choice is insufficient.
- Persist vote locks before sending votes. The existing
  [durable journal](../crates/version-journal/src/durable.rs) validates and fsyncs
  blocks before publishing them, but does not record prepared/committed vote locks.
  A separate bounded vote WAL needs crash-safe replay and fail-closed corruption.

SQL integration additionally needs a composite data/control verifier: stable
private row identities, complete ordered candidates, actual conflicts and skip
reasons, lock ownership for every write, and one atomic multi-shard COMMIT. WAIT
needs an authenticated bounded wait graph and ordered abort decisions. After a
wait, isolation-specific predicate and version rechecks still apply.

Disconnect cannot prove global session death. Release, rollback and abort must be
agreed before an incompatible grant. Any timeout/renewal policy needs explicit
generation fencing and exact recovery of ambiguous outcomes. PostgreSQL exposes
separate transaction, lock and idle-transaction timeouts, disabled by default;
silently introducing a local lease changes that behavior. See [client defaults](https://www.postgresql.org/docs/18/runtime-config-client.html).

## Decisions and evidence still needed

Before treating this candidate as the live lock contract, establish the Byzantine
and unavailable resource budget, independent failure assumptions, delay/partition
policy, committee size and lifetime election-risk bound, honest bootstrap,
historical-key model, isolation and dead-session policy. No numerical choice or
500-ms/scaling claim is established by this research.

The first implementation gate would exercise conflicting views and proposals;
crash/restart after preparing; duplicate work tickets; concurrent reconfigurations
and old/new cutover; stalled partitions without quorum shrinking; immutable
finalized prefixes despite heavier work forks; invalid computation/authorization
under otherwise valid certificates; stale barriers; lost grant acknowledgements;
abort/renewal races and fenced old writers; and omitted conflicts or SKIP LOCKED
candidates. These tests must accompany the actual protocol, not stand in for it.

Storage/query optimizations can proceed independently while these requirements
remain explicit. No current SQL operation accepts a metadata receipt, transport
acknowledgement, timeout or decryption as a substitute for the required proof.
