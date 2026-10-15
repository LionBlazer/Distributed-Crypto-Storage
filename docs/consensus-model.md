# Consensus direction for an open storage network

Status: bounded validation, durable peer journals and client integration implemented;
production resource/security parameters and autonomous mining/discovery remain open.
This is not a claim that all requirements are jointly achieved.

The user requires free peer admission, no invitation authority, and no dependence
on a third-party consensus network. The user delegated the resource-model choice.
We select an internally operated Nakamoto-style **cumulative-work metadata journal**
as the first direction to implement and evaluate. No token, issuance, payment
mechanism, fixed validator roster, or final security parameters are selected.

## Scope and trust boundaries

The journal orders commitments to authorized database state transitions. It does
not store the complete database on every peer, decrypt SQL data, or replace FHE
execution. Peer identities alone confer no consensus weight; a valid work proof
contributes according to its verified target, not the advertised CPU or disk size.
Fork choice uses accumulated validated work, not block count or signatures counted
as votes. The database owner authorizes writes; the owner is not an always-online
ordering server or an invitation authority for infrastructure peers.

Accepting a query answer or publishing a mutation requires all three gates:

1. **Authorization:** the request and state transition have the necessary rights;
   an owner signature is authorization, not an execution or freshness proof.
2. **FHE correctness and completeness:** a genuine cryptographic proof binds the
   exact request, input state commitment and encrypted output; omitted matching
   records or an incorrect transition must fail verification without rerunning SQL.
3. **Fresh agreed head:** the state is committed in the validated journal under
   the requested freshness and confirmation policy, checked separately from FHE.

TLS, a checksum, successful decryption, a locally cached owner head, or work on an
invalid transition satisfies none of the missing gates. Journal validators must
reject unauthorized or unproved transitions regardless of their work. Missing
computation proof or unavailable agreed state remains a hard rejection.

## Security assumptions that still need quantitative choices

- Honest participants must continuously contribute sufficient effective hashpower
  relative to an adversary. Security depends on work, not the number of people or
  processes. Required margins and the minimum honest resource budget are unchosen.
- Honest communication must resume with sufficiently bounded propagation delays;
  block timing must be evaluated against that bound. A client must reach the honest
  network rather than remain eclipsed by attacker-controlled connections.
- Clients need a pinned network identity, genesis and protocol profile. Header,
  target, difficulty-adjustment, timestamp, transition-validation and fork-choice
  rules must be specified and validated together; a hash puzzle alone is not them.
- Hash and signature security, protected authorization keys and an explicit clock
  model are necessary. CPU/ASIC advantages, rented hashpower, energy cost and honest
  participation without a chosen reward system remain unresolved.

These are conditional guarantees. No attacker fraction, confirmation depth,
rollback probability or numerical delay is established here. Any proposed values
must remain unvalidated until the complete model and measurements justify them.
[Nakamoto's paper](https://bitcoin.org/bitcoin.pdf) supplies the cumulative-work
starting point, not a security analysis of this database protocol.

## Confirmation, partitions and freshness

Nakamoto confirmation is probabilistic: a sufficiently strong competing branch
can reorganize previously observed history. A partition can produce competing
branches; eventual reconnection does not make both histories final. Writes must
not be reported as confirmed without the selected confirmation policy, and reads
must fail or wait when their freshness condition cannot be established. Never
silently downgrade a request to an older snapshot to preserve availability.

Freshness modes must identify what the caller actually needs:

- **Exact root:** execute against a specific agreed snapshot commitment. This is
  explicit snapshot selection, not evidence that no newer state exists.
- **Minimum head:** require the requested head or a valid descendant on the
  confirmed branch. A larger version number on an unrelated fork is insufficient.
- **Read after write:** a confirmed write supplies its head reference; subsequent
  reads use it as their minimum. A reorganization or missing confirmation must be
  surfaced rather than silently reading an ancestor or claiming absolute finality.

References include the network and database identity, head hash and state root.
The exact confirmation and maximum-age contracts remain to be specified. A query
proof for an old root stays a correct computation proof while failing a newer-head
requirement. Persistent metadata synchronization can establish a client's current
validated branch; it is not comparison of several peers' SQL answers.

An unconditional claim of the globally latest version is unavailable during an
arbitrary partition, eclipse or unbounded message delay: unseen newer data cannot
be ruled out by an old proof. This observation does not relax requirement 13;
unmet requested freshness must prevent acceptance. Read latency for an already
confirmed snapshot and confirmation latency for a new write must be measured
separately, with no current promise of 50-100 ms final write confirmation.

## Why storage proofs are separate

PDP/PoR storage challenges do not by themselves prevent colluding identities from
sharing a copy. Filecoin introduces replica-specific encoding and timed proofs for
this problem; possession also does not identify independent physical failure
domains. [Filecoin's whitepaper, section 3](https://filecoin.io/filecoin.pdf), and
the [storage-proof specification](https://spec.filecoin.io/algorithms/pos/) describe
the distinction. Such proofs can support storage-service verification, but are
not selected as identity weight or proof of SQL computation here.

Filecoin's [Expected Consensus](https://spec.filecoin.io/algorithms/expected_consensus/)
also needs historical power tables and drand randomness. Its examined EC version
has a protocol-specific attack threshold, not a generic disk-majority guarantee
([AFT 2023 analysis](https://arxiv.org/abs/2308.06955)). Its production sealing
[resource profile](https://lotus.filecoin.io/storage-providers/get-started/hardware-requirements/)
does not demonstrate operation within this project's 1-2 GB RAM and 10-30 GB quota.

Chia adds VDFs and defenses against grinding and history construction to space
proofs ([greenpaper](https://docs.chia.net/files/ChiaGreenPaper_20241008.pdf)). Its
plots do not contain database data, and
[PoSpace 1.0](https://docs.chia.net/chia-blockchain/consensus/proof-of-space-1.0/)
has a minimum plot larger than our quotas. The
[PoSpace 2.0 status](https://docs.chia.net/chia-blockchain/consensus/proof-of-space-2.0/new-proof-introduction/)
explicitly describes an unfinished design. Smaller test parameters cannot inherit
the security of either production system without a new analysis.

## Implementation boundary

The [version journal](../crates/version-journal/README.md) now validates bounded
forks, real work, retargets, timestamps, owner signatures, complete transition bodies,
ancestry and confirmation policies. Persistence fsyncs before publication and
revalidates against a pinned genesis on reopen. [Peer runtime](../crates/peer-runtime/README.md)
provides actual mining/publication/synchronization RPCs and neighbor propagation.
[Session](../crates/storage-client/README.md) checks confirmed heads before and
after queries, and publishes mutations after genuine FHE proofs and complete private
selection. Public job validation and private owner AEAD finalization remain separate
obligations. This is not a public proof of AEAD decryption.

Contract tests cover retargets, cumulative-work forks, partitions/reorganizations,
unavailable bodies, replay, proof rejection and durability. Real-process tests cover
SELECT/INSERT/UPDATE, failed mutations and read-after-write across peer restart.
Mining runs in bounded requested RPC chunks. There is no autonomous production
mining/discovery service or quantitative adversarial resource budget. Easy playground
work demonstrates behavior only. The complete profile is caller-pinned, with no
production defaults; all FHE proof and mutation-acceptance gates remain mandatory.

The existing targets remain unchanged: CPU baseline, 1-2 GB RAM for the entire peer,
10-30 GB disk quotas, compact encrypted storage, and independently recoverable data
replicas. Neither journal confirmation nor a storage proof establishes data
availability. Measure these properties and the full proof/SQL cycle separately
before claiming compliance; do not hide journal growth or proof costs as free.
