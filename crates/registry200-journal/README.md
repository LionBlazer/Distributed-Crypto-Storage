# Registry200 Journal application

This is the concrete private-control application for
[version-journal](../version-journal/README.md). It reconstructs exact expectations
from the actual validated parent and verifies genuine Source/Lifecycle proofs
through [registry200-proof](../registry200-proof/README.md). Its other direct
dependencies are compact-store for canonical public head geometry and SHA256 for
the preserved application/request identities.

ApplicationDescriptor owns the fixed 312-byte DCSLFA01 descriptor: network32,
distinct source/control IDs, both 112-byte original heads and canonical C_key,
preceded by magic8. Both fixed N4 schemas, same database and storage key-domain
are checked before an application exists. The application identity includes the
actual fixed proof-contract fingerprint and excludes G/q/C_open/C_cmd. Genesis
must pin exactly the sorted Source+Pending initial state. No caller-provided
verifier/configuration/receipt is accepted.

Request is the unchanged canonical 2716-byte DCSLFJ01 codec. Its preproof intent
query binds application/G/actual parent/nonce/enrollment/phase before C_open/C_cmd.
The signed request commits complete 60/2384-byte packets and opaque C_cmd; it does
not prove exact SQL parsing or controller-signature possession.

RegistryVerifier::new revalidates the application and exact independently pinned
Genesis. Its TransitionVerifier checks actual G/parent/state roots, exactly two
sorted shards, immutable complete Source, one control CAS, sticky enrollment and
all original request fields. It then genuinely verifies both proofs under sealed
expectations and matches the next control head. Unchanged-root WAIT/NOWAIT
evidence cannot append; failed Commit resolving EndAbort may mutate. Control heads
re-encode both complete 112-byte manifests including reserved zeros.

The ordinary Journal checks strict owner authorization before this verifier,
publishes state only after validation, and re-verifies stored transition proofs
on durable reopen. Calling this verifier directly establishes computation
consistency only. Valid forks are permitted under their actual validated parent;
freshness/reorganization is a separate client decision. The library does not
select a current tip, claim decentralized agreement, expose private owner state,
enforce data-writer locks or admit SQL answers. N4/T2/D2, immutable Source and
bounded 256 MiB full history remain explicit restrictions.

The descriptor/runtime integration and genuine two-peer control flow are covered
by the [validation record](../../experiments/hiding-fri-sha256-gate/REGISTRY200-PEER-CONTROL-VALIDATION.md).
Existing proof/body/history limits are unchanged.
