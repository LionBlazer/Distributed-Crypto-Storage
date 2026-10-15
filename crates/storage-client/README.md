# Storage client

The owner's real-network composition. It retains the sole compact/BFV owner and
independently trusted object heads. Peer storage and FHE execution are reached
through authenticated RPCs; no evaluator is used locally to answer a query.

| Direct project dependency | Responsibility |
| --- | --- |
| [sql-plan](../sql-plan/README.md) | Typed statement plans, without plaintext execution |
| [compact-query](../compact-query/README.md) | Authenticate exact selection and prepare fresh BFV inputs |
| [compact-store](../compact-store/README.md) | Exact trusted heads and bounded canonical formats |
| [peer-runtime](../peer-runtime/README.md) | Remote object transfer, FHE replies, copies and metrics |

`Database::create` encrypts owner-provided input, sends actual bundles and public
setup to distinct peers, and retains keys/heads rather than plaintext tables.
`copy_shard` delegates a real source-to-target ciphertext transfer. Read routing
uses surviving holders; missing objects never fall back to owner fixtures.
`replace_participant` reinstalls public setup after a peer process restart.

`execute` parses SELECT/COUNT/SUM/INSERT/additive UPDATE, fetches and authenticates
real stored ciphertext, prepares the operation and sends it to a peer evaluator.
Current wire replies are explicitly `UnverifiedCiphertext`. Requirements 11–13
therefore cause `MissingComputationProof`: no result is accepted, no plaintext query
answer is exposed, and no INSERT/UPDATE head is committed. `AcceptedResult` has no
inhabitants until the missing verification contract exists. Neither TLS, a hash,
a signature nor successful decryption is substituted for a computation proof.
Lower-level diagnostic tests independently decode the real encrypted peer output;
that is not a production acceptance path.

Visible owner-assisted exact-index access remains the selected existing backend.
Public setup/geometry/query metadata, access patterns and timing are not hidden.
Owner restart/key recovery, decentralized current-head agreement, production
parameter review, distributed transactions and the resource/scale targets remain
open. A peer restart with a still-live owner is distinct from owner recovery.
