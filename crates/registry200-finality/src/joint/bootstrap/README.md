# Closed own Bootstrap association

`bootstrap.rs` owns the distinct Pending-parent contract and exact own Bootstrap
expectation/receipt. It uses the existing [Joint history](../history.rs),
[Joint verifier](../../../../registry200-joint/README.md), Journal and Work QC
implementation. It has no storage/client policy, proof producer, supplied
verification callback or secret owner state. The owning tests, compile-fail
contracts and independent-process lifecycle passed
[native validation](../../../../../docs/joint-owner-lifecycle.md); no general
resource or liveness bound is inferred.

`JointHistory::bootstrap_parent()` first requires its live closed state, the actual
ancestry floor and Pending control shards. With no prior decision it requires the
exact genesis head and independently pinned initial Context. After an applied
EmptyPending decision it requires that actual last checked head/control and the
corresponding next slot/previous semantic decision. It does not use best candidates
or accept a raw Journal/HeadRef. The sealed metadata can be cloned as a historical
snapshot, never converted into an Active `VerifiedJointParent`.

`BootstrapExpectation::new` pins the complete installation, Context, full parent,
canonical own Bootstrap request, full Bootstrap104 claim including raw Source
heads/packets and exact one-pair manifest. It checks association only.
`apply_bootstrap` validates this expectation before any Journal import, then runs
the same concrete Source/Lifecycle replay, owner Body/header and weighted QC/floor
checks as ordinary application. Only afterward can the private constructor return
`VerifiedJointBootstrap`. Exact latest semantic retry uses its real prior Context
and full proof replay; a QC, earlier receipt or retained blob identity is never a
cached proof substitute. Ordinary `apply` and Acquire/Control behavior are retained.

The receipt exposes exact historical metadata for one operation: before Pending
parent, checked Active successor, next Context id, own request/statement/manifest,
Header/Body and QC bytes. It cannot be caller-constructed or cloned and certifies no
globally current lease, fresh network observation or owner state installation.
[Owner completion](../../../../storage-client/src/private_predicate/source/locking/joint/bootstrap/README.md)
must consume its actual private candidate and reopen the committed default bank.
Bootstrap has no Result144 or ControlKind relation and does not run a dummy FHE job.

The proof profiles, wire bytes, Source/Lifecycle caps, Journal limits and fixed
roster are unchanged. OwnerVault phases, lost ACK exact signed-byte persistence,
rollback protection and Session SQL capability remain separate work.
