# Keyless original-application follower

`Follower::new` takes an independently pinned `Binding`; no signer key, peer
receipt or accepting callback is accepted. `apply` verifies the actual signed
weighted commit QC, complete descriptor/parent/slot and the original canonical
Header/Body/owner/Source-first Lifecycle proofs. It imports the block and installs
an in-memory mechanical floor before deriving the next context. It accepts only
the next slot or an exact latest-slot semantic duplicate; a duplicate still
rechecks the QC and actual application Body. Different valid QC signer sets or
rounds cannot change the semantic decision identity.

`VerifiedCheckpoint` has private fields. It is evidence of these checks under the
local pins, not a durable signer floor, an externally agreed current freshness
barrier or a SQL grant. The client must retain and recheck its own required head
policy. Follower state is in-memory and cannot be imported from an opaque marker.

Parent `CandidateBlock` and `Checkpoint` codecs are bounded public DTOs, not
proof authority. `RegistryFinality::candidate_block` exports one original retained
Body; `checkpoint_after` exports one persisted QC with a rechecked floor-log
prefix. Cursor restoration and owned header integrity are checked; export I/O
failure closes the signing owner. The caller still independently verifies every
exported block and QC. No existing disk, vote, work, application or RulesId format
is changed by these distinct export codecs.
