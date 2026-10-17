# Private registry bootstrap

This experiment defines a distinct `registry-bootstrap` relation for the missing
initial-state edge of the closed N4/two-transaction registry. Existing locking
proofs preserve their supplied old registry; they cannot establish that its initial
holdings were empty. This child opens the complete canonical source, a separately
anchored private enrollment, and the exact stable Registry112 encoding.

Release and test builds, strict Clippy, 24 numerical modes and 85 affected tests
have executed on the same source. Actual layout is W1082/T512/PV104, with 512
periodic columns, 4996 constraints, degree 3 and 16 quotient chunks. Both SDK
per-proof security estimates pass 128 bits; a composed-security claim is not
established. See the [validation record](../../../PRIVATE-REGISTRY-BOOTSTRAP-VALIDATION.md)
for exact scope and observed process resources.

## Ownership and entry points

| Module | Responsibility |
| --- | --- |
| [statement.rs](statement.rs) | Independently owned exact canonical `Expected`, proposed registry output and fixed enrollment64 fields. |
| [air.rs](air.rs) | Source capture, shared private controllers, fixed initial fields, three complete sponge streams and padding holds. |
| [trace.rs](trace.rs) | Owner-local plaintext/controller/salt witness and genuine Poseidon witness generation. |
| [mod.rs](mod.rs) | Real source-first prove/verify composition and PUBLIC NONSECRET CLI fixture. |
| [tests.rs](tests.rs) | Owning genuine proof code, native two-Begin oracle and rebuilt hostile traces. All 12 bootstrap tests passed. |

Direct dependencies are the existing [source opening](../README.md),
[private registry encoding](../locking/README.md), [Poseidon gadget](../poseidon.rs),
[fixed schedule](../schedule.rs), [statement contract](../../primitive.rs) and
[checked hiding backend](../../backend.rs). `transaction-state` is already a dev-only
dependency and supplies a native test oracle; the verifier does not rerun it.
There are no dependency or lock changes.

`Expected::checked` accepts only CanonicalIndex source. The caller supplies the
actual genesis, agreed parent and independently owner-authorized `C_enroll`; this
module does not authenticate those anchors. `Statement::checked` adds
`C_registry`. `prove` generates the genuine canonical source proof and bootstrap
proof. `verify` verifies that exact independently expected source first, then
compares every Expected field, then verifies the child. Missing/byte/State evidence
cannot stand in for the canonical proof. Non-word-sized packets reject before
source public-value conversion or a child factory. Public values are:

`profile8 | request8 | sourceHeads56 | C_key4 | C_open4 | genesis8 | parent8 | C_enroll4 | C_registry4`.

## Exact encodings and schedule

The private enrollment64 is `newDomain4 | version1 | newProfile8 | genesis8 |
DB-and-keyDomain8 | C_key4 | TableId8 | capacity2:1 | (ID1:1, controller0:8) |
(ID2:1, controller1:8) | salt4`. Its TableId is captured from the same C_open.
Both controllers are exactly 256 Boolean bits and nonzero. Nonzero bytes do not
prove curve-key validity, permission or possession.

Registry112 retains the existing registry domain, profile, stable scope and field
order exactly. All four ordinal RowIds and TableId are captured from that same
full source opening. IDs 1 and 2, revision 2, sequence 1, Failed=false and every
held-mode zero are AIR constants. They describe two Active entries after native
`State::new -> Begin1 -> Begin2`; the native transitions are only a test oracle.
The witness exposes no mutable initial revision/status/held bank to trust.
Controllers are shared with enrollment, and the registry has its own private salt.
Source, enrollment and registry salts are sampled independently in the fixture.
The stable enrollment and registry exclude query request, current heads/C_open
and parent; the full proof statement still binds those exact values.

Rows 0..84 absorb the original 680-field source (`prefix87 | plaintext587 words |
zero6`). Rows 85..92 absorb enrollment64; rows 93..106 absorb Registry112. Each
stream resets capacity to zero. Outputs at rows 84,92,106 are constrained to the
public roots. One actual Poseidon permutation is constrained on every row,
including zero-input padding. Checkpoint, controllers, source-captured identity
banks, salts and inverses hold through row511. Source scratch bits are Boolean,
all 587 source words are hashed, and non-payload scratch is zero. No field-valued
identity is accepted without its exact source-u32 capture.

## Boundary and reproduction

```
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- security registry-bootstrap
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- prove registry-bootstrap
```

The prove CLI uses a full real source/child composite. Its inputs, rows and
controllers are explicitly PUBLIC NONSECRET. The source and bootstrap work remain
owner/client-local, with private AEAD/source witness material. This does not replace
peer-only encrypted SQL computation or provide a live SQL/lock grant.

A later owner-signed canonical Journal registration must bind the exact
post-genesis target, source identity, enrollment, proposed initial root and proof.
Its parent must already belong to the actual genesis; the bootstrap root is not
inserted into `Genesis.initial_shards`, avoiding a genesis-hash fixed point.
The experiment does not authenticate that signature, controller entitlement,
network membership, fresh agreement, persistence, writer fences or rollback.
C_enroll must be independently supplied rather than chosen from the submitted
witness. No StateLease branch or production accepting API is added.
