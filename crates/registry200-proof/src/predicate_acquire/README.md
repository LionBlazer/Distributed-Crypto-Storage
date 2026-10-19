# Private predicate / successful Acquire linkage

This separate mathematical relation opens the **same private 256-bit mask** in
the coefficient module's Cmd48 and Registry200's Acquire Cmd160. It also opens
Result144 as operation Acquire, outcome success, with the same full transaction
ID. It does not relabel these distinct commitments or change an existing profile,
operation, wire allowlist or Journal application.

| Direct dependency | Responsibility |
| --- | --- |
| [coefficient_encoding](../coefficient_encoding/README.md) | PrivateMask Statement/PV772, original Cmd48 prefix and real Source-first DCSCEP01 verifier |
| [lifecycle](../lifecycle/mod.rs) | Statement/PV116 and unchanged public Cmd160/Result144 prefix expressions |
| [Source](../source/README.md) | Canonical Source re-audit, full Source691 and exact original heads/packets |
| [wire](../wire/mod.rs) | Genuine Source/Lifecycle DCSLFPW1 pair verification |
| [bfv-hiding-stark](../../../bfv-hiding-stark/README.md) | Fixed hiding configuration, actual AIR assessment, Poseidon gadget and bounded canonical proof codec |
| p3-air/field/matrix, zeroize and sha2 | AIR/trace expressions, explicit owned witness clearing and full public identity |

## Public contract and private openings

`Expected::new(query, lifecycle)` retains complete immutable copies, requires the
PrivateMask role and a Lifecycle transition, and reaudits and compares **all**
Source691 values plus both exact heads and packets. Its 896 public values are
new profile8, complete Query772 and complete Lifecycle116, in that order. The
SHA512 frame identity binds all896 and length-delimited original heads/packets.
Construction and matching establish mathematical association, not proof authority,
authorized SQL compilation or a current/confirmed parent.

`circuit::Opening` owns the private mask, transaction64, principal label,
controller256, revision64, sequence64, mode, WAIT/NOWAIT/SKIP selector, offset,
limit, projection, twelve result flags and three private four-field salts.
`Witness::new` reconstructs all three committed preimages. It owns their exact
Expected; typed `prove` rejects a different Expected before prerequisite work.
Drop clears explicitly owned Opening fields and the integer witness bank. Caller
copies, native field traces and SDK scratch are outside that clearing claim.

The fixed width1005/height512 AIR constrains 733 Boolean bank cells and twelve
canonical field salts, all held constant through final padding. The three
Poseidon overwrite8/capacity4 streams are Cmd48, Cmd160 and Result144, resetting
at rows0/6/26 and binding roots at5/25/43. The two commands share every mask bit,
including255. Cmd160 is specifically Acquire with zero unused name/Begin/abort
fields and original zero padding. Result144 is specifically Acquire success,
with the same transaction64 and all returned/skipped/visited flags. No packed
64-bit counter is recomposed in Gold; each is two exact u32 limbs.

`circuit::Witness::trace` is an explicit owner-side mathematical API for genuine
false-trace tests; a different Expected may yield a trace the AIR must reject.
It is not a verifier callback. Actual lock conflicts, the canonical row scan,
actor membership/counters/controllers, offsets and limits are established by the
mandatory original Lifecycle proof, not a native Registry model in this module.
The original Query proof establishes reversed coefficient encoding of that same
mask. WAIT, NOWAIT and aborted End remain valid separate Lifecycle outcomes; they
cannot satisfy this success-only link.

## Detached bounded evidence

`prove(expected, witness, Prerequisites { query, lifecycle })` and `verify` require
both existing proof pairs. Their complete Source proof bytes must agree. Both
frontends really verify Canonical Source before their respective child and drop
the decoded Source proof/backend before child decoding/allocation. Query772,
Lifecycle116 and their output commitments are compared completely. Persisted
prerequisites are reverified; neither an Expected, Evidence object, root, cached
Boolean nor decoded claim skips cryptography. Source is intentionally verified
twice by the two unchanged frontends.

Only then does the fixed link backend assess this AIR, require its individual
security target, prove/self-verify or bounded-decode/verify. `Evidence` retains
Expected and public bytes; `VerifiedLink` has a private Expected and can only be
constructed after all three mathematical verifications. Neither type grants
application permission. `wire::encode` is serialization, not verification.

The new detached DCSPAL01 frame has an exact120-byte header: magic8, tag1,
zero7, fixed profile32, full public identity64, payload length u32, zero4.
Its proof cap is16MiB and total frame cap is16MiB+120. The canonical Postcard
decoder independently limits sequences to16384 and total decoded elements to
16Mi; element counts are not byte or RAM bounds. Missing/foreign/bad Source and
prerequisite proofs fail before decoding the link proof. No combined SignedBody
or aggregate dependency-transport fit is asserted. Existing 32MiB Body and all
old proof limits remain unchanged; atomic durable composite evidence is an open
integration boundary.

## Consumer and remaining obligations

The [owning consumer tests](../../../../experiments/hiding-fri-sha256-gate/src/opening/registry_lifecycle/journal/predicate_acquire_tests.rs)
build actual signed Bootstrap → Begin1 → Begin2 → other Acquire → SKIP Acquire
history, genuine Source/Query/Lifecycle/link proofs, and independently valid
same-q/different-mask and unsuccessful-outcome attempts. Core tests retain
conditional mathematical fixtures for high-u64 field ABI and genuine AIR attacks
with repaired hash gadgets/roots. All three Core tests and five genuine consumer
tests passed in the [native validation record](../../../../docs/private-predicate-acquire.md).
The measured unique proof payload already exceeds the existing 32MiB Body cap;
bounded atomic durable dependency admission remains required.

The query fixture does not claim the current plain-SELECT compiler accepts
locking SQL. This relation does not derive a jointly authorized q from SQL or
parse SQL inside AIR. A future adapter must independently compile the hidden
predicate, pin the acyclic query context and both commitments, and validate the
actual authorized Registry parent. It must also tie the FHE result to the exact
returned ordinal/RowID/window/projection relation. This module verifies no Key,
Basis, Formation or full MulRelin proof and admits no network SQL result.
Controller labels are not signature possession; mathematical Acquire success is
not a live lease, writer fence, MVCC state or agreed freshness/finality. Hidden
WHERE privacy, the work-weight quorum rule and complete SQL admission remain
binding requirements. Individual proof assessment is not a composed128 claim.
