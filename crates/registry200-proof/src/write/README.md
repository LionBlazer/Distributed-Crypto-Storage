# Fixed Registry200 AddAmount eligibility and logical image

This module owns a separate mathematical relation for four original rows and the
existing two-transaction/two-savepoint Registry200 layout. It opens the exact
canonical Source commitment, principal enrollment and current registry, and proves
that every predicate-selected original row is held by the selected active,
nonfailed transaction in NoKeyUpdate (3) or Update (4) mode. Another transaction's
holding, KeyShare, Share or silently skipping a matching row cannot suffice.

| Direct module dependency | Responsibility |
| --- | --- |
| [Source commitment/layout](../source/mod.rs) | Original canonical Source domain, complete opening and fixed geometry |
| [Shared registry bank](../lifecycle/registry.rs) | The single canonical Registry200 bank, including counters, absent slots and savepoint holdings |
| [Shared opening fields](../lifecycle/opening.rs) | Original Source/Enrollment/Registry field expressions and controller mapping |
| [Predicate scan](../lifecycle/predicate.rs) | Complete 256-age equality/accumulation relation |
| [Ranges](../lifecycle/ranges.rs) | Exact two-u32-limb successor equations; callers separately Booleanize bits |
| [Hiding engine](../../../bfv-hiding-stark/README.md) | Existing Poseidon gadget, fixed actual SDK and assessment machinery used by the consumer |

Expected owns a reaudited immutable CanonicalSource plus independently supplied
parent/application/genesis, enrollment, registry, exact SQL/nonce identity and
new command commitment. Parent labels are mathematical inputs, not evidence of
Journal history or freshness. The consumer must supply that independent context
and genuinely verify the canonical Source before constructing a child trace.
This module defines no Kind dispatcher, prover, backend or network admission.
The [experiment consumer](../../../../experiments/hiding-fri-sha256-gate/src/opening/registry_lifecycle/write/README.md)
owns the private compiler, witnesses, trace generation and bounded proof pair.

The new profile and command/image domains cannot relabel an old lifecycle
operation or Return168 encoding. Context has 116 fields; public values append
C_registry, C_command and C_image for 128 total. The complete Source packets are
compared separately by the typed consumer. Exact SQL/nonce identity commits the
client's compiler context; AIR does not parse SQL. Principal/controller equality
does not establish controller-signature possession.

The private streams are Source680, Enrollment64, the actual Registry200,
AddAmount160 and Image192, with independent resets at rows 0,85,93,118,138 and
last-root checks at 84,92,117,137,161. Source and stable enrollment/registry keep
their original domains/profiles. The complete predicate scan closes at row256;
all actor, source-data, mask, matches, amounts, IDs, salts and successor banks
remain bound through row511. All 96 original data bits are captured, including
amount bytes crossing Source words87..89. TableId and every word of all four
RowIds come from that same complete Source opening.

For every original row, old_u16 + selected * delta_u16 = new_u16 over integers
below 2^17. Any selected overflow rejects the entire proof; an unselected 65535
remains unchanged. Empty selection is valid with an active actor and counter
room. Zero delta still requires every matching lock. Actual 64-bit revision and
sequence successors, all 128 Boolean bits and their carries prove room for a
future consuming write, but no successor is consumed or published here.

Image192 commits TableId and all four original-order (ordinal, full RowId, age,
new amount) tuples with private salt and fixed padding. It does not compact rows,
change age or identifiers, or reveal a selected count/delta. Different salts can
change C_image without any logical data change. This is a complete logical N4
image, not an authenticated new CSTORE/AEAD/index image or BFV ciphertext. A future
data-head change requires a new index-header/AEAD linkage; the current immutable
control application cannot perform that Source CAS.

Actual [native validation](../../../../experiments/hiding-fri-sha256-gate/REGISTRY200-WRITE-IMAGE-VALIDATION.md)
measured width4216/PV128/height512, degree3, individual 128-bit floors and a
26,801,190-byte Source/child frame within its separate 32 MiB cap. All ten new
owning tests and the affected old Registry200 tests passed. No composed128, SQL
permission, writer fence, MVCC, agreed freshness or finality follows. The module
contains no owner key or private witness object. It does not claim secure erasure
of native field vectors, trace, FFT or SDK RAM.
