# Closed Query/DATA opaque INPUT forest

This private child of the [shared research hash owner](../README.md) constructs
four opaque private INPUT commitments and genuine native MMCS multiproofs.
Its constructor takes only `DenseFamily::{Query,Data}`, Programmer and a caller-
owned CryptoRng. It accepts no caller-selected forest height, widths or PP role.
The two exact mappings are:

| Role | Matrices | Query columns per matrix | DATA columns per matrix |
| --- | ---: | ---: | ---: |
| Random | 1 | 10 | 10 |
| Main | 1 | 421 | 517 |
| Quotient | 8 | 10 | 10 |
| Aux | 1 | 425 | 415 |

Every forest has32768 combined leaves and a one-root cap. Private tiny-tree
helpers retain their existing tests, with maximum width derived from the chosen
family in BOTH sample/from_labels guards: Query425, DATA517. Query does not gain
DATA's width allowance. Full constructors always use their closed role mapping.
Public PP remains genuine ordinary native setup outside this enum; the eventual
five-round order remains [Random,Main,Quotient,normal public PP,Aux].

One opaque32-byte label is sampled per combined leaf. Internal NODE hashes run
normally bottom-up in the shared raw-key oracle. New openings program only the
complete canonical salted LEAF to its old label. Four Gold salts per matrix row
remain interleaved with that row. Native query order, repeated rows and salts,
canonical pruned frontier and every bound are preserved from the Query engine.

Full forests require exactly192 raw native indices and at most192 cumulative
unique rows per tree. Shape, contradictory rows and disclosure-limit errors
preflight before new salt sampling/programming. Cached replay consumes no new
salts. A programming conflict is discovered AFTER the attempted salts determine
its raw leaf: those draws are consumed, no old answer is overwritten, and the
ENTIRE forest becomes permanently unusable. There is no rewind, retry, per-role
fallback or collision resampling.

[ro](../ro.rs) owns Programmer/Oracle, canonical bytes and conflict rejection;
[config](../config.rs) fixes the genuine native binary hiding MMCS and salt4.
Owning [Query layout](../../query_formation/layout.rs) and
[DATA layout](../../dense_data_inventory/layout.rs) determine their AIRs and
accepting frame contracts separately. This module uses pinned native dimensions,
caps, pruned paths/BatchMultiOpening and caller-owned CryptoRng. Its returned
multiproof has no accepting-verdict field or verifier callback.

The original tiny native example, independently committed native frontier
comparison and full Query case are preserved. The same full failure/replay/
resource suite now also uses literal DATA517/415 dimensions and real native
verification. A focused case checks both constructor width bounds before RNG
use, including rejecting517 in Query. All five owning opaque cases passed in
observed optimized run r890, alongside the three shared raw-oracle cases.
Both full-family cases verified five native positives and24 hostile mutations.
The combined eight-case process took397.9206ms with OS peak67436544B.
[Shared validation](../README.md) records all gates, build/hash and unchanged
resource/handle policy. Historical Query measurements remain in the owning
validation record; these new arithmetic commitments do not time complete SQL.

This engine does not evaluate either AIR, form joint V/B, assemble FRI or create
a native proof frame. Seeded tests are not ideal-cell, privacy, soundness or PRG
theorems. Production guards, profiles and normal hash/config types are unchanged.