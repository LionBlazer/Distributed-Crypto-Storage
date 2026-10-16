# Canonical private-index format vectors

These are explicitly **PUBLIC NONSECRET** test rows and identities, never
participant data or owner keys. The core codec test and source-proof experiments
may consume the same immutable bytes. Core code does not depend on an experiment.

`index-v3-four-row-suffix.hex` contains the 2,224 bytes after the independently
supplied 112-byte data head in one 2,336-byte `CQAGEINDEX000003` plaintext.
The fixture excludes encryption, nonces, packet revisions and snapshot roots.
Its owning test compares the complete output of the actual core encoder,
including the independently produced data head, to this fixed byte vector.

| Ordinal | Age | Amount | RowId |
| --- | ---: | ---: | --- |
| 0 | 255 | 0 | 31 zero bytes, then `01` |
| 1 | 0 | 65,535 | 31 zero bytes, then `02` |
| 2 | 255 | 256 | 31 zero bytes, then `03` |
| 3 | 128 | 255 | 31 zero bytes, then `04` |

TableId is 32 bytes of `31` hex. Only counts 0, 128 and 255 are nonzero:
1, 1 and 2. Offset 0 is zero; offsets 1 through 128 are one; offsets 129
through 255 are two; offset 256 is four. All words are little-endian u32.

The posting stream is exactly `01 03 00 02`: row 1 in bucket 0, row 3 in
bucket 128, then absolute row 0 and positive delta 2 in bucket 255.
Eight zero bytes follow before the aligned identity tail at offset 2,208.
IDs remain in ordinal order and differ only in their last byte, exercising
full-width identity comparisons. No TableId/RowId ordering rule is implied.

Matching this vector establishes byte compatibility for this bounded example.
It is not a cryptographic source proof, a global index validator, a query answer,
a freshness certificate or a lock grant. Format changes require reviewing both
the codec and any relation consuming the vector.
