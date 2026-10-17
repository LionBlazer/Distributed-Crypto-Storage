# Private selected encoding

This experiment-private gate opens the exact existing request-bound `C_sel` and
constrains all 8192 original BFV plaintext coefficients for the bounded four-row
schema. Release build, strict Clippy, fourteen actual numerical reports, three
upstream matrix gates, the genuine composite and all 114 serial tests passed.
The [validation record](../../../../SELECTED-ENCODING-VALIDATION.md) separates the
observed results from remaining ciphertext, resource and SQL requirements.

The composite verifies the genuine [canonical source and selection proofs](../README.md)
first against independently expected public values. It then proves the original
age/amount/presence packing, public SIMD index map, inverse NTT modulo114689 and
`W = (78307 * M) mod114689`. Projection does not replace originals with answers.
All other input slots are zero. Private ordinals/RowIds remain committed and never
enter public values or periodic columns. This is not BFV secret-key encryption,
a ciphertext formation proof, accepted SQL or a lock grant.

| Module | Responsibility |
| --- | --- |
| `matrix.rs` | Fixed public 12-column inverse-SIMD matrix and canonical digest |
| `statement.rs` | Exact Selection PV88, distinct profile and output commitment |
| `air.rs` | All integer ranges,8192 coefficients, immutable banks and sponge links |
| `trace.rs` | Private nonserializable witness and genuine trace generation |
| `mod.rs` | Source-first composition and private CLI gate |
| `tests.rs` | Whole-vector upstream oracle and rebuilt malicious proofs |

Public parameter root64917 is derived from pinned fhe-math0.1.1's public root
selection (first candidate81323, exponent7). Its exact convention and every matrix
entry passed the upstream basis tests. The verifier builds only
public basis vectors; it never transforms private source values. No runtime
dependency is added. Three pinned dev-dependencies (`fhe`, `fhe-math`, `fhe-traits`
0.1.1) are used only for upstream oracle tests. The resolved lock retains rand0.9.2
and native NTT for that oracle, alongside the backend's separate rand0.10.3.

The fixed matrix has rows `j=0..8191`, columns
`[0,1,2,3,4096,4097,4098,4099,512,513,514,515]`. Physical row r owns exactly16
consecutive coefficients. Boolean quotients/slacks enforce integer equality:
`dot=M+114689*k`, `78307*M=W+114689*l`, `M+slackM=W+slackW=114688`.
The largest dot is30181752832<2^35, k is19bits and l17bits; neither equation can
wrap the Goldilocks field. Every tuple field, including32bit RowId words, is ranged;
inactive tuples are zero and presence is a prefix.

`C_enc` is the pinned Poseidon2 overwrite-rate8 sponge over8208 fields:
SHA256(public domain/profile/exact Selection PV) as8u32, fresh4-field private salt,
four zeros, then8192 W fields. C_sel uses its unchanged88-field encoding/salt.
Gadgets A/B process C_enc every row. Gadget C processes its first coefficient block
at row0, the11 C_sel blocks at rows1..11, and the final coefficient block at row511;
otherwise C's columns are zero. Eight carry words link consecutive rows.
There is no witness-provided routing, matrix or schedule.

Validated geometry is T512/W3580/PV100/205public periodic columns. With the existing
hiding backend, trace/masked/main-LDE arrays are14663680/29368320/234946560 bytes;
these exclude quotient, Merkle, periodic and other process allocations. Actual AIR
analysis found5215 constraints, degree4,16 quotient chunks,7340 batched functions
and BOTH128bit reports before any Encoding trace. Both hiding MMCS,
OS masks/salts, single-opening discipline and q192/r5/ext5/blowup8 remain required.

After the dependency/compile/numeric gates, commands are
`hiding-fri-source-primitives security selected-encoding` and
`hiding-fri-source-primitives prove selected-encoding`. The latter includes genuine
source/selection proof production and verification before encoded-vector proving;
its proving timer includes prerequisite proof checks and encoded Backend/trace/STARK
work, but excludes fixture preparation and the preceding security report. Its
verification timer checks all three proofs with fresh Backends. These timers are
not the cost of the encoding proof alone. No generated proof codec or
network API is exposed. Production owner-key custody, global security composition,
private BFV s/e/NTTs, freshness and consensus finality remain separate obligations.

## Shared internal coefficient kernel

[LockReturnedEncoding](../../locking/encoding/README.md) reuses this AIR/trace
through a typed producer constructor. The old Selected path retains source 88,
11 source blocks, PV100, 205 periodics and its context/profile/arithmetic. The new
successful Return168 path binds actual canonical/certified parents, PV128 and
21 source blocks; its distinct [formation child](../../locking/formation/README.md)
consumes only the new exact C_enc. Old Encoding/LocalFormation proofs are not
accepted by renaming a root or Kind.

All 20 prior complete ordered JSON object lists are unchanged; compilation/strict Clippy,
three owning oracles and three genuine new CLI compositions passed. The full 235-case suite passed after this shared-source change. See the [validation record](../../../../LOCK-RETURNED-BFV-VALIDATION.md).
The shared kernel adds no secret custody, peer witness construction or live
production acceptance.


## Registry200 original-row encoding

kernel.rs now owns the shared stateless coefficient/range equations and lane writer. Selected88 and Return168 retain their own commitments, profiles and producer contracts; the separate Registry200 adapter reuses only this mathematical kernel. All 28 affected former encoding controls passed. See the
[validation record](../../../../PRIVATE-REGISTRY-LIFECYCLE-ENCODING-VALIDATION.md).
