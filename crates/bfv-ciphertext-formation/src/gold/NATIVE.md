# Closed CoreGold native evidence

This additive N4096 namespace uses one real native full Formation AIR. The old
N8192 modules, public APIs, profiles and proof behavior are unchanged. Actual release proving, cold receiving verification and native rejection gates
passed the [owning validation](VALIDATION.md). End-to-end security and
complete-query latency remain unestablished.

`evidence` owns `prove(&Expected, Prepared) -> UnverifiedFormationEvidence` and
`verify(&Expected, &[u8]) -> VerifiedFormation`. `Expected` is the complete
independent mathematical expectation from the owning Gold relation. Producer
bytes deliberately receive no self-verification or success marker. The receiver
checks their exact header binding, canonical topology and the actual native
proof before constructing the private move-only result. Unexpected backend panics
return Backend; only actual native proof rejection returns Verification. Its only retained data
is the complete public expectation. It supplies no Source, installed-key,
freshness, current-head, lock, SQL or cache-lease authority.

`setup` is sealed and accepts only the concrete same immutable `ProgramAir`.
The actual full symbolic/security and resource gates run before PP or MAIN.
PUBLIC PP is independently regenerated with domain-separated deterministic seeds
from the new mathematical/wire profiles and complete Expected binding. Only
native `ProverData` escapes; the seeded config and all RNG owners die inside the
helper before any private commitment. MAIN, AUX, quotient masks, private salts
and randomizing codeword use the real OS-fresh `bfv-hiding-stark::config()`.
No generic AIR factory, callback, accepting verifier, remote CommonData or
persistent verification cache exists.

The receiving path first rejects an invalid header, then freshly assesses the
same immutable AIR and decodes bounded bytes. It independently regenerates the
PUBLIC PP and trusted native CommonData, dropping PP prover buffers before real
`verify_batch`. A previously generated proof, a decoded terminal0 or a local
metadata assessment cannot construct `VerifiedFormation` without this call.
`Prepared::require_expected` checks full original request/association/roots before
setup; its consuming private trace rechecks before allocation and is overwritten on a best-effort basis by
its owning Drop guard on return or unwinding. SDK-internal clones/scratch do not
acquire a new erasure guarantee from that guard.

## Direct dependencies

| Dependency | Owned role |
| --- | --- |
| Gold relation/program siblings | Exact Request/Expected, private openings, full MAIN, trusted PP and actual analytical assessment |
| [bfv-hiding-stark](../../../bfv-hiding-stark/README.md) | Fixed Gold/EF5 hiding configuration, actual OS-fresh private randomness |
| [bounded-postcard](../../../bounded-postcard/README.md) | One shared per-decode nested-container budget |
| Native Plonky3 0.8 | Concrete batch prover/verifier, automatic same-bus LogUp packing, hiding FRI and canonical field serialization |
| SHA2 and named `rand-public-pp` | Public-only PP seed derivation; the alias pins Rand0.10 used by the hiding config while old N8192 test Rand0.9 remains unchanged |

## Fixed new wire policy

The new 128-byte header is `DCSGFM01`8 / native-wire-profile32 /
complete-Expected-binding64 / payload-length-u32LE4 / reserved-zero20. The total
frame is at most32 MiB, including its header. The native profile is distinct and
includes mathematical Gold profile, codec budgets, geometry and full-round rules.
No old N8192 frame or profile can be relabeled. Header mismatch rejects before
PP or native decoding; the proof is separately bound to all36 AIR public values.

The actual fixed shape is H8192/MAIN512/PP272/PV36, extended degree14, EF5,
192 queries, blowup3, salt4/random5, default128 original interactions packed43,
AUX220 and8 committed quotient chunks. MAIN and AUX open at two points; PP at
one. All five native PCS rounds are mandatory: random, MAIN, quotient, PP and
AUX. Fourteen binary FRI commits, all siblings, salts, roots and zero-grinding
witnesses are checked. The sole decoded lookup terminal must be0, and the real
native equations/PCS must still verify. No terminal numeral is proof authority.

The analytical honest upper count is232026 direct Gold fields,4536 EF5 values
and19365 frontier digests. The fixed binary frontier bound is
`sum(level=0..depth, min(192, 2^(depth-level-1)))`; input depth17 gives1983,
and commit depths16..3 cover the14 FRI rounds. This gives3,022,467 major serde
slots and2,657,328 bytes. A separate32,768-container allowance gives3,055,235
slots and2,755,632 bytes. The finite decode budgets are4096 slots per sequence
and8 Mi slots globally, comfortably above that fixed honest shape; these are
new-namespace policies, not changes to any older4 MiB codec. The complete frame
cap remains32 MiB. These are logical codec bounds, not measured proof bytes or
RSS, and the actual honest native gate must confirm them.

The pinned Gold binary deserializer rejects every representative>=p before a
field value exists. The same recursive type covers EF coordinates, OOD values,
blind openings, leaves, salts, digests and PoW values; it never silently reduces
untrusted raw field bytes. Bounded decode additionally rejects oversized nested
containers, trailing bytes and noncanonical reserialization. Only the exact
native topology reaches mathematical verification.

## Owning validation for Root

The release crypto gates and compiler checks passed as recorded in
[VALIDATION.md](VALIDATION.md). The cheap codec tests use actual native Gold/EF serde positive and negative contrasts
and arithmetic bounds; they create no verified proof fixture. The two privacy
compile-fail examples name the actual private `expected` field and missing
owned Clone behavior.

The one lower owning false-wire case uses the genuine same-key SDK fixture and
real native full proving. Only first graph gate input0 and its two outputs change;
local gate equations stay true while every other row, all four final AS outputs,
S/W ranges and hashes stay unchanged. Release must produce the actual unbalanced
argument. The native verifier must return exact `Lookup(TerminalSumNonZero)`.
Repairing only the terminal to0 passes codec shape but must then fail the real
native opening or OOD equation. Panic, Shape, Resource or a fake verifier cannot
satisfy these release assertions. SDK debug bus replay may reject earlier and
is explicitly not the required release proof oracle.

The upper owning Source/pair consumer must generate ONE actual complete Source,
both real encoding children and one genuine Formation frame, then perform actual
cold verification. It should reuse that frame for header/Expected, EOF, canonical
field, size/shape and repaired OOD negatives; wrong header context must fail
before another PP rebuild. A changed trace-local OOD value with canonical
reserialization must reach `gold::Error::Verification` through actual cold math.
No lower test injector or serialized success capability is exported to upper
code. A mandatory external1792 MiB held-PID bound and the unchanged120 s native
gate remain Root responsibilities; the preallocation ledger is not an RSS theorem.

When `cfg(test)` is active, fixed public phase start/end labels and real elapsed
milliseconds bracket PP setup, private full trace, native proving, canonical
encoding, cold PP setup and native verification. Ordinary builds add no logging,
environment policy, fake cryptographic path or test feature. An upper dependency
built without cfg(test) measures its whole actual calls externally.

Installed-key authentication, N4096/Q2 lattice/noise assurance, fresh agreed head,
hidden SQL compilation, actual BFV computation proof and durable transaction
completion remain separate obligations. In particular the request-bound Gold
relation cannot reinterpret SourceVersion's immutable tag. Neither this source
packet nor a successful local proof establishes the500 ms complete-query goal.
