# Two-AIR role-only coefficient inventory

This is a test-private, nonaccepting metadata candidate. It contains no private
MAIN writer, full PP factory, setup, prover, verifier, frame, admission token or
runtime path. All four metadata tests passed on 2026-10-21, followed by unchanged
Pair/Data goldens and the existing Dense honest/hostile proof gate. The
[validation record](VALIDATION.md) distinguishes these scopes. The original
families keep their profiles and behavior; aggregate proof security remains
UNASSESSED and the proof-security guard always rejects.

## Closed responsibilities

| File | Responsibility |
| --- | --- |
| gold/graph/schedule.rs | One typed static FFT schedule, shared with the original graph Plan |
| layout.rs / plan.rs | Fixed Data rows and all combined producer/consumer counts |
| public.rs | Canonical full public Expected, own public FFT, coefficient root, new IV/profile |
| air.rs | Exactly [Data, PublicCoefficientHash], ordinary PV constraints and global LogUp |
| assessment.rs | Actual per-AIR SDK geometry/default packing and simultaneous workspace model |
| tests.rs | Old gate comparison, PP invariance, independent native public hash oracle, metadata reports |

Direct dependencies are the parent [Gold mathematics](../../README.md), its
existing FFT/parser/range equations, the existing hiding Poseidon2 gadget,
P3 AIR/batch/lookup/commit/field/security metadata interfaces, SHA2 and Postcard.
The independent native permutation oracle adds only a test dependency on the
already pinned p3-symmetric 0.8.0. Cargo.lock adds that package edge without
changing package versions. No new production dependency or public API is added.

The original graph Plan resolves a typed pointwise position with exactly its old
A-frequency coefficient. Its constructor identity, audit, build and product code
are preserved. There is one butterfly/twiddle implementation, no copied FFT,
arbitrary callback or dummy Expected used to construct the static Schedule.

Plan::new() takes no request or Expected. New AIR eval retains only static routes.
PublicExpected::checked() separately reparses the complete canonical DATA request,
derives public A-frequency with the existing public FFT, and retains the literal
request and complete Expected binding. It accepts no spectrum or root from a peer.
This is public preprocessing, not secret-key evaluation or WHERE execution.

## Exact new format

The ordered public stream has exactly16384 canonical Gold words:

1. A-frequency Q0,4096 words.
2. A-frequency Q1,4096 words.
3. c0 Q0,4096 words.
4. c0 Q1,4096 words.

The capacity IV is the first four LE64 words of SHA512 of the literal IV domain,
literal order/format descriptor and six fixed LE64 parameters defined in
public::iv(), each reduced modulo Gold. It is derived independently of the
profile, so there is no cyclic IV/profile/root definition.

The four IV values are
4533083410485068889,3810787125653393502,4166276515102124294,18416595238704041011.
The SOURCE-derived profile is
0f390643bb7d2371181d3ba24dd6f70b165f82278482120460f763ccd1b7784c.
These are fixed source-transcript vectors, not native proof results.

The new public hash starts at [0;8] || IV4. Every row adds eight literal words to
the rate, copies the capacity, applies the full existing width12 Poseidon2
permutation and carries all twelve resulting coordinates. There are exactly2048
absorptions, no prefix rows, salt or padding. The root is the first four final
coordinates. The provider emits (fixed ID,row[i]-checkpoint[i]), so its value is
the literal public word, not the accumulated rate state. The native independent
permutation test covers every word, first IV, final root and changed last word.

This is a new hash format/domain. It inherits no Cw hash-format approval or
security claim. The original private Cw514/Cs66 salted overwrite-rate streams and
their full context/salt/payload equations remain unchanged.

## Relation coverage

Data keeps H2048/MAIN512 and all81920 original graph gates, shared S/E, both K,
all4096 ranges, Cs packing, Cw514/Cs66, active/fanout flags, unused cells and
checkpoint/accumulator continuity. Pointwise Y is now a bus-bound public
A-frequency input and the equation is Z=X*Y. Four c0 MAIN cells consume the
matching public coefficient IDs. There are no secret or query constants in PP.

The new Data PP width is656 and PV width48:
new profile8,binding16,Cs root4,Cw root4,Cw context8,Cs context8.
The first24 ordinary PV equalities use fixed MAIN467..490 on every row.
Roots and contexts are ordinary endpoint constraints at the corresponding hash
rows. C0 occupies463..466;491..495 and509..511 remain constrained zero.

The public hash AIR has H2048/MAIN260/PP10/PV4:248 permutation columns and twelve
checkpoint columns, eight static node IDs plus first/last flags. Its PV is the
independently computed coefficient root. A single closed constructor supplies
both public tuples from the same complete retained Expected. Metadata labels
are not Source, key, DATA admission, query origination or fresh-head authority.

Global IDs41..44 cover all16384 public coefficients. All old IDs0..40 retain their
meaning. Data has247 original messages with bound4; hash has8 with bound1.
Combined inventory checks every use, duplicate multiplicity, unique producer,
all coefficient positions, final inactive slots and exact global balance.
Native packing, AUX, chunks, degree and openings are derived per instance.
No old packed count is copied.

The intended future verifier must require both terminals to exist and their
sum to be zero, and still run the actual native batch verifier. Individual
terminals generally are not zero. A decoded sum or header never verifies math.

## Assessment limits and next gate

Pinned P3 batch security supplies per-instance opening counts to sum across the
batch, but no complete heterogeneous-AIR security helper. The assessor logs actual
per-instance symbols/default packing and one explicitly UNASSESSED analytical
candidate report using combined constraints/openings/global original messages.
Its power-of-two DEEP envelope is labeled analytical, not native committed chunks.
Its shared-challenge reduction still needs independent mathematical review.
require_proof_security() always returns Security. Numeric128-bit SDK report
terms do not change that refusal or any cryptographic/security flags.

The checked stage ledger includes both AIRs in every simultaneous raw, mask,
salt, tree, retained LDE and opening bank, sixteen full EF opening vectors, the
old16MiB guarded private-equation reserve and64MiB public/IR/runtime allowance.
Its unchanged ceiling is1792MiB; the actual ledger is906264576 bytes. This is a
policy prescreen, not observed private proving memory. No PP/MAIN matrix is
built for this stage, and future writer lifetimes remain unmeasured.

The added hash AIR costs2048 genuine Poseidon2 rows and raises raw MAIN from512
to772 columns (+50.78125%). It may erase the saved per-request PP cost. Neither
reusable role PP nor this inventory proves a speedup or the500ms COMPLETE SQL
target. Actual product proof, private query/command relation, Source/DATA/key
admission, noise/confidentiality assumptions, fresh head/quorum and durable locks
remain separate obligations.

A possible native public-MMCS seam is not implemented: P3 CommonData commits
preprocessed matrices, but putting the request-specific coefficient table there
restores per-request PP. An additional public commitment alone is not consumed
by these lookup equations. Removing the hash AIR would require a separately
reviewed native PCS/constraint link, not adoption of a remote commitment.

The four metadata tests passed in0.10s. Actual native geometry is Data
BASE1156/EXT86/degree4/chunks8/original247/packed83/AUX420 and hash
BASE268/EXT6/degree4/chunks8/original8/packed3/AUX20, with3310 combined openings.
Complete1050159-byte ordered symbolics and all1363968 streamed PP fields now
have unconditional goldens captured before any new private proof. The original
Pair/Data full snapshots passed in0.07s; all six existing Dense cases, including
actual honest/false-input proofs and cold receiving, passed in4.34s.

```sh
cargo test --release --locked -p bfv-ciphertext-formation gold::program::role_coefficient_inventory:: -- --nocapture --test-threads=1
```

No accepting fallback or automatic proof-golden capture is present. Aggregate
security, a private writer/backend/codec and comparable complete-operation
performance measurements are still prerequisites for using this candidate.
