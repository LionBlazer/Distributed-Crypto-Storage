# Full Gold Formation AIR

This private experiment owns the complete fixed Formation constraints and their
native shape, security and resource inspection. The [executed checks](VALIDATION.md)
cover symbolic analysis and public metadata. There is no private MAIN builder,
Formation prover, receiving verifier, proof codec or SQL admission path yet.
Passing this inspection establishes neither a Formation proof nor 500 ms queries.

## Responsibilities and dependencies

`descriptor` binds the complete original ciphertext request, Source/Cw statements,
independent nonce and key identity to one immutable expectation. It checks exact
roles, full Source values, raw heads/packets, key29 and mask nonce. `require_pair`
compares the full claims to an actual opaque VerifiedPair. The geometry-only
constructor retains no claims and cannot pass that fence.

`pp` derives every node ID, coefficient, c0, hash context/root and phase control
from the actual canonical request and fixed graph. Its inventory checks every
port, signed count, unique producer and consumer. `air` constrains the complete
graph, integer ranges and commitments in ONE AIR. All secret LogUp messages remain
internal; a future native verifier must check its sole actual terminal sum is zero.
`assessment` derives real BASE/EXT constraints, domain-aware degree, default
packing, ZK quotient chunks, openings and security terms before any PP commitment
or private proof trace. The resource gate remains mandatory.

Direct dependencies are the parent Statement/geometry/Gold graph, SHA2,
registry200-proof's two_lane_encoding metadata and opaque pair, bfv-hiding-stark's
Gold/EF5/Poseidon/configuration types, and native 0.8.0 p3-air, p3-batch-stark,
p3-commit, p3-field, p3-lookup, p3-matrix, p3-security and p3-uni-stark. The new
Cargo edges belong only to this consuming experiment. Core never depends on it.

## Complete relation

H8192 has 4352 arithmetic rows, 2048 range rows, 514 Source-Cw rows, 514 mask-Cw
rows, 66 Cs rows and 698 zero padding rows. MAIN512 overlays 128 real port values,
368 range/Poseidon columns, 12 hash checkpoints, a Cs accumulator and three zero
columns. PP272 supplies 128 node IDs, 128 constants and 16 phase flags. PV36 binds
profile8, full Expected SHA512 words16, Cs4 and the two Cw4 roots. All are checked.

The 32 arithmetic slots cover all 139264 graph gates, using public A transforms
derived from the literal request. Each coefficient uses the same S across four
products and the same E across both bases of an operand. S/E lie in [-20,20];
biased six-bit values and complement bits sum to 40. K lies in the exact symmetric
[-524287,524287]: twenty biased bits plus a nonzero inverse exclude -524288.
W and its seventeen-bit slack sum to 65536. W is ALREADY scaled; no second SCALE
multiplication occurs. All four integer Formation equations are constrained.

Both W4096 arrays feed their complete Cw hashes: context8/salt4/zero4/W4096,
514 absorbs each. The same S bit bank builds 512 packed 48-bit words for the new
Cs528: context8/salt4/zero4/packed-S512, 66 absorbs. All last coefficients, reset,
checkpoint, inactive cells and padding are constrained. Native tuples contain
direct public IDs and private values; signed counts have bound four. Shared
forward outputs have four consumers, other arithmetic edges one. A decoder's
numeric terminal zero cannot replace actual native equations and PCS checks.

The NEW request contract is q=H(domain,length,exact original request); the request
contains an independent nonce, also required by mask.public_nonce. This differs
from both old q(parent) and SourceVersion's version_tag(images,key). No old proof,
checkpoint or SourceVersion result can be relabeled or reused here. Source C_key
is the storage AEAD-key commitment. The distinct Cs context hashes key identity25
and this new profile, excluding its own Cs4 and all query/Source/Cw values.
Key29 remains metadata, not authorized key installation. Old Key33/N8192 is separate.

## Usage and limits

```sh
cargo run --release --offline --locked -p bfv-unrelinearized-certificate -- --unverified-formation-air-plan
```

The CLI obtains a genuine SDK request as PUBLIC geometry, then runs the actual
native inspector. It has no Source/Cw/Cs claims, allocates no private MAIN and
commits no PP. All proof/key/Source/freshness/SQL/network flags remain false.
Security or resource failure returns an error after the numerical report.

The numerical workspace estimate is 1819017216 bytes under the unchanged
1879048192-byte gate. It accounts for actual bank lifetimes, conservatively two
current-bank copies, all original reserves and a separate opening reserve.
This is not measured RSS or a whole-process upper bound. Any actual proof run
still requires the original held-process cap; allocator/caller state may exhaust
the remaining margin. Do not raise the cap or accept a partial proof to pass it.

The complete 25-test owning suite passed in 0.57 s, including two new exhaustive
metadata/binding/native-inspector cases and three stage/overflow cases. Four
temporary evaluator heap allocations were removed without changing the equations.
A future accepting path still needs an actual consuming W/salt/S opening, fresh
pair verification, private OS randomness, sealed public PP setup, genuine proving,
bounded canonical decoding and independent cold verification. Lattice/noise,
composed security, current QC, network and the complete-query target remain open.
