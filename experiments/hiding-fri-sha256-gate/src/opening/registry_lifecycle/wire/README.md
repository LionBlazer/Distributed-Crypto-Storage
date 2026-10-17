# Registry200 proof wire

Validated experimental transport for actual canonical Source and Registry200
Bootstrap/Transition proofs. Release/Clippy, genuine SDK verification, signed Body
measurements and all eight owning tests passed; see the
[validation record](../../../../PRIVATE-REGISTRY-LIFECYCLE-WIRE-VALIDATION.md). It is not a Journal
adapter, SQL acceptance path, controller authorization or live lock grant.

[mod.rs](mod.rs) owns the typed encode/verify API and normal measurement gates;
[frame.rs](frame.rs) owns this frame and its budgets; [transport.rs](transport.rs)
is a PUBLIC NONSECRET signed Body example. [tests.rs](tests.rs) owns adversarial
transport and actual proof examples. The shared internal
[SDK codec](../../proof_codec.rs) checks canonical bounded Postcard and fixed SDK
topology. The [legacy policy](../../proof_wire/README.md) keeps its old DCSLKPW1
roles, Kind whitelist, profiles, byte/slot caps and test bodies.

## Independent statements and exact proofs

`verify(expected, bytes)` requires independently selected Registry200 Expected.
The frame never imports Expected, genesis, parent, C_enroll, Source packets or
C_cmd. It carries only output roots and both mandatory actual SDK subproofs.
The original lifecycle composite verifier checks the genuine canonical Source
first, compares Expected, then checks the child. Byte-only Source, missing proof,
a cache Boolean or receipt is not a fallback. Canonical bounded decoding, complete
topology validation and reencoding precede SDK verification. The outer panic
boundary converts SDK panics into rejection; it does not catch allocator aborts.
Finite preallocation budgets remain required.

DCSLFPW1 has an 88-byte common header: magic8, role1, reserved7, Source profile32,
child profile32 and two u32LE component lengths. Bootstrap carries next32, giving
header120. Transition carries next32/result32, giving header152. Role is chosen
from independent Expected.phase; header bytes cannot select dimensions or Kind.
Registry200 next/result are not legacy returned/owned/next or Return168 outputs.

The shared codec contains no roles, semantic Kind whitelist, public profiles,
resource policy or accepting verifier. Each consumer derives sealed topology
from its actual trusted statement and real SDK analysis. The legacy policy is
unchanged; the new policy permits only canonical Source, lifecycle Bootstrap and
lifecycle Transition with their exact existing widths/public-value lengths.

## Explicit transport reservation

| Bound | Value |
| --- | --- |
| Source serialized bytes | 20 MiB |
| Child serialized bytes | 12,578,091 |
| Entire frame | 33,549,763 bytes |
| Maximum sequence elements | 16,384 |
| Source shared decoded-container slots | 24 Mi |
| Child shared decoded-container slots | 16 Mi |

All nested sequences, tuples, fixed arrays and binary Gold byte arrays share the
component budget before SDK Vec reservation. Source finishes decode and topology
checks before child decode. Byte bounds and both length-delimited regions are
checked before deserialization. The budgets are finite structural policies, not
claimed process RSS or composed soundness. Old 5 MiB child/26 MiB frame/8 Mi child
slot policies stay unchanged.

The new ceiling reserves one update and at most 4,096 request bytes within the
unchanged 32 MiB Body cap:
`117 + request_bytes + 456 * 1 + frame_bytes`.
Thus the maximum frame is `32 MiB - 117 - 4096 - 456`; the child ceiling also
subtracts the Source ceiling and maximum 152-byte header. This is a transport
envelope, not a production Request200 codec. More updates or a larger request
require a separately reviewed capacity policy. Actual full emitter, signed Body and process-resource observations are recorded
in the linked validation report; they do not establish whole-peer bounds.

## Real signed Body example and owning tests

The normal `prove` gates drop the original proof objects, then create an actual
owner-Ed25519-signed `version_journal::Body`, encode/decode/reencode it, strictly
verify its signature, and freshly verify the decoded frame under independent
Expected. Body decoding alone does not authenticate a signature or prove a
computation. The request is explicitly opaque PUBLIC NONSECRET test data, and the
one sorted update contains opaque transport-test heads. No parser connects them
to Expected or Registry200, and no Journal import/update admission is performed.
A signature proves permission for exact bytes, not their computation semantics.

Eight new executed owning tests cover both genuine roles, original-object
drop/fresh roundtrip, independent Expected fields, canonical output roots, a real
foreign enrollment child that verifies under its own Expected, mandatory proofs,
all 31 malformed nested SDK families, canonicality and shared-budget rejection,
same-shape cryptographic corruption, and an invalid Source with a genuine child.
Full signed Body tests use realistic 2,716-byte and maximum 4,096-byte opaque requests,
check exact body length and valid-profile actual-size−1/exact/+1 boundaries, and
reject signature tampering of request, proof, update, parent and genesis. All eight executed successfully; 48 prior leaf controls and two actual contract
tests also passed. Actual discovery lists 304; the other 248 bodies were not rerun.

From the standalone leaf:

```powershell
cargo run --release --locked --offline -- security registry-lifecycle-bootstrap-wire
cargo run --release --locked --offline -- security registry-lifecycle-wire
cargo run --release --locked --offline -- prove registry-lifecycle-bootstrap-wire
cargo run --release --locked --offline -- prove registry-lifecycle-wire
```

Each security gate emits individual analytical Source and child reports without
trace/proof/Body generation. Each prove gate emits actual component, frame, request,
update-count and whole Body byte lengths. Its timer covers owner signing, Body
encode/decode/canonicality, strict signature checking and fresh Source-first proof
verification. The parent observer owns full process elapsed time and RAM. The
transition fixture first establishes the genuine new empty-bootstrap root.

No combined 128-bit claim follows from individually checked proofs. Missing fresh
agreed heads, delegated private controller signatures, Request200/Journal admission,
peer-only encrypted query execution, completeness of full SQL, MVCC, writer fences,
decentralized finality and compact encrypted storage remain separate requirements.
