# Source circuit and canonical producer

This module owns one Source statement, AIR, arithmetic kernels, schedules and
owner-side trace writer for Bytes, CanonicalIndex, PackedCanonicalIndex,
FactorizedPackedCanonicalIndex and StateCertificate. The original five profiles,
constraints, values and layouts are unchanged. It does not compile SQL or confer
admission, custody, lock, agreed-head or query-result authority.

| Direct dependency | Responsibility |
| --- | --- |
| [compact-store](../../../compact-store/README.md) | Complete encrypted image/head, geometry and canonical root auditing |
| [bfv-hiding-stark](../../../bfv-hiding-stark/README.md) | Actual hiding backend, analytical assessment, bounded codec and shared Poseidon writer |
| [coefficient wire](../coefficient_encoding/wire/mod.rs) | Existing bounded 20 MiB Source byte serialization contract |
| p3-air/field/matrix and sha2 | Existing circuit, trace and profile/commitment labels |
| zeroize | Explicit owned key, salt and age storage cleanup |

`Statement` remains a mutable low-level PUBLIC mathematical claim. `reaudit()`
reconstructs and checks both complete original encrypted images, exact geometry,
database/key domain and canonical digest encoding. It is not an AEAD or index
proof. `admission::CanonicalSource` remains sealed and Canonical-only.

`circuit::Witness::new(key, key_salt, opening_salt, ages)` accepts caller-owned
private input, without an Owner key getter or fixture dependency. It cannot be
cloned, debug-printed or serialized. `trace(&Statement)` bounds packet geometry
before constructing an AIR, then runs the single shared writer. This explicitly
mathematical API permits false well-shaped claims for AIR rejection tests and
contains private trace data. Other consumers must prove and verify it; a trace is
not a checked proof or admission token.

`prove(&CanonicalSource, &circuit::Witness)` reaudits the immutable canonical claim,
assesses the fixed backend before trace allocation, proves and self-verifies,
then bounds canonical public serialization. `SourceEvidence` retains only the
immutable statement and bytes, with read-only `statement`/`as_bytes` access and
consuming `into_bytes`. No public configured factory or raw proof object is added.
The fixed backend accepts CanonicalIndex only; legacy finite relations continue
to use the same low-level writer with their existing experiment policy.

The witness guards its owned key, two salts and four ages. Caller copies, local
field arrays, private traces, cryptographic scratch, FFT and SDK allocations are
not claimed erased. Clear source input is an explicit owner-side producer input;
this extraction does not approve per-query owner plaintext execution.

The [producer/epoch validation](../../../../experiments/hiding-fri-sha256-gate/PRIVATE-INPUT-PRODUCER-EPOCH-VALIDATION.md)
records executed Core guards, all five Source relations, coefficient/Poly
regressions and the actual linked input16 consumer. It grants no SQL admission.
