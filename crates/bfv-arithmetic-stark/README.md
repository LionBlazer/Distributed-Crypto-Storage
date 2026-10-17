# Fixed arithmetic STARK backend

This library owns the identical linked Plonky3 configuration shared by the public
RNS-scaling, native-NTT and tensor proof experiments. It removes duplicate
configuration and security-floor code while consumers retain their operation
contracts. The extraction and all three consumers have passed native validation.

| Direct project dependency | Responsibility |
| --- | --- |
| [bfv-fixed-geometry](../bfv-fixed-geometry/README.md) | Existing fixed degree 8192 |

`Val`, `Challenge` and `Config` expose the linked types required to instantiate
ordinary SDK proof APIs. The fixed configuration is Goldilocks, extension degree
5, Poseidon2-12/rate8/digest4, binary MMCS/cap0, blowup 8, 192 queries, binary FRI,
final polynomial length 1, and zero grinding. `HEIGHT`, `LOG_HEIGHT`,
`EXTENSION_DEGREE`, `LOG_BLOWUP`, `QUERIES` and `MIN_SECURITY_BITS` expose those
fixed numbers. `LINKED_P3_DESCRIPTOR` identifies the pinned SDK/hash/MMCS; it is
not a complete operation profile or an acceptance capability. There are no caller
configuration knobs, SDK loader, SDK fork or runtime cache.

`checked_config(&air)` returns the linked `Config` and a `SecurityAnalysis` derived
by the actual SDK from that exact compiled AIR. It derives current/next opening
multiplicity from the AIR, rejects Boolean/boundary assumptions, and returns
`None` if either individual SDK bound is below 128. The supplied AIR must obey the
pinned SDK's symbolic-analysis prerequisites. This path creates no trace or public
preprocessing commitment and does not evaluate the caller's arithmetic operation.

Consumers own their role wrappers and profile/domain bytes, report serialization,
errors, frame/decoder limits, canonical public inputs, preparation, independent
verifier key, proof generation/verification and lifecycle. The pure arithmetic
circuit libraries do not depend on this backend. Existing RNS and NTT profile
bytes, numeric report fields/order, codecs, caps and acceptance behavior stay with
those consumers. Configuration metadata is not proof evidence or a composed
128-bit security, privacy, whole-process resource or SQL correctness guarantee.

The owning rejection example covers an AIR that requires a Boolean-trace
assumption. Complete arithmetic, security-report, genuine serialized proof and
hostile-proof examples remain at each consumer boundary. Native validation passed
all 44 owning tests across this library and the three consumers, all four strict
Clippy checks, and all 32 actual SDK security analyses. All 22 prior RNS/NTT numeric
reports are unchanged. See the [validation report](../../experiments/bfv-tensor-proof/VALIDATION.md)
for reproduction, scope, resource observations and retained evidence.
