# Fixed arithmetic STARK backend

This library owns the identical linked Plonky3 configuration shared by the public
RNS-scaling, native-NTT, tensor and relinearization proof experiments. It removes duplicate
configuration and security-floor code while consumers retain their operation
contracts. Native validation covers the fixed configuration and the shared
`ProfileAir` delegation wrapper across all four consumers.

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

`ProfileAir<A>::new(inner)` preserves the inner evaluator and all pinned `BaseAir`
metadata, including overridable periodic methods, Boolean/boundary declarations,
current/next openings and preprocessing. It only declares eight additional public
values; `inner()` keeps preparation and role-specific checks with the consumer.
`PROFILE_WORDS` is fixed at eight. `profile_words(profile32)` encodes that caller-owned
digest as the existing eight little-endian u32 words. Consumers append the words
after their unchanged arithmetic public prefix (currently 32 then 8). The SDK
observes the entire verifier-owned public vector in its transcript. The wrapper
adds no arithmetic assertion, profile choice, prepared-data check or accepting token.

Consumers own their role checks and profile/domain bytes, report serialization,
errors, frame/decoder limits, canonical public inputs, preparation, independent
verifier key, proof generation/verification and lifecycle. The pure arithmetic
circuit libraries do not depend on this backend. Existing RNS and NTT profile
bytes, numeric report fields/order, codecs, caps and acceptance behavior stay with
those consumers. Configuration metadata is not proof evidence or a composed
128-bit security, privacy, whole-process resource or SQL correctness guarantee.

The two owning tests cover rejection of a Boolean-trace assumption and complete
metadata forwarding, including explicit periodic overrides, unchanged boundary
indices and exact suffix ordering. Arithmetic, security-report, genuine serialized
proof and hostile-proof examples remain at each consumer boundary. Native
validation passed all 61 owning tests across this library and four consumers,
all five strict Clippy checks, and all 34 actual SDK security analyses. All 32
preceding RNS/NTT/tensor report dictionaries are unchanged. See the
[validation report](../../experiments/bfv-relinearization-proof/VALIDATION.md)
for reproduction, scope, resource observations and retained evidence.
