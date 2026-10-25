# Public Query native FRI assembly

This isolated child of the [owning research harness](../README.md) consumes
PUBLIC V/B and a complete presampled raw FS tape. It assembles the genuine
native Query BatchProof layout without an original trace, Prepared, witness or
key. The caller still uses the parent's bounded encode/decode/Receiver boundary.
The module exists only in the crate's unit-test build.

`TapePlan::checked` requires exactly277 accepted Gold draws with contiguous full
64-byte retry digests and no unused entries, within4096 raw draws. It retains
native192 low15-bit indices, duplicates and their first-unique physical7H32768
positions. `sample` samples the raw tape before constructing V/B. The law is
Gold rejection plus native low bits; indices are not replaced with IID uniform
samples.

`Inputs::new` owns one fresh attempt: four fixed opaque R/MAIN/Q/AUX trees,
ordinary native public PP, their shared research oracle and separate salt
streams. It reconstructs actual PP from its zero-interleaved4096-row polynomial,
builds native salted MMCS data and requires exact cap equality to independently
created CommonData. `public_pp_coefficients` returns shared read-only PUBLIC
association data. Consuming `prove(plan, view, B, walks)` checks fixed dimensions,
actual PP coefficients/rows/OOD and plan/physical-point association.

The real BatchProverTranscript and PcsProverTranscript drive every observation,
challenge and bracket. Native `prove_fri` receives actual B evaluations on the
bit-reversed32768-point coset, with unchanged EF5/blowup8/query192/salt4/cap0 and
zero PoW. It creates all12 fold commitments, folds, final polynomial, query
indices and FRI multiproofs. All five INPUT openings are then supplied: four
from opaque_inputs and PP from genuine native MMCS. INPUT leaf programming is
after ordinary FRI hashing, so shared-oracle aliases are actual conflicts.
Repeated native indices reuse their exact rows and salts. Wrapper OOD claims
retain native [round][matrix][point] nesting: five per private matrix/point,
zero for PP. R carries five outer coordinates plus five wrapper coordinates.

Direct dependencies are [research_ro](../research_ro.rs),
[research_config](../research_config.rs), [opaque_inputs](../opaque_inputs/README.md),
[public_deep](../public_deep.rs), actual public_image/FullAir/setup/codec, pinned
P3 native transcript/FRI/MMCS types, rand-public-pp and standard owned collections.
The separate full receiver test additionally needs the owning joint-disclosure
sampler. No config override, approving callback or production facade is exposed.

Tests include raw retry/duplicate rejection cases, a genuine native
PCS/FRI positive with explicit public zero-private algebra and true PP (whose
complete AIR verification MUST reject), and a separate jointV+B native receiver
positive using the actual owning samplers. Hostile omissions, rows/salts,
wrapper claims, PoW, FRI roots/final value and OOD coordinates are checked through
native receivers. All three tests passed in runs r821/r822/r823 from build r819.
Both heavy cases are opt-in and were explicitly run alone under the owning
held-process resource observer. Their harness times were 1.56 s and 4.55 s,
including preparation and mutation checks. See the
[executed validation](../../RESEARCH-VALIDATION.md) for image pins, process
measurements and scope. These are research tests, not full SQL measurements.

The additional shared-session gate builds two fresh complete frames in one
dictionary with independent presampled tapes and owned sampler streams. It
replays the first immutable frame after the second, forces an existing-different
full raw512 FS cell, then replays both old frames through the same query-only
receiver. Actual FIELD/CAP/SAMPLE/RAW walks remain equal. Selected concrete
PUBLIC helper finalizations have equal complete algorithm/input/result manifests;
all seven instrumented helper families and all three PP stream labels are required.
This finite gate passed in r846; its 8.03 s harness time includes preparation,
two productions, repeated verification and conflict controls.

The dictionary is an explicit seeded regression/programming model. Concrete SHA
cannot be programmed. Ordinary public helper SHA calls remain outside this
shared dictionary; no complete helper-ROM or concrete PRG theorem is claimed.
A successful research frame grants no normal-SHA authority, privacy theorem,
production admission, SQL result or full-query latency claim.
