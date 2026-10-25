# Complete Query and DATA sessions in one research oracle

This private cfg(test) gate exercises both owning frame factories with one
retained raw-input history. Query and DATA keep separate Expected, AIR, PP and
frame/codec types. The [shared owner](README.md) supplies one Programmer and
query-only receiver handles. No normal API, crypto config or admission changes.

## Owned sequence

The [Query factory](../query_formation/research_query/public_frames.rs) moves
from the existing two-Query test without changing its samplers, native calls,
seed arithmetic, assertions or producer drop boundaries. The old test body is
unchanged. Its new byte entry preserves the same header, normal shape, second
bounded parse, EOF, canonical re-encode and actual verify_batch.

The [DATA owner](../dense_data_inventory/research_data/README.md) is consumed
unchanged. Two distinct complete raw tapes are sampled before either V/B
construction. Exactly one Programmer supplies both receivers and producers.

1. Produce and receive Query, dropping producer PP/Inputs/V/B/proof banks before
   the factory returns.
2. Produce and receive DATA, retaining both true public PP histories and every
   old dictionary answer.
3. Replay both immutable frames and require each complete old native walk.
4. Pass each frame to the other byte receiver: reject before challenger draws
   or selected concrete PUBLIC helper finalizations.
5. Require both concrete normal-SHA facades to reject these research frames.
6. Reconstruct DATA's existing first raw FS key, flip digest byte63 preserving
   its first LE64 candidate, and catch the named programming conflict outside
   the SDK receiver guard.
7. Replay both old frames through the same query-only handles and dictionary.
   No producer rerun, table reset, overwrite, fresh mask or tape retry follows.

Walk comparison retains every FIELD/CAP/SAMPLE observation and full 64-byte
retry digest, with 277 accepted samples and 17 caps per frame. Actual adapters
supply five INPUT and 12 native FRI rounds. Query retains PP545/83 lookups/
2327 opening terms; DATA PP668/81 lookups/2622 terms. This DATA sample consumed
383021 Gold cells at 192 unique points. Source-domain degree may shrink at
rotation overlaps; the generic maximum 383953 is not assumed for every tape.

## Selected concrete PUBLIC helpers

Separate non-nested calling-thread captures observe both Expected constructions,
receiving setups, productions, first receives, replays, foreign rejection and
normal-SHA rejection. Each call retains its actual SHA kind, raw input and result.
The registry independently recomputes SHA and checks overlapping raw cells.
Three PP stream labels must contain their owning complete Expected binding.

Required Query/DATA prefixes are disjoint from proof LEAF/NODE/TRANSCRIPT inputs.
Setup/receive subset checks and replay call-vector equality stay within a family;
different Query/DATA parameter manifests are not equated. The executed registry
contained 16 unique selected helper cells. No answer is substituted or planted
into the proof oracle; arbitrary-worker and all-string capture are not claimed.

## Executed checks

Strict Clippy r910 and optimized build r911 passed. All three exact cases passed
with zero ignored; r912/r913 explicitly selected their ignored heavy targets.

| Run | Owning case | Harness | Process wall | OS peak |
| --- | --- | ---: | ---: | ---: |
| r912 | Mixed Query/DATA, replay and raw-tail conflict | 9.62 s | 9636.3207 ms | 1,041,694,720 B |
| r913 | Preserved complete two-Query shared-session gate | 9.11 s | 9123.1701 ms | 710,311,936 B |
| r914 | Preserved exact Query raw-tape parser | 0.00 s | 19.0275 ms | 5,554,176 B |

Mixed CPU time was 17.78125 s; peak private allocation 1,074,503,680 B. Query frame size
was 2,946,493 B, DATA 3,284,405 B. Captured factory durations were 3762.768 ms and 4770.255 ms.
They include setup, public research sampling, native assembly and observation.
The total also covers both receiving setups, repeated verification and negative
controls. These are not production proving benchmarks or full SQL latency.

Executable SHA256:
`C52EEFF4A6D6FE34A924FFC80613D5F32981A06DDBA2BB6E83ADB8D613A3573E`.
The held exact executable/creation handle, 120 s/1792 MiB fuse, 20 ms sampling, Rayon8
and dictionary caps remain unchanged. Both true PP histories count toward memory.
All source/image pins matched, with no observer fault or cleanup. Normal owning
check r915 and requirements_sync r916 passed. Independent source review found
no blocking issue; it did not independently execute these gates.

Select the owning heavy target under the held-process observer:

    cargo test --release --locked -p bfv-ciphertext-formation gold::program::research_hash::mixed_sessions_tests::query_and_data_complete_frames_share_one_raw_oracle_and_replay_after_a_named_raw_tail_conflict -- --ignored --exact --test-threads=1

## Remaining boundary

This finite seeded regression is restricted proof-MMCS/FS ROM plus concrete
PUBLIC helpers, retaining fixed-instance/ideal-cell/honest-AIR premises. It is
not an adaptive privacy theorem, concrete SHA/PRG/BFV assurance or full Source/
Role3/Word composition. Both normal SHA verifiers reject programmed frames.
Fresh version authority, application admission, network SQL, weighted agreement,
finalized FOR UPDATE/SKIP LOCKED and the full 500 ms request remain unproven.
