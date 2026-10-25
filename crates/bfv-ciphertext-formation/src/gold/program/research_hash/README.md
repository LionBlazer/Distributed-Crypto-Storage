# Shared owning research hash harness

This module is declared only under `#[cfg(test)]` in `gold::program`. It owns
one physical proof-MMCS/FS research implementation shared by the owning Query
and DATA test hierarchies. `ro` moves the existing finite H256/H512 raw-key
state; `config` moves its fixed native hiding PCS/MMCS/FRI adapter; the
[opaque engine](opaque_inputs/README.md) accepts only two closed family layouts.
It defines no production crypto configuration, public API or accepting verifier.

`Programmer` owns assignment rights; native receivers get only `Oracle`.
State, Access, dictionary/RNG storage and plant512 stay private to ro. Public-to-
the-test-owner contracts have visibility `pub(in crate::gold::program)`.
Clones of either role retain one Arc/Mutex state. Same literal raw keys share
answers regardless of which family or native role queried them. No per-family
namespace is added to LEAF, NODE or transcript bytes.

FIELD/CAP/SAMPLE/DRAW encoding, full64-byte retries, native Gold rejection,
all trace bounds and the original finite dictionary caps remain unchanged.
A repeated identical plant succeeds; an existing-different answer is never
overwritten. The raw dictionary is not reset after an attempted conflict.
An explicit seeded regression RNG supplies new answers; this is not concrete
SHA or an implementation proof of an ideal random oracle or PRG assumption.

The native config retains EF5, blowup8,192 queries, random5, salt4, cap0,
12 FRI folds for degree12, and all zero-PoW slots. Query keeps its actual AIR,
Expected, PP factory, codec, Receiver, transcript schedule and native assembler.
The [DATA research owner](../dense_data_inventory/research_data/README.md)
supplies its own corresponding contracts. Moving
these helpers does not itself assemble a DATA proof or a mixed-family receiver.

Direct dependencies are fixed bfv-hiding-stark field/namespace/parameter aliases,
pinned P3 native challenger/MMCS/PCS/FRI types, rand0.10 and standard owned
collections/synchronization. Family Expected, witness, AIR and codec types do
not enter this shared component.

Existing raw-retry and native opaque tests move with their owner. Added tests
exercise exact shared LEAF/NODE answers, same full transcript-prefix answers,
a conflicting digest tail with unchanged acceptedLE64, old-walk replay, DATA
native multiproofs and both closed width bounds. All eight shared cases passed
after relocation. The preserved Query tape and complete two-frame Query
shared-session gate also passed under the existing observer.

## Executed validation

Strict Clippy r888 and optimized build r889 passed. The three observed gates used
one pinned executable, SHA256
`A449CAE103056923B28DC49145225FD9F80108D1C47182A49601788F153B23AB`.

| Run | Owning gate | Passed | Harness | Process wall | OS peak |
| --- | --- | ---: | ---: | ---: | ---: |
| r890 | Shared raw retry/coupling/conflict, native Query/DATA opaque cases and bounds | 8 | 0.37 s | 397.9206 ms | 67,436,544 B |
| r891 | Preserved complete Query tape parser | 1 | 0.00 s | 10.3268 ms | 5,492,736 B |
| r892 | Two complete public Query frames, shared dictionary and conflict/replay | 1 | 8.81 s | 8817.2222 ms | 709,193,728 B |

All10 selected cases passed with zero ignored; the last explicitly selected its
ignored heavy target. Source/image pins matched and no observer fault or cleanup
occurred. The held executable/creation handle,120s/1792MiB fuse,20ms sampling
and Rayon8 remained unchanged. Normal owning check r893 and requirements_sync
r894 passed. Source review found no blocking defect and confirmed old Query RO/
config arithmetic and hash encodings were preserved.

Each full-family opaque case includes five genuine native positives and24 native
hostile checks, cache replay, disclosure cap, and permanent forest failure after
an actual leaf conflict. The two-frame Query gate includes native receive/replay
and normal SHA rejection; its duration is a multi-attempt test, not query latency.
This stage does not execute a complete DATA frame or a mixed Query/DATA session.

The model remains restricted proof-MMCS/FS ROM with concrete PUBLIC helpers,
fixed conditioning/ideal-cell premises and explicit conflict failures. It is
not all-helper ROM, adaptive privacy, concrete SHA/PRG/BFV assurance, Source/key/
current-version authority, application admission, executable SQL or a <=500ms
query measurement. Whole-process resource compliance still needs the unchanged
held-process observer; dictionary limits alone do not establish it.
A subsequent [DATA native gate](../dense_data_inventory/research_data/README.md)
also passed complete frame acceptance/replay and21 hostile native checks using
this same implementation. The subsequent [mixed Query/DATA gate](MIXED-SESSIONS.md) also passes native
acceptance, same-history replay after a raw-tail conflict, foreign-header
rejection and selected concrete helper consistency. Whole-process memory includes
both PP histories. Source/Role3/Word and adaptive/concrete assurance remain open.
