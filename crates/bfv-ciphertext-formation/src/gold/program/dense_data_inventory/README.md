# Dense Data metadata inventory

This test-private research child proposes a new 56-gate row layout for ONE Data
ciphertext Formation relation. It has no MAIN writer, full-PP factory, native
setup, prover, verifier, wire, admission token, or production registration.
MetadataAir only exposes the actual symbolic relation for native assessment.

The plan streams unchanged graph::Plan::row32 and supplies every original gate,
node ID, coefficient and signed occurrence. Per-slot active/pointwise/fanout flags
handle unaligned stage boundaries. The last graph row has 48 active and 8 zero
slots. 1463 graph rows + 514 Cw + 66 Cs + 5 range-only rows fill H2048 exactly.
All physical rows carry two full coefficient range groups: all4096 shared S/E,
twoK, W, AS0/1 and nonzero-biased-K inverses remain. Cs emits all512 words.
The DATA layout uses the same private range_equations emitter as old Pair/Data.

MAIN512: graph uses0..223, hash uses0..247 in exclusive phases; range values248..266,
196 bits267..462, zeros463..495, hash checkpoints496..507, secret accumulator508,
zeros509..511. There are 224 graph/hash and 19 range ports. PP668 is fixed by this
candidate. Global lookup occurrences use verifier-owned counts, including fanout2.
A hash consumes its rate cells directly instead of a duplicated payload buffer.
Poseidon equations and complete514/66 context/salt/payload schedules are unchanged.

Tests compare complete streamed original-vs-dense graph semantics, range/c0/
secret-word schedules and all hash preimages. They check every node balance and
producer multiplicity, all coefficient/phase boundaries and zero inactive slots.
The actual pinned SDK symbolic, default-packing, security and resource checks
passed on 2026-10-21. This result covers metadata; no private proof exists here.

| Native metadata | Value |
| --- | ---: |
| Height / MAIN / PP / public values | 2048 / 512 / 668 / 32 |
| BASE / EXT constraints | 1248 / 84 |
| Degree / committed quotient chunks | 4 / 8 |
| Original / packed lookups / AUX | 243 / 81 / 410 |
| Batched openings | 2622 |
| Modeled workspace bytes | 669,417,472 |
| Individual UDR / LDR floor | 128 / 128 bits |
| LogUp analytical term | 297.075187496394 bits |

Three owning tests cover full semantic preservation, every phase boundary, and
the complete ordered native BASE/EXT/original/packed tuple. The latter is 571,450
bytes, captured before any MAIN writer and then pinned unconditionally alongside
every field of the streamed PP. The separate original Pair/Data golden tests
also pass after extracting the shared range equations. Their original ordered
relations, complete PP, profiles, requests and public bindings remain unchanged.

Run the two focused filters serially in the repository's release configuration:

```sh
cargo test --release --offline --locked -p bfv-ciphertext-formation --lib constraints_lookups_and_full_preprocessing_snapshot -- --nocapture --test-threads=1
cargo test --release --offline --locked -p bfv-ciphertext-formation --lib gold::program::dense_data_inventory:: -- --nocapture --test-threads=1
```

Assessment retains the original checked SDK default-packing, hiding, full
baseline/composed UDR/LDR and LogUp checks under the same128 floor, EF5/Q192/rate8/
5random-codeword/4salt policy. Its stage-specific resource formulas are preserved
with actual new widths/height. The estimate is NOT whole-process RSS and cannot
authorize proof execution. A later writer/backend requires independent lifecycle,
memory, full proof/hostile native verifier and codec gates under the1792MiB cap.
This analytical floor does not assess lattice confidentiality or composed-system
security. Smaller height and modeled workspace establish no latency improvement.

The new research domain/BUS is separate from old Data/Pair profiles. No old proof,
QC, Source/Data admission, owner-query binding, current head or SQL result is cast.
Expected PUBLIC32, c0 and frequency coefficients still depend on the exact request:
this is NOT cross-request PP caching. A new query Stmt96/encoding association and
actual FHE/product/fresh-quorum composition remain separate future obligations.
