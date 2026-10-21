# Internal complete Word proof backend

This private implementation is compiled in ordinary library builds behind the
[public Word mathematical API](../word/README.md). It owns a separate
State208/Cmd160/Statement96 mathematical relation, typed witness writer and
actual hiding-STARK probe. It grants no Source/DATA admission, verified prior
state, current head, SQL result or finality authority. The public facade exposes
this exact mathematical backend; existing runtime/finality admission profiles
are unchanged. Fixtures, owner cases and diagnostic/attack helpers remain test-only.

## Responsibilities and dependencies

- `complete_role` constructs the sole graph from the role alone. `schema`,
  `canonical`, `control`, `predicate` and `streams` own its words and equations.
  `complete_build` is a private metadata adapter.
- `expr` records SSA and typed private origins/recipes; `plan` owns public routes
  and multiplicities. `air` lowers the graph to Poseidon2 and native LogUp.
- `public_values` derives the 309 constrained public words from full metadata.
  `goldens` pins the complete graph, every PP cell and native public commitment.
- `owner`, `evaluate` and `witness` own guarded private MAIN construction. Public
  command/walk input ownership and clearing live in `word/inputs.rs`. Bounded
  owner examples are test-only. `check` evaluates actual SDK constraints and original
  lookups for diagnostics; it is not a proof verifier.
- `owner_cases` independently serializes typed public branch examples and
  retains their explicit expected outcomes before creating any trace or proof.
- `assessment` derives actual SDK geometry, conditional security reports and a
  workspace policy before allocating PP or MAIN.
- `structural_setup` constructs immutable public preprocessing. `probe` owns
  producer and independently constructed receiving setups; `probe_wire` owns
  bounded canonical encoding. Internal receiving returns `Result<()>`; only the
  facade constructs its privately owned move-only mathematical result afterwards.
- `inventory_encoding` owns the unchanged exhaustive semantic byte stream used
  by mandatory literal IR/PP/commitment pins. It is normal code; it no longer
  imports a serializer from the test module.

The module uses this crate's SourceVersion metadata and encodings,
[bfv-hiding-stark](../../../../bfv-hiding-stark/README.md) for the actual hiding
suite and Poseidon2 gadget, and
[bounded-postcard](../../../../bounded-postcard/README.md) for shared decoding
limits. Direct test dependencies include the pinned P3 batch STARK, lookup, DFT,
FRI and security APIs, Postcard, SHA2 and the matching public-setup RNG. Default
library builds do not compile this module.

## Complete bounded relation

Both 208-word banks, both 53-word slots, full names/controllers, u64 carry/order,
authorization, savepoints and selected continuation preimages are routed. The
complete hash streams contain 1672 fields and 209 width-12 Poseidon2 absorbs:
Source680, Enrollment64, Old208, Cmd160, New208, Result160, Statement96 and two
Progress48 streams. Source IDs and physical ages share 587 ranged words. Policy25
and all 256 private mask bits have bounded multiplicities; duplicate physical
mask reads count separately.

The equations check conflicts before OFFSET, acquire qualifying OFFSET rows,
skip conflicts before consuming OFFSET and perform no search for LIMIT0. Resume
binds its original statement and blocked revision. NOWAIT derives failure while
restoring the latest saved locks. End compacts complete slots and progress by
transaction identity. Honest native cases cover Begin, Start/Done and the six
additional branches below; this does not establish all PostgreSQL semantics.
Untouched progress also requires independently proved bootstrap and OldRoot
history. Normalized windows 0..4 are bounded mathematical inputs, with no SQL
parser or runtime bridge.

The explicit `word208-v2-structuralPP-direct309PUBLIC` profile allocates public
values by typed address, never by their current field value. Five public provider
rows constrain all 309 words, including an otherwise unused word and padding.
Actual Source openings, banks, mask/WHERE, names and salts remain private.
BlindSql is the existing blinded identity. Public preprocessing depends only on
role, profile and fixed label; no query metadata or fixture chooses it.

Control/Predicate have 462/460 rows, padded to H512, with MAIN568 and PP714.
The actual SDK reports BASE1624/1623, EXT37, degree4, 98 original messages,
34 default packed groups, AUX175, eight committed quotient chunks, 3024 opening
powers and 404 hiding rows. MAIN2/PP2/AUX2 rotations, Q192, EF5, random5, salt4 and
rate8 are retained. Individual SDK baseline/composed reports reach 128 bits under
their existing model; they do not establish BFV or complete-system security.

## Independent setup and per-query verification

`ProverSetup::new(role)` owns the fixed AIR, recipes, assessment and public
ProverData. `VerifierSetup::new(role)` independently derives its own preprocessing,
then drops recipes and prover-only data, retaining its own AIR and CommonData.
There is no constructor accepting producer-supplied CommonData. Neither setup
retains a private input, trace, RNG or verification verdict.

Every request independently derives its current Expected309. The producer fills
the same complete MAIN and creates a new native proof with fresh OS randomness.
The receiver checks the complete original Source images and public metadata,
canonical bytes and actual native proof against its own current expectation.
Deterministic public configuration dies before private commitments. Reusing
immutable public setup does not cache Source admission, authorization or a proof
verdict. Cold wrappers include construction of that setup.

The private v2 frame `DCSWCW02` rejects old v1 frames. Its limits are 4MiB per
frame, 4096 elements per sequence and 4Mi shared decoded slots. Canonical Gold is
LE[8], EF5 has five canonical coordinates; EOF and exact re-encoding are required.
All five PCS rounds, rotations, ten binary FRI folds, digests, salts, PoWs and the
sole zero lookup terminal are checked before mandatory native verification.
The conservative honest envelope is 353962 Gold fields plus 4946 EF5 values,
including at most 9513 frontier digests: at most 3127840 payload bytes and 3455834
decoded slots. Shape checks do not authenticate a proof.

The workspace policy reserves 789257618/789652334 bytes, including an additional
independently owned public setup. The external held-process cap remains 1792MiB.
The ledger and sampled memory are not universal whole-process bounds. Private
buffer fills are best effort, without a stack/compiler/allocator erasure claim.

## Reproducible owning checks

```sh
cargo clippy --release --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --locked -p registry200-proof registry_progress::word_inventory:: -- --nocapture --test-threads=1
```

The first 16 cases passed in 3.94s: complete inventory and unconditional literal graph
and PP pins, actual assessment, honest MAIN checks, public-value constraints,
independent preprocessing invariance, three genuine honest proofs and receiving,
and canonical/resource/hostile proof gates. The warm predicate case uses the
same producer setup and a separately constructed receiver for distinct valid
expectations. Repairing a plain header for the foreign expectation passes shape
but fails actual native verification; its own fresh genuine proof succeeds.

A repaired Add passes every local BASE equation but fails the original wire
multiset. Actual release proving creates its proof; the native verifier rejects
exact `Lookup(TerminalSumNonZero)`. Forging terminal0 then fails actual opening/OOD
verification. Wrong MAIN/PP/AUX openings and FRI leaves are likewise rejected.
Header/scope, canonicality, EOF, sequence/global/frontier budgets and a restored
honest verification are checked without generating another honest proof.

One CPU/Rayon2 diagnostic recorded cold creation plus independent verification
at 477.811ms for Control and 473.021ms for Predicate. With already prepared public
setups, a distinct Predicate request took 184.436ms to produce and 67.525ms to
receive, totaling 251.961ms. Independent receiver setup took 113.873ms separately.
Frames were 2934954/2935946 bytes cold and 2941770 bytes for the distinct request.
These single samples do not establish a controlled speedup or a complete query.
The exact executed source, phase breakdown and resource receipts are recorded in
[AIR validation](../AIR-VALIDATION.md).

## Six independently specified branch proofs

The two additional tests passed with the existing sixteen in one 19-case,
6.00s native gate. The nineteenth case belonged to a temporary compression
measurement, whose code/dependency was removed after archiving. Eighteen owning
tests remain. Each of these six positive branches has its own genuine proof:

| Case | Independent expected outcome |
| --- | --- |
| WAIT before OFFSET | row0 conflict, cursor0, no visited/selected, Park with real Progress48 |
| SKIP before OFFSET | skip row0, lock offset row1 AND selected row2, Done/cursor3 |
| LIMIT0 | no attempted row despite row0 conflict, Done, no new locks |
| WAIT resume | original row0 prefix retained, old holder absent, select rows1/2, micro2/Done |
| NOWAIT latest savepoint | selected prefix row0, Error, failed1, restore latest saved row0 and release row2 |
| End A | move B's entire53 slot +5 progress fields to slot0; Result for ended A has newProgress0 |

Typed Bank/Slot/Frame examples independently serialize complete bank208, Cmd160,
Stmt96, Progress48 and Result160. Only the original nonsecret Source/enrollment
fixture is shared. Every case checks all old/new bank words and physical scan
and Result wires, then creates a fresh native proof and verifies it against an
independent current Expected309. Producer and receiver public setup is reused
within a role and released before the other role. These math roundtrips measured
245.142-258.317ms, excluding fixture/direct-check and public setup preparation.

All six fully repaired wrong outcomes fail actual witness equations; an honest
proof with a repaired header for each wrong claim also fails native verification.
Six additional resume negatives preserve the historical progress root while
changing its revision, prefix, wait mode, holder or original SQL identity. Resume
retains the original snapshot/call/statement while its current parent changes;
the historical holder may already have ended. The fixture does not prove the
intervening EndB or prior history. Opaque nonactor progress still depends on
independently established bootstrap and OldRoot induction.

Re-Park, named rollback/release, NOWAIT without a savepoint, End actor1/abort/failed
and counter overflow are not newly covered. NOWAIT's selected prefix represents
an error, never successful returned rows. See the owning validation record for
exact source, byte, timing and resource receipts.

Source/DATA proofs, original FHE request/product, owner provenance, bootstrap and
history, fresh weighted QC, transport and durable completion are absent from
these timings. The separate [QueryCt formation composition](query_mask_inventory/VALIDATION.md#fused-original-query-formation)
now proves the complete Stmt96-mask/original-QueryCt relation through a public
lower mathematical API. Its independent Word/Source/DATA/current-head admission
is still required; local owner custody does not supply that evidence. The
complete DCS query has not met the <=500ms target.
