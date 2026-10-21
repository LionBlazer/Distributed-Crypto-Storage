# Private complete word-level proof candidate

This module is compiled only for this library's tests. It owns a separate
State208/Cmd160/Statement96 mathematical candidate, its typed witness writer and
actual hiding-STARK probe. It grants no Source/DATA admission, verified state
history, current head, SQL result or finality authority. Existing production
profiles and receiving APIs remain unchanged.

## Responsibilities and dependencies

- `complete` constructs the sole typed semantic graph. `schema`, `canonical`,
  `control`, `predicate` and `streams` own its fixed words and equations.
- `expr` records SSA and private typed origins/recipes; `plan` owns deterministic
  public routing and multiplicities; `air` lowers the complete graph to Poseidon2
  and three native LogUp buses. No caller supplies an AIR or verifier callback.
- `owner`, `evaluate` and `witness` construct bounded public examples and guarded
  private MAIN traces. `check` evaluates the actual SDK BASE constraints and
  original lookup expressions for diagnostics.
- `assessment` derives actual SDK geometry, conditional security reports and a
  conservative workspace policy before allocating PP or MAIN.
- `probe` creates real proofs and independently verifies them with its own
  trusted PUBLIC preprocessing. `probe_wire` owns canonical bounded encoding.
  Their private receiving result is `Result<()>`, without an installable token.

The module uses this crate's SourceVersion expectation and Source encodings;
[bfv-hiding-stark](../../../../bfv-hiding-stark/README.md) supplies the actual
hiding suite and Poseidon2 gadget, and
[bounded-postcard](../../../../bounded-postcard/README.md) supplies shared decoding
limits. Direct test dependencies additionally include the pinned P3 batch STARK,
lookup, DFT, FRI and security APIs, Postcard, SHA2 and a matching public-setup RNG.
Default library builds do not compile this module.

## Complete bounded relation

Both 208-word banks, both 53-word slots, full names/controllers, u64 carry/order,
authorization, savepoint state and selected continuation preimages are routed.
The actual hash streams contain 1672 fields and 209 width-12 Poseidon2 absorbs:
Source680, Enrollment64, Old208, Cmd160, New208, Result160, Statement96 and two
Progress48 streams. Source table/row IDs and physical ages reuse the same 587
ranged Source words. Policy25 and all 256 mask bits have bounded multiplicities;
all four physical mask reads count separately, including duplicate ages.

Scanning checks conflicts before OFFSET, locks qualifying OFFSET rows, skips
conflicts before consuming OFFSET, and performs no search for LIMIT0. Resume
binds its original statement and older blocked revision. NOWAIT keeps the
requested command while its failure effect restores the latest saved locks.
End compacts complete slots and progress roots by stable transaction identity.
Canonicality of untouched progress depends on an independently proved bootstrap
and OldRoot history; this probe does not supply either. Normalized windows0..4
are this bounded relation's inputs, without a SQL parser bridge.

The complete graph uses 455 rows/H512, MAIN568 and PP708. Eight range values and
256 bits occupy spare hash-row space; twelve policy reads share fixed public
flags. Constants and every route/count remain verifier-owned. Three literal bus
names belong to this one closed instance; multiple instances cannot be batched
without separate namespaces. The historical internal graph-domain bytes remain
unchanged; the native probe has its own explicit wire profile.

## Proving, receiving and limits

The producer returns unverified bytes. A deterministic config is used solely for
PUBLIC preprocessing and is dropped before private commitments. MAIN, AUX,
quotient and masking use fresh OS randomness through the unchanged hiding suite.
The cold receiver binds the complete independently retained public expectation,
rebuilds the full AIR and trusted preprocessing, then runs actual native verify.
A header, canonical shape, hash or successful decode cannot replace verification.

The frame is at most 4MiB, each decoded sequence at most 4096 elements, and the
shared per-call slot budget is 4Mi. Canonical Gold is binary LE[8], EF5 has five
such coordinates; EOF and exact re-encoding are required. All five PCS rounds,
MAIN2/PP2/AUX2 openings, ten binary FRI folds, digests, salts, PoWs and the sole
zero lookup terminal are checked before native verification.

The actual SDK reports 98 original messages, 34 packed groups, AUX175, degree4,
eight committed chunks, 3012 opening powers and 404 hiding rows. Q192, EF5, random5,
salt4 and rate8 remain fixed. Individual baseline/composed SDK reports reached
128 bits; they do not establish BFV confidentiality or complete-system security.
The workspace policy is about 680MiB; the external held-process cap is 1792MiB.
Neither the ledger nor sampled memory proves a universal memory bound. Private
buffer fills are best effort, without a stack/compiler/allocator erasure claim.

## Reproducible owning checks

```sh
cargo clippy --release --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --locked -p registry200-proof registry_progress::word_inventory:: -- --nocapture --test-threads=1
```

The 13 cases passed in 2.32s: complete inventory and unconditional full-IR goldens,
actual assessment, both honest MAIN/proof/cold roundtrips, exact false-wire
terminal rejection and forged-zero native rejection, malformed fields/openings,
per-sequence/global/frontier budgets, and restored honest verification. Honest
fixtures cover Control Begin and Predicate Start/Done; the other business
branches still need honest witness/proof coverage.

One optimized CPU/Rayon2 sample measured Control 296.452ms preparation/proving
through encoding plus 178.022ms cold receiving; Predicate 303.881+174.624ms, with
2926794/2925098-byte frames. Each side spent about 91–95ms on PUBLIC preprocessing.
Other unrelated compiler processes were active, so these are diagnostic single
samples, not isolated or complete-query benchmarks. Source/DATA proofs, original
FHE request/product, history/bootstrap, fresh weighted QC, transport and durable
completion are absent. The <=500ms complete DCS query target remains unmet.

The exact executable/source archive and phase/resource receipts are described in
[AIR validation](../AIR-VALIDATION.md). No whole-system guarantee follows from
this private proof candidate.
