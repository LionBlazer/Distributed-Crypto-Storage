# Full raw-history research harness


The private [full-history module](../full_history.rs) adds `FullDriver::sha512` over
all five fixed native templates. It parses exact nested SDK seeds, canonical
FIELDs and CAPs, global SAMPLE counters, and a final DRAW at any coordinate with
any `u64` retry. Each group is restored from its complete byte-prefix identity;
all claimed earlier SAMPLEs must match actual SHA512 first-accept sampling.
A query after that first accepted retry still gets its actual raw hash answer,
but is explicitly outside the native rejection-sampling path.

All MAIN/PP/AUX/quotient/random/FRI words retain their first `(schema, root)`
snapshot in the shared SHA256 history. Geometry preserves ordered matrices,
base/EF5 projections, hiding codewords and per-matrix salt4. MAIN/PP retain the
original driver's exact snapshot identity. Other words use immutable first cuts
and a real zero-completed row oracle. Complete public-source classification and
relevant word notifications precede group restoration. No Expected or configurable
verifier callback is accepted.

The module uses the parent classifier/dictionary, actual suite Challenger audit,
actual SDK PCS/FRI separators, and `sha2`. Its eleven owning cases are covered by
the r755 observation below; the five-family primitive case uses actual Challenger
calls with opaque unverified commitments, not five genuine receiver proofs.
Word correctly reports missing fixed PP in that primitive case. The earlier
validated genuine Word association remains owned by the [first-coin tests](../README.md).

```sh
cargo test --release --locked -p registry200-proof --features owner-read registry_progress::word_inventory::generalized_mu::first_coin::full_history::tests:: -- --test-threads=1
```

The analysis harness limits new groups/typed words to 1024 each and retained group
anchors to 32 MiB; it does not reject a long raw suffix before early notifications.
Existing groups survive a resource refusal. The underlying SHA256 recorder and
initial source cache still have research-trace ownership, not a production RAM
guarantee. Restoration draw computations and external queries are counted
separately, without claiming a deduplicated random-oracle budget.

This restores deterministic actual-hash ancestors. It does not implement a
programmable random oracle, geometric ROM coupling or the uniform pointwise RBR
state function. In particular, App/list, rational-balance/alpha, OOD/MCA/FRI-live
predicates and quantitative restoration equations remain mathematical obligations.
No proof/native-admission or full-query latency conclusion follows.

## Genuine receiver capture gate

The test-only `check_actual_histories(&[audit::Trace])` entry point is reexported
through the private owning modules into `word_inventory`. The existing genuine
five-proof receiving test calls it only after its native verification and typed
CAP/opening checks. It consumes those actual receiver captures, rather than a
metadata-generated transcript or a new configuration/verdict callback.

The gate checks constructor-only traces before filtering them, identifies every
closed family from its actual seed, and feeds the entire collection of raw DRAW
preimages to `FullDriver` in reverse. It compares every actual SHA512 digest,
counter, coordinate, retry and native first-accept eligibility. It requires all
1335 accepted coordinates, 77 groups, 75 typed words, three PP words and eight
original MAIN/PP snapshots. After a late SHA256 query it replays the captures in
forward order and requires the exact same group, word and snapshot objects and
cutoffs. The bounded observer must see the gate's explicit success marker.
The reversed schedule uses the chosen concatenation of captures and their own
draw order. The audit API does not record one global temporal interleaving of
concurrent Word/Query calls; the gate does not reconstruct that chronology.

This gate supplies no SHA256 PP preimages. Word's fixed-PP association must
therefore fail; DATA/Query's degree-valid zero fallback is explicitly not
authenticated receiver PP. Successful native verification and successful RAW
history recognition remain distinct observations. The code does not claim
complete public-PP extraction or an admission capability.

## Executed observations

Rust 1.99.0 MSVC, optimized release/native CPU, locked offline dependencies,
eight shared Rayon workers and serial test execution. Both bounded observers
held the exact executable handle and creation identity, with a 120-second/
1792-MiB process bound and 20-ms memory sampling. Both exited zero with no faults,
ignored cases or cleanup actions; build sources and image bytes stayed pinned.

| Gate | Cases | Harness time | Process wall | Sampled OS peak |
| --- | ---: | ---: | ---: | ---: |
| r755, owning history/negative/retry/row cases | 11 | 8.12 s | 8181.9164 ms | 75,243,520 B |
| r756, genuine five-proof receiver plus restoration | 1 | 15.14 s | 15166.4716 ms | 586,010,624 B |

The genuine gate preserved the existing native verification and hostile-opening
checks and required the new helper's explicit success marker: five families,
77 groups, 1335 accepted samples, 75 roots and three PP words. The observer
separately required `complete_PP_extraction=false`, failed Word PP association
and unauthenticated DATA/Query PP fallback. No missing PP was silently promoted.

The shared executable SHA256 was
`64534FED04191AED6C5088ED29BCC7FBD4B0EF2A3A2AE0E73A4ED97C3C8797C9`.
Strict Clippy passed (r753) after explicitly consuming parsed canonical fields
and collapsing one nested condition; no warning allowance was added.
Independent source reviews found no blocking defect in the stated deterministic
harness and narrow actual-capture adapter. These checks do not establish a
random-oracle theorem or the complete SQL latency target.
