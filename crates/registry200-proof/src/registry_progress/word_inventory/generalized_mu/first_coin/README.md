# First-coin source association research harness

This private test-only module joins actual SHA256 query registration to the
[all-five public-instance classifier](../README.md). Its internal `Driver` owns
the hash dictionary, typed first snapshots and classification cache. It never
returns an admission capability or changes the production challenger/verifier.

`Driver::sha256` answers with actual SHA256, keeps the first preimage of each
digest and records collisions and hits on previously protected targets. Exact
binary node children become protected only after that query's output is checked.
`Driver::sha512` identifies one of the five complete native SDK seeds without a
caller-supplied family, then parses degree, MAIN, complete public values and PP.
MAIN is notified as soon as its cap is complete, even when public values are
missing or malformed. PP is notified before inspecting any trailing events.
An arbitrarily large unrelated suffix cannot defer either notification.

Each `(schema, root)` retains its first immutable snapshot. Traversal uses only
preimages known at that snapshot's cutoff. Unknown or malformed subtrees become
fixed zero cells. A private `Read` adapter copies root/cutoff from those registered
snapshots, streams only public values and PP data cells, and completes the actual
classifier before SHA512 is computed. The cache key is the complete initial
event prefix. Late hash queries, repeated queries, reverse retry order and later
public metadata cannot repair or retime an existing association.

The exact first DRAW has counter zero and any `u64` retry. Other suffixes still
conservatively freeze and classify a recognizable complete initial prefix, but
are not reported as canonical first draws. Every raw query receives its actual
SHA512 digest, including queries whose source classification fails.

Direct dependencies are the parent classifier and geometry, the suite hash and
separator inspection APIs, pinned uni/batch transcript shapes, Goldilocks field
encoding, `sha2`, and standard immutable `Arc`/collection/stream facilities. Tests
also use native P3 transcript helpers and the suite's existing transcript audit
feature to compare first-query bytes with the actual challenger.

```sh
cargo test --release --locked -p registry200-proof --features owner-read registry_progress::word_inventory::generalized_mu::first_coin::tests:: -- --test-threads=1
```

## Executed checks

The r748 bounded release gate passed all eight owning cases, with no failed or
ignored cases. The cases cover all five source associations (including a complete
actual-SHA Word PP tree), reverse and repeated retry order, MAIN notification
before incomplete public data, a malformed suffix larger than 8 MiB, permanent
invalid Word PP, a later target hit that cannot replace a frozen zero word,
seed/degree/canonical-field/cap/extent mutations, and correspondence with actual
uni/batch SDK helpers and the actual challenger's first SHA512 draw.

Rust 1.99.0 MSVC, optimized release/native CPU, locked offline dependencies,
eight shared Rayon workers and serial test execution. Harness time was 2.81 s;
process wall was 2841.7215 ms and sampled OS peak was 164,290,560 bytes. The
observer held the executable's process handle and creation identity, with a
120-second/1792-MiB bound and 20-ms memory sampling. It recorded no faults or
cleanup actions. Build inputs and executable bytes matched before and after.
The executable SHA256 was
`CE46B46BB69D2FC3AFAC71B000CF75A2712D8EB00AFB4E2025C6F620C822748C`.
Strict Clippy passed (r746) after replacing two constant chunk iterators with
`as_chunks`; no warning allowance was added.

Review removed an early raw-query length guard: rejecting a long unrelated tail
before parsing could defer the first notification of a recognizable initial
word. The new large-tail case checks that later shortening and dictionary growth
preserve the original cutoff and snapshot identity. Only the fixed initial
grammar is parsed; SHA512 still hashes the entire caller-provided query.

The executed `Driver` boundary above is finite source association, not a complete
random-oracle experiment or Fiat-Shamir security theorem. That first-coin driver
does not recognize later canonical histories, restore ancestors, simulate proofs,
establish hiding or integrate with live SQL, freshness or locks. Its hash
dictionary is a research trace recorder without a production process-memory
guarantee. No complete-query latency follows from these component tests.

The [full-history harness](full_history/README.md) extends this boundary to
canonical later groups and reverse ancestor queries. Its checks and limitations
are documented at that owning boundary.
