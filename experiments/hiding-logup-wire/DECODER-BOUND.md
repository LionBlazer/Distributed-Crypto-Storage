# Bounded native proof decoding

These are admission bounds for the closed H512/native0.8.0 profile, not an
alternative verifier or a process-memory guarantee. The decoder charges each
container's fields before its visitor runs, including nested arrays. Gold's
binary `[u8;8]` costs eight internal slots. An EF5 costs47 (two struct fields,
its five-element array and five Gold arrays). A four-Gold digest costs36; its
entry in a Vec costs37. A one-root cap costs39. Primitive values and Option
tags add no container slots.

For Q192 transcript queries, a binary tree of depth d needs at most
`B(d) = sum(level=0..d-1) min(192, 2^(d-level-1))` missing sibling hashes.
Each missing child belongs to a distinct opened parent at that level; there
are at most192 such parents and at most the total number of parent positions.
This positive sum remains valid when query indices repeat. Input depth13 gives
1215; the ten FRI depths12..3 give
`[1023,831,639,447,255,127,63,31,15,7]`, totaling3438.

The five input rounds have `(matrix_count, base_width)` equal to
`[(1,10),(1,24),(8,10),(1,3),(1,20)]`. With salts and wrappers, one input batch
costs at most `5 + 192*(2 + matrix_count*(38 + 9*base_width)) + 37*B(13)`.
All five batches, including their outer Vec, cost at most551013 slots. Each FRI
step costs `5 + 87*192 + 37*B(depth)`; all steps including their Vec cost294306.

| Complete component | Container slots |
| --- | ---: |
| Commitments and four caps |160|
| Opened values, including both AUX rotations |4675|
| Hiding random openings across five rounds |2910|
| FRI proof including both opening collections, caps and final polynomial |845880|
| Complete BatchProof including all outer fields and witnesses |853699|

The final row includes the other rows; they must not be summed again. An
independent coarser accounting gives856957. Even increasing the actual AUX15 to
the wire guard's maximum25 adds only18240 to the detailed total, yielding871939.
The cap1048576 therefore admits the full honest shape without accepting unbounded
nested containers. The per-sequence cap4096 and payload cap4MiB remain separate.
Exact shape, field canonicality, EOF, canonical Postcard reencoding and the
unmodified native cryptographic verification are all still required.

The first unpublished cap262144 rejected a genuine proof during bounded decode.
The corrected cap and tighter frontier bounds are included in the new profile
digest. No existing DCS wire profile or production resource limit changed.
The tests reuse one genuine proof to exercise both sequence and aggregate
container rejection and a frontier one hash above its admitted bound.
