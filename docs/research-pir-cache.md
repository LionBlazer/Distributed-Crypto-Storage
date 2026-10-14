# Spiral native cache representation and cold conversion

Source-only review of main `78584b539bcc32540271032ed4dbb52498bac0cb` and the clean
pinned SDK `fdb7206517c249603b0c91b65f1f29f95272107c`. No SDK edits, build, cache
files, compression experiment or new latency measurement are part of this review.
The parallel conversion helper and disk-LRU admission now have separate read-only
source reviews below. Helper execution evidence belongs to the root experiment;
the reviewed disk package was unbuilt during this review.

## Exact native representation

The current profile is N=2048, `n=2`, one instance, 512 records of 8192 bytes,
`nu_1=7`, `nu_2=2`, plaintext 256 and CRT primes 268369921/249561089. SDK
[server.rs:320-355](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/server.rs#L320-L355)
allocates `instances*n*n*records*N` aligned u64 words, builds each plaintext
polynomial with `load_item_from_seek`, recenters modulo256 into the CRT product,
applies the existing NTT, and stores both residues together.

| Representation | One data or index cache | One table's data+index pair |
| --- | ---: | ---: |
| Fixed proof-record input, 512*8192 | 4,194,304 B | 8,388,608 B |
| Native u64 cache, 1*4*512*2048*8 | 33,554,432 B | 67,108,864 B |
| Hypothetical exact 7-byte packed-word archive | 29,360,128 B | 58,720,256 B |
| Archive reduction from native | 4,194,304 B (12.5%) | 8,388,608 B (12.5%) |

The source stores `r0 | (r1 << 32)` and the evaluator extracts low/high 32 bits
([server.rs:153-218](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/server.rs#L153-L218)).
Both primes fit 28 bits: eight physical bits per u64 are unused. A lossless wrapper
can store `r0 | (r1 << 28)` in exactly seven bytes and unpack to the original
low32/high32 layout using public `AlignedMemory64::new/as_mut_slice`. This is an
ordinary representation codec, not ciphertext packing or changed crypto. It must
validate the exact profile, fixed word count and unused-bit/residue bounds; it
cannot assume every possible SDK profile has 28-bit moduli.

Scalar forward NTT ends with reductions using `>=`; the AVX2 path uses strict
`>` comparisons ([ntt.rs:68-210](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/ntt.rs#L68-L210)).
The latter can retain a modulus-valued representative for zero, still fitting28
bits. An exact archive should preserve such representatives rather than silently
normalize them or claim byte equality across different compiled NTT paths.

These 56 significant bits are not 56 independent entropy bits for every entry.
Both complete CRT streams derive from the same padded byte-valued coefficient
polynomial. The transform expands a structured input; ordinary entropy compression
of NTT words has not been measured. This review makes no incompressibility claim
and no expected compression ratio beyond removing the eight known unused bits.

`process_query` and `multiply_reg_by_database` accept a contiguous `&[u64]`; their
indexed loop expects the complete native layout. There is no public 7-byte, paged,
stream-decompressing or bounded-chunk database interface. A compressed archive
therefore **does not reduce the active 32 MiB allocation per database** through
these existing calls. Stream-unpacking directly into the final native allocation
can avoid retaining a second 29 MiB compressed buffer, but still needs the native
cache and a bounded I/O buffer. Keeping compressed inactive RAM caches remains
expanded auxiliary state and must be counted.

## Cold conversion cost and safe parallel boundary

The published owning `records`/`prepare` in
`experiments/private-bfv-amortization/src/main.rs:22-64` creates one fixed 4 MiB
proof-record buffer and calls `load_db_from_seek` sequentially, then drops the
record buffer. Source work per database is 2048 calls to `load_item_from_seek` and
4096 degree 2048 prime-specific forward transforms (two primes per polynomial).
The loader also decodes 8-bit coefficients through `read_arbitrary_bits`, allocates
per-polynomial buffers and transposes the results into query layout. None of
these costs disappear merely by storing the same u64 words in fewer bytes.

The destination index is exactly:

```
slab = instance * (n*n) + trial
slab_len = N * num_per * dim0
within_slab = (z * num_per + i % num_per) * dim0 + i / num_per
index = slab * slab_len + within_slab
```

Thus four trials are disjoint slabs for the current one-instance profile. A
wrapper may fill safe mutable slabs in parallel, with a separate `Cursor<&[u8]>`
per task, calling public `load_item_from_seek`, `recenter_mod`, and `.ntt()` and
using the identical packing/index expression. Data/index construction may share
one fixed eight-worker Rayon pool. This changes orchestration, not the SDK NTT or
cryptographic parameters. It must gate the full profile and checked buffer sizes
before allocation; no shared seek cursor or overlapping mutable output is valid.
A full-buffer byte equality check against the official loader and real first/
middle/last private queries are necessary, including nonzero last-slot contents.
No speedup is established until the cold construction and full operation are
measured together; per-stage timers must not be added when they overlap.

With two output caches constructed together, 64 MiB outputs and 8 MiB full input
record buffers are live simultaneously, plus bounded per-worker polynomial/NTT
and existing process material. Native peak/commit and preallocation admission
remain necessary. Optimizing the helper does not erase this peak or the cost of
creating Merkle proof records from canonical snapshots.

## Existing preprocessed-file API and practical options

The SDK exposes `load_file`, `load_file_unsafe` and
[load_preprocessed_db_from_file](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/server.rs#L359-L387).
There is no matching authenticated/framed portable database-cache codec.
`load_file` allocates a 16 MiB BufReader, repeatedly calls `read` for an 8-byte word,
does not check the returned count, and interprets native-endian bytes. Truncation
or a short read need not be rejected. `load_file_unsafe` instead uses `read_exact`
through an unsafe byte view, but still supplies no length/profile/root/table/hash
validation. Calling either bare API is not safe cache admission from untrusted
storage. A safe wrapper should use a held file handle, independently bounded
expected length, `read_exact`, an explicit version/endian/profile/table/head
binding, integrity verification and no admission before all gates succeed.

| Option without SDK edits | Concrete tradeoff |
| --- | --- |
| Persist native u64 cache | Avoids NTT reconstruction, adds 64 MiB/table plus framing/integrity; active RAM unchanged. |
| Persist 7-byte archive | Avoids NTT reconstruction, adds 56 MiB/table plus framing/integrity and O(words) unpacking; active RAM unchanged. No implementation or measured benefit yet. |
| Keep only canonical data/index images and rebuild one active table's pair | No persistent expanded cache; pays actual canonical read/decode, proof-record construction and NTT on every miss. Parallel public-API conversion is the immediate experiment. |

Even the 7-byte pair alone is 19.57x a 3,000,000-byte logical table, before canonical
images or shared keys. It cannot establish a full-state 2x result. Main's actual
20-table retained report already counts forty native caches as 1,342,177,280 B and
explicitly disclaims full-state 2x. Capacity-one canonical-disk admission addresses
the number of live caches; archive packing alone does not address that target.

For disk LRU admission, the trusted catalog must provide exact per-table identity,
full independent data/index commitments and expected bounded file lengths. Before NTT conversion: bound metadata, read exactly, decode both images with
complete Merkle-root reconstruction, and compare the full independently trusted
heads. This authenticates the encrypted canonical image before expensive public
conversion. Before fresh BFV preparation: retrieve the required pages through the
actual private/visible path, verify their Merkle proofs against those heads,
perform owner AEAD decryption, and enforce cached-header/head binding. Selected
AEAD decryption does not precede private-cache construction. A failed load must
never become a cache hit. Capacity-one must be an
ownership property, not just a map-size claim while evicted buffers remain live.
Replacement must invalidate/rebind data head, index header, catalog entry and both
native caches; old responses are checked against independently held new heads.

## Independent parallel-helper source review

Reviewed the new `experiments/spiral-cache-core/src/lib.rs` in the integration
worktree, final SHA-256
`4DA15C08050DD6F55FA2B0811088513DF8A31540848A91B56F4E9B059A5E6DCE`,
with its five owning contract tests and `examples/cache_setup.rs`. The first
unbuilt draft called `.iter_mut()` directly on SDK `AlignedMemory64`, which has no
such public method or Deref implementation. This compile defect was reported and
corrected to `.as_mut_slice().iter_mut()` before root validation.

The corrected source preserves the exact full `Params` gate, rejects both bad
input lengths before either output allocation, splits into disjoint trial slabs,
uses per-task immutable-input cursors and the original public loader/recenter/NTT
calls, and preserves the native low 32/high 32 residue layout. No further profile,
indexing, aliasing or packing defect was found. Tests compare every native word of
two distinct complete input images to the serial SDK and perform actual serialized
PIR first/middle/last queries with explicit decoded guard-byte checks. Root reports
those five tests and strict package Clippy passed; no build or run was performed
by this reviewer. Pair-setup timings from that experiment are not full query or
disk cold-miss timings and do not change the native 64 MiB cache-pair accounting.

## Independent disk admission source review

Reviewed the new `experiments/private-bfv-disk` in the private-index-research
worktree, still unbuilt at review time:

| Reviewed owning source | SHA-256 |
| --- | --- |
| `src/disk.rs` after reported refinements | `7FA0D7EDE107A2538BB2326378C29E4550AEB7F1FF193DAC232B3DF8B460990B` |
| `src/native.rs` after reported refinements | `E2349B6E05A1A95512EC3EF699AD7CD7575D97E82BAC2A7D8A93152AD3218603` |
| Lifecycle harness snapshot `src/main.rs` | `CD6089F3A7304F91FAABDFEBD5C3F1D2DAD7FE44338FEEDC8CC2ED370981CAF3` |

The catalog retains owner keys, file paths/lengths, independently held full heads
and owner-cached header metadata; it contains no snapshots or native caches.
`Loader::new` accepts capacity one only. Misses take/drop the old owned table
before file allocations; Visible loads no NTT, and Private builds one pair after
admission. Held-handle metadata, exact bounded `read_exact` plus EOF checks,
full snapshot root reconstruction and independent complete-head equality all
precede native conversion. Read/decode/authentication failures publish no entry.
`Loader::execute` starts its whole timer before ensure/file I/O and ends after the
actual fresh BFV query. Native conversion is a nested stage, not extra query work
to exclude from a miss. The catalog ID and selected store are public supplied
routing; neither disk access pattern nor global SQL routing is concealed.

Two source findings were reported and corrected before this reviewed snapshot:
`native::prepare_pair` now checks exact Params before record-buffer allocation,
and native-pair admission failure drops the canonical loaded entry rather than
leaving a successful-looking visible-only cache entry after a Private load error.
Conversion errors also drop the entry. No further concrete defect was found in
the requested wrong-head/tamper/admission/capacity scope.

The harness contains genuine file truncation, same-length ciphertext tamper,
wrong-table data/index and appended-byte controls, all before BFV preparation;
failed loads must leave no current table. Owner replacement changes the actual
data page and bound index header, rewrites canonical files/catalog, invalidates
both native caches, then performs a full fresh miss. Old ciphertext at new heads,
stale independent catalog heads and stale owner headers are rejection controls.
These are source observations, not a claim these tests have run in this review.
In-place writes have no atomic durable recovery/fsync promise; live owners and
trusted catalog state remain available throughout.

The ledger separately exposes canonical/public files, loaded snapshot/hash/native
payload, per-table owner/head/header state and disk plus native current/peak
process counters. Raw proof-record inputs are dropped after conversion. Existing
file-cache/OS effects remain explicitly outside process counters, so an application
cache miss is not a guarantee of physical cold-disk I/O. Neither this audit nor
seven-byte archive arithmetic establishes full-state 2x or a full-query deadline.

## Pinned source hashes

| SDK file | SHA-256 |
| --- | --- |
| `server.rs` | `18E4DD4EC23C6FDD4AD60B1943D43F14B4CDFFDFABE8C49E727619DF882463D4` |
| `ntt.rs` | `6754193D9195753CEFAB981459C16AF33EB3BB8A89B6960A260F701163B47E39` |
| `poly.rs` | `C2B1C2D627F8BDEC328A5E8B671513C57820A2A514386F52EE417B5AA248C0F9` |
| `aligned_memory.rs` | `D01FFCC5683BD0A040CCD6A4747FD918A1FB6FA7D28F16ED48045B4979F247BD` |
