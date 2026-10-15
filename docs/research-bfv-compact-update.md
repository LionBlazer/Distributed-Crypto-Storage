# Indexed BFV amount UPDATE with compact writeback

**Writeback proposal with an implemented cryptographic API.** The arithmetic/API
portion now lives in the [experimental BFV core](../experiments/bfv-byte-limb-core/README.md),
whose 37 runtime tests and two doctests pass alongside strict Clippy. Compact
writeback, repeated-update timing and storage lifecycle remain unimplemented for
this BFV path. The original proposal was based on main
`a25dc82e9685221bea161c19e51a9e248ff204ff`, unchanged BFV core
`83D3E4E23803F96544617E88AA6EF2B17DFEC274DCB962C168BDAFD7DBA82C7A`
(`src/lib.rs` baseline SHA-256), and `fhe 0.1.1` source revision
`fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a`. No full UPDATE latency, storage
lifecycle or independent noise/security result is established here.

## Exact operation and arithmetic

First scope: unsigned
`UPDATE records SET amount=amount+delta WHERE age=...`, `delta:u16`, supplied table,
no more than 256 **complete exact matches**, one authenticated posting page and
one authenticated data page. Excess count/page budgets reject before encryption;
there is no partial or capped update. Preserve N=8192, existing five Q about 2^218 primes,
t=114689, CBD(20), variance 10, native arithmetic and level 0 input/output.

A single 16-bit plaintext slot cannot distinguish overflow: `65535+65535=131070`,
but `131070 mod 114689=16381`, a plausible u16. Instead encrypt original amount
bytes and a separate delta-byte vector:

```
amount = a0 +256*a1        delta = d0 +256*d1
low[i] = a0+d0             high[i] = a1+d1
candidate[i] = low[i] +256*high[i]    // checked u32 reconstruction at owner
```

Each limb is 0..510, below t. Do not mask low with 255 before reconstruction.

| Amount | Delta | Low/high | Reconstructed | Decision |
| ---: | ---: | --- | ---: | --- |
| 0 | 0 | 0/0 | 0 | Accept/no physical change |
| 255 | 1 | 256/0 | 256 | Accept |
| 256 | 255 | 255/1 | 511 | Accept |
| 65280 | 255 | 255/255 | 65535 | Accept |
| 65535 | 1 | 256/255 | 65536 | Reject entire operation |
| 65535 | 65535 | 510/510 | 131070 | Reject entire operation |

Rows256 uses slots 0..255 for low bytes and N/2..N/2+255 for high bytes. Set all
other slots, including the aggregate core's COUNT region, to zero. Inactive rows
have zero amount **and zero masked delta**. Independently encrypt both vectors
under the existing owner key. Server performs **only ciphertext addition** and
returns per-row limbs, without summing rows or computing carry. Owner encoded
original values, delta and masks, not updated answers. Empty/delta-zero profiles
still run the scheduled fresh addition; unchanged canonical data needs no reseal.
Matching-row count comes from trusted index metadata unless FHE COUNT actually runs.

## Why an exact index can supply WHERE

Omitting repeated FHE age comparison is valid only for an explicitly named indexed
update with these owner-side guarantees:

- Owner built a complete exact age index consistent with the table. Its bound
  data head, independently trusted full data/index heads, all selected posting/
  data Merkle proofs and owner AEAD decryptions pass. Canonical postings yield
  every match, with no duplicates or invalid addresses.
- Owner checks selected ages satisfy the predicate as a consistency gate, without
  calculating updated amounts. A private pending selection binds active-slot order
  to authenticated ordinals under those heads; peer cannot supply replacement
  addresses or active flags. Completion/commit rechecks live heads.

This is exact indexed WHERE execution, not plaintext peer evaluation. Authenticated
index integrity does not independently prove completeness: owner construction and
index/table consistency are explicit trust assumptions. Coarse candidates, full
scan, stale/untrusted/incomplete indexes, age changes or missing shards cannot use
this shortcut; require a real encrypted predicate or reject that path.

Operation, geometry, supplied table, heads, timing and write locations remain
observable. Fixed256 empty scheduling still needs actual authenticated dummy reads.
Encrypted inactive masks conceal no global routing or access pattern. Owner stays
online and learns selected plaintext. Age/indexed-field updates are outside scope.

## Existing API and proposed minimal boundary

Pinned [`&Ciphertext + &Ciphertext`](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/ops/mod.rs#L15-L68)
requires pointer-identical parameter Arcs, equal level/component counts and adds
corresponding polynomials. Decode both inputs against the **same evaluator Arc**,
validate two components/level 0 and bounded wire before calling its asserting
operator. No rotation, multiplication, relinearization or modulus switch is needed.
Reuse the existing Owner and restored PublicSetup/PeerEvaluator; unused evaluation
keys remain counted. Public setup restoration does not recover the owner secret.

Addition clears the seed marker, so the output serializes both polynomials;
fresh input ciphertexts can serialize one polynomial plus seed. Measure actual
wire rather than copying input-size assumptions.
[Serialization source](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/ciphertext.rs#L135-L225).

Implemented cryptographic entry points; storage staging remains a proposal:

- `Owner::prepare_indexed_update_for_experiment(context, fields, delta)` returns
  two encrypted inputs and a one-use `PendingIndexedUpdate`. Bind owner/key handle,
  operation tag, geometry, query ID and both complete heads. Active mapping remains
  owner-only. A public-setup fingerprint can bind keyset identity, not arithmetic.
- `PeerEvaluator::evaluate_indexed_update(request)` validates input, performs
  genuine encrypted addition, and emits an operation-tagged updated-limb response.
- `Owner::decrypt_indexed_update_unverified_for_experiment(pending, response)`
  checks bindings, bounds every active limb 0..510, requires inactive/reserved zeros,
  and reconstructs every active result in u32. Return an unverified batch or one
  global overflow outcome; never a partially accepted batch and never page writes.

Use existing bounded/reject-trailing wire conventions. A storage compositor's
`stage_amount_update_for_experiment(selection, batch)` must compare every actual
returned value with the original authenticated amount plus delta **after peer
execution**, as a local experiment check. Count this work in completion timing.
The TFHE experiment already uses this explicit boundary at
`crates/compact-query/src/owner.rs:202-303`; it is not a succinct query proof.

## Atomic compact writeback

Before any page staging or encrypted-snapshot cloning, validate the entire output
and reconstruct all active results. If any exceeds 65535, reject the **whole
operation** before staging, canonical mutation, head/revision change, file writes
or writeback-triggered cache invalidation. Wrong but in-range arithmetic also must
fail the owner local check. Bounds alone do not authenticate the answer.

On success, patch only amount bytes in bounded zeroizing owner page buffers and
stage encrypted state separately. `compact-store/src/crypto.rs:154`
`Owner::replace_pages` already validates all replacements and stages fresh
nonces/packets before mutating its target snapshot, under one new revision. Use a
staged target. Then follow `compact-query/src/index.rs:305` `rebound`: authenticate
old index, clone its ciphertext image, replace its embedded data head in page 0,
reseal with fresh nonce/revision. Ages/order/counts stay unchanged, so postings do
not change, but the **index header must bind the new data head**.

Publish both staged images/heads together after a final old-head comparison.
Clones contain encrypted state, not keys, but count toward peak memory. Invalidate
the owner header and both native caches after commit, refresh metadata, rebuild
before private reads. Empty/no-physical-change updates need not change heads.
Following operations freshly encrypt newly authenticated compact data; discard
all expanded BFV outputs rather than retaining overlays or chaining their noise.

This is owner-held in-memory table atomicity. Existing in-place two-file/catalog
writes provide no crash-atomic commit, fsync recovery, consensus, hidden writes or
multi-shard transaction. General indexed-field updates require new maintenance.

## Noise, feedback and finite execution gates

Fresh ciphertext addition adds error terms without comparator multiplication
depth. That is not a measured margin or probability-of-failure bound: SIMD lifting,
BFV scaling/rounding and intended-message exactness still need actual validation.
`SecretKey::measure_noise` subtracts its own decrypted plaintext and is explicitly
unsafe/variable-time; it cannot alone certify the intended UPDATE and is unnecessary
in normal peer/owner APIs.
[Noise diagnostic source](https://github.com/tlepoint/fhe.rs/blob/fe47bac2e2abf0077c0e8d95f5c2ce7ce8a40b2a/crates/fhe/src/bfv/keys/secret_key.rs#L55-L98). Independent parameter-security validation remains open.

Before complete composition/performance claims, run these gates with public fixtures,
real serialized peer addition and the unchanged parameters:

1. Carries and exact boundaries across 0/1/254/255/256/257/65280/65534/65535,
   including exact 65535 and maximum 131070. Check all per-row limbs/values.
2. Complete 0/1/16/256 selections, mixed amounts, empty/delta 0, inactive/reserved
   zeros and fresh ciphertexts; no plaintext active count/delta. Oversize groups,
   duplicate addresses, unsupported pages and stale/index bindings reject before
   input encryption, never truncate.
3. One overflowing last row among safe rows: actual FHE runs, then no staging,
   canonical/head/catalog change or writeback invalidation. Retrieval/LRU fills are
   separate read effects. A controlled in-bounds forged output must also reject
   every write; no owner-precomputed answer or early plaintext-overflow shortcut
   substitutes for the FHE operation in the measured experiment.
4. Wrong owner/keyset/query/head/operation/geometry/version/parameters/level,
   components, oversized/trailing wire and duplicate completion reject. Merkle/
   AEAD/header failures precede BFV. Output remains explicitly unverified.
5. Successful amount-only writeback, failure between staged data/index, and live
   head change before commit. Fresh snapshot decode verifies rows, fixed encoded
   lengths, unchanged postings, fresh changed-page/header nonces and stale proofs.
6. At least 100 real updates with fresh encode/decode, stable shared keys, no
   persistent expanded overlays and actual cache invalidation/rebuild. Full timing
   includes retrieval/wire, encrypted addition, owner oracle/overflow checks,
   staging, reseal/rebind, publication and cache readiness. Record native process
   peaks and distinguish warm/cold/private/visible profiles.

No numeric UPDATE latency, 500 ms or full-state 2x result follows from this proposal.
There is no arithmetic proof, CCA/active-feedback safety claim, general SQL or
production recovery guarantee.
