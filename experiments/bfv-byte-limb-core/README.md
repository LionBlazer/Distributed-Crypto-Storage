# Experimental BFV byte-limb core

Reusable owner-online exact COUNT/SUM roles extracted from the
[measured byte-limb probe](../../docs/experiment-bfv-byte-limbs.md). This package
has its own workspace/lock, and does not promote a production backend. Its
outputs are explicitly UnverifiedAggregate: matching metadata and unsigned
bounds do not establish arithmetic correctness against malicious evaluators.
The owning proof-boundary test demonstrates an in-bounds forged answer.

This module owns BFV setup, fresh fixed-shape input encryption, bounded wire,
public-only evaluation, output binding/decryption and unsigned aggregate
bounds. It has no project-module dependency, storage snapshot, SQL planner,
PIR/index reader, AEAD key, fixture store or GUI. Its direct libraries are
fhe/fhe-traits=0.1.1 (BFV), rand (fresh randomness), serde/bincode (bounded
wire), and zeroize (owner temporary vectors). Callers retain retrieval,
Merkle/AEAD authentication, current trusted heads, active-row selection and
whole-request timing/resource accounting.

## Public contracts

- Geometry::Rows16 or Rows256 fixes the public shape, including empty results.
- Owner::generate returns an owner secret handle and serialized public setup.
  PublicSetup::{to_bytes,from_bytes,byte_counts,profile} and Owner::profile
  expose actual parameters/material counts. Only the owner offers secret-key
  serialized byte COUNT; it exposes no serialized secret.
- Owner::prepare(context,fields,predicate) returns encrypted request bytes and
  a one-use PendingQuery token. SelectedField holds caller-owned authenticated
  age:u8/amount:u16/active:bool plaintext. Fields beyond the fixed geometry
  are rejected; missing/inactive fields have encrypted zero low/high/COUNT
  weights. No actual selected cardinality is sent in the request.
- Predicate supports encrypted Equal, AtLeast and valid ClosedRange. Reversed
  closed bounds are rejected before input encryption. The range is ONLY the
  additive GE(age,lo)+GE(hi,age)-1 identity, with no extra product/depth.
- PeerEvaluator::from_public_setup restores public keys only; evaluate includes
  request decode, FHE evaluation and response encode and reports those stages.
- Owner::decrypt_unverified consumes PendingQuery, matches query ID and BOTH
  trusted112-byte data/index head bindings and geometry, then checks unsigned
  COUNT/limb bounds and returns UnverifiedAggregate with ProofStatus::Unavailable.
  PendingQuery::context exposes the expected binding without cloning the token.
- PreparedQuery::ciphertext_payload_bytes excludes IDs/heads/kind/geometry for
  optional ciphertext-only fresh-encryption comparison by the experiment.

QueryContext::new accepts an ID and the caller's two exact112-byte head
encodings. Heads remain opaque to this library. The caller must authenticate
and choose current heads before preparation, and recheck live heads before
completion if writes can occur in flight. This library neither parses manifests
nor tracks a persistent freshness/replay ledger. A consumed Rust handle prevents
accidental repeat completion through that handle, not all possible protocol replay.

The fixed packing and keys use ONLY native/unfused/level0 N8192/Q218/t114689,
with q_i=[8796092858369,8796092792833,17592186028033,17592185438209,17592184717313].
Runtime gates compare official serialized parameters exactly and reject
wrong-level or non-two-component ciphertexts. All secret/error distributions
remain the release's CBD(20), variance10. The named upstream profile says
ABOUT128 bits; independent security estimates and worst-case noise bounds
remain open. See [the independent profile investigation](../../docs/experiment-bfv-security.md).
This package requests no optimized-ntt feature. Consumers must record their
resolved dependency features/artifact; upstream feature unification can change
an implementation even without changing this manifest.

Setup builds only the pinned N8192 entry with BfvParametersBuilder. A test
compares the complete serialized parameter wire against the upstream default
catalog entry, including its variance. This avoids constructing four unused
degrees on every setup/restore; it changes neither the kernel nor its profile.

For r16/256, four predicate groups support low at0, high at4096, COUNT at8r.
Each limb<=255*COUNT and COUNT<=owner's active fields<=r; total sum<=65535*COUNT.
All decode is unsigned, and low+256*high uses checked u64 then u32 conversion.
No extra validity product is required. Owner temporary plane/value/secret-byte
buffers are zeroized; caller field buffers remain caller-owned. No plaintext
aggregate substitutes for peer FHE evaluation.

## Example composition

    let (owner, setup) = Owner::generate(Geometry::Rows16)?;
    let peer = PeerEvaluator::from_public_setup(&setup)?;
    let context = QueryContext::new(query_id, data_head, index_head);
    let prepared = owner.prepare(context, &authenticated_fields, Predicate::AtLeast(18))?;
    let evaluated = peer.evaluate(&prepared.request)?;
    // Caller rechecks its live heads here if writes are possible.
    let unverified = owner.decrypt_unverified(prepared.pending, &evaluated.output)?;

Place the timer around actual authenticated retrieval plus prepare, evaluate,
and decrypt_unverified; count all request/output bytes and setup public keys.
The core's EvaluationStats do not include caller retrieval or network transport.
Memory caps and native whole-process counters remain the experiment runner's
responsibility, alongside the library's fixed geometry and64MiB wire bound.
That framing limit is not an allocator hard cap or an audit of hostile upstream
ciphertext/key decoders. This experiment supplies no decryption-oracle protection.

## Validation

Using a dedicated CARGO_TARGET_DIR, release/offline/locked tests pass:4 unit
contract tests and7 public API tests. They cover actual16/256 FHE EQ/GE/range,
max SUM16,776,960 and unsigned65280 limbs, inactive/missing/zero-value COUNT,
byte/age boundaries and absent results, reversed/oversize preparation rejection,
query ID/data-head/index-head mismatch, changed ciphertexts under identical
public context, public setup roundtrip, malformed/trailing wire, exact parameter
profile drift, wrong ciphertext level, and the explicit lack of arithmetic proof.
Authored strict Clippy passes with --all-targets --no-deps -- -D warnings.

    cargo test --release --locked --offline --manifest-path experiments/bfv-byte-limb-core/Cargo.toml --jobs 2 -- --test-threads=1
    cargo clippy --release --locked --offline --manifest-path experiments/bfv-byte-limb-core/Cargo.toml --all-targets --no-deps --jobs 2 -- -D warnings

The public-fixture `profile_setup` example measures cold owner generation,
wire serialization/decode, public peer restore and three actual GE queries.
Its first argument is an output label, not a backend switch; the measured
catalog control was built from the preceding source revision. See the
[paired cold setup measurements](../../docs/experiment-bfv-profile-setup.md)
for exact sources, commands, all timings and whole-process memory. These
measurements exclude index/PIR/network/proofs and do not replace the separate
[composed index/PIR measurements](../../docs/experiment-private-bfv-index.md).
