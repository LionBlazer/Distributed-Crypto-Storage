# Separate hash-based hiding suite

This reusable module owns the SHA-256 leaf/node encodings, full event-prefix
SHA-512 challenger, fixed hiding PCS configuration and bounded single-AIR codec
first measured by the [Source experiment](../../../../experiments/hash-hiding-fri/VALIDATION.md).
The original Poseidon suite and its profiles are unchanged.

Direct dependencies are the existing Plonky3 field/challenger/commit/FRI/Merkle/DFT
interfaces, SHA2, OS-seeded rand and bounded Postcard. No product, peer, Owner,
fixture, experiment or batch-STARK dependency enters this module.

`config()` creates independent OS streams for private masks/input salts/FRI salts.
`Config`, `Pcs`, `Mmcs`, `ChallengeMmcs`, `Challenger::new`, `LeafHash` and
`NodeCompress` are low-level fixed-suite types. Owning libraries may construct a
separate deterministic **PUBLIC-only** preprocessing config; they must destroy
it before private commitments and retain only public ProverData/CommonData.
No seeded config or adopted CommonData is accepted by the closed proof facades.

The suite fixes EF5, 192 queries, blowup 8, five random codewords, four salt
fields, cap zero, binary FRI, final polynomial length one and zero grinding.
Each owning AIR additionally fixes its own height, role, full statement, frame
identity and byte/sequence/slot limits. `profile_digest()` identifies the shared
suite only. `codec::Topology` is the fixed 512-row hiding single-AIR topology;
batch owners retain their own strict five-PCS-round topology checks.

Raw digests keep all 32 bytes. Typed full-prefix observations, sample events,
draw/retry counters and exact Gold rejection preserve the independent byte
vectors from the original candidate. The primitive tests now live here, rather
than in a second implementation under experiments.

The disabled-by-default [transcript-audit feature](audit/README.md) records exact
observations and real SHA512 draw digests in bounded scopes for owning tests.
It observes actual verifier call stacks and changes no coin or verification
decision. It supplies source-correspondence evidence, not a security theorem.

This is conditional native mathematics, **not** quantified composed security or
operation admission. The independent-domain ROM/Merkle/Fiat–Shamir reduction,
codec expansion/retry accounting, semantic Poseidon assumptions and complete
live contract remain separate obligations. Existing live Predicate rejection is
unchanged. Run the optimized primitive gate with:

```sh
cargo test --release --locked -p bfv-hiding-stark hash:: -- --test-threads=1
```
