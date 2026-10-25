# Isolated native Query oracle harness

This module exists only in the owning crate's unit-test build. It uses the program-owned [shared research hash harness](../../research_hash/README.md) for an
explicit finite H256/H512 dictionary, separate programming and query-only
handles, and a research configuration over the genuine hiding PCS, Merkle MMCS,
EF5 and FRI with unchanged geometry. All roles share each dictionary. The seeded
regression RNG is not a proof of an ideal random oracle or concrete SHA security.

`Programmer` may assign absent points and repeat an existing value; conflicting
assignments reject. Native receiver code gets only `Oracle`. Its challenger
retains exact FIELD/CAP/SAMPLE/DRAW bytes, including rejected full-digest retries.
The Query-owned adapter reconstructs actual public PP and packed lookups from the
full Query Expected, bounds and canonically decodes the normal frame shape,
then invokes the genuine `verify_batch`. Normal SHA types and facades stay closed.

The separate ignored `honest_reference` case creates an ordinary real Query
witness and proof to check this wiring. It requires complete producer/receiver
walk equality and native rejection of missing or changed input openings. It
also requires the normal SHA backend to reject the research proof. This case
does not generate a proof from public inputs alone or validate a public sampler.
The [whole-B arithmetic](public_deep/README.md) samples an affine polynomial
from supplied public disclosures. The [opaque-input forest](../../research_hash/opaque_inputs/README.md)
constructs the four private INPUT multiproofs. The
[fixed-coin joint disclosures](../public_image/public_disclosures/README.md)
preserve the actual fold and correlated quotient fiber before whole-B sampling.
The [native FRI assembler](native_fri/README.md) composes that public V and B with
the genuine native prover, normal public PP and opaque input openings. Its
complete receiver test passes without an original private witness. Causal
shared-oracle privacy composition remains separate work.
See the [executed validation](../RESEARCH-VALIDATION.md) for exact checks and scope.

Direct dependencies are the owning Query AIR/setup/codec, pinned P3 MMCS and
challenger interfaces, `rand-public-pp`, bounded postcard and standard owned
collections/synchronization. The shared DATA setup source exposes a test-only
PUBLIC RNG stream helper; its dead-code allowance covers the DATA host, which
does not own this Query research module. No private seed is exposed.

Local dictionary bounds are 1,048,576 entries, 768 MiB of raw keys and 1 MiB per
input; walks have separate finite caps. These do not establish a whole-process
RAM guarantee. Heavy checks must use the existing 120-second/1792-MiB observer.
Ordinary public helper hashes still use their concrete source implementations;
the [finite PUBLIC helper observer](../../../public_hash_trace.rs) records selected
synchronous helper inputs/results without changing them. The shared-session test
requires their exact manifests to agree across two fresh proofs in one dictionary.
The model is restricted proof-MMCS/FS ROM with concrete PUBLIC preprocessing.
It does not claim a global all-string SHA ROM, complete helper capture or admission.

```sh
cargo test --release --locked -p bfv-ciphertext-formation gold::program::research_hash::ro:: -- --test-threads=1
cargo test --release --locked -p bfv-ciphertext-formation gold::program::query_formation::research_query::honest_reference::actual_query_native_verifier_and_complete_walk_use_the_same_research_ro -- --ignored --exact --test-threads=1
```

The [owning public frame factory](public_frames.rs) now has one definition shared
by the preserved two-Query gate and the
[mixed Query/DATA gate](../../research_hash/MIXED-SESSIONS.md). Its original
producer operations/drop boundary and old two-Query test body are unchanged.
Query frame/receiver/tape visibility is limited to the program's unit-test owner;
foreign bytes still use the actual bounded Query decoder. The affected old gate
and new mixed gate passed after extraction; no normal API was widened.
