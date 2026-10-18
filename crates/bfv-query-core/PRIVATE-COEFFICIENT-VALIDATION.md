# Private coefficient-predicate native validation

The fixed four-row mathematical candidate executed real BFV ciphertext-by-ciphertext
multiplication with both the original rows and the predicate encrypted. All eight
new owning tests passed. The evaluator neither receives a clear predicate nor
selects rows on the owner before FHE. Its result remains explicitly unverified;
the live SQL admission policy is unchanged.

## Executed scope

Validation used Rust 1.99.0/MSVC, locked offline dependencies, release optimization,
`-C target-cpu=native`, two Cargo jobs and two Rayon threads. A fresh target directory
received independent copies of existing cache files, without hardlinks. The original
degree 8192, ordered Q5, auxiliary basis, plaintext modulus 114689, keys, arithmetic and
ciphertext caps were preserved. The existing full upstream parameter-wire test ran.

| Owning boundary | Actual passing tests |
| --- | ---: |
| Default Core library, including the eight new private predicate tests | 70 |
| peer-runtime library | 86 |
| storage-client library | 29 |
| Actual OS peer processes / transport | 24 |
| SQL capability refusal | 2 |
| Unsupported locking-plan refusal | 1 |
| **Unique behavioral tests, once each** | **212** |

Default-core checking and strict Clippy passed. Core Clippy covered all features and
targets; consumer Clippy covered storage-client, peer-runtime and dcs-peer targets.
All 15 Core compile-fail doctests passed with all features. Optional key/basis/Formation
proof-producing runtime tests were not rerun or credited. The unchanged requirements
and architecture contract sources each passed once, compiled directly with the pinned
rustc; this was not a full playground/GUI build.

The new tests exercised all four original ordinals, empty/full/range/noncontiguous
hidden masks, randomized encryption, ages 0/255, amounts 0/65535, repeated ages with distinct
ordinals, and every one of the 8192 decrypted product coefficients against independent
integer negacyclic convolution. They also exercised actual foreign-owner round trips,
full query/context/keyset/request-digest replays, malformed borrowed envelopes and
polynomials, and genuine encryptions of hostile output ranges/padding. The test oracle
does not participate in evaluation. Shape checks do not authenticate ciphertext origin
or malicious arithmetic; a well-shaped forgery can remain unverified.

The old 61 SQL-success scenarios remain unchanged and unignored. This is **not a green
full SQL suite**: the prior [capability validation](../storage-client/SQL-CAPABILITY-VALIDATION.md)
records a real legacy failure under the required refusal policy. This stage did not
rerun those scenarios or convert refusal into PostgreSQL functionality. In particular,
successful FOR UPDATE / SKIP LOCKED execution is not established.

## Actual measurements and their limits

One new owning test printed the following real operation measurements:

| Test region | Milliseconds |
| --- | ---: |
| Fresh Owner generation and evaluator setup | 155.6195 |
| Both encryptions and request preparation | 6.5749 |
| Evaluator call: decode, actual multiply/relinearization and response encoding | 16.7139 |
| Owner completion and decryption | 3.7139 |
| Through completion, including setup | 182.6393 |

It used one ciphertext multiplication and zero rotations, with 446890 request bytes
and 446854 response bytes. The enclosing process had already run earlier Core tests;
parameter caches and the allocator can be warm. The region excludes destruction,
process startup, networking, Source/query Formation, computation/completeness proofs,
freshness and transaction agreement. It is one observation, not cold-process or SQL
latency, a noise margin or a security bound. There is no fixed latency acceptance target.

All six behavioral commands were observed with nominal 100 ms aligned root/target-owned
descendant sampling. Across 264 CSV rows and 23 PID instances, the maximum sampled working
set was 455860224 B, sampled private usage 457814016 B and observed OS peak working set
575635456 B. Those maxima belong to the **whole Core process running 70 tests**, not an isolated
four-row operation. The maximum actual sampling gap was 455.1182 ms. At most three processes
were observed together; all command durations totaled 54099.7202 ms, with no aborts.
The 1792 MiB per-PID sampled soft fuse and 1200 s command limit were observation safeguards,
not hard memory guarantees or evidence that the full distributed SQL operation fits.

## Reproduction and frozen evidence

The local frozen source included 1156 project inputs on parent
`4202748d42774709359e14273b14fcb2bdc98100`; this report was written after native closure.
The runner pinned actual emitted executables before execution and rediscovered their
test inventory. It rechecked all old 2867 PE artifacts, 864 SDK anchors, 5 tool hashes and
8306 prior evidence files without changing them. Logs, memory samples, caches and
generated receipts remain local and are not committed.

| Local receipt under `.local/` | SHA256 |
| --- | --- |
| private-coefficient-predicate-validation-r1/source.json | 0AD7444049C2F7AC07056CF7F5A747AC37F7DB7B31B247857C15E2AF2205191A |
| private-coefficient-predicate-validation-r1/compile/success.json | 455E375CAC524231BEB619D52FDA4D42FB2A5ACC09A3980FDF8CAD7382D00A6B |
| private-coefficient-predicate-validation-r1/tests/success.json | 118DA9D7E2430C54056410656976515D972FBD97486B9A01A06170A82D842AB8 |
| private-coefficient-predicate-validation-r1/docs/success.json | E437F9B7B3E73228B44298BF116C8E5B9DEE2FF0787C48C2696F303D7FD64648 |
| private-coefficient-predicate-validation-r1/contracts/success.json | A760758E912D3E6A692782DC4819158E820FE61010AE17B4F70E9A22EF947590 |
| private-coefficient-predicate-native-closure-r1/success.json | B41482D6F5CA6F1D53F3A9A4BDED4AAC52B4992D7194531DF73F50E48A453FAF |

The actual Core test executable hash was
`153C9ACE2BAF93F8B4980D00E959A448F4895BE54EEF96DB9775A797DE53B17E`;
the actual peer executable hash was
`EE8721FEE818FC29BCF70D473670981DAC3069152ABE77071C5B1229C8DB017B`.

To reproduce the owning FHE behavior with the same toolchain and native CPU flags:

~~~text
cargo test --release --locked -p bfv-query-core --lib -- --test-threads=1 --nocapture
cargo clippy --release --locked -p bfv-query-core --all-features --all-targets -- -D warnings
cargo test --release --locked -p bfv-query-core --all-features --doc
~~~

## Remaining required links

No Source-to-all-original-onehot proof, privately committed query-to-mask proof, either
actual input Formation, complete linked MulRelin proof, or agreed fresh SQL result is
provided. Formation requires scaled `W=78307*m mod114689`; the raw coefficient vector
cannot be substituted for that root. Two operands also require a reviewed opaque owner
scope retaining the same full KeyPV33, without exposing secret openings. Existing
32-component relinearization alone is not full ciphertext multiplication provenance.
The result is not a fresh-noise Formation and the public-mask bound 5120 does not bound
private ciphertext multiplication. No mutation, lock grant, writer fence or live SQL
role is added by this mathematical candidate.
