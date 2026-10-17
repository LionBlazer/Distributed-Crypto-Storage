# Canonical public relinearization key source

This library parses public bytes and expands public randomness. Native validation
passes all nine owning tests, strict all-target Clippy and explicit rustfmt.
It supplies no proof, secret key access,
complete relinearization/MulRelin operation, key authority or SQL acceptance.

| Direct project dependency | Responsibility |
| --- | --- |
| [bfv-query-core](../bfv-query-core/README.md) | Borrowed original public material and complete existing setup identity |
| [bfv-fixed-geometry](../bfv-fixed-geometry/README.md) | Unchanged N8192 and original ordered Q5 |

`decode_seeded(material, independently_expected_keyset_id)` consumes a borrowed
`PublicRelinearizationMaterial` view, compares its COMPLETE setup identity first,
and returns `UnverifiedSeededRelinearizationKey`. The input view already checks the
existing fixed parameter bytes; it borrows original parameters and key bytes.
The independent expected identity must come from the trusted owner/application,
not from the responding peer. All decoded types have private fields.

The accepted language is precisely the pinned fhe/fhe-math 0.1.1 seeded level 0/0,
log_base 0 key. The original protobuf is retained, with no new key wire, private
core bincode mirror, subset hash, secret callback or decode/re-encode replacement.
The private cursor is a fixed, bounded envelope reader rather than a generic
protobuf decoder. It requires minimal varints, canonical field order, exact nested
lengths, no duplicates/unknowns/trailing bytes and the SDK's omitted-default policy:

- Outer RelinearizationKey: exactly field1 containing one key-switch key.
- KeySwitchingKey: exactly five ordered field1 c0 values, then field3 32-byte seed.
  c1 must be absent, including empty repeated aliases. Required zero ciphertext
  level, key level and log_base fields must be omitted, not encoded as zeros.
- Each c0 Rq: representation 3 (NttShoup), degree 8192, exactly 223232 packed coefficient bytes,
  followed by optional Boolean true. False must be omitted. The serialized values
  are PowerBasis despite the NttShoup tag: this is the actual SDK wire convention.

Each polynomial has at most 223243 bytes. Including five polynomial envelopes,
seed and outer envelope, the exact maximum is 1116273 bytes. Count/length/varint,
canonical envelope and ALL five-by-five-by-8192 residue checks occur in a borrowed
first pass before any coefficient vector allocation. Packed rows use 43/43/44/44/44
bits in original Q5 order; every value must be strictly below its modulus.
Only then are five bounded 40960-element c0 vectors allocated. Future unseeded or
other-level formats reject; no migration or compatibility path is supplied.

`parameters()`, `relinearization_key()`, `geometry()`, `keyset_id()` and `seed()`
preserve the original context. `c0_power_basis(i)` returns all five modulus rows
for ordered decomposition index i from 0 through 4. This is not an NTT table: a verifier must
still check 25 complete PB-to-NTT certificates before treating these as K0 inputs.
The adapter never calls `Poly::from_bytes`, constructs a polynomial/NTT context,
or executes a butterfly, scaling equation, key-switch or modular MAC.

`expand_c1_ntt()` explicitly returns `UnverifiedExpandedSeededKey`, with the same
full setup identity and five complete `c1_ntt(i)` arrays. It reproduces the exact
pinned public seed chain: outer ChaCha8(master_seed), five sequential 32-byte seed_i values,
SHA256(seed_i), inner ChaCha8, then fhe-math `Modulus::random_vec` over each Q row.
These are directly sampled NTT values, without a hidden transform. Expansion
allocates bounded public buffers; there is no cache or whole-process RAM claim.
No unchecked caller modulus, decomposition size, parameter blob or NTT array is
accepted. The library needs no proof backend, SDK loader, runtime or consumer.

Owning tests use an actual non-secret Owner-generated setup and public
`RelinearizationKey::relinearizes` impulse probes. They compare ALL ordered K0/K1
and all 8192 coefficients: parsed c0 is transformed only in the test oracle and
compared with SDK output; expanded c1 is compared with the other SDK output.
Further cases cover SDK Boolean/default/c1 serialization behavior, every last Q5
residue, independent expected identity, seed changes, malformed/count/length
limits, duplicate/nonminimal/unknown/trailing fields and unsupported roles.
All nine cases pass with zero failed, ignored or filtered cases. The SDK accepts
omitted false polynomial flags and silently discards a supplied c1 when seeded;
the adapter accepts the canonical omitted-false encoding and rejects explicit
false aliases or ignored c1 bytes. Every last coefficient in all 25 c0 rows is
also tested at its forbidden modulus value. Seed-identity comparisons hold all
other setup bytes fixed.

Validation on 2026-10-17 used Rust 1.99.0/MSVC, release/locked/offline, a fresh
`.local/target-relinearization-key-source-r1`, native CPU flags and two Rayon
threads. All 541 previous lock package records are unchanged; integration adds
only this local package and its core member/default-member entries. Reproduce:

```sh
cargo test --release --locked --offline -p bfv-relinearization-key-source --lib -- --test-threads=1
cargo clippy --release --locked --offline -p bfv-relinearization-key-source --all-targets -- -D warnings
```

The whole nine-case test child took 1.46s in its harness and 1510.5801ms under an
owned-process observer. Fifteen samples observed an OS peak working set of
142196736B and sampled private maximum of 134447104B, with actual gaps of
100.1284–100.6749ms. Sampling can miss short peaks; these are test-process
observations, not a hard RAM bound, a relinearization proof measurement or SQL
query latency.

Ignored evidence under `.local/relinearization-key-source-validation-r1/` retains
source snapshots, exact commands/environment, tool and SDK hashes, raw logs,
the actual libtest executable hash and memory CSV:

| Receipt | SHA256 |
| --- | --- |
| `source.json` | `BFB9AFFA5570A529D7543AE09FD249B4EB4059792D4F64E95ADE8C3ACB1620C9` |
| `compile/success.json` | `0884EDDA24338B670B61B9081576D2F2735031B9C72316D38FDF9D0D81C2FEE4` |
| `tests/success.json` | `EA6FCABDEF86A3AAF24498338BDD7142DD2A63AF9BDEB15F96DBA94594EFC1AF` |

Frozen bundle EAFDD070… supplies source provenance; the passing SDK and rejection
results above come from actual execution. No arithmetic proof is produced here.

Trusted local `Owner::generate` provenance can give an application its independent
expected setup: that existing factory derives evaluation keys from its retained
secret and returns the original public bytes. A decoded or assembled PublicSetup
has no such provenance merely because it hashes to its own ID. Setup signatures
or IDs can authenticate selected bytes; they do not replace arithmetic proofs or
prove same-secret consistency. Owner authorization, certified input formation,
complete selection, finality/freshness and writer fences remain separate.
