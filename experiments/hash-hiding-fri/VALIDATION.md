# Actual SourceVersion candidate validation

2026-10-22. This gate proves and independently verifies the existing complete
SourceVersion AIR with the separate hash candidate. **It is not a network SQL,
FOR UPDATE, full five-AIR composition or production-security gate.**

The public producer and independent receiving verifier ran on the same checked
source expectation. Both candidate and existing-suite baselines constructed fresh
OS RNG/configuration and actual private-witness native proofs. Neither result was
an echoed fixture, a substituted hash check, a simulated evaluator or a cached
proof receipt. The two stored source pages and their canonical index are the
reviewed public nonsecret core fixture.

## Complete component measurements

Final accepted capture `r538`, optimized native Rust 1.99.0 MSVC, two Rayon
workers, one test thread, no concurrent heavy job:

| SourceVersion operation | Candidate SHA256/SHA512 | Existing Poseidon suite |
|---|---:|---:|
| Public producer, including AIR assessment, trace, config, native prove, encoding and drops | 1431.077 ms | 2412.782 ms |
| Independent receiver, including bounded canonical decoding, AIR assessment, fresh config, native verify and drops | 431.488 ms | 747.148 ms |
| Producer + receiver | **1862.565 ms** | **3159.930 ms** |
| Serialized output | 12,254,443 bytes, including new 44-byte frame | 12,250,495 bytes, existing raw Source certificate |

The preceding accepted `r534` measured 1904.403 vs 3013.662 ms, on the same
mathematical relation/configuration; its subsequent test-only edit explicitly
discarded the unreachable result in the positive-grinding panic test for Clippy.
These are two component observations, not a latency percentile, throughput claim,
constant-time guarantee or prediction about other AIRs.

The final candidate producer phases were: actual symbolic AIR assessment
187.443 ms, witness trace 8.152 ms, fresh config 0.007 ms, native prove
1218.100 ms and bounded encoding 14.397 ms. The independent receiver phases
were: canonical bounded decode/re-encode 31.999 ms, actual AIR assessment
183.188 ms, fresh config 0.007 ms and native verification 214.257 ms. Public
end-to-end timers also include object destruction and surrounding call costs,
so they are not defined by summing rounded phase lines.

Source width/height remain 7161 × 512, with 691 public values, 512 periodic
columns, no preprocessed matrix or lookup AUX, hiding committed log-height 10
and 16 quotient chunks. Hiding stays at five random codewords, four salt fields
per matrix, EF5, 192 FRI queries and blowup 8. Actual proof topology is checked
before native verification, including all zero PoW witnesses, masks, caps,
three PCS input batches and ten FRI rounds.

## Owning checks and resources

All **17 tests passed**: five Merkle primitive/encoding tests, ten challenger
tests and two closed Source API tests. Independent .NET SHA byte vectors pin the
Merkle domains and complete challenger prefixes. Forced rejection tests execute
the actual sampler with `p`, `u64::MAX`, then `p-1`. Native verification rejects
changed state even with an unchanged version tag, changed key, modified OOD
opening, altered public value and different transcript context. Tests also
reject cross-suite proofs, wrong frame/profile, bad shape and oversized,
truncated or trailing data. A valid Postcard length of 16385 is rejected as
`ResourceLimit` before cap-vector reservation; policy allows at most 16384.

The total decoder budget is the same 24 Mi container slots as the existing
owning Source decoder. Gold's canonical binary representation is an eight-byte
array: its eight nested slots must be charged in addition to the containing
vector slot. The whole frame remains capped at 20 MiB. No proof or resource
requirement was relaxed to obtain a successful measurement.

The whole test process, including baseline proofs and hostile verification,
completed in 7238.8995 ms. Its OS peak working set was **570,376,192 bytes**
(about 543.95 MiB), peak private bytes 563,494,912, with 354 samples. The held
exact-image/creation-time observer sampled every 20 ms, enforcing a 120 s fuse
and 1792 MiB whole-process limit. There were no faults or cleanup actions.
The roughly 7.2 s suite duration is **not** Source operation latency or SQL time.

Strict all-target Clippy (`-D warnings`) passed. The new package is a workspace
member only; it does not enter Cargo default members. Existing production proof
profiles, peer admission, fresh-head rules and consensus paths are unchanged.
The requirements mirror and owning repository contract are checked separately.

Final native executable:

```text
hash_hiding_fri-bdb0cad2ebb92b07.exe
bytes=6411776
SHA256=FD0226A483B1FDA8798961C9779923410555790AB60DAF93FE00C4F39020D2CE
observer SHA256=2635D0D6EB9F22AA5057DED84282E2A511D4DBB9A4752778428780732C5E26C3
```

Local source-pinned build/capture receipts are
`.local/word-cmd-native-r537-hash-hiding-fri-build-tests/result.json` and
`.local/word-cmd-native-r538-hash-hiding-fri-observe-tests/result.json`.
Generated logs, proofs, binaries and captured outputs remain local and are not
committed. The test sources provide the reproducible public measurement path.

## Next integration boundary

The candidate still lacks the quantified composed ROM/Fiat–Shamir/Merkle model
described in [README.md](README.md). A successful native proof supplies neither
that reduction nor production security approval. Semantic Poseidon commitments
inside the AIR retain their separate assumptions.

Role3 already exposes its complete actual AIR/witness. Word, dense DATA and
fused Query deliberately keep their AIR/plans/preprocessed factories and private
writers behind their owning libraries. Their MAIN contains the protected owner
secret; a public raw-trace getter or arbitrary caller-configured callback would
violate that boundary. The next implementation should place the fixed hash suite
in a reusable core module and add closed suite-specific producers/receivers that
consume the existing opaque Expected/PrivateInputs/Prepared values and reuse the
same private AIRs/writers. Core must never depend on this experiment.

The next complete mathematical gate is Source → Role3 → actual DATA, Word and
fused Query → original product certificate, with all original shared bindings and
independent native checks. Live admission requires a new complete contract plus
the cryptographic model; afterwards the real network/fresh-quorum/lock operation
must be measured. **The 500 ms full-query goal remains unmet.**
