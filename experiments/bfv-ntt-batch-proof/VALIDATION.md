# Native validation of atomic ordered NTT batches

Complete ordered batches of 2, 4 and 8 native degree-8192 transforms passed
generation and fresh verification. The full statement is proved in sequential
two-operation units; only the complete outer result can be accepted. Four
genuine altered-program proofs first verified under their own programs and then
failed the honest verifier. This validates public arithmetic, not a SQL answer.

## Tested implementation and ownership

The additive core API retains the original single-operation arithmetic, wire,
profiles and bus labels. Each batch instance has a private data namespace and
the four range providers share checked aggregate frequencies. The consumer keeps
the original globally labelled Request bytes, full ordered input/output
coefficients, q/setup labels and full SHA512 outer profile in every unit's
transcript. The ordinal and exact range are also fixed. A unit for instances
6..8 is not retagged as 0..2.

Each unit reconstructs its own trusted AIRs, preprocessing, config and VK. Heavy
Backend/PK/VK/PCS data drops before the next unit. The verifier keeps all bounded
public decoded proof objects but never evaluates an NTT or creates Aux. Actual
SDK reports are reconstructed locally, must be finite and fully assessed, and
must satisfy 144 bits. The outer conservative union is
`min(actual component bits) - log2(component count)`; there is no partial grant.

The frame remains capped at 16MiB. One Expected-selected fixed Postcard array
shares the sequence limit 16384 and total 8Mi container-slot budget across all
proofs. Canonical re-encoding, EOF, exact component boundaries, cap-zero trees,
derived schedules and pruned-frontier bounds are checked. No report or VK from
the sender is trusted. The [README](README.md) describes the format and conditional
ceilings, including the inverse/inverse case.

The consumer uses the scoped SDK's
[per-AIR raw-row cache](../p3-multi-stark-streaming/PER-AIR-ROW-CACHE-VALIDATION.md).
The SDK proof/verifier/security/transcript contracts remain unchanged. Root
workspace manifests, lock, default members and the original registry SDK did not
change; all resolved p3 packages are exactly 0.8.0.

## Executed checks

Windows x86_64 MSVC, Rust 1.99.0, release mode, locked offline dependencies,
`RUSTFLAGS=-C target-cpu=native`, one Cargo build job and two Rayon threads were
used. Compiled executable hashes were checked before and after execution.

| Owning runtime boundary | Passed executions |
| --- | ---: |
| SDK, original dense default | 516 |
| SDK, opt-in streaming | 517 |
| Core: default / plonky3 / multistark / both | 7 / 9 / 17 / 20 |
| Original main-witness NTT consumer | 13 |
| New ordered batch consumer | 9 |
| Total | 1108 |

These are executions across overlapping feature selections, not 1108 distinct
behaviors. SDK alone has 517 distinct cases. All originally ignored heavy SDK
tests ran. Exactly its original two fixture writers were excluded per mode:
`generate_the_compatibility_fixture` and `generate_whir_fixture`; their readers
ran and public fixture bytes were preserved. No NTT owning case was skipped or
newly ignored.

The nine new cases cover all twenty native CPU SDK direction/basis targets over
every 8192 coefficients, complete envelopes and unique ordered bindings, genuine
2/4/8-operation proofs, and four genuine weaker/foreign programs. Full-eight
attacks repair headers after swaps, duplicates, omissions, extra components,
q/setup changes and full-outer last-output changes. A hostile nested array fits
each individual component's caps and decode but fails the one shared total
budget. Altered programs remove the final equations, inverse normalization or
instance isolation, or replace full-IO preprocessing; each must establish its
own genuine proof before the honest verifier rejects it.

Three type-check commands passed, including SDK library cfg(test) code in both
modes and every new consumer target. Six strict all-target Clippy commands
passed: four core feature selections and both NTT consumers. Optimized SDK
library plus six integration targets compiled in both modes; all selected core
and consumer targets compiled. Seven doctest commands passed with **zero doctest
cases**, separate from the runtime total. Upstream examples and benches remain
outside this selected gate, including the unchanged example with an earlier
LLVM allocation failure. The requirements mirror matched before and after.

## Actual security and CLI observations

The fixture-selected units have main arity 23, preprocessing arity 22 and lookup
arity 23. Each unit's actual complete SDK report gives 157.301048 bits under the
fixed protocol assumptions, with no unassessed terms. The outer union is
157.301048 / 156.301048 / 155.301048 bits for 1 / 2 / 4 units respectively.
This is neither a hiding theorem nor a global SQL composition assessment.

| Complete operations | Generate ms | Fresh verify ms | Frame bytes | Sampled working set bytes | Sampled private bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2 | 68153.4851 | 627.6511 | 2330935 | 1025433600 | 1023250432 |
| 4 | 134042.6219 | 935.8213 | 4638707 | 1030086656 | 1028722688 |
| 8 | 254595.8013 | 2224.0412 | 9294378 | 1035870208 | 1039122432 |

Generation includes full output evaluation, actual security/setup passes,
regenerated pair witnesses, genuine proofs, own verification and serialization.
Fresh verification includes the shared bounded decode/canonicality pass,
sequential trusted setup, security/layout checks, actual SDK verification and
the final union. CLI runs a separate numerical analysis before the generation
timer; total command times were 69461.7199 / 136181.3475 / 258600.7205ms.

The sampler observes the target process and owned descendants at nominal 100ms;
the actual maximum CLI gaps were 505.887 / 584.000 / 573.228ms. A sampled
1792MiB-per-PID soft fuse and 1200s-per-command limit did not fire. Across all
observed checks/runtime commands, maximum sampled process working set was
1108041728 bytes and private bytes 1105432576; the largest sampling gap was
704.5873ms. These are observations, not a hard upper bound, whole-peer RAM budget,
controlled speed comparison or a complete FHE SQL cycle.

The earlier monolithic four/eight-operation attempts hit the same soft fuse.
Their failed receipts and executables remain preserved. This result retains all
eight operations and changes the heavy prover ownership policy to complete
sequential pairs; it does not establish that the monolithic policy fits.

The fixture-specific derived total frame ceilings are 2576548 / 5152776 /
10305232 bytes and decode ceilings 1615965 / 3231930 / 6463860 slots. Actual
emission and shared decoding passed below these limits. The more conservative
all-pair-family ceilings in the README are also enforced against derived
schedules. No frame, Body32MiB, transport64MiB or Journal256MiB cap was raised.
This standalone experiment does not build or admit those network envelopes.

## Reproduction and local evidence

Use the explicit target selection and fixture-writer exclusions in the
[SDK recipe](../p3-multi-stark-streaming/VALIDATION.md#reproduction). For this
consumer, with a fresh target directory and the pinned release toolchain:

```powershell
1..3 | ForEach-Object {
    $count = [int][Math]::Pow(2, $_)
    cargo run --release --locked --manifest-path experiments/bfv-ntt-batch-proof/Cargo.toml -- security $count
    cargo run --release --locked --manifest-path experiments/bfv-ntt-batch-proof/Cargo.toml -- prove $count
}
cargo test --release --locked --manifest-path experiments/bfv-ntt-batch-proof/Cargo.toml -- --test-threads=1
```

For measured runs, build first and invoke the emitted executable directly so
compilation is outside the operation timer. The local harness records exact
arguments, environment, executables, stdout/stderr and memory samples.

| Ignored local evidence | SHA256 |
| --- | --- |
| `.local/atomic-ntt-validation-r5/source.json` | `FBFA1CAA18DB87BD8B50C0699EEE44D379A7B351F5312751D4B415CD451BD531` |
| `check/success.json` in that directory | `77223A6E64B5FB3E5A105CC8F5FE667D613980C216618C0832C404F3217B7C76` |
| `contracts/success.json` | `2E0AD277513BB8D9C786BF8E1FDC6AEF0A51FC72A7D79D11603648AA886BD891` |
| `compile/success.json` | `31C05CCCB3207179D4D207B8D8589FBF950F5B90851EE5A8316A50681A2CC83B` |
| `numeric/success.json` | `9D1967A264641F618977BF9C3441F75B2676D6113E9F8795F6534656B715F08B` |
| `prove/success.json` | `D5533CB2FC2615E0D00CBB54DABFDF772813ADFD3CB0F4300B68BAF585F2887E` |
| `tests/success.json` | `479FF42A80D6BE8DC68EE392FA142DB3410A53E40AC0B20ED130E92AB4F8FA54` |
| `docs/success.json` | `B793CEEDD0883C8B329900C6826A61B370305A27175FAC38D853728E44E5BFA0` |
| `.local/atomic-ntt-source5-review-r1/success.json` | `5928107510D31F3DD7CA338C8DAE09AFFD5229DD74F4E1CADB706C0CA248D73F` |
| `.local/native-ntt-batch-r1.py` | `9505DD6E4D9EA317EFF1C6C45BF86FAA4D3837E5C45D2DF41A9535048C8CFC38` |
| `.local/review-atomic-ntt-source5-r1.py` | `F4950D505B9A0AE1C32B2940C3825A5AD4ACE609F28EB278538025A25985B525` |

The source parent is ac8c4f798373db64b633164d5525af94a71cd154. The final native
audit matched 16266 prior controls, all compiled executables, 83 upstream packaged
files with the same six reviewed deltas and 77 byte-identical paths, and the
complete original test prefixes. Independent production source review found no
actionable defect; it is separate from the native evidence. Subsequent edits are
documentation only and receive a final closure check before publication.

Remaining requirements include causal MulRelin and its exact ciphertext wire
links, setup/key provenance, hiding WHERE and constants, complete SQL proofs,
fresh decentralized agreement, durable admission and whole-peer resource limits.
Historical SQL failures were not rerun by this gate and remain unresolved. The
repository Goal is incomplete.
