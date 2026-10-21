# Native arithmetic observation

On 2026-10-21, the real SDK experiment passed its owning checks and one bounded
release observation. This validates the implemented public-fixture arithmetic
example; it supplies no computation proof, SQL answer, security estimate or
full-query latency result.

## Operation and checks

Both operands were freshly encrypted: the complete four-row source and a private
truth table over the public age domain. The evaluator received serialized
ciphertexts and parameters only, performed one actual ciphertext multiplication
without relinearization and returned three serialized components. The client
performed actual decryption and checked the complete polynomial's bounds.
Plaintext expected answers were compiled only in the owning tests.

Strict release Clippy with all targets and `-D warnings` passed in 0.453 s.
Three ordinary rejection/domain tests passed with a 0.00 s body (8.375 s wrapper,
including compilation). The single genuine SDK test performed six products:
two profiles, each with all, none and hidden age>=128. It compared every output
coefficient with a test-only plaintext ring-convolution oracle and independently
checked all four original ordinals, including selected zero amounts. It passed
in 0.15 s (0.453 s wrapper). No network or expensive DCS scenario was repeated.

The initial giant report macro failed compilation at the default recursion
limit. Root grouped the report into separate parameter, timing, wire and operation
objects; the limit was not raised. The frozen donor also changed one predecessor
line ending in Cargo.toml. Root preserved the original bytes and added only the
workspace member. The lockfile adds one local package using already locked
dependencies; default members and production profiles are unchanged.

## One observation, two new arithmetic profiles

The direct prebuilt command was:

```text
bfv-unrelinearized-selection.exe --mode pair --case all
```

Both profiles use the new two-lane layout and unrelinearized output. The N8192
baseline matches the original parameter basis only; it is not the existing live
three-lane/relinearized operation, and this is not a before/after SQL comparison.

| Wall phase | N8192/Q218 baseline | N4096/Q60 candidate |
| --- | ---: | ---: |
| Parameter construction | 52.6887 ms | 4.1527 ms |
| Secret-key generation | 0.0556 ms | 0.0166 ms |
| Complete source preparation, encryption and wire | 2.8464 ms | 0.6156 ms |
| Private-mask compilation, encryption and wire | 2.6143 ms | 0.5903 ms |
| Request association | 0.1772 ms | 0.0302 ms |
| Peer request decoding | 2.5527 ms | 0.4889 ms |
| Actual SDK product | 8.0100 ms | 1.6398 ms |
| Peer response serialization | 2.1585 ms | 0.3937 ms |
| Client binding, decoding, decryption and complete bounds | 5.2522 ms | 0.9632 ms |
| **Complete measured arithmetic interval** | **24.2051 ms** | **4.8228 ms** |
| Setup-phase sum plus arithmetic | 76.9494 ms | 8.9921 ms |
| Request / response | 446,650 / 669,821 B | 61,626 / 92,285 B |

The complete arithmetic timer includes fresh input construction/encryption,
request/response byte association, actual multiplication and client completion.
It excludes parameter/key setup, observation formatting, proof generation and
verification, Source authentication, authorization, fresh head, locks, storage,
agreement and real network I/O. The setup sum is the sum of separately timed
phases, not a separately measured whole process. These are individual samples,
not percentiles, throughput or an all-input correctness/noise guarantee.

The candidate's actual ordered primes were `[1073692673,1073668097]`, t=65537,
degree4096 and CBD variance10. Its parameter SHA256 was
`7f4fd9731c2f4ebc33739e68c27df215c5792778f1869c36f24cbf3720953f36`.
Neither this parameter set nor the baseline is independently security/noise
certified by this experiment. A smaller modulus is never installed into a live
profile on the strength of successful samples.

## External evidence and limits

The existing release/native CPU policy, Rayon2 and buildjobs2 were retained.
A single actual process ran, with a 30 s observer fuse and unchanged 1,792 MiB
per-process memory veto. Its held Windows process object had matching creation
time and final exit0; no observer fault, extra child or forced cleanup occurred.
All pinned experiment/dependency source bytes and the binary were unchanged.
Final OS counters report 0.09375 CPU-seconds and a 101.7924 ms process lifetime
for both profiles together. The observer itself took 438 ms, including OS queries;
that is not the native process's arithmetic time.

Only one memory sample was obtained around process exit. It retained the actual
OS peak working set of 65,957,888 B, but the sampled private/working counters do
not establish their transient peaks or an entire RAM guarantee. In particular,
the small final private value must not be advertised as peak memory. Global
system CommitPeak is diagnostic only and is not attributed to this experiment.

Reproducibility SHA256 identities:

- Frozen source manifest: `AAA4EFA50979AC81D0EF555632E95B23800129B9A547CCEB636859E4E7BB68C4`.
- Direct exe, 964,096 B: `E24764C93BDAF82A82D04908260A6325E6F016DDCE8D02C99CD59C35D6BB7F31`.
- External sampler: `428150581EFDBB713D1E973226727554F2DDC2CD9C7125B8DE815FB0AC14CAF6`.
- Root-formatted source with grouped reporting: `231D18A63B6E67A461835A64AFFAE45B81FEC762DEFE46C2CA347A18C05B6616`.
- Local final observation: `98AA58FFF5342DF279942B8C36300745A5BA59EEA1FA4AE8BFE836E71FA06560`.

Raw observations, binaries and generated keys remain ignored. Reproduce with
the owning README commands and separately monitor the direct release binary.
No result is accepted into DCS from this executable.

The next gate is a complete, compact, independently verifiable product
certificate with assessed security and bounded memory, plus compatible
Source/private-program/Formation proofs. The current many-proof protocol is
still expensive. The **500 ms complete-query target remains unmet**.
