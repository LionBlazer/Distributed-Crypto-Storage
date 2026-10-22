# Native public arithmetic certificate observation

The 2026-10-21 local observation completed the actual N4096/Q2/P2 SDK product,
construction and fresh checking of the complete experimental arithmetic
certificate, and actual client decryption. It does not establish an accepted DCS
proof or the <=500 ms complete-query target. All security, Source, freshness,
network and SQL acceptance flags remained false.

## Owning verification

```
cargo clippy --release --offline --locked -p bfv-unrelinearized-certificate --all-targets -- -D warnings
cargo test --release --offline --locked -p bfv-unrelinearized-certificate -- --nocapture --test-threads=1
cargo build --release --offline --locked -p bfv-unrelinearized-certificate --message-format=json
cargo test --release --offline --locked -p repository-contracts --test requirements_sync
```

Strict Clippy passed in 0.875 s including the wrapper. All thirteen tests passed
in 0.53 s of test-body time, 3.953 s including compilation/wrapper. They cover
actual SDK geometry and two exact SDK scalers over all 4096 coefficients in all
input/output bases, full-vector public convolution, canonical frames and bounds,
every scalar quotient, original Q copies and repaired final-coefficient changes.

The complete positive case uses fresh actual SDK ciphertexts. The compound
negative changes their product, constructs an SDK-readable false output,
recreates all seven scalar certificates and outer bindings, and independently
confirms all seven scalar checks pass. The complete checker still rejects its
false product identity. Other cases alter final Y/H/P coefficients, swap scaler
jobs, exceed degree/residue caps and append/truncate frames. These assertions
provide arithmetic evidence, without constituting a cryptographic assessment.

The requirements mirror check passed. An initial helper command named the old
playground test owner and ran no test; the corrected command above passed at the
actual `repository-contracts` boundary. Initial strict Clippy found two constant
chunk-iterator lints and one indexed-test-loop lint; all were fixed. No warning
suppression, weakened assertion, lowered proof strength or timeout change was
used to make the gates pass.

This isolated experiment changes no production consumer or network boundary.
The expensive multi-process/recovery gates were therefore not rerun. Existing
production proof profiles, timeouts and accepted guarantees remain unchanged.

## One observed complete local experiment

The release executable ran with the trusted native-CPU build, two Cargo jobs and
two Rayon threads; ambient and saved DCS feasibility switches were removed. Its
fixture has four explicitly public nonsecret rows, an encrypted age>=128 truth
table, fresh secret key and genuine encrypted multiplication. Only the client
fixture owns the key. The checker sees public ciphertext-derived values only.

| Local phase | Observed milliseconds |
| --- | ---: |
| Parameters, public fixture/oracle, fresh encryption and input serialization | 6.1096 |
| Actual SDK unrelinearized product | 1.7132 |
| Complete certificate construction, including all seven exact scaler certificates | 34.9626 |
| Fresh complete arithmetic certificate check | 49.4285 |
| Actual output deserialization, decryption, decoding and full-N public-oracle comparison | 1.0596 |
| Whole local operation, including statement construction and phase overhead | **94.3640** |

The whole-operation timer ends before report hashing/JSON output. The independent
OS process lifetime was 117.9433 ms; summed process CPU time was 0.109375 s.
This is one observation, without a percentile or repeated-run throughput claim.
The earlier 103.6799 ms observation used the predecessor without client completion;
it is retained separately and is not relabeled as this final operation.

The original complete frame was exactly 1,737,899 bytes: header256 + extended P253952 +
products282624 + quotients282555 + seven scaler frames918512. Original request
bytes are 123,052 and output ciphertext bytes are 92,205. These exclude Source,
hidden-program, authorization, agreed-head and consensus evidence. At 100 Mbit/s,
the certificate alone has a payload floor of about 139 ms per recipient before
transport overhead. No actual network observation or end-to-end SQL speedup is
claimed, and comparing this partial relation directly to an old full-query
duration would be invalid.

An examined Stage35 STARK union was rejected before allocation: its padded MAIN
plan alone required 1,073,741,824 codeword bytes plus 1,073,741,760 Merkle-tree
bytes, exceeding the 1,879,048,192-byte process fuse before its other allocations.
This is a static bound for that candidate plan, not a native failure or a claim
about every possible STARK implementation. The new experiment does not raise
the cap or install a partial replacement as an accepted proof.

## External observation limits and evidence pins

The observer held the actual process handle, image and creation-time identity
through terminal exit0. It sampled memory every nominal 5 ms without process-table
enumeration on the measurement loop. Nineteen samples observed at most
11,800,576 private bytes; the retained OS peak working set was 16,031,744 bytes.
Sampling does not certify the peak private allocation or memory for a live peer.
The terminal child snapshot found none; the experiment source spawns no processes.
The 30 s observation fuse and 1792 MiB per-process cap did not fire. There were
no observer faults or cleanup kills. Source and executable pins remained exact.

Generated evidence is ignored and intentionally not committed:

| Local record | SHA256 |
| --- | --- |
| `.local/unrel-cert-native-r2-observe/result.json` | `5AA878C4552152DF25F38EA19A4116D9082A74CA8FBDD2A414139FF4D48128F4` |
| `.local/unrel-cert-native-r2-test/result.json` | `90CD93F2A58B6C233F5039ABA6EFE92EBFBEB0E2DD4740FED847A94854CAF5E8` |
| `.local/unrel-cert-native-r4-clippy/result.json` | `CE40471F7A0B4BEF96A1C9365F357CF8A1FA603C1F74C1664A379E7FF89266F6` |
| `.local/unrel-cert-native-r2-build/result.json` | `1BE199DA7D1B10103BB64C85E37E66A0FE8BEFACBBDEF162F8312F641EFB6862` |
| `.local/unrel-cert-native-r2-requirements/result.json` | `317C13CBAAA88F5FEEAC49445520F2602F8E2DF9CF0E1E716D1939799EE49756` |

Final executable: 1,023,488 bytes, SHA256
`8A84BCE6A53A44DD0E532F4D41E8B90DB44416B48FB9F1896F1A1F63F02FA958`.
Observer: `.local/observe-unrel-cert-r2.py`, SHA256
`7E7C20E9343518F50966B41EC5F065155CAB089C317DF366473853514B076023`.
Profile SHA512:
`9d97f6eede741c9a179fc359d8b33f299720ab54576fbfe955f6192af65a5724fecbfad31bf8b4f7ba1d88c2d9aebcdcd2a2c925b0f9b838b71be1806b343bed`.

The recorded code and protocol boundaries are described in [README.md](README.md)
and [SOUNDNESS.md](SOUNDNESS.md). Independent agent source reviews found no
concrete composition, parsing or client-completion defect; they are source review,
not additional native evidence or approval of a cryptographic security level.

## Public checker arithmetic follow-up

The follow-up replaces per-coefficient u128 remainder division in the public
Horner checker with Montgomery multiplication. It changes no coefficient,
identity, challenge, transcript byte, profile digest, count of eighteen points,
scalar certificate, decoder gate, accepted guarantee or production consumer.
The independent prover's original remainder-based convolution is unchanged.

For each fixed odd p<2^62, R=2^64 and a,b<p, t=a*b<p^2<2^124. With
m=(t modR)*(-p^-1) modR, t+m*p fits u128 and is divisible by R. Its quotient is
below p+p^2/R<2p, so one subtraction makes the result canonical. Six Newton
steps obtain the inverse modulo R. Multiplying an ordinary accumulator by a
point represented as point*R preserves the ordinary accumulator domain after
reduction. Thus the complete coefficient vectors need no conversion or cache.
These bounds rely on the closed checker's mandatory canonical-vector validation;
the private arithmetic module does not grant authority to unvalidated values.

The three added tests compare every pair of residues for p=3,5,97 with independent
BigUint arithmetic, check all4096 coefficients and boundary evaluation points in
all four actual fields, test powers/products at those boundaries, and reject
unsupported moduli before setup. All sixteen owning tests passed in 0.58 s of
test-body time, 5.328 s including compilation/wrapper. Strict all-target Clippy
passed in 3.625 s including its wrapper. The original full-certificate SDK and
repaired-adversary tests remain mandatory and passed. Independent source review
found no reduction, range or domain-conversion defect; it ran no native code.

One further native run used the same complete operation, public fixture schema,
trusted build/thread policy, caps and observer method as above, with fresh keys:

| Local phase | Observed milliseconds |
| --- | ---: |
| Preparation | 7.1727 |
| Actual SDK product | 2.5556 |
| Complete certificate construction | 38.2438 |
| Complete arithmetic certificate check | 36.6900 |
| Actual client completion and full-N comparison | 1.2524 |
| Whole local operation | **87.4687** |

The independent process lifetime was 126.6838 ms and CPU time 0.09375 s. Twenty-two
memory samples observed at most 11,771,904 private bytes; the retained OS peak
working set was 16,113,664 bytes. The process exited0 without faults, cleanup,
fuse, source drift or observed child. This is another single observation, not a
controlled repeated benchmark; the individual phase changes do not establish a
stable speedup factor. The same 1,737,899-byte frame and unassessed profile were
used, and every security/Source/freshness/network/SQL acceptance flag stayed false.
The missing full-query obligations described above remain unchanged.

| Additional ignored local record | SHA256 |
| --- | --- |
| `.local/unrel-cert-native-r3-observe/result.json` | `40113D0F3E724CEA97A12B8DCA291F929F279B086F730C2DB16B33D5ECCF068F` |
| `.local/unrel-cert-native-r3-test/result.json` | `E6A52792E4AF6587E57CA7D3E2A8CF6856F6DF58998E73530B8A0EA48FA84662` |
| `.local/unrel-cert-native-r5-clippy/result.json` | `AF17903B6D462B7FD2B1DA1E0024EE237A8E166FA4E2F59E0C5A3B6C4ECC3428` |
| `.local/unrel-cert-native-r3-build/result.json` | `F1A44751A1B6B14A2107B3A6A7A82BC08ADB16EA319928F7E85E2920621B2DB6` |

Follow-up executable: 1,013,760 bytes, SHA256
`AB6DC5205F23943F4596F1E085C674C80342249D7954A0536C3D7FA903BEB180`.
Observer: `.local/observe-unrel-cert-r3.py`, SHA256
`5FE43141EDC87902B65C75E98C7C38130619472C027980C63E985E22A57FF492`.
