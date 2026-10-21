# BFV ciphertext formation

This reusable library proves the fixed 8192-coefficient bounded-noise formation
relation for the original five BFV moduli. It depends downward on
[bfv-basis-convolution](../bfv-basis-convolution/README.md),
[bfv-key-transform](../bfv-key-transform/README.md) and the fixed
[hiding engine](../bfv-hiding-stark/README.md). It has no Core, SQL, Journal,
application or fixture dependency.

`EncodedOpening` owns caller-supplied scaled polynomial words W and a private salt.
It checks exactly 8192 canonical words below 114689 and recomputes the original
salted commitment under the supplied exact encoding context. `EncodedCommitment`
is public mathematical metadata; it does not establish Source or SQL authority.
`Expected` binds that commitment, all 33 Key public values, the original request,
complete canonical parameter/ciphertext bytes, and five ordered Basis statements.

`prove` and `verify` cryptographically verify the actual Key and all five Basis
components before preparing a formation claim or constructing its AIR/trace.
Basis proofs are decoded and dropped one at a time. `Prerequisites` borrows the
fixed five bounded PUBLIC frames; it does not serialize an aggregate message or
retain a vector of SDK proof objects. The consumer owns independently trusted
producer/setup pins. A checked result is not a formation-chain, SQL or freshness
acceptance token.

`verify_scoped` is the typed composition path. It borrows exactly five genuine
`ScopedBasis` results from one actual transform instance, validates every complete
Basis Expected and all public values (including parameter/ciphertext bytes, q,
order, result and ALL33), and then verifies the real Formation proof with the
same header, AIR, codec limits and security assessment. It cannot construct or
accept a result from public claims alone. The borrowing caller owns independent
setup and fresh-call policy; the closed MulRelin verifier produces these results
locally in that same call. Standalone `prove`, `verify` and their prerequisite
byte checks keep their previous behavior. The scoped path and genuine Input16
rejection gate passed the [owning validation](../../docs/joint-query-fast-path-validation.md);
no performance result or new authorization/freshness capability is claimed.

For every coefficient j and basis i, the circuit proves the exact INTEGER equation

```text
B_i[j] + R_i[j] - e[j] - DELTA_i * W[j] = q_i * k_i[j]
```

The SAME e is in [-20,20] for all five bases, W is in [0,114688], R is signed63
biased by 2^62, and k is signed20 biased by 2^19. Those ranges keep the entire
residual strictly inside (-Goldilocks modulus, Goldilocks modulus), so the field
zero test is an integer equality. Seven original-context streams open the five
raw Gold R vectors, original raw W and the new signed-noise commitment. No root
is relabelled. The exact existing circuit has height 512, width 12752, 44 public
values and 592 periodics. Its degree hint is 5; actual SDK symbolic degree and
security are assessed for the immutable instance before allocating its full trace.

The witness derives noise AFTER encryption from the independently supplied W:
center `(B_i+R_i-DELTA_i*W) mod q_i`, require common support20, then derive an exact
quotient. No encryption RNG capture, fixture noise seed, decryption-derived W or
re-encryption comparison is used. This proves bounded-noise existence, not the
CBD sampling distribution or ciphertext origin.

`circuit` is the low-level exact evaluator/row writer for explicitly caller-owned
mathematical inputs. Existing experimental Selected/Return168 adapters preserve
their original profiles, contexts and public-value order while delegating here.
The new fixed relation has its own profile and the DCSFMP01 component frame:
magic8/profile32/full-setup-label32/Expected-binding32/noise-root32/payload-length4
(140 bytes). The binding is fixed-domain and covers all canonical Expected fields.
The genuine emitter and hostile/resource tests validate the payload 24 MiB,
sequence 16384 and nested-element 32 Mi limits at this owning boundary. See the
[executed validation](OWNER-FORMATION-VALIDATION.md). Dimensions and
quotient chunks are derived from the fixed actual AIR, never selected by a peer.
Canonical nested decode/reencode and topology checks precede SDK verification.

Explicit W/R/k/e/salt storage is guarded with Zeroizing where represented as native
integers. Native Gold vectors, trace/LDE/FFT/P3/SDK buffers and caller-owned input
buffers are not promised securely erased. No private-opening persistence or recovery
exists. The standalone Owner job is in [Core](../bfv-query-core/README.md); Registry200
producer authority belongs to its separate experimental adapter.

Mandatory main openings of Key plus five Basis already exceed 64 MiB. No aggregate
transport registration, Journal cap change, live SQL grant, evaluation-key
same-secret consistency or agreed freshness is established. Composed security must
sum every actual term: six individual 128-bit floors alone give 125.415 bits; a
larger Source/Lifecycle/Encoding/Formation composition does not claim composed128.


## CoreGold mathematical family

The additive [`gold`](src/gold/README.md) namespace owns a separate N4096/Q2
full Formation relation. It includes its exact canonical request, consumed
private W/secret/salt inputs, all four full negacyclic equations, full Cw/Cs
commitments, actual native analytical/resource gates, bounded new batch wire,
producer and independent cold verifier. It depends downward on the fixed hiding
engine, bounded codec and native Plonky3 libraries; no registry or experiment
imports enter this library. The original N8192 APIs and profiles above retain
their behavior.

Producer bytes are explicitly unverified. Only actual native receiving
verification creates the move-only mathematical result. The upper
`registry200-proof::two_lane_encoding::formation` consumer separately verifies
Source/encoding prerequisites and owns their association. The
[executed native gates](src/gold/VALIDATION.md) establish local proof behavior,
not key admission, lattice assurance, current-head freshness, SQL acceptance,
network latency or the 500ms complete-query target.
