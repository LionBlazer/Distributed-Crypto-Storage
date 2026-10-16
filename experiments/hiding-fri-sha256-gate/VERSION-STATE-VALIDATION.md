# Version-bound source certificate and private selection

This experimental change separates one proved fixed N4 source version from
request-specific private Selection proofs. A sealed certificate is constructed
only after actual SDK source verification and exact comparison with the
independently expected full public state. Subsequent queries open the same
`C_state` with their own request, plan, result commitment and genuine proof.

The two distinct profiles reuse the existing packed source and Selection AIRs.
All old profiles retain their previous encodings. This is a nonaccepting research
gate; it does not enable network SQL answers or establish full PostgreSQL/FHE
query evaluation, private row locks, freshness or agreed-state finality.

## Ownership and binding

The deterministic version tag binds the new profile, complete canonical public
images and independently fixed `C_key`. `C_state` is excluded from that tag to
avoid circularity, and is checked separately in full statement comparison.
The source constructor retains complete canonical/root audits. Neither a tag,
root, successful decryption nor a trusted Boolean credits a certificate.

The bounded process-local cache owns one completed proof and its public
statement. It stores no Backend, RNG, FFT/prover data, source witness or key.
An exclusive borrowed lease prevents replacement/clear while it remains in use.
Every nested allocation is charged by capacity using checked arithmetic. SDK
Merkle caps are consumed, their actual root Vec capacities measured, and the
same roots rewrapped. Admission charges the retained entry plus the prospective
candidate before verification/publication; rejection preserves the old entry.

The CLI budget is 64 MiB of retained-owned storage, including fixed metadata
and one lease header. Candidate construction, temporary normalization, allocator
overhead, verifier/query work and other process memory remain outside it. It is
not a bounded network decoder or a whole-process RAM limit. In the certificate
invocation, admitted owned storage was **12,883,164 bytes**. The separate warm
invocation creates its own independently randomized source proof.

## Numerical and native gates

Native Windows MSVC Rust/Cargo 1.99.0, release, `-C target-cpu=native`, two Cargo
jobs and two Rayon threads, locked/offline dependencies. A fresh R2 target
preserved earlier outputs and the initial failed compilation.

- Release build, test compilation and strict all-target Clippy exited zero.
- All eleven earlier actual security reports matched field for field.
- Both new modes passed actual SDK analysis before trace/proof execution.
- One certificate proof was genuinely admitted; a second invocation admitted
  one certificate and proved/verified two different requests over that entry.
- All 97 tests passed once in 634.43 s, zero failed/ignored/filtered; the
  observed process duration was 634768.2482 ms.

| New relation | Width / height | Public fields | Assertions | Actual degree | Quotient chunks | Batched functions | Decoding bounds |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| StateCertificate | 7161 / 512 | 691 | 16133 | 3 | 16 | 14502 | 128 / 128 |
| VersionSelection | 957 / 512 | 88 | 4814 | 3 | 16 | 2094 | 128 / 128 |

Both retain 512 public periodic columns, two complete current/next openings,
degree hint 5, 192 FRI queries, five random codewords, extension degree 5 and
four salt elements. No preprocessing or grinding was added. Per-proof model
bounds do not establish composition-wide 128-bit security.

The first release build passed. Its test compilation failed E0599 after an
integration cleanup replaced `!ConstraintReport::is_ok()` with nonexistent
`is_err()`. That cleanup was reverted exactly to the reviewed donor test; no
equation, witness, profile or cryptographic parameter changed. R2 completed all
three native commands. No proof or repository test was run from the failed build.

Local generated evidence is retained in ignored `.local/` directories:

| Evidence | SHA-256 |
| --- | --- |
| Frozen R2 source, parent `adbfaef` | `F1CFB2447CA98BCA008AC5C8210BBCD4B3E0FEAF71A61AA536063A9A31BD46D9` |
| Three-command compile receipt | `1D33D7FA94073B164C46F52E6067C9043593E49277E52CA4CB3E9E1CCD126630` |
| CLI executable | `B4FF21418575364D1A56C0101226161E4EFD5D141B1F24A1085649EC10691036` |
| Test executable | `863801852E309E7F92DAD91C5FBB91A61CCCDD12E39052721A957EE22E873A58` |
| Thirteen-report receipt | `A792787F5EBB9B70C6B8818C2B3FFDF50EA06269FB85E4C22A76FB5C60C678DB` |
| Certificate invocation receipt | `D4029E67546D6526C3398EB2A6BB15255188FFE338D72922235948EFA3786EEA` |
| Two warm queries receipt | `3FEDAA793F08A1A08A29D7D72051898100276F7C8D28DC92B9F16693BE4BF14D` |
| Full97 receipt | `85B441B5EAB52EBBCFF830CF2FB5AEF8251767C0C539851A7BA10A31F1133091` |

The frozen source predates final README/report validation text. All compiled
Rust, dependency and pinned SDK inputs remained exact after the run.

## Observed timings

Single invocations and two distinct warm requests, not a latency distribution:

| Operation | Proving ms | Verification/admission ms |
| --- | ---: | ---: |
| Certificate | 1839.4487 | 659.8536 |
| Warm query 1: nonempty plan, LIMIT 2 | 476.6118 | 116.0082 |
| Warm query 2: empty plan, LIMIT 0 | 537.9013 | 114.8186 |

Certificate proving includes trace generation and STARK proving; initial source
Backend setup, fixture encryption/audits and native commitment construction are
outside that timer. Admission includes exact binding, budget checks, fresh
Backend setup and actual verification. Candidate accounting/construction and
cache construction precede the admission timer.

Each warm timer includes a fresh query Backend and its real analysis/configuration.
Proving includes the query trace and STARK proof; verification includes actual
query proof verification. Lease acquisition and fixture construction precede
the timers. The source proof is generated/verified once before both queries;
the source Backend/witness are scoped out before warm work. No proof witness,
commitment opening or RNG stream is reused as prover data.

Warm proving plus verification was **592.6200 and 652.7199 ms**. Codec, network,
freshness, FHE execution and SQL processing are absent. A complete SQL operation
at 500 ms is not established. The preceding request-bound composite observations
in [owned-AIR validation](OWNED-AIR-VALIDATION.md) have different source/timer
scopes and do not establish a causal benchmark comparison.

An external observer requested 100 ms waits and sampled working/private/OS
peak working-set counters. The 1792 MiB fuse is a sampled soft abort condition,
not an allocator or lifetime RAM guarantee. The full suite produced
2917 valid samples from 441.728 to 634390.356 ms; gaps were 156.077 to
643.696 ms (mean 217.403508 ms). Maximum sampled working set and sampled OS
peak were 996,855,808 bytes; private bytes reached 1,016,262,656. The child
exited zero without abort or observer exception.

## Verification coverage and remaining work

Owning examples cover two genuine warm queries with the same source commitment,
miss/restart/clear, capacity versus length, checked overflow, jointly oversized
but individually fitting genuine replacements, proof corruption with old-entry
preservation, wrong profiles, independent head/packet/key/commitment changes and
forced same-tag substitutions. Rebuilt false private originals are rejected
under the retained authentic `C_state`. Old raw-SDK rejection cases remain.

Freshness, authorization and agreed-head checks remain independent per query;
the cache provides none of them. Live missing-proof/freshness rejection remains
unchanged. Production key custody, historical identities, typed/nullable SQL,
actual BFV formation/linkage, mutations, lock conflicts/finality, scalable
source proofs and composition security remain unresolved. The
[module contract](src/opening/state/README.md) describes the exact private API.
