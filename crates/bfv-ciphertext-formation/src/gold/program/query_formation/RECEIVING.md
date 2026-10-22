# Query receiving preparation and measured cost

Historical v1 record. The structured-W v2 relation is recorded in
[the range projection](PROJECTION.md); current v3 checks are in the
[public preprocessing record](PUBLIC-PREPROCESSING.md).

The fixed Query relation, full public preprocessing and all literal profile/
ordered-symbolic/full-PP pins are unchanged. The new `gold::query::Verifier`
independently derives public receiving preparation for ONE captured complete
Expected before evidence arrives. Construction retains only that expectation,
its immutable AIR, locally derived resource/security assessment and CommonData.
Producer-only PP storage and setup configurations/RNGs are dropped. No caller
can import CommonData, replace the expectation or supply an accepting verdict.
Every verify binds the original frame, bounds and canonically decodes it, then
runs the actual native verifier. The original cold path keeps decode-before-PP
rejection. No secrecy, soundness, resource gate, timeout or SQL guard is relaxed.

## Baseline decomposition

The source-pinned r180 seven-case run used the existing test-only native phase
instrumentation without changing the cryptographic code. In its honest case:

| Phase | Milliseconds |
| --- | ---: |
| Producer public PP setup | 367.212 |
| Private complete trace | 8.068 |
| Native proof construction | 843.251 |
| Canonical encode | 3.299 |
| Complete producer entry | 1245.059 |
| Receiver public PP setup | 437.314 |
| Successful native verification | 93.891 |
| Complete cold receiver entry | 562.083 |

The ~3ms native samples belonged to early rejection of forged OOD arguments,
not successful verification. Metadata prescreen, decoding, configuration and
object lifetime costs explain additional time outside named phase scopes.
The complete proof is3353589 bytes; these are conditional Formation timings,
without Word, Source admission, FHE product, network, freshness or SQL.

## Closed prepared receiver and failure model

All7 original owning cases passed after the change (r181,8.59s harness time).
The existing repaired canonical OOD, changed original statement/header, global
mask lookup, repaired lookup terminal and genuine nonzero high-W proof examples
remain. The prepared receiver additionally rejects those false native arguments,
rejects a foreign repaired binding, and still verifies an honest frame after a
prior successful and failed call. No previously accepted verdict is cached.

The honest r181 cold producer/receiver measured1389.528/545.554ms. Independently
constructing a prepared receiver cost512.698ms, followed by105.298ms successful
receiving,617.996ms together. Preparation has not disappeared: it belongs in
EVERY new query's latency. This API permits overlap; these sparse observations
are not a claimed speedup or a latency distribution. The7-case image is6373376
bytes, SHA256
`E5D33C81F93768C00620542BCE74356D7A829F0F037B9C856FC7794619B1714A`.
The process lived8606.3096ms, used15.484375 CPU-seconds and reached516104192
OS peak working-set bytes and506769408 sampled private bytes across422 samples.

## Complete local read pipeline

The normal [Word read composition](../../../../../registry200-proof/src/registry_progress/word/read/README.md)
adds a closed `read::Verifier` tied by immutable borrow to ONE full read Expected.
It still compares the complete retained DATA theorem and freshly verifies Word,
Query and the actual product certificate. The owning case additionally rejects
a genuine Query frame from the prior different request. Original native failures,
full Source/C_state/Cw/Cs/request retention failures and all missing frames remain.

The sequential r182 new-query control included686.363ms receiving preparation,
210.736ms prepared receiving and2928.118ms from original query preparation through
protected client completion. No preparation cost was excluded. Its full owning
case passed in28.92s. The image is12193280 bytes, SHA256
`0AD30E254E90D35552815BE099779B3261B26A1B21811C9C355B94DBBFBF919B`.
The process lived28941.2608ms, used40.640625 CPU-seconds and reached567889920
OS peak working-set bytes and568483840 sampled private bytes across1418 samples.

The final r184 owning case starts a public receiving thread BEFORE producing
Word/Query proofs. That thread independently constructs its own normal verifier,
then receives only public proof bytes through a bounded channel and performs the
actual verification. Owner and private source/Word/Query inputs stay on the
originating thread. This is a local component pipeline using one shared Rayon2
pool, one owner caller and one additional receiving thread, not peer transport,
a live fallback or a full network SQL benchmark.

| Phase | Milliseconds |
| --- | ---: |
| Protected owner preparation | 4.014 |
| Actual FHE product and certificate | 46.761 |
| Public receiving preparation, OVERLAPPING production | 811.023 |
| Word proof, sharing the CPU pool | 938.512 |
| Query proof | 1504.186 |
| Prepared actual Word/Query/product receiving | 183.439 |
| Protected client completion | 1.040 |
| Entire local new-query interval, including setup | 2679.455 |

The three query frames total8032458 bytes. Shared CPU contention increased Word
production time; summing overlapping phase durations is incorrect. This does
not demonstrate an improvement over the earlier r1722458.043ms observation or
prove a causal gain over the sparse sequential control. It demonstrates actual
preparation/production overlap and the unchanged successful receiving boundary.
The complete-query <=500ms goal remains unmet. Substantial proof-construction
cost, actual network transfer, fresh weighted agreement and durable SQL/locking
completion remain; preparing the receiver early alone cannot satisfy that goal.

The final owning case passed in27.45s. Its image is12307968 bytes, SHA256
`327BF29F1F15C2B563F06B19DDBA383D1D1B2604670F3864C272AF1D6CC9E24B`.
The process lived27474.3313ms, used38.328125 CPU-seconds and reached569008128
OS peak working-set bytes and563105792 sampled private bytes across1346 samples.
All recorded observations used the pinned Rust1.99 MSVC/native/release/locked/
offline environment, one harness thread, held process/image identity and unchanged
120s/1792MiB whole-process research fuses. Each terminated with exit0, no faults,
no remaining direct child and no cleanup action. No other build/test was
intentionally run during a capture. These are test processes, not complete peers.

Strict release/all-target Clippy passed for both affected libraries. All6 Gold
and8 Word compile-fail contracts passed. The dependency-free requirements mirror
guard passed. Actual code pins were compared with the successful source captures;
new documentation is written afterwards. No generated proof/key/output is committed.
