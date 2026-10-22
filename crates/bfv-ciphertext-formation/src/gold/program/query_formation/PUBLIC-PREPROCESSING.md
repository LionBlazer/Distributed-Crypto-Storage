# Exact public selector sharing

The v3 `DCSGQF03` Query backend stores eight public selector columns in place of
171 duplicate columns. It retains all 57 logical slots, 81,920 Formation gates,
4096 coefficients, all range/hash/Stmt96 equations and the original signed lookup
counts. MAIN remains 416 columns. Public PP decreases from 708 to 545 columns.

## Fixed geometry and relation

For physical row `r` and logical slot `s`, the gate index is `57*r+s`. ACTIVE is
one below 81920, POINTWISE on `[24576,32768)`, and FANOUT on `[22528,24576)`.
Across all 2048 rows these give exactly eight distinct full column vectors:

| Selector | Logical slots sharing one column | Rows with value one |
| --- | --- | --- |
| ACTIVE | 0â€“10 | 0â€“1437 |
| ACTIVE | 11â€“56 | 0â€“1436 |
| POINTWISE | 0â€“8 | 432â€“574 |
| POINTWISE | 9â€“49 | 431â€“574 |
| POINTWISE | 50â€“56 | 431â€“573 |
| FANOUT | 0â€“8 | 396â€“431 |
| FANOUT | 9â€“12 | 396â€“430 |
| FANOUT | 13â€“56 | 395â€“430 |

The AIR uses direct column aliases, preserving the degree of every expression.
The planner and inventory still visit every logical slot and port. The first 509
PP columns retain their literal positions; the eight selectors occupy 509â€“516;
the old trailing columns 680â€“707 move to 517â€“544. No secret witness field,
coefficient, input or required constraint is removed.

This is equality of deterministic public trace data and of the corresponding
unmasked selector polynomials. It does not claim that old and new masked PCS
polynomials, commitments, transcript challenges or proofs are identical. Each
request constructs its own complete public setup through the original fixed
native factory. No setup is reused across different expectations. Private MAIN,
AUX and quotient commitments retain their original unpredictable randomness.

The raw public trace saves 333,824 Gold fields, or 2,670,592 bytes. Fewer public
polynomials also reduce LDE, commitment and opening work. The 23.02% PP reduction
is not a claim of that much whole-query acceleration or a production RAM bound.

## Independent preservation checks

The test-only expansion restores every former 708-column row and compares each
cell with a separate adapter over the original 32-gate public planner. It retains
both original full-matrix literals: v1 prefix `d37135â€¦1932` and v2 prefix
`c37659â€¦4406`. The separate full old range-constraint extension and its damaged
slack-bit rejection remain in place. The native assessor must independently
derive constraints, degree, original/packed lookups, AUX/chunks, openings and
security/resource bounds for the smaller public layout.

The v3 mathematical and frame profiles bind PP545 and the exact selector mapping.
Both old `DCSGQF01` and `DCSGQF02` frames are rejected, with no compatibility
decoder or supplied setup. The original 4MiB frame/decoded-slot limits, native
verification, FRI/hiding parameters and upper SQL/finality admission guards remain.
The complete 500ms SQL target requires reproducible end-to-end measurement.

## Executed validation, 2026-10-22

Base: `53ec609b86c3463297f32e001c76404e5753b066`. Before any new private proof,
capture 477 passed the independent every-cell expansion and both old full-PP
literals; capture 479 passed the new strict symbolic/matrix/profile captures.
The native assessor derived 1098 BASE/86 EXT constraints, degree 4, 248 original/
83 packed lookups, AUX 420, eight chunks and 2327 openings. Individual UDR/LDR
floors remain 128; the original LogUp term remains 297.045803689613 bits. Checked
workspace decreased from 657,719,296 to 606,978,048 bytes. These are component
assessments, not composed cryptographic or whole-process guarantees.

The new ordered symbolic tuple is still 564,835 bytes, SHA256
`b7461b6ec1579cca0c3e42d2f64cfcf0446e1854be4ee309c6237ef609629149`.
The new full-PP digest is
`8ced166061c407c6b5c0ee9d53d94085604087ee626c772592117482ad9a53d3`.
Mathematical/profile and native-frame profile digest hashes are respectively
`eee4eafdabf0b273da352046d993bc3fc16f426a0a935309bd1bb505e4470f81` and
`c456e707462ac315c45d4849f97034c4ac6538b19765329e9a014ddd85cfb038`.
These new captures supplement the preserved old expanded-matrix literals.

All 35 Gold cases passed, including actual native Query production/receiving,
false high-W and repaired lookup/terminal/header/argument rejection, old-frame
rejection, and all original Pair/DATA symbolic and full-PP pins. The separate
upper 16 mask/Formation cases, three real owner-journal cases and five normal
public SQL-producer cases also passed. The owner completes only after actual
public receiving; the complete decrypted ring matches its independent oracle.
No private input conversion or owner-local verdict replaces the public proofs.

One standalone Query proof was 2,945,213 bytes; producer/cold receiving measured
1370.491/441.165ms. Independent receiver preparation plus actual verification
took 358.691+86.192ms. The normal public producer used a 2,948,669-byte Query frame
and measured:

| Local phase from the prepared original request | ms |
| --- | ---: |
| Actual Word and Query proof production | 1664.083 |
| SDK FHE product and certificate | 30.579 |
| Complete public receiving | 775.371 |
| Client decryption | 0.979 |
| Complete observed interval including bookkeeping | 2471.635 |

Its full unverified Predicate packet was 26,069,016 bytes; encode/parse/full
six-proof receiving/decryption took 2237.824ms. In the actual owner-journal
receiver, cold six-proof receiving took 2109.867ms, exact-candidate rechecking
680.945ms, and receiving a fresh encryption against retained DATA 783.885ms.
These intervals exclude network SQL, current-head agreement and locking. Sparse
latency observations are mixed across paths and establish no latency ratio or
distribution. The smaller public matrix/proof and observed memory are the
confirmed benefit; the full 500ms SQL goal remains unmet.

The source/image-pinned release/MSVC Rust 1.99.0 runs used native CPU, Cargo jobs 2,
Rayon budget 2, one harness thread, unchanged 120s/1792MiB fuses and 20ms samples.
Each run used held image/creation identity and exact source/image hashes; no
build or other heavy test overlapped a capture. Every process exited 0 without
faults, forced cleanup or surviving task children.

| Capture | Owning cases | Lifetime ms | OS peak working set bytes |
| --- | ---: | ---: | ---: |
| 480, Gold | 35 | 29917.7100 | 1351991296 |
| 484, Joint Word | 3 | 27248.5836 | 661512192 |
| 485, public SQL producer | 5 | 31846.7247 | 599785472 |
| 486, mask/Formation | 16 | 6481.1337 | 511840256 |

The largest Gold peak includes the unchanged original Pair. These are test-process
observations, not complete production-peer RAM guarantees. The corresponding
generated receipts are not committed and live under
`.local/word-cmd-native-rREV-PACKAGE-observe-tests/result.json`:

| Capture | Receipt SHA256 |
| --- | --- |
| 477 | `C2BB6B28ED7C5B835EA738CAB526EC680D21510EEE650F0046375E8E8B66E76C` |
| 479 | `B42C146DCE8F0DAE8479EAE1C63E015C4C7CDFF12CFBDC2B514F91677DEF8E62` |
| 480 | `0A38E8B2BCA32214CD33B1815B7A66AD52E3705863DA12EFCFB79124FB150A76` |
| 484 | `1727E3767FFD5FA6AB0D918A69D4433A935B3F5BA54F9F99358EE9886BFFEEA3` |
| 485 | `50B6E1A6ABECE8D3F3741266CD3D8737A96885C8CE349789202488C82CFC7497` |
| 486 | `250BBC1F3459B664F648C2468E97A0E5B59EA300CB447A0826975E000136856D` |

Strict all-target Clippy passed for Formation, registry200-proof, Joint and the
word-query client. All 23 affected external compile-fail examples and the
dependency-free requirements mirror test passed. Independent read-only review
found no relation, count, profile or boundary bypass. Formatting and local links
were checked; no executable source changed after the successful captures.

```powershell
$env:RUSTFLAGS = '-C target-cpu=native'
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
cargo test --release --offline --locked -p bfv-ciphertext-formation --lib gold:: -- --test-threads=1
cargo test --release --offline --locked -p registry200-proof --features owner-read --lib registry_progress::word_inventory::query_mask_inventory:: -- --test-threads=1
cargo test --release --offline --locked -p registry200-joint --lib word::tests:: -- --test-threads=1
cargo test --release --offline --locked -p storage-client --features word-query --lib word_query:: -- --test-threads=1
```

All original native,
proof/resource/security and fresh-head/finality/SQL guards remain mandatory.
No transport, accepted consensus, WAL or recovery behavior changed; the expensive
four-peer recovery gate was not repeated. Assessed composition and actual network
SQL/locking admission still require completion.
