# Static aggregate source comparison

On 2026-10-16, the full accepted COUNT/SUM operation used the same public
million-row fixture on two pinned sources. Before is
`32fd038b861c75ffce0f4fbba967c44d596086cb`; after is
`443027daebb663f7bfe80a730e76932ce6f8ee37`, which includes static aggregate
preparation from `16ac62def76f3965d24cb7bb4a7ac6996a5dbdc1` and the subsequent
core static UPDATE staging integration. That UPDATE API is not used by this read
scenario. The randomized object-profile upgrade is not included in either source.

The measured change replaces the aggregate's full Fetch with the existing fixed
ReadImage: complete data plus the public padded posting prefix, omitting the
encrypted RowId tail. Complete authenticated selection and the 2560-match bound
remain. Both versions execute a genuine full-residue BFV convolution proof and
check confirmed freshness. The new version retains encrypted partial results
until all proofs and final freshness pass, then rechecks the full logical TableId
and both heads before decryption. There is no plaintext aggregate answer path.

## Complete accepted operations

One independent peer holds 1,000,000 rows with 256 rows per data page. Ordinals
0 through 997439 have age 7; the final 2560 have age 42. Every amount is
`ordinal % 65536`. The public fixture derives expected values only for assertions
after the real accepted SQL operation. No owner fixture supplies a peer answer.

Three fresh scenarios per version ran in alternating before/after order. Each
scenario creates new keys, encrypted images, peer and confirmed journal, then
executes the three queries in the order below. Startup, key generation and table
creation are outside the SQL timer; preparation, actual TLS I/O, physical custody
audit, real FHE/proof generation, local proof verification, final freshness and
checked result completion are inside it. No build, other proof test, PID/RPC hook
or memory monitor ran during this timing window. Unrelated host background load
was not controlled. All six scenarios and all count/sum/version assertions passed.

| SQL | Before min / median / max ms | After min / median / max ms |
| --- | ---: | ---: |
| `SELECT COUNT(*), SUM(amount) FROM records WHERE age = 42` | 464.079 / 465.165 / 470.504 | 347.732 / 359.874 / 362.899 |
| `SELECT COUNT(*) FROM records WHERE age = 18` | 465.114 / 470.022 / 474.585 | 352.496 / 354.453 / 377.868 |
| `SELECT SUM(amount) FROM records WHERE age > 255` | 470.003 / 474.324 / 478.575 | 351.099 / 376.139 / 380.782 |

The differences between variant medians are -22.6%, -24.6% and -20.7%, respectively;
these are not medians of paired percentages. All eighteen samples are retained.
The empty cases still require genuine encrypted computation. This is one CPU,
one healthy peer and one fixed schema, not a tail-latency SLA, failure bound or
general 500-ms claim. Full UPDATE, complete PostgreSQL, private SQL row locks,
public source-completeness proofs and production finality remain unfinished.
The runtime still audits the complete physical object, including the omitted tail;
reduced transfer does not establish sparse disk I/O or a memory saving.

## Reproducibility and artifacts

The host is Windows x64 on the same AMD Ryzen 9 9950X3D2 used by the preceding
[shared-packet comparison](SHARED-PACKETS-MEASUREMENTS.md). Rust 1.99.0/MSVC release
used `-C target-cpu=native` and build jobs 2. Each measured owner and peer used
eight Rayon threads; peer logs and owner metadata report AVX-512. Both use the
unchanged N8192/Q218 proof profile v3 covering all 81,920 residues, FRI blowup 8,
192 queries, extension degree 5 and the 128-bit floor. The profile ID in every log
is `D3F9B6A762AE7E99C0C19393CAC12C63BFBF6A115036F83920E0B3BA0C07E343`.
The job application domain is v3 in both sources. Actual application commitments
vary with each fresh public setup and are recorded separately; they are not
asserted identical across freshly generated databases. The fixture's easy work
target and one descendant confirmation are not a production attack budget.

Raw logs, all 18 timers, generated measurement harnesses and binary copies remain
in ignored `.local/static-aggregate-runs/20261016-081214-810/`. Each temporary
harness appends the same measurement function to its source's unchanged
`proved_sql.rs`, allowing that scenario to run on the before source too. The
appended fixture SHA256 is
`3EADBC25F72B01C117E3741324F96C74B37474D6BE4D0891FCC5EA036CC8ADBA`.
Full harness SHA256: before
`A2A1F41A46A0CCCA6F30591D5A4C51533692CB39669C6D36DCCD73551256686B`, after
`58D559152A6283201AEFF501EDAD6FBCD2F881AE0C8465D12939BD5395634311`.
Those temporary wrappers are generated outputs, not product source changes.
The reusable authored [fixture](aggregate_fixture.rs) is now included as an ignored
measurement module by the real daemon's SQL test; its timed body is the same.

| Artifact | Before SHA256 | After SHA256 |
| --- | --- | --- |
| Native owner `aggregate_measurement-f583cfb702e28b94.exe` | `65355DE2082DB19D0A109C6674CF416FADFCAE8CD5E4AA738CCF961EC413BC75` | `679681EA154834F9883813925AC48D069F056248FE447C3E6B07324729A1BE92` |
| Native `dcs-peer.exe` | `BF57BB57F34DEA6B0A27293CE1F12247D01A77CF28632C8CF2AE783DFC16D276` | `8A9B6C49B663DDDCCC5DFE2702DD4B8D97C7D6FB3F6B2C6BED51C2641E4FCFA6` |

Both sets use AVX2 kernel SHA256
`EFC34097320282CCAE4C5D2D4608F5656C9FDB54E92C9B702ADF8920FADA1B5C`
and AVX-512 kernel SHA256
`6AD4FDEC0E021ECA57AE7EC08F51D06E74519BFF260E8067551DD9CEA7E56975`.
Hashes of all eight archived artifacts and unchanged originals were checked.
Before's owner launches the baked peer path under
`.local/target-static-aggregate-before/release/`; after uses
`.local/target-static-aggregate/release/`. A copied owner alone does not select
its matching archived peer. Preserve these paths or explicitly restore the
matching archived peer and kernels before rerunning an archived owner.

For a new source measurement, build outside the timing window, using an isolated
target and trusted kernels beside its peer:

```powershell
$env:RUSTFLAGS = '-C target-cpu=native'
cargo test --release --locked -p dcs-peer --test proved_sql --no-run
$env:RAYON_NUM_THREADS = '8'
$env:DCS_TEST_PEER_THREADS = '8'
# Run the actual compiled owner path printed by Cargo, three fresh times:
<compiled-owner.exe> --exact aggregate_measurement::measure_sparse_million_row_count_sum --ignored --nocapture --test-threads=1
```

Clear optional `DCS_TEST_RPC_PROFILE`, `DCS_TEST_FIXED_PIDS` and
`DCS_TEST_TYPED_PIDS` before latency runs. Keep independent functional/proof,
failure, memory and RPC observations outside those distributions. Core static
sources passed 65 behavioral and one compile-fail test; the combined live SQL
contract passed all 32 tests, strict five-package Clippy and independent review
before measurement. The owning functional aggregate tests additionally cover
missing prefixes, over-budget rejection, TableId/head/evidence substitution,
identical source frames and cancellation at image retrieval or final freshness.
