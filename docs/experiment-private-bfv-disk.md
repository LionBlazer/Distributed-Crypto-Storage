# Disk-backed private index → PIR → BFV

The final three-table dry run completed 288 same-table matrix queries and five
additional full operations with exact COUNT/SUM and actual index-selected ordinals.
The complete 500 ms target remains unmet: two uncached private range misses took
502.0542 and 513.691 ms. All cached-header queries, all private hits and all visible
queries stayed within 500 ms in this bounded sample. The original slower baseline
(74 overruns, maximum 899.9261 ms) is preserved. A 1,000-table run is a separate next
stage; this dry-run report contains no large-dataset result or projection.
## Measured lifecycle and boundary

`experiments/private-bfv-disk` creates three independent public synthetic tables of
1,000,000 age/u 16-amount rows, with distinct keys and data/index roots. Every supplied
ID (0, 1, 2) runs each EQ absent/1/16/256, GE 256 and closed-range256 case, both access
profiles, cached/uncached headers and visible/private retrieval, with a real miss
then a hit. One sample per table yields three observations per condition below.
The fixture oracle runs after the complete timer. EQ/GE age 255 yields the exact
all-maximum sum 16,776,960; closed range 240..241 selects all 256 (64+192) rows.

The timer starts before capacity-one eviction/admission and held-handle file I/O.
It includes exact read/EOF checks, full snapshot decoding and Merkle reconstruction
against independently trusted complete heads, actual proof-record/NTT construction
on private misses, complete encrypted posting selection, real selected-page
retrieval/authentication, fresh BFV encryption, serialization, public-only peer
predicate/COUNT/SUM, response decoding and owner decryption. The selected ordinals
come from authenticated encrypted postings through the real retrieval callback.
No unloaded snapshot/native cache or precomputed answer is retained. Query nonces
are generated immediately before the timer; freshness-payload serialization is
inside it. Stage timers nest/overlap and must not be added to claim whole latency.

The owner is online and sees selected plaintext before fresh BFV encryption. The
BFV peer receives public setup, encrypted request and public query/head context;
it does not receive a compact ciphertext, nonce, ordinal, page or secret key.
The arithmetic result is explicitly `UnverifiedAggregate`; authenticated inputs
and bound context provide no proof of the returned computation.

## Final complete dry3 measurements

The exact published combined expansion/trial scheduler plus memory-only admission
ran the same 288 cells, three same-table upgrade controls, compact replacement/fresh
miss and restored recovery miss: 293 real BFV operations, nine before-BFV rejections.
28 focused release tests and strict authored Clippy pass. The additional admission
contract checks decimal cap, 80 MiB reserve, both native peaks and arithmetic overflow.
No cryptographic parameter or query work was weakened. Independent read-only review
found no actionable file/cache/admission defect in the scoped boundary.

Milliseconds below are min/median/max, n=3 tables per cell. A miss includes actual
eviction, file reads, full image reconstruction and native cache preparation.

| Case | Profile | Header | Visible miss | Visible hit | Private miss | Private hit |
|---|---|---|---:|---:|---:|---:|
| eq0 | AddressOnly | Cached | 93.0/95.2/99.4 | 87.2/92.8/99.3 | 131.6/135.0/140.0 | 88.9/92.3/92.5 |
| eq0 | AddressOnly | Uncached | 89.9/94.1/97.1 | 87.5/91.5/94.3 | 217.7/221.7/225.8 | 170.2/170.6/170.8 |
| eq0 | Fixed256 | Cached | 93.7/98.9/103.8 | 91.6/93.2/101.6 | 288.5/289.2/298.0 | 240.3/240.6/243.8 |
| eq0 | Fixed256 | Uncached | 97.2/100.3/100.4 | 88.7/90.2/96.0 | 361.4/367.0/372.4 | 318.5/322.5/325.5 |
| eq1 | AddressOnly | Cached | 97.6/98.0/102.8 | 89.5/93.3/94.8 | 291.8/296.8/301.0 | 244.5/244.7/257.9 |
| eq1 | AddressOnly | Uncached | 91.0/91.6/98.2 | 92.5/94.4/96.9 | 369.5/369.6/388.7 | 319.8/323.3/332.3 |
| eq1 | Fixed256 | Cached | 100.3/100.4/103.1 | 84.7/85.5/87.5 | 286.8/292.3/296.6 | 243.0/243.0/244.1 |
| eq1 | Fixed256 | Uncached | 100.5/101.6/105.9 | 84.0/84.9/87.0 | 368.0/371.0/373.2 | 321.1/324.6/326.3 |
| eq16 | AddressOnly | Cached | 99.5/105.4/108.9 | 90.7/90.8/91.1 | 291.5/297.3/300.4 | 238.0/239.5/247.3 |
| eq16 | AddressOnly | Uncached | 95.4/97.6/101.0 | 92.7/93.0/93.9 | 367.5/369.6/372.4 | 322.7/325.5/328.6 |
| eq16 | Fixed256 | Cached | 93.2/93.6/97.7 | 93.9/94.9/95.5 | 286.3/296.8/323.6 | 245.8/250.4/256.1 |
| eq16 | Fixed256 | Uncached | 99.6/101.0/105.5 | 90.2/94.7/98.0 | 372.7/377.2/378.5 | 324.5/324.9/327.0 |
| eq256 | AddressOnly | Cached | 92.1/92.9/96.6 | 87.8/91.4/93.1 | 288.7/290.1/296.9 | 242.5/243.9/247.9 |
| eq256 | AddressOnly | Uncached | 99.1/99.1/104.3 | 89.5/92.8/95.5 | 370.7/372.2/376.4 | 319.6/322.6/327.3 |
| eq256 | Fixed256 | Cached | 96.1/100.2/101.9 | 90.7/92.1/96.0 | 287.2/291.8/294.8 | 247.3/248.2/251.8 |
| eq256 | Fixed256 | Uncached | 96.4/97.9/100.6 | 87.2/88.7/94.8 | 360.2/367.0/371.3 | 318.6/325.6/368.7 |
| ge256 | AddressOnly | Cached | 132.2/133.8/134.3 | 123.6/124.3/125.7 | 326.0/328.3/332.6 | 279.4/281.5/285.1 |
| ge256 | AddressOnly | Uncached | 131.0/133.9/137.0 | 119.7/123.3/129.8 | 391.8/411.9/414.1 | 354.0/360.8/364.7 |
| ge256 | Fixed256 | Cached | 132.1/140.7/142.1 | 123.8/125.8/131.0 | 324.0/325.6/338.8 | 284.7/284.9/286.8 |
| ge256 | Fixed256 | Uncached | 138.9/140.4/142.3 | 123.1/125.6/126.2 | 408.1/411.9/414.0 | 357.3/360.5/363.4 |
| range256 | AddressOnly | Cached | 226.2/237.6/253.6 | 218.7/224.8/239.7 | 405.9/417.1/434.8 | 374.4/374.7/378.8 |
| range256 | AddressOnly | Uncached | 218.7/226.1/228.9 | 211.2/219.6/233.1 | 492.7/499.2/502.1 | 448.0/451.9/452.0 |
| range256 | Fixed256 | Cached | 225.4/231.3/236.9 | 224.4/229.7/230.0 | 409.8/431.5/436.9 | 379.1/381.0/381.5 |
| range256 | Fixed256 | Uncached | 220.2/225.6/226.6 | 211.6/224.1/225.0 | 488.2/497.4/513.7 | 452.7/459.2/464.9 |

Every overrun is retained:

| Case / profile / header / access / table | Whole ms | Load ms | Admission ms | Native prepare ms |
|---|---:|---:|---:|---:|
| range256 / AddressOnly / Uncached / Private / 2 |502.0542|41.7938|0.0429|35.0281|
| range256 / Fixed256 / Uncached / Private / 0 |513.6910|46.5360|0.0327|42.0352|

Cached private maxima were 436.9376 ms miss and 381.5184 ms hit; uncached maxima
513.6910 ms miss and 464.8772 ms hit. Visible maxima were 253.6399 ms miss and
239.7100 ms hit. Private-miss load stages took 34.7350–52.2573 ms, with admission
0.0218–0.0473 ms, data read 0.6079–1.3064 ms, index read 0.2928–0.7658 ms and full
snapshot authentication 2.4004–3.7927 ms. Maximum admission across all matrix calls
was 0.1657 ms. No earlier timing was subtracted to obtain these measurements.

Same-table additional controls took 96.6053 ms visible miss, 280.3158 ms private
NativeUpgrade (38.5377 ms load, including 38.3842 ms native preparation), then
251.1302 ms private hit. Shared setup plus three independent table writes/header
captures took 960.6055 ms: BFV keygen 213.8040 ms, public restore 207.3060 ms and PIR
generate/restore 449.0568 ms. These setup costs are excluded from per-query times
and reported separately. The online shared owner/public setup remains live.

All nine malformed/wrong-table/stale probes again failed before fresh BFV preparation.
The real owner compact replacement + actual file/catalog writes + invalidation +
fresh complete private miss took 295.9750 ms, including 8.9007 ms write/invalidation
and 287.0548 ms fresh miss; final restored miss 305.7017 ms. Data/index/catalog byte
lengths did not grow. This is not FHE UPDATE or crash durability.

## Complete baseline measurements

Milliseconds are min/median/max, n=3 tables per cell; each miss is followed by its
same-table hit. These are application-cache misses using real file APIs; OS file
cache was not flushed, so physical cold-disk latency is not established. Rayon 8,
capacity 1, original trial-only public scheduler, unchanged cryptographic parameters.

| Case | Profile | Header | Visible miss | Visible hit | Private miss | Private hit |
|---|---|---|---:|---:|---:|---:|
| eq0 | AddressOnly | Cached | 228.5/229.8/237.1 | 88.4/89.9/96.7 | 374.1/409.7/463.4 | 91.5/95.3/104.5 |
| eq0 | AddressOnly | Uncached | 239.2/265.4/299.9 | 94.7/95.4/96.3 | 498.9/511.7/573.3 | 188.5/189.4/192.4 |
| eq0 | Fixed256 | Cached | 228.0/228.4/251.8 | 91.1/94.0/97.4 | 585.4/620.5/635.8 | 281.6/286.4/289.9 |
| eq0 | Fixed256 | Uncached | 229.7/231.0/254.1 | 91.8/93.6/96.1 | 681.7/691.2/714.5 | 374.8/375.6/391.6 |
| eq1 | AddressOnly | Cached | 216.5/239.5/247.3 | 88.4/93.5/93.5 | 561.8/577.7/665.1 | 284.6/287.9/288.4 |
| eq1 | AddressOnly | Uncached | 216.9/229.4/261.0 | 91.6/92.1/96.0 | 671.3/715.6/739.0 | 373.5/377.9/387.5 |
| eq1 | Fixed256 | Cached | 221.1/241.3/264.4 | 90.6/96.8/98.4 | 566.1/569.1/580.3 | 275.0/279.7/281.9 |
| eq1 | Fixed256 | Uncached | 214.7/246.1/265.9 | 88.0/94.8/98.0 | 714.1/720.3/749.0 | 376.0/381.1/394.4 |
| eq16 | AddressOnly | Cached | 223.5/225.3/254.6 | 88.2/93.3/98.3 | 562.2/570.8/619.9 | 277.7/278.1/280.9 |
| eq16 | AddressOnly | Uncached | 227.8/232.2/246.4 | 91.5/95.4/96.3 | 702.9/713.7/739.9 | 371.9/377.7/379.0 |
| eq16 | Fixed256 | Cached | 219.0/225.9/244.6 | 93.6/93.8/99.9 | 550.2/591.7/653.5 | 283.9/285.4/292.4 |
| eq16 | Fixed256 | Uncached | 221.3/232.2/241.7 | 94.1/96.5/101.7 | 673.0/700.7/720.5 | 382.6/386.5/388.3 |
| eq256 | AddressOnly | Cached | 224.4/235.8/235.9 | 88.7/90.7/95.3 | 563.2/565.0/583.6 | 283.0/284.8/289.9 |
| eq256 | AddressOnly | Uncached | 226.9/229.9/252.8 | 89.6/94.9/95.6 | 644.3/670.3/722.6 | 378.1/381.3/386.1 |
| eq256 | Fixed256 | Cached | 213.5/230.7/234.6 | 86.1/92.9/100.4 | 567.1/594.3/653.0 | 278.7/279.5/283.3 |
| eq256 | Fixed256 | Uncached | 230.4/236.8/239.0 | 95.2/95.8/95.8 | 657.2/665.7/722.4 | 370.5/373.0/379.8 |
| ge256 | AddressOnly | Cached | 258.3/263.2/309.2 | 127.2/129.1/134.2 | 597.7/621.0/641.4 | 315.2/320.4/323.5 |
| ge256 | AddressOnly | Uncached | 281.5/289.2/289.3 | 127.2/129.6/130.8 | 759.4/765.0/782.3 | 417.4/418.5/419.5 |
| ge256 | Fixed256 | Cached | 265.2/280.7/285.5 | 131.6/132.8/135.2 | 618.2/668.8/671.1 | 321.4/325.6/335.7 |
| ge256 | Fixed256 | Uncached | 248.0/265.8/271.3 | 127.7/130.6/134.0 | 723.2/759.1/779.0 | 416.2/423.8/438.0 |
| range256 | AddressOnly | Cached | 352.8/361.6/361.8 | 220.0/224.3/225.8 | 728.4/770.6/800.9 | 414.9/422.5/427.6 |
| range256 | AddressOnly | Uncached | 341.4/380.9/384.9 | 220.7/228.9/229.9 | 826.5/833.8/842.2 | 506.5/508.5/511.5 |
| range256 | Fixed256 | Cached | 341.6/368.1/372.7 | 223.3/231.5/236.5 | 707.9/722.4/729.4 | 416.6/417.4/423.0 |
| range256 | Fixed256 | Uncached | 361.0/366.8/377.0 | 219.6/224.0/231.0 | 833.9/895.4/899.9 | 513.1/515.9/516.8 |

The full 288 raw cells, including all 74 threshold overruns, are retained. Additional
same-table controls measured a visible miss 223.8259 ms, real private native upgrade
437.3446 ms (36.7773 ms native preparation nested), then private hit 283.4321 ms.
Initial shared setup plus three table writes/header authentication cost 1,372.8279 ms:
BFV keygen 212.2863 ms, BFV public restore 204.6662 ms, PIR generate/restore 457.4197 ms.
Cached headers were authenticated locally during table creation; setup does not
claim a private PIR header bootstrap or prewarm any native table cache.

Nine failures (data/index truncation, same-length corruption, wrong-table data/index,
extra byte, stale data file, stale trusted catalog head, stale cached header) were
rejected before fresh BFV preparation. Failed disk loads published no partial
snapshot/cache. The owner-authorized compact replacement wrote actual data/index
images and public catalog metadata, invalidated the loaded pair and performed a
fresh full private miss:716.8597 ms overall, including 565.7092 ms fresh read.
Canonical/catalog lengths did not grow. This is not FHE UPDATE and no fsync, atomic
commit, restart or crash-durability guarantee is established.

## Diagnosed and remeasured admission overhead

Baseline admission called `resources::sample()` inside the whole timer. That helper
also enumerated every system thread. A separate direct eight-call diagnostic measured
85.7805–97.5931 ms per full sample versus 0.0018–0.0024 ms for the same
`GetProcessMemoryInfo` current/native-peak memory fields alone. This explains a
material possible source of observed load-stage overhead; new query latency is
**not** obtained by subtracting those numbers.

The final source separates `memory_sample()` for admission and keeps full thread
sampling in the monitor/outside query timing, preserves all four memory checks,
and adds explicit `admission_ms` to load stages. The complete rerun is measured above;
baseline source/binary remains archived separately. The copied SDK
retains its pre-existing lifetime/static-mut warnings; no SDK edits or secret test
hooks are enabled.

## Exact disk and process accounting (final combined run)

All expansion ratios use 9,000,000 logical row bytes (3 tables ×1,000,000 ×3).

| Item | Actual bytes |
|---|---:|
| Six canonical data+index files |15,195,444|
| Shared BFV public wire |13,395,426|
| Shared PIR original public wire |6,029,344|
| Public catalog |2,085|
| All 9 actual dataset files |34,622,299|
| Shared BFV secret serialized count |8,195|
| Shared trusted PIR owner image |336|
| Three per-table AEAD keys |96|
| Catalog owner keys + duplicate trusted heads + header payload |7,596|
| Catalog structs (excludes dynamic payload/capacity) |7,920|
| Retained expanded PIR public polynomial payload |23,855,104|
| One loaded canonical snapshot pair |5,065,148|
| One loaded Merkle-hash payload |63,008|
| One native NTT overlay pair |67,108,864|
| Transient fixed proof-record inputs during pair construction |8,388,608|
| Persisted NTT/retained raw record buffers/unloaded snapshots/caches |0|
| Final process RSS / private commit |327,688,192 /332,587,008|
| Whole-process native peak RSS / commit |355,000,320 /361,426,944|
| All dataset files + final RSS |362,310,491 (40.256721x)|
| All dataset files + native peak commit |396,049,243 (44.005471x)|

Canonical alone is 1.688382667x. Files plus known serialized secret counts are
34,630,926 B; this is a payload subtotal, not a full-state 2x result. All expanded
representations, scratch, owners and public evaluators are included in native process
memory, even where not individually partitioned. BFV native secret/evaluator/context
allocations are not separately enumerated; the BFV secret count is not a portable
restart image. The shared PIR live client's four secret/identity polynomial payloads
are source-derived 180,224 B (49,152 B base secret plus 131,072 B identity-extended matrices); they are included in process
memory, not exported. Allocator/Vec bookkeeping and OS file cache outside the process
are not separately partitioned. The latter is not included in process RSS accounting.

Admission uses decimal 2,000,000,000 B, current and native-peak RSS/commit, and 80 MiB
reserve before table/cache additions. Both runs had maximum sampled thread count 13;
final stable process count 10. The loaded-table count never exceeded 1. Eviction drops
the old native pair before reading the new files. Cache identity is checked against
both trusted complete heads; updates invalidate it. No larger-capacity or restart
behavior is claimed.

## Wire and leakage

Both profiles use fixed Rows256 BFV geometry. Equal and GE requests are 670,134 B;
range requests 893,423 B; outputs 446,764 B. Real EQ/GE/range kernels respectively use
5/8/15 ciphertext products and 11/14/20 rotations. No predicate work is skipped for
empty/dummy rows. A private fetch uses 16,449 request +20,480 response bytes; visible
fetch requests 41 B, index responses 4,448 B and data responses 6,496 B.

For nonempty AddressOnly and every Fixed256 query, cached-header private total wire
is 1,190,756 B for EQ/GE or 1,414,045 B for range,3 sequential RPCs (two fetches +BFV).
Uncached adds one private fetch:1,227,685 /1,450,974 B and 4 RPCs. Cached visible totals
are 1,127,924 /1,351,213 B; uncached 1,132,413 /1,355,702 B. Shared public setup wire
19,424,770 B is counted once separately. No network transport/latency is measured.

AddressOnly skips posting/data requests for absence, exposing absent vs nonempty
shape; positive 1/16/256 counts have identical fixed BFV and one-page fetch wire here.
Fixed256 performs real dummy fetches and freshly encrypted zero low/high/count
weights for inactive rows, so structural lengths/RPC counts are asserted equal across
0/1/16/256 for each public predicate kind. This is not a constant-time or formal
cardinality-hiding proof. Visible access exposes page addresses and repetitions;
private PIR hides the page within the selected table. Table/root identity, current
heads, public predicate kind, load/update events and allocation/setup traffic remain
visible. Active corrupt-response/feedback composition is not established; neither
PIR nor authenticated retrieval proves SQL computation. Complete selection is limited
to 256 rows and one posting/data page; crossing budgets are rejected, never truncated.

## Reproduction and provenance

Run from the isolated package with a unique target:

```powershell
./experiments/private-bfv-disk/run.ps1 -Tables 3 -Samples 1 -TableIds '0,1,2' `
  -Threads 8 -MaxCanonicalBytes 67108864 -ServerSchedule combined -Offline `
  -Cargo E:/Users/white/.cargo/bin/cargo.exe `
  -CargoHome E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home `
  -TargetDirectory E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/target/private-bfv-disk
```

In this research worktree, explicit dependency directories pointed to current main
for BFV core, PIR owner/cache and compact-store. The runner copies and hashes those
sources into a unique generated package, rewrites only local path/workspace manifest
fields, verifies the clean SDK pin, and uses a locked offline dedicated target.
`-PrepareOnly` does no compilation/keygen/data writes. Dataset directories are new,
file writes use CreateNew initially, and count×6 MiB is checked against the explicit
write budget before generation. Current reproduction uses Combined plus memory-only admission; historical baseline reproduction uses its retained executable/source archive. Final raw evidence:

- WT `.local/private-bfv-disk/disk-3-s1-t8-parallel-20261014-233706-399.jsonl`,
  SHA256 `3D56DF98469C6385AD2B60DF56E1C87EDC277823CE5D5D38CC45E05851540C6F`.
- Baseline executable SHA256 `CBE09254E5C8183D8EC0A6AB9D762A7E3B7611C755C24ADB2032380815CE3B1D`;
  exact source/exe manifest in `.local/private-bfv-disk/baseline-trials-only`.
- Sampler diagnostic `.local/private-bfv-disk/counter-cost.jsonl`, SHA256
  `28256ED2321754815C2422A98C362D32C7BDA50AF90F11A48CD1E7C35E97E5A7`.
- Final raw `.local/private-bfv-disk/disk-3-s1-t8-combined-20261014-234723-935.jsonl`,
  SHA256 `B94F17A2B8A77FEDF4A4D773EB5C1950BDE6FD47CABBCCFF63F8548E2288F37E`.
- Final executable SHA256
  `F1A7695BB6AEFB30A0268B173ABAD7C26B45ACCA2BA4D9DDCB3BA660743308CA`.

BFV source `83D3E4E23803F96544617E88AA6EF2B17DFEC274DCB962C168BDAFD7DBA82C7A`,
owner-state `32CF886EEAD6D14CA887E13B8A595FFAA5049E3ACB17844919A5B31F4AE25E3B`,
cache-core `4DA15C08050DD6F55FA2B0811088513DF8A31540848A91B56F4E9B059A5E6DCE`,
exact copied server scheduler `F9B343135A377CF6559415C7C62584A66B823E007DA98DBF43B1EC88C861B3FC`.
The frozen baseline owning sources are main`95927213…`, disk`E96ACBC0…`,
resources`F784CCED…`; its lock is`D8D7F2D63797711E238BB2475AAE5F6CF8B4144D4D58CD1B6F34441C2ECFFA12`.

Final owning source hashes are main
`1FD55CD65E53D90CAC741C1D8E6B8CD5994F3D03A18445EF924FD4321CBDA1E6`, disk
`51DF6045F3E5A6CE0E890FE2F8BE4180C6C008FBDDA9E63EC67789A36EE709B0`, resources
`A08890AD588524374C9D1B282A00038F9750DFA63F8FCB78AC466FCBF7A934D7`, native adapter
`A188F526EAE01FA3BB236DD509220BCEDA13BA103EF5283D4EA7655ED2CDC4C4`.
The exact copied combined scheduler is
`931FD2B0775E10D83872F8E35D04D9C8CBBC055D373BBA221B6C097F01E78F98`, published
in main `d8575e37ce2ecdf66876722970a244df92256687`; the trial-only module remains exact.
Primary implementation is pinned [Blyss SDK](https://github.com/blyssprivacy/sdk/tree/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs)
and the repository's current compact-store/BFV/cache/owner modules. Spiral parameters
remain N2048, CRT268369921/249561089, width 6.4, n 2, p 256, nu 1/nu 2=7/2,512×8192 B.
BFV remains N8192,t 114689,Q bits 43/43/44/44/44,CBD(20)variance 10, level 0/native/
unfused/additive; upstream about 128 security and independent security/failure analysis
remain unresolved. Owner keys and envelopes are never written to peer files/logs.
