# Selected-gadget PIR scratch: exact, no measured qualifying gain

Measured 2026-10-15: allocating only the selected fresh gadget buffers preserves
all checked native expansion buffers and serialized PIR responses. It fails the
predeclared performance gate. SelectedCombined total server time is1699.4336ms
versus1707.5023ms for frozen PairedCombined, ratio0.99527456 (about0.47% difference),
above the required0.95. This run establishes no useful latency improvement.

Accordingly, the full32-query matrix,11 runtime rejection controls and owner
replacement/UPDATE controls were NOT run for this candidate. No whole-query or
new FHE aggregate timing is claimed. The earlier
[paired expansion](experiment-private-pir-expansion.md) remains the best measured
variant; its full-query results are separate evidence. This
[new isolated package](../experiments/private-pir-scratch/README.md) retains exact
copies of that931FD2... baseline and the F9B343... trial scheduler.

## Bounded change and exactness

Pinned primary source is SDK
[coefficient_expansion](https://github.com/blyssprivacy/sdk/blob/fdb7206517c249603b0c91b65f1f29f95272107c/lib/spiral-rs/src/server.rs#L19).
The baseline action allocates left8 and right56 raw/NTT pairs before selecting
one. The derivative chooses the identical key/dimension branch first, then
allocates only that fresh zero-initialized pair. It reuses no buffer and makes no
uninitialized-memory assumption. Native ring primitives, local index/key choice,
stop conditions, sequential round barriers, old-before-mutation copy, paired
Rayon join and four-trial scheduling remain unchanged.

At N2048/CRT2, omitted unused right payload is2,752,512B per left action, and
omitted unused left payload393,216B per right action. These are source allocation
counts; they are not actual peak-memory or execution-time savings. This finite
measurement does not establish why the allocation change has little observed effect.
SDK provenance, Copyright2023Blyss and full MIT license are retained.

A separate public512-page fixture has64B authenticated payload per page and the
same512x8192B native PIR parameters. For each position0/1/2/63/64/127/128/255/256/
488/511, two fresh serialized ciphertext requests are used. Native, frozen-paired
and selected expansion outputs match every reoriented selector u64 and every
folding matrix dimension/u64. All four schedule responses match exactly, and
owner native recovery, trusted-head Merkle verification, AEAD decryption and
complete8192B record oracle pass. Four additional real million-row controls
(index0/488 and data0/488) pass the same checks. Slot511 belongs to the separate
public fixture, not the489-page million-row data or493-page index.

Schedules: Official uses native serial trials; PairedCombined is frozen931FD2...
with parallel trials; SelectedExpansion uses chosen scratch with serial trials;
SelectedCombined uses chosen scratch with parallel trials. The isolated comparison
is PairedCombined versus SelectedCombined. Fresh0 uses forward order, Fresh1
reverses it. These are server-only times, excluding direct-buffer comparison,
owner recovery/authentication and oracle work. Every one of88 times is retained:
| Slot | Fresh | Official ms | PairedCombined ms | SelectedExpansion ms | SelectedCombined ms |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 0 | 112.0663 | 84.9646 | 89.7768 | 81.7992 |
| 0 | 1 | 118.0411 | 75.5881 | 93.9613 | 76.1845 |
| 1 | 0 | 116.8572 | 79.6627 | 90.1299 | 79.1626 |
| 1 | 1 | 111.3924 | 79.9590 | 104.8618 | 79.0142 |
| 2 | 0 | 116.5764 | 78.3982 | 92.9924 | 81.3556 |
| 2 | 1 | 116.7732 | 77.4602 | 92.7019 | 80.9337 |
| 63 | 0 | 119.8502 | 73.1344 | 97.2938 | 76.8664 |
| 63 | 1 | 109.6943 | 79.2639 | 91.1263 | 77.0233 |
| 64 | 0 | 110.9059 | 82.0486 | 90.7038 | 83.8818 |
| 64 | 1 | 112.6023 | 83.4521 | 88.9787 | 82.3117 |
| 127 | 0 | 108.9312 | 79.9102 | 91.1560 | 76.0766 |
| 127 | 1 | 111.0469 | 83.3168 | 89.2141 | 79.3517 |
| 128 | 0 | 115.3703 | 71.4932 | 97.9654 | 67.9605 |
| 128 | 1 | 114.0530 | 74.4592 | 93.2966 | 73.4785 |
| 255 | 0 | 115.5384 | 73.7020 | 92.2805 | 73.1359 |
| 255 | 1 | 108.3583 | 76.1907 | 91.9675 | 76.4363 |
| 256 | 0 | 109.1878 | 80.6420 | 87.4500 | 80.4221 |
| 256 | 1 | 106.6485 | 80.5148 | 90.7415 | 79.3444 |
| 488 | 0 | 114.0759 | 70.4448 | 94.8975 | 73.2863 |
| 488 | 1 | 116.7353 | 70.3908 | 95.4379 | 70.1302 |
| 511 | 0 | 118.6142 | 77.5869 | 93.1029 | 73.6710 |
| 511 | 1 | 109.7561 | 74.9191 | 97.1942 | 77.6071 |

The <=0.95 gate uses ALL22 paired boundary times, with no sample dropped or rerun.
All26 exactness/authentication controls pass, but run_full_matrix=false. The test
code for the full pipeline remains present and unexecuted, not claimed as tested
new whole-query behavior. Twenty-five focused tests and strict authored Clippy
pass; these include existing codec/page/count/freshness contract examples and
schedule-order examples. Four existing unmodified SDK warnings remain.

## Actual parameters, resources and scope

Spiral keeps N2048,CRT268369921/249561089,p256,q2_bits20,n2,instances1,nu1=7/nu2=2,
t_gsw8,t_conv4,t_exp_left8/t_exp_right56,Gaussian sampler width s6.4,version0,
expanded queries,512x8192B. Exact profile/extent gates remain. Neither a sampler,
key, modulus, ciphertext format nor privacy assumption is weakened. Public-only
server functions receive no owner secret. BFV roles are initialized with the
unchanged N8192/t114689/Q218,CBD(20)variance10,83D3E4... core, but no new BFV query
executes after the negative gate. Independent security/noise/active-response
validation and arithmetic verification remain open. No proof or sub500ms claim.

| Actual item | Bytes |
| --- | ---: |
| Logical million-row compact table | 3,000,000 |
| Canonical data+fixed-per-N index | 5,065,148 (1.6883827x) |
| Additional real-table Merkle hashes | 63,008 |
| PIR /BFV public serialized setup | 6,029,344 /13,395,426 |
| BFV owner secret serialized count | 8,195 |
| PIR base /derived live secret payload | 49,152 /131,072 |
| Compact key+independent heads+cached header | 32+224+2276 |
| Known canonical+public/owner payload subtotal | 24,680,869 (8.2269563x) |
| Both retained real NTT arrays (persisted0B) | 67,108,864 |
| Separate boundary fixture logical /canonical | 32,768 /57,456 |
| Boundary fixture Merkle /transient NTT | 32,736 /33,554,432 |
| Actual combined whole-run peak resident set | 387,772,416 |
| Actual combined whole-run peak private commit | 392,404,992 |

The mixed serialized/raw subtotal excludes unserialized PIR framing/sampler/CDF,
container/allocator and decoded-key/scratch overhead. Actual native combined
owner+peer peaks include live allocations and all four control schedules. They
are cumulative, not an isolated per-schedule RAM comparison. Decimal2GB gates
check current and OS-native peak resident/private counters, sampled every25ms.
The boundary cache is dropped after controls. No permanent FHE copy, portable
complete owner image, replicated-system or full-state2x claim follows.

Cold setup is1231.2006ms (BFV keygen200.6499ms, actual peer public restore206.6958ms,
real private owner-header installation116.3080ms). Boundary NTT setup is separately
105.9247ms. Native real-table cache preparation stays serial. Actual network,
disk service, consensus and arithmetic proof are not measured. No whole-query
latency is synthesized by adding these subsystem numbers.

## Reproduction and frozen evidence

Use the module README commands, the pinned SDK and current reviewed core. Unique
package and target/private-pir-scratch prevent same-name shared-artifact reuse.
No SDK/main edit, parameter reduction, global install, commit or destructive
reset occurred. All earlier frozen source/report/raw artifacts remain intact.
The negative gate is the completed bounded outcome; it is not permission to
silently remove the threshold or run a selective successful full query.

Ignored raw:
`.local/private-pir-scratch/private-pir-scratch-1000000-2-t8-20261014-234610-732.jsonl`
SHA2561D110EAF7C9781F2E19BB72357255455F09CF3BD435DC02124AF4EDBFF77CED2.
Thirty records: provenance+setup+fixture+22boundary+4real-page+gate. Executable
SHA25699B16D2D508BD9F6231F3C3774A54CC855BE63C7E3D0AB5B9D294B9C6DDE10C7.
Scratch sourceD1773B4869DBB13A90BAF3EE33857CD39D9EE5872B116EE8731DF232820D660B;
mainF3B369E2E930879FE3D972397A65FE13316CF04C20DA6F0D95BC2C6662F01F89;
controlsB14201767DD7F954FCFBF6BF63D6929904385EABD8F5D30A04185A9EF55605ED.
Raw provenance records both exact frozen baselines and every authored source.
