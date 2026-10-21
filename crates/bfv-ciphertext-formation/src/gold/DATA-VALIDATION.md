# Single-DATA Formation validation

Executed locally on 2026-10-21 with Rust 1.99.0/MSVC, release optimization,
`-C target-cpu=native`, two Cargo jobs and two Rayon threads. These are local
mathematical boundaries. No network SQL result or 500 ms complete-query result
is established.

## Implemented boundary

`gold::data` proves one actual canonical N4096/Q2 ciphertext against one complete
already-scaled W4096 opening and the original SDK secret/Cs528 opening. A closed
private Pair/Data layout shares the graph, AIR, preprocessing, witness writer,
assessment, codec and native backend. There is no second ciphertext for DATA.

The upper `registry200_proof::two_lane_encoding::data_formation` first verifies
the actual immutable StateCertificate and Role3 encoding. Its producer then
consumes the SAME final witness, W and salt into the actual DATA producer. Its
receiver independently repeats State/encoding verification and cold DATA
verification before returning a private-field, move-only mathematical result.
Full literal ciphertext/request, State statement, heads/packets, key29, Cw and
DATA-specific Cs context are bound. No query-q or old Pair profile is cast.

The DATA graph has 81,920 gates and 2,560 arithmetic rows, 2,048 range rows,
514 W-hash rows and 66 Cs-hash rows. All 3,004 padding rows and inactive cells
are constrained zero. The actual native assessment reported:

| Property | Observed value |
| --- | ---: |
| Height / MAIN / PP / public values | 8192 / 512 / 272 / 32 |
| BASE / EXT constraints | 1408 / 46 |
| Native degree / committed quotient chunks | 4 / 8 |
| Original / packed lookups / AUX width | 128 / 43 / 220 |
| Batched openings | 1846 |
| Modeled workspace bytes | 1,819,017,216 |
| Individual UDR / LDR floor | 128 / 128 bits |
| LogUp analytical term | 296 bits |

These actual-AIR analytical checks precede PP and private MAIN. They are not
a lattice assessment, composed-system security statement or observed RSS.
The 32 MiB frame cap, canonical nested decode/reencode/EOF, terminal-zero check,
actual native verification and fresh OS randomness for private commitments remain.

## Owning gates

The focused runtime commands were:

```sh
cargo test --release --offline --locked -p bfv-ciphertext-formation --lib gold:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib two_lane_encoding::data_formation -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-proof --lib two_lane_encoding::formation -- --nocapture --test-threads=1
```

Actual test executables were selected from successful Cargo JSON artifacts and
run serially under held Windows process handles. Creation time, executable hash,
source hashes, terminal exit zero and absence of live children were checked.
Whole-process sampling used the unchanged 20 ms interval, 120 s wall fuse and
1792 MiB memory fuse. All observations completed without a fuse or cleanup.

| Gate | Passed | Harness time | CPU seconds | Peak private bytes | OS peak working set |
| --- | ---: | ---: | ---: | ---: | ---: |
| Final CoreGold | 14 | 12.46 s | 23.296875 | 1,345,527,808 | 1,351,000,064 |
| New State/Role3/DATA chain | 1 | 12.57 s | 18.25 | 1,370,509,312 | 1,371,611,136 |
| Existing Source/Pair/Formation/product chain | 1 | 19.58 s | 26.984375 | 1,376,620,544 | 1,372,069,888 |

Final CoreGold executable: 5,382,656 bytes, SHA256
`81320A185144F6F6EB9C0E952701D4B1B23633D55B1A90446F9AAB2BF85A7DAA`.
The upper gates used the same 9,290,752-byte executable, SHA256
`8D159B286FC9AE84B6475E30C0077A38F8411EB5004874D69F651BBAA092E4DB`.
Their recorded process lifetimes were respectively 12,485.2456, 12,600.0264 and
19,586.8592 ms; harness time is not query latency.

Coverage includes genuine SDK encryption, full bindings, repaired wrong-key Cs,
shared-E violation, changed W4095, excluded K endpoint, unused bits/ports and
padding. A genuine false-wire proof preserves local equations and final products
but reaches native `Lookup(TerminalSumNonZero)` rejection. Repairing its terminal
still fails actual cryptographic verification. Canonically repaired OOD arguments
must report exact `Verification`, rather than accepting a panic/backend error.
The upper test requires actual State OOD rejection at both producer and receiver.

Strict all-target Clippy passed for both crates. Its first lower run found two
style warnings; the bounded port comparison and negative-fixture iterator were
simplified, then all 14 CoreGold tests were rerun. The Pair golden was also made
unconditional. The upper production source was unchanged by these cleanups;
its prior full-chain checks and the final exact Pair relation golden cover the
shared boundary. Four new compile-fail examples passed, two per result type.
Requirements synchronization passed; no requirements, profiles, caps or timeouts
were relaxed. Formatting and documentation links were checked separately.

## Preserved Pair contract

Before adding Data dispatch, a metadata-only native test captured both profiles,
all ordered BASE/EXT constraints, original and packed lookups, and every field of
the full 8192-by-272 PP matrix. The same unconditional constants pass afterward.
The symbolic stream contains 573,458 bytes; the PP contains 2,228,224 fields,
including all padding. No private proof or encryption is simulated by this test.

| Native baseline | SHA256 |
| --- | --- |
| Mathematical profile | `1d46aabee8b12e654743ca89bd9f8e22f6eca41eba415d0a4de860790f6ffa09` |
| Frame profile | `b4026496eec3f20a214ebe6f5a1ce2de4a7ae5a6394977c5c69c548cd8601d4b` |
| Ordered symbolic relation and lookups | `be34a0d28c815be2e06e2ed8a7e8cdc9df5c443d3a66832525f6c4b7ee83ddd3` |
| Complete preprocessing matrix | `2734dbd8f156b96508c4db6269586f03294502f6ed8ac986723bc8846dbc0a07` |

Independent source reviews checked the lower and upper frozen packets and their
complete preimages. Lower manifest SHA256:
`E01B929CB5AA498E094E6563A68F3AAFACB17C587D86C3B706118424FA3C60C7`;
upper manifest:
`36D0E49AC150C6A12D6AEEA9379D90113297E2B3EC355DF0E15971F979BAD550`.
Source review was kept distinct from the actual native gates above. Detailed
build, process, phase and failure records remain in ignored local artifacts.

## Measured costs and remaining work

| Operation | Observed time |
| --- | ---: |
| Lower DATA proving, including public setup | 3178.416 ms |
| Its actual private full trace | 10.139 ms |
| Its actual native proving | 2564.695 ms |
| Lower DATA cold receiving | 649.313 ms |
| Cold public preprocessing within receiving | 564.575 ms |
| Actual native verification within receiving | 59.174 ms |
| Upper StateCertificate production | 1912.059 ms |
| Role3 production, including fresh State verification | 1376.904 ms |
| Upper consuming DATA production | 3910.464 ms |
| Upper fresh State/Role3/DATA receiving | 1378.583 ms |
| First checked encrypted product on the same DATA Ct | 65.408 ms |
| Second checked encrypted product on the same DATA Ct | 64.543 ms |

The final lower proof was 2,510,739 bytes; the upper fixture's separate actual
DATA proof was 2,514,387 bytes. Its State and Role3 frames were 12,251,999 and
3,357,863 bytes. Each product certificate was 1,737,899 bytes. Randomized proof
sizes are observations, not replacement codec limits.

The two product timers start AFTER query encryption. They include genuine public
SDK multiplication, complete conditional arithmetic production/checking and
owner decryption followed by an independent full4096 ring oracle. Both reuse the
SAME accepted DATA ciphertext. The evaluator has no key/plaintext/mask/oracle.
This is a local input-reuse fixture, not a complete SQL request, query/Cmd proof,
network measurement or a speedup comparison with the earlier real-peer request.

Keeping H8192 gives no factor-two proving or memory improvement. The important
new boundary is request-independent DATA mathematics that a future authorized
installation can retain. Protected owner query origination/recovery, key and
parameter security assessment, new Cmd/lock/finality/WAL contracts, fresh agreed
heads and an actual peer-process integration remain necessary. Current APIs do
not install such authority or accept SQL. The complete-query 500 ms target remains
unmet and must be measured only after that production path exists.

## Private input consistency

A subsequent extraction makes the existing complete private equation derivation
available as `data::Prepared::check_private_consistency(self, &Expected)`. The
original full proof builder uses the same operation-local Plan, guarded graph,
products, common E and bounded K banks. The equation loop and entire MAIN writer
were independently checked against their complete preimages; the graph is built
once. All buffers retain their original cleanup. Profiles, AIR, PP, codec,
resource gates and the receiving proof verifier are unchanged.

This consuming API returns only `Result<()>`. It creates no PP, MAIN, native
proof, accepted token or serialized verdict. It can check the original ciphertext
of an owner-private query against the independently retained mask/W and the SAME
SDK key/Cs. It supplies no Source/DATA admission, encryption-randomness theorem,
query provenance, authorization, freshness or SQL permission. Owner origination,
protected custody and exact cold recovery remain separate work.

The actual SDK query case passed in 0.11 s, including setup and the existing
repaired-secret/shared-error/final-W negatives. The successful public-API call,
including checked openings, took 7.539 ms after query encryption/metadata setup.
Its held-PID observation recorded 124.7177 ms lifetime, 0.125 CPU seconds,
10,182,656 peak sampled private bytes and 15,978,496 OS-peak working-set bytes.
It allocated no private MAIN or proof; resource sampling is whole-case data,
not an isolated allocation measurement for the API call.

All 14 CoreGold tests then passed in 12.37 s on the same successful release
artifact. Query and DATA input checks took 7.675 and 7.550 ms in that run.
The genuine DATA proof, repaired OOD, real false-wire terminal rejection and all
four Pair goldens still passed. Process lifetime was 12,384.6032 ms, CPU time
23.296875 s, peak private bytes 1,345,994,752 and OS peak working set
1,351,450,624. Both observations preserved the same 120 s / 1792 MiB fuses,
20 ms sampling, exact source/image pins and terminal-zero/no-child checks.

Executable: 5,399,552 bytes, SHA256
`05CE0DF1B861D67E6210DC06B68F73F273AA70CFDC7998CE4A8D9FD5335B0E0B`.
The source packet manifest was
`A84C4F4CE399C22A1316CB14E7EBAC3581A0797C28E737A1BA6598A06BA79B52`;
all 31 images and four sidecars were independently checked. Root added only two
bounded test timing measurements before the successful build. Strict all-target Clippy,
formatting, requirement consistency and documentation checks passed. No extra
full proof fixture was introduced; existing owning proof tests were reused.

The local consistency check and cold public proof verification are different
operations. The 7.539 ms measurement cannot replace peer-verifiable evidence or
establish a speedup for the complete SQL/locking request. Its purpose is a fast,
shared input check for the planned protected owner recovery path.

## Dense DATA metadata

A test-private candidate packs the same 81,920 original graph gates into
56-slot rows and overlays all 4096 original range coefficients across every
physical row. Per-slot phase and fanout flags preserve unaligned boundaries.
Its 1463 graph rows, 514 Cw and 66 Cs rows leave five range-only rows in H2048.
Every gate coefficient, node occurrence, range/c0/secret-pack schedule and full
hash preimage is compared with the original implementation. All-node balance,
unique producers, inactive slots, checkpoint resets and accumulator boundaries
are also checked. This is a complete mathematical inventory, not a proof.

The private `range_equations` extraction preserves every original expression in
its original order. Before extraction, an actual native original-DATA capture
pinned all ordered BASE/EXT constraints, both original and packed lookups, full
PP, PUBLIC32, profiles, original request and binding. All seven literals passed
after extraction, alongside the existing four Pair literals. No post-extraction
capture or fallback can replace those constants. Production AIR, PP, profiles,
witness, native backend and receiving behavior are otherwise unchanged.

The new metadata tests reported H2048, MAIN512, PP668, PUBLIC32, BASE1248,
EXT84, degree4, eight committed quotient chunks, 243 original messages,
81 packed lookups, AUX410 and 2622 batched openings. The actual SDK baseline
and composed UDR/LDR reports met the same individual 128-bit floor, including
every finite term; the LogUp term was 297.075187496394 bits. The modeled workspace
was 669,417,472 bytes, below the unchanged 1792 MiB policy. These are analytical
proof-profile checks, not observed proving memory or lattice/system assurance.

Before adding any private writer, a separate native test captured the full
571,450-byte ordered symbolic tuple. Its unconditional SHA256 is
`6fe109f433d7f0c66dc51ec403cd103bdbf0056a72634af2cc0888a8ba8b3814`.
The full streamed PP SHA256 is
`6f4bdb87a034d70a662a9948098c5c6aefb1d69f67b0c8aedee50f3e1e465170`.
Both hashes include the distinct research domain; neither relabels an old proof.

There is no MAIN writer, complete PP factory/commitment, native setup, producer,
verifier, codec, installation or SQL acceptance in this child. PP still depends
on the exact request; cross-request reuse is invalid. Genuine proofs and hostile
native verification, full resource observation, query-mask/Stmt96 association,
installed DATA provenance and fresh quorum composition remain required. A
smaller height or workspace estimate does not establish a speedup or the 500 ms
complete-query target. Module ownership and focused commands are in the
[inventory README](program/dense_data_inventory/README.md).

## Local thread-count experiment

A separate experiment ran the existing original-DATA owning proof test twice
on the same release image and source, once with 16 Rayon threads and once with
two. Each execution produced one honest and one actual false-wire proof, with
fresh OS randomness and strict native rejection. The machine reported an AMD
Ryzen 9 9950X3D2, 16 physical cores and 32 logical processors. Run order was 16
then two; background load was uncontrolled. This is one paired observation.

| Original-DATA phase | Two threads | Sixteen threads |
| --- | ---: | ---: |
| Public preprocessing within production | 584.520 ms | 127.090 ms |
| Actual native proving | 2711.298 ms | 630.625 ms |
| Complete local production | 3338.311 ms | 811.960 ms |
| Cold preprocessing within receiving | 799.192 ms | 115.289 ms |
| Actual native verification | 66.953 ms | 59.635 ms |
| Complete cold receiving | 906.353 ms | 204.303 ms |

Both limited processes passed without a fuse, forced cleanup or live child.
The sixteen-thread test observed 1,334,018,048 peak private bytes and
1,349,459,968 OS-peak working-set bytes. This test includes a second hostile
proof; its process lifetime is not one-query latency. Separate randomized proof
bytes prevent claiming an identical transcript comparison. No production thread
policy changed: assigning 16 threads to each peer would need whole-node
scheduling and multi-process resource measurement. Even the faster standalone
production plus cold receiving exceeded one second and omitted the complete
SQL/FHE/finality route.
