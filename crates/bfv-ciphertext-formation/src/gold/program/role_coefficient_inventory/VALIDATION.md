# Role coefficient metadata validation

This stage checks the shared FFT refactor and a new test-private two-AIR
inventory. It supplies no private proof, accepting API or runtime behavior for
the new relation. Aggregate security is explicitly UNASSESSED, with an always
rejecting proof-security guard. Numerical exploratory report terms do not change
that guard or establish a shared-challenge security theorem.

## Actual gates

On 2026-10-21, strict release all-target Clippy passed. The final release test
build took 28.844 seconds. Four new metadata tests passed in 0.10 seconds, two
unchanged original Pair/Data full snapshot tests in 0.07 seconds, and six
unchanged Dense cases in 4.34 seconds, all on the same final executable. The
Dense gate genuinely produces an honest proof and a false-wire proof and invokes
its independent cold native verifier; this does not prove the new two-AIR scheme.

The tests compare every one of the 81,920 original DATA gates against the single
extracted static Schedule, check exact producer/consumer balance across all
16,384 public coefficients and prior private endpoints, and compare the full
public hash stream with an independent native permutation. First-IV, changed
last-word and false-root cases exercise actual hash equations. Two distinct
canonical Expected values change the full binding/root but never structural PP.

The first metadata capture preceded the new unconditional goldens. The final
tests pin the complete ordered BASE/EXT/original/packed lookup tuples for both
AIRs: 1,050,159 serialized bytes, SHA256
945255af8155abb0893782f1e4e8de40001b918043a818be91df274e351c9578.
All 1,363,968 streamed PP fields, prefixed by the new profile, have SHA256
7593a725266c1cd508b1f78b8b5bc0e1fe86581351f853fcb58518225d88451a.
The original Pair/Data/Dense profile, request/binding, full AIR, PP and semantic
goldens remain unchanged. No accepting proof or success flag is captured.

## Native geometry and resources

| Instance | H | MAIN | PP | PV | BASE | EXT | Degree | Chunks | Original messages | Packed | AUX |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Data |2048|512|656|48|1156|86|4|8|247|83|420|
| Public coefficient hash |2048|260|10|4|268|6|4|8|8|3|20|

The SDK derives each instance's packing, degree and chunks independently. There
are 3,310 combined openings and 255 original global interactions. The expected
future native verifier must require the sum of the two present terminals to be
zero and run actual batch verification; each individual terminal need not be
zero. No such new receiving path is implemented in this stage.

The combined simultaneous-bank ledger totals 906,264,576 bytes under the
unchanged 1792 MiB policy. It includes both AIRs' banks, masks, salts, trees,
retained LDE, sixteen opening vectors and explicit private-equation/runtime
reserves. This is an analytical allocation prescreen for future implementation,
not observed private proving RSS. The extra 2,048 permutation rows increase raw
MAIN by 50.78125%; static PP alone does not demonstrate a speedup.

The metadata observer lived 136.5773 ms, used 0.109375 CPU-seconds and reported
9,945,088 OS-peak working-set bytes. The old Dense regression lived 4,361.9955 ms,
used 7.625 CPU-seconds and reported 526,790,656 OS-peak working-set bytes. These
are different scopes: only the latter creates private proofs, in the old scheme.
All runs retained the 120-second/1792 MiB fuses and 20 ms observation, held image/
creation identity, successful terminal state and no surviving direct child.
There were no faults or forced cleanup; system memory was diagnostic only.

## Change boundaries and provenance

The original graph resolves typed static pointwise slots with its same public A
coefficients. There is one butterfly/twiddle algorithm. Source review verified
the original constructor/butterfly extraction and full-image inverses; native
literal regressions and real Dense proofs then checked the result. Root's new
code overlays were formatting, explicit generic PUBLIC-expression conversion,
equivalent iterator/chunk spelling and unconditional first-capture goldens.
The offline lockfile change adds only the already pinned p3-symmetric test edge.
There is no package-version update or production dependency addition.

Local held receipts 51/52/53 share the release executable of 5,977,088 bytes,
SHA2567A2AC261E066102BBB4D568510590DA9160E9BE55B1C46E4515E7AF0B6505170.
The final executed source image contains 134 files, 1,917,030 bytes, aggregate
SHA25640EC691151738266A97639604F507C78AF46704D8C33B25B795FDA648D802038.
The initial capture has its separate retained source image and receipt. These
archives precede this documentation-only update and are not checked-in fixtures.

No private MAIN, committed PP, backend, canonical frame or proof for the new
relation has run. The shared-challenge security derivation remains unresolved.
Query Formation, original Stmt/Cw/Cs/QueryCt association, Source/DATA/key
admission, fresh weighted finality, durable SQL locks and complete-query latency
remain separate unfinished obligations. No 500 ms full-query result follows.

## Continuation verification

The unchanged release image was executed again on 2026-10-21: all 25 Gold tests
passed in 21.53 seconds, including the original Pair/Data, Dense native proofs
and all four role-coefficient cases. Strict all-target release Clippy also passed.
The held process exited zero after 21,546.3568 ms; sampled peak private bytes
were 1,345,372,160 and OS peak working set was 1,351,475,200 bytes, below the
unchanged 1792 MiB fuse. No time/resource fuse or forced cleanup occurred.
The local r62 observer report remains explicitly failed: its input contract
omitted `scope`, so report finalization failed after confirming all 25 results.
This reporting error is preserved; it is not a failed cryptographic test or a
successful observation receipt. These are component regression measurements.
