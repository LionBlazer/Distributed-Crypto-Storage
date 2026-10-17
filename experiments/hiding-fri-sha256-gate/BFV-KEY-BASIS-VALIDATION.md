# BFV key-transform and basis-convolution validation

**Validated experimental prerequisites:** locked graph, release build, strict
Clippy, nineteen numerical gates, three native oracle filters, both genuine
proof commands and all 189 serial tests passed. This record reports individual
observed processes, not a benchmark or a hard RAM bound. These nonaccepting
experimental Kinds do not accept live SQL.

## Exact contracts and scope

[KeyTransform](src/opening/key_transform/README.md) binds independently expected
SetupDescriptor/C_s to C_Shat for every 8192 signed-support coefficient. The AIR
constrains s in[-20,20], a public psi twist/bit reversal, all 13 DIT stages and
natural odd Goldilocks evaluations. The descriptor is database 16B, key-domain 16B,
setup-digest 32B and LE-u32 epoch. C_s hashes s+20; C_Shat hashes raw natural field
evaluations under their exact distinct role contexts. Two private salts are
separate from public values. Support includes zero and is not a sampling proof.

[BasisConvolution](src/opening/basis_convolution/README.md) first verifies the real
KeyTransform proof against its independently expected full statement, then
checks one complete ciphertext-basis negacyclic convolution. It opens the EXACT
old C_Shat context/encoding, multiplies by verifier-derived public Ahat, performs
bit reversal/inverse13DIT/normalization/untwist, and commits all 8192 natural output
Goldilocks residues under a new C_R context. Every bank transition, hash-phase
hold, salt, last-active checkpoint and inactive P2 permutation is constrained.

The typed decoder fixes pinned fhe/fhe-math/fhe-traits 0.1.1, N=8192, t=114689,
variance 10, five ordered 43/44-bit qi, level 0 and exactly two Ntt polynomials.
Trusted canonical parameter bytes are checked before attacker parameter decoding;
full ciphertext roundtrip, canonical residues and byte caps remain mandatory.
It accepts no separate A vector or digest-as-authority input. Public A comes from
the SAME decoded ct[1] changed to PowerBasis: upstream wire coefficients are not
an unchecked NTT vector. Full c0/B, c1/A, seed, level and representation remain
bound in context. Parameter/CT caps 1024B/512KiB bound input bytes, not total RAM.

The mathematical output is modulo Goldilocks. With genuine signed-support s and
canonical public A, the true integer negacyclic coefficient has magnitude
at most8192*20*(max(qi)-1)=2882303758832762880<2^62. A later signed-integer formation
relation must open that unique lift and link all five bases, common e and exact
SelectedEncoding W. This stage does not establish those links or BFV formation.

## Provenance and dependency graph

Compilation recorded ROOT parent 37d7faac2ed42324b5555c73d72af2269191acb3 on
codex/feature/sql-latency. The frozen 24-path source manifest is
`.local/bfv-basis-validation-r2/source.json`, SHA-256
`BDB377ED2ECD6DA92325BCF7E0257878D082F8BA536270956709F528906E5676`.
The new source was contextually integrated from KeyTransform FC26736C and revised
Basis B68C7320; previously validated Version/PrivateLock report bytes are preserved.
The BFV source/report scope is 24 task paths plus this new report = 25. The
separately authorized current PostgreSQL-contract latency clarification adds one
controlled documentation path, for 26 total. It removes the obsolete fixed cutoff
and updates two current README target sentences; historical timing observations
and dated reports remain unchanged. Other validated README prefixes are preserved.

Actual offline metadata/tree receipt
`.local/bfv-basis-validation-r1/dependency-success.json` has SHA-256
`C6297AF31283FDF23BA951AF90EF98543636CEB8617ECF16D2F3597DB6D827E0`.
All 141 resolved package identities match the 141 lock records (137 registry,
four local); nineteen P3 packages remain 0.8.0. The standalone lock SHA-256 is
`036FEB3584690ECBED906A9F8771F24F4244B0DA193D5CC1A2EED69C35728F33`.
No lock version/source/checksum was regenerated for the validation retry.
Existing FHE dependencies moved to normal experimental fixture use; transaction-state
remains dev-only. Production/root manifests do not acquire an experiment dependency.

The actual resolved fhe-math 0.1.1 feature set is empty, so its `tfhe-ntt` and
`tfhe-ntt-nightly` BACKEND features are OFF and its native NttOperator is selected.
The dependency package tfhe-ntt 0.6.1 was nevertheless compiled with default/std;
package presence/build output is not evidence that fhe-math selected that backend.

## Actual build and numerical results

Rust 1.99.0 (`b940084d7`, host x86_64-pc-windows-msvc, LLVM 23.1.1), native CPU flags,
two Cargo/Rayon workers and offline/locked mode were recorded. The isolated target
was `.local/target-basis-r2`; shared CARGO_HOME was `.local/cargo-home`.
Release build, release test--no-run and strict all-target Clippy each exited 0.
Test discovery found exactly 189 unique names: old 158 + 15 KeyTransform + 16 Basis.
Discovery was followed by actual execution: all 189 source-exact names passed
in the complete serial suite recorded below.

Compile receipt `.local/bfv-basis-validation-r2/compile-success.json`:
`902C30E108F7A75CE2E0B2B5BD0355F136E6BACE1EFEEBB47B10608F4BFA1601`.
Compiled CLI SHA-256:
`8B55618522CCB7DAAEF854A6DC2BC403760993C32CD91DEBE33AFF8C5BFB0875`.
Compiled test executable `deps/hiding_fri_source_primitives-27444e049153b0a0.exe`:
`8B688426B0B44233680546E90505BBBBA14819F4ECDC6177C3E8C01F84BC7741`.

The combined 19-command Numeric_ONLY receipt is
`.local/bfv-basis-numeric-continuation-preparation-20261017-014517-193/numeric-run/numeric-success.json`,
SHA-256`2131A2EE8F8FE7465CFA6FF4348CC799BBA6F6ACECDD72FE0FD06F81A8866331`.
All 19 child exits were 0 with empty stderr; old 17 reports matched the frozen
VersionLock baseline. Numeric CLI performs no AIR trace/proof allocation, although
the Basis security command constructs a real public-nonsecret upstream encryption
fixture. The separate native oracle filters and the complete 189 serial suite also passed
on these unchanged compiled inputs.

| Actual new profile | T/W/PV/periodics | Constraints | Actual degree | Chunks | Batched | Unique/list bits |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| bfv-key-transform |512/9932/33/512|10065|3|16|20044|128/128|
| bfv-basis-convolution |512/9452/62/512|9534|3|16|19084|128/128|

Both retain q=192, extension degree 5, random-codewords=5, blowup=8, post-ZK degree-bits=10,
TWO complete-width openings and the reviewed 404 hiding budget. Degree 3 comes
from the actual symbolic AIR report; the conservative declared bound 5 still
determines 16 quotient chunks. Batching is 2*(W+5)+16*10+10. The finite SDK reports
reach 128 under the existing model; this is not production certification, empirical
privacy testing or a composed 128 theorem for the prerequisite/child pair.

| Calculated array payload | KeyTransform bytes | Basis bytes |
| --- | ---: | ---: |
| Main trace |40681472|38715392|
| Masked trace |81403904|77471744|
| Main LDE |651231232|619773952|

Each public periodic table adds 512*512*8=2097152 raw bytes. These named arrays
exclude symbolic DAGs, twiddle/periodic transforms, FFT reallocation, quotient/MMCS,
proofs, FHE fixtures, retained witnesses and allocator overhead. They are not whole-
process RAM bounds. The separate process samples below are observations, not
resource compliance or proof of a whole-process maximum. Reasonable practical
latency remains an empirical operation requirement.

## Actual oracle and genuine-proof observations

Exact observer `.local/observe-bfv-basis-r2.py`, SHA-256
`0C8E77647F76CC77C4CA919D9304DA9F6F4C0281D582E69CEDD99DB703F791B3`,
owned each separate hidden child with the same frozen source, CLI/test artifacts
and two Rayon workers. It used a sampled 1792MiB fuse, a nominal 100ms wait (not an
exact sampling interval), 900s proof timeout and 180s oracle timeout, finally
kill/join on failure. No abort occurred. This is an observation/abort policy,
not a hard OS memory limit or certification of a worst-case memory bound.

Raw ROOT-relative run directories and success receipt SHA-256:

- `.local/bfv-basis-observations/20261017-015955-511-ShapeOracle`:
  `24AF8B5DBF4462183826D4BFB53AAC3F745517374435ACD4DE9C511CFB1379FD`.
- `.local/bfv-basis-observations/20261017-020025-574-KeyProve`:
  `438440DDCCE1558465DBAFE0DF3E3DC64C7164A6CC9D932FC0C3342194FC3C78`.
- `.local/bfv-basis-observations/20261017-020053-588-BasisProve`:
  `254ED2DFFBE5BAF8AB00DC863E5550F685EFF819D527619440E6032C6D62C8F5`.

The shape and two native filters each reported 1 pass/0 failed/0 ignored/188
filtered. They exercised exact public shape, all 8192 KeyTransform evaluations
against pinned DFT natural order, and all five 8192-coefficient convolutions
against two native-prime transforms and centered CRT. Stderr was empty.

| Filter | Observer elapsed ms | Samples | Actual gap range ms | Max sampled WS / private / OSpeak bytes |
| --- | ---: | ---: | --- | --- |
| shape |355.9278|4|107.9047–111.4323|157310976 /158175232 /157310976|
| native key oracle |634.6572|6|106.7794–111.6154|157265920 /158191616 /157265920|
| native basis oracle |102.1336|1|no interval|2056192 /401408 /2056192|

The one-sample native-basis row mostly observes startup and can miss the work's
memory peak. No samples were discarded; all rows had populated counters. These
filters establish native equivalence for the fixtures, not full adversarial
coverage or encrypted SQL acceptance.

| Exact proof argv | Proving ms | Verification ms | Observer outer ms | Samples | Actual gap range ms | Max sampled WS / private / OSpeak bytes |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `prove bfv-key-transform` |2720.3122|1055.1946|4169.6179|39|99.9848–111.0396|733175808 /730435584 /736735232|
| `prove bfv-basis-convolution` |7309.316|2019.3352999999997|9732.0739|89|106.5049–124.5254|787279872 /784117760 /789618688|

Both commands exited 0 with empty stderr and actual verified-experimental markers.
KeyProve's security case is `public-nonsecret-key`; the earlier trace-free
numerical command used `public-shape`. Geometry/model bounds match, but they are
different statement cases and are not relabelled as one witness observation.
BasisProve uses the real public-nonsecret upstream ciphertext fixture.

Timers are fixture-excluding. Key's proving timer starts after fixture creation
and checked Backend preparation and includes trace/proof construction. Basis's
proving timer starts after actual upstream fixture creation and its security
report, then includes the KeyTransform proof, real prerequisite verification,
child Backend preparation and child proof. Its verification timer genuinely
verifies both prerequisite and child with their expected contexts. Verification
also includes fresh Backend analysis as performed by these entry points; these
are not isolated PCS timings. Observer outer time covers process creation,
fixture/security work, proof/verification, exit and observation overhead.

The public key/noise fixture values are deliberately nonsecret. Caller noise
replay does not replay public A: pinned upstream encryption independently samples
A's seed through its own OS RNG. Salt/mask configuration remains unchanged.
One observation of each command is not a comparative benchmark, a latency
percentile, a full-operation SQL latency or a universal whole-process RAM bound.
The raw WS/private/OSpeak counters are different measures and remain separate.

The complete suite subsequently finished successfully in
`.local/bfv-basis-observations/20261017-020125-967-FullSuite`; success receipt
SHA-256 `9D89ADD613F5A08DB313CD0FEADCB7F0B3C44A4A5E90878CCDA6FBE5568F1E81`.
The frozen test executable ran with exactly `--test-threads=1`. All 189 unique
source-exact names passed once, with zero failed, ignored, measured or filtered;
the harness reported 1056.53s. Stderr was empty. Child exit 0, abort_reason=null
and postflight MATCH are actual terminal facts.

| Complete serial suite | Actual observation |
| --- | --- |
| Observer outer elapsed |1056575.273ms|
| Populated CSV rows / gaps |9714 /9713|
| Actual gap min/max/mean |99.785 /192.0299 /108.77861151034696ms|
| Max sampled WS / private / OSpeak |1077026816 /1101062144 /1077026816B|
| Sample fuse / suite timeout |1792MiB soft sampled fuse /2400s; no abort|

CSV SHA-256 is `7385F74C29664218DC4EAB0DC76EDDCB9F935029F8B3195376FFBD16EBB33752`;
stdout SHA-256 is `5249B4690181BCD0EFD150D909090B3A51CC3AF23801988D0C2AF90850269C8E`.
All counters were populated, no rows were dropped, and raw gaps retain their
floating-point values. A full test process includes proof construction/rejection,
native fixture work and allocator reuse; it is not one query or one proof latency.
Its sampled/cumulative counters do not certify an all-input peak or a hard RAM cap.

## Retained failures and corrections

The first build attempt `.local/bfv-basis-validation-r1` had release 0 / no-run 0 and
strict Clippy 101. Its sole finding was an unused must-use `poseidon::write` return
at KeyTransform tests.rs:272. The correction is exactly `let _ = poseidon::write`
in that existing test; no AIR, profile, assertion, lock or test-name change.
Original source/logs/artifacts remain retained. Corrected test RAW SHA-256 is
`9769F19F7D717AFD3C1E4EFD0F5BA0F409E14EE018E0E4521C2DBDCA83654231`
(canonical-LF SHA-256`A3375D7559923A66CEA0F5A2610EEFEB4DFB022E9F280453A2AA54F3FD32E538`).
Fresh R2 build/no-run/strict checks passed on that corrected source.

The first Numeric driver 22C61E18 retained eight exit 0 commands, indices 0..7,
then its one-JSON parser rejected historical pair-opening stdout containing both
security and candidate_geometry JSON objects. It was an observation/parser failure,
not a failed cryptographic result. Original numeric-result receipt
`C9BB4800408372D9CC8B18A0D10AB4A3ECBCE81ED8EFF15AEA58284FA88C8B3C`
and all raw outputs remain unchanged. A first continuation helper 900539D3 stopped
on a Python NameError before CLI invocation; its source/evidence are retained.
Corrected helper 95E985D4 validated the full expected JSON-stage lists, reused the
same eight actual outputs without rerunning them, and executed ONLY indices 8..18
(eleven new commands). No Rust source change, rebuild or new crypto parameters
occurred between numeric attempts. Combined success preserves that split.

## Validation status and reproduction

| Gate | Current actual status |
| --- | --- |
| Locked graph, release build, test compilation, strict Clippy |PASS|
|19 numeric CLI commands / old 17 parity / two new 128 floors|PASS|
|Full 8192 native KeyTransform and two-prime CRT equivalence filters|PASS: three exact filters including shape|
|Genuine KeyTransform proof and proof-first Basis composite|PASS: one observation each|
|All 189 serial behavior/adversarial tests|PASS: exact 189/zero ignored or filtered|
|Single-process samples and proof/verify elapsed|RECORDED above; no universal bound|

The receipts retain the full executable paths and argv. Reproduction requires
the unchanged source/lock, actual offline cache, a fresh target and the same
case-insensitive environment sanitizer as reviewed driver 22C61E18's
`environment()` (also reused by continuation 95E985D4). Do not rerun a driver on
its frozen historical target. The following mirrors that sanitizer and all pins;
replace UNIQUE with a fresh directory for a reproduction:

```powershell
$explicit = @(
  'CARGO_BUILD_TARGET','CARGO_BUILD_RUSTC','CARGO_BUILD_RUSTDOC','CARGO_BUILD_RUSTFLAGS',
  'CARGO_ENCODED_RUSTFLAGS','CARGO_ENCODED_RUSTDOCFLAGS','CARGO_BUILD_ENCODED_RUSTFLAGS',
  'CARGO_BUILD_ENCODED_RUSTDOCFLAGS','CARGO_BUILD_RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
  'CARGO_HOME','CARGO_BUILD_JOBS','RAYON_NUM_THREADS','CARGO_NET_OFFLINE','CARGO_TERM_COLOR'
)
$prefixes = @('RUST','DCS_','CARGO_PROFILE_','CARGO_TARGET_',
  'CARGO_BUILD_RUST','CARGO_BUILD_ENCODED_RUST','CARGO_ENCODED_RUST')
foreach ($item in @(Get-ChildItem Env:)) {
  $upper = $item.Name.ToUpperInvariant()
  $clear = $upper -in $explicit
  foreach ($prefix in $prefixes) { if ($upper.StartsWith($prefix)) { $clear = $true } }
  if ($clear) { Remove-Item -LiteralPath ('Env:' + $item.Name) }
}
$toolchain = 'E:/Users/white/.rustup/toolchains/1.99.0-x86_64-pc-windows-msvc/bin'
$env:CARGO_HOME = 'E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/cargo-home'
$env:CARGO_TARGET_DIR = 'E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/.local/target-key-basis-reproduction-UNIQUE'
$env:RUSTUP_TOOLCHAIN = '1.99.0-x86_64-pc-windows-msvc'
$env:RUSTC = "$toolchain/rustc.exe"
$env:RUSTDOC = "$toolchain/rustdoc.exe"
$env:RUSTFMT = "$toolchain/rustfmt.exe"
$env:RUSTFLAGS = '-C target-cpu=native'
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
$env:CARGO_TERM_COLOR = 'never'
$env:CARGO_NET_OFFLINE = 'true'
$env:PATH = "$toolchain;$env:PATH"
$cargo = "$toolchain/cargo.exe"
$manifest = 'E:/Users/white/Documents/ChatGPT/DistributedCryptoStorage/experiments/hiding-fri-sha256-gate/Cargo.toml'
& $cargo build --release --locked --offline --manifest-path $manifest
& $cargo test --no-run --release --locked --offline --manifest-path $manifest
& $cargo clippy --all-targets --release --locked --offline --manifest-path $manifest -- -D warnings
```

The executed new numeric argv were `security bfv-key-transform` and
`security bfv-basis-convolution`. Proof argv were `prove bfv-key-transform` and
`prove bfv-basis-convolution`. Three oracle filters used
`--exact <full-test-name> --test-threads=1`; the complete test executable used
`--test-threads=1` without --nocapture. Actual children were separately observed
by the pinned observer, rather than treating Cargo compilation as behavioral
execution. Logs/receipts bind commands, source/binary hashes, output and gaps.

## Remaining obligations

All fixtures are explicitly public and nonsecret; there is no Owner key exporter
or accepting production API. Hiding configuration plus a public-fixture proof
would not empirically establish private participant witness secrecy. Key support
is not CBD distribution/entropy/independence or honest sampling. A setup digest,
C_s and C_Shat do not establish the authorized BFV decryption/evaluation key,
key lifecycle or same-secret link to AEAD. Signed-integer lift/common-noise/
SelectedEncoding/all-five-basis formation is still a separate obligation.
No live grant, SQL result/completeness acceptance, peer FHE query protocol,
writer fencing, private MVCC/control anchoring, fresh agreed head or finality is
established. Earlier validated VersionLock and PrivateLock reports retain their
own exact scopes and are not relabelled as BFV formation or composed security.
