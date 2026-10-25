# Public image and native oracle adapter validation

These checks exercise the owning test-only [image arithmetic](public_image/README.md)
and [native oracle adapter](research_query/README.md). Neither test boundary
produces a public-only simulated proof or grants normal SQL/Word/Source admission.

The actual Query AIR, automatic packed LogUp, padded public preprocessing and
global constraint order are used. Three image cases check literal polynomial/
tensor products, the actual SDK field folder at base point 49 with no input-row
locations, and enlarged-to-target maps/Frobenius framing. The first comparison
checks all five quotient coordinates without a private trace or configuration.
This is not a 192-location or full-degree performance observation.

The oracle vector deliberately plants a rejected full digest followed by an
accepted one. The query-only challenger must reproduce the same raw/event walk;
conflicting programming must reject while exact repeats remain consistent.

The separately ignored honest-reference case was explicitly executed. It uses
the existing guarded nonsecret Query fixture and genuine `prove_batch`, then the
normal bounded shape codec and genuine `verify_batch` under the research MMCS.
Producer/receiver FIELD/CAP/SAMPLE/raw retry histories match exactly, including
277 accepted base samples. Missing all input openings and a changed MAIN row
fail direct native verification. The ordinary concrete SHA backend rejects the
research proof. No normal verifier was made configurable or replaced.

## Observations

Windows MSVC Rust 1.99.0, optimized release/native CPU, locked offline packages,
two Cargo jobs, eight shared Rayon workers and serial test execution. The bounded
observer holds the exact executable handle and creation identity, with a
120-second/1792-MiB fuse and 20-ms memory sampling. All three runs exited zero
with no faults or cleanup actions. The ignored reference case reports zero
ignored cases in its explicit `--ignored --exact` run because it was executed.

| Run | Cases | Harness time | Process wall | Sampled OS peak |
| --- | ---: | ---: | ---: | ---: |
| r770, planted rejection/query-only vector | 1 | 0.00 s | 15.7937 ms | 6,148,096 B |
| r771, image arithmetic/source comparisons | 3 | 0.22 s | 232.5134 ms | 63,823,872 B |
| r772, genuine Query oracle reference | 1 | 1.51 s | 1527.2478 ms | 1,150,156,800 B |

The shared executable SHA256 was
`333088F173CF2EFDB4D8A124AEF291E3345A4AC75E47EF88EAD857A1EF1A455A`.
Source and image pins matched before and after every run. The high reference
memory includes retained raw-preimage dictionaries and genuine native setup;
local dictionary caps are not a production process-RAM guarantee.

Compilation found and corrected a stale fixture-module path, ambiguous basis
inference and constant-chunk/iterator/getter issues. Clippy passed before the
native build (r768). A preliminary invocation ran before a candidate import
had completed and failed on the missing module; the complete import and source
pins were verified before build r769 and all observations above. No failed run
is counted as executed evidence. The shared test-only public RNG forwarder has
one documented dead-code allowance for its unused DATA lexical host.

Final strict Clippy (r774), the owning all-targets check (r776), and the
dependency-free requirements-mirror test (r775) passed. Independent source review
found no blocking defect. Its lifecycle-comment correction clarifies that public
setup already precedes frame decoding; only that comment changed after the
measured executable was built.

## Public assembly components

The next owning stage adds the private test-only
[whole-B arithmetic](research_query/public_deep/README.md) and
[opaque INPUT forest](../research_hash/opaque_inputs/README.md). The first
constructs the affine polynomial from supplied public disclosures, using the
exact native 2327-term order, base-field CRT/Frobenius consistency, two DEEP
divisions and a native all-coordinate DFT product. Seven algebra cases cover
literal values, the full 4096/192 affine image and explicit shape/coin/PP failures.
An eighth case uses the actual zero-interleaved 545 public Query polynomials:
it checks all 2327 DEEP terms at each of 192 physical locations, independently
checks PP rows by Horner arithmetic and checks the mask away from those locations.
Its non-PP columns are public algebra inputs, not an honest Query witness.

The forest fixes all four private Query commitments at 32768 leaves and the
actual widths. Only disclosed salted LEAF answers may be assigned; every
internal NODE is a normal query to the same oracle. Genuine native MMCS checks
the returned multiproofs. Three cases cover a literal eight-leaf tree, exact
frontier equality with the genuine native public-matrix prover, and the full
four-tree/192-index geometry. The last includes five positive and 24 hostile
native verifications, repeated-row/salt reuse, cumulative disclosure limits,
non-overwriting programming conflict and permanent forest failure afterwards.
The Query entry point requires exactly 192 indices; shorter batches belong only
to the private tree test helper. Public PP is never an opaque forest role.

These two runs used the same environment and held-process observer limits as
above. Build r785 completed before both runs; source and image pins matched
before and after each run. Neither run reported faults or cleanup actions.

| Run | Cases | Harness time | Process wall | Sampled OS peak |
| --- | ---: | ---: | ---: | ---: |
| r786, native opaque INPUT multiproofs | 3 | 0.12 s | 145.9271 ms | 66,871,296 B |
| r787, whole-B arithmetic and actual public PP | 8 | 0.79 s | 803.5709 ms | 54,472,704 B |

The shared r785 executable SHA256 was
`4757B88B333A9296599233C1927C1A1424B4BA47062F387456824B7B9306181C`.
Strict Clippy r784, requirements-mirror test r788 and owning all-targets check
r789 passed. Earlier compile checks found an unsupported test RNG
clone and two style issues; all were corrected before the measured build. The
test wrapper delegates randomness to the actual `StdRng` and counts its calls;
the forced-conflict regression uses a separate explicit public seed/preview.
No private RNG clone API or dependency was added. Independent source reviews
found no blocking arithmetic or forest-protocol defect. The process memory and
durations above cover these component checks, not full proof assembly or SQL.

## Complete Query image comparison at 192 locations

The opt-in `public_image::tests::full_locations` case was explicitly executed
under the same held-process limits. It uses the actual Query AIR and packed
LogUp folder independently from the symbolic ring evaluator. The target/source
moduli have degrees 197/394, with 192 disjoint current/next physical locations
and a nonbase OOD point. MAIN/AUX are dense public residue fixtures of degree
393, without a private configuration, witness, RNG or proof.

At every base location, all five native folder coefficients are compared
separately: 960 equalities. At fixed nonbase z, five distinct Frobenius maps
apply only to the coefficient extension and coins, keeping evaluation values
and selectors fixed. Their nonzero Vandermonde determinant establishes that
the five scalar comparisons determine all five extension-valued coordinates.
Together with the base locations this determines each degree<197 residue.
The nonzero control `P_S(X)*((X-2)-u)` is invisible to those base checks and the
first OOD map but is detected by the remaining four maps.

Actual public PP comes from the existing getter; native DFT evaluates its 545
columns in batches of 16, with selected scalar Horner checks of coset order and
rotation. This gate does not independently reconstruct the PP commitment or
establish a globally valid AIR trace. It invokes the real SDK folder 197 times.
An independent source review found no blocking arithmetic or association issue.

| Run | Cases | Harness time | Process wall | Sampled OS peak |
| --- | ---: | ---: | ---: | ---: |
| r798, exact opt-in full image/native folder | 1 | 2.50 s | 2535.3662 ms | 121,270,272 B |

Build r796 completed before the run. The executable SHA256 was
`70DDAE1792B19A5E2E9B29EDE077C79C8EBFA0665BBDBBF098112854C69E677A`.
Source/image pins matched before and after; the observer reported no faults or
cleanup actions. The explicit ignored target ran, so the resulting harness count
is one passed and zero ignored. Strict Clippy r795 passed after an explicit
coordinate-slice annotation and an iterator correction. These are arithmetic
checks; their duration is not full proof production, acceptance or SQL latency.

## Fixed-coin joint trace/quotient disclosures and whole B

The private [joint disclosure sampler](public_image/public_disclosures/README.md)
was executed through four unit cases and two owning consumer cases. It draws
the enlarged MAIN416/AUX420 base residues and ten appended trace columns, uses
the actual Query fold with the same coins, and preserves all five correlated
quotient-coordinate fibers. Each fiber draws seven free masks; the eighth is
determined by the native normalized c-weighted relation. The appended five
quotient columns have the separate full independent image. R10 and actual PP545
complete the 1481-column public view, without an original trace or witness.

The unit cases compare native split order and normalized physical vanishing
polynomials, all five fibers at the full 192-location budget, and independent
rank-seven kernel images at every one of the eight zero-vanishing roots. They
also require malformed locations and exceptional z to reject before RNG advance.
No inverse of a possibly zero quotient vanishing factor or new rank exception
is introduced.

The first consumer samples the full 197/394 image using 350069 Gold cells, then
composes it with whole-B preparation/convolution. Every one of the 192 physical
rows agrees with a direct 2327-term DEEP reference. The second fixes the same
cell tape while changing only the constraint coin: the original/appended trace,
R, PP and appended quotient images stay identical, while every original quotient
chunk receives the same changed offset. It also covers base z and overlapping
current/next location sets.

| Run | Cases | Harness time | Process wall | Sampled OS peak |
| --- | ---: | ---: | ---: | ---: |
| r810, fixed native geometry/fiber/failure laws | 4 | 0.10 s | 147.0161 ms | 54,239,232 B |
| r811, actual joint V to whole-B consumers | 2 | 2.26 s | 2271.3342 ms | 103,964,672 B |

Both use build r808 and executable SHA256
`48FBE99498FF5352F3276A5487DF73C3B12CF1E9D81412B223DF2C31733DDCE4`.
Source/image pins matched before and after; the observer reported no faults or
cleanup actions. Strict Clippy r807, owning all-targets check r812 and
requirements-mirror test r813 passed after explicit base-to-extension division
conversions and a corrected test ring receiver. Independent source
review found no blocking law/association defect. These are conditional fixed-coin
algebra checks, not distribution tests, full native proof production, adaptive
Fiat-Shamir simulation, concrete privacy or SQL latency observations.

## Public Query disclosures to a genuine native FRI frame

The private [native assembler](research_query/native_fri/README.md) now consumes
the joint public V disclosures, the public whole-B polynomial and a presampled
complete raw Fiat-Shamir tape. It invokes the real batch/PCS transcript drivers
and native FRI prover with unchanged Query geometry. No original trace,
`Prepared`, private key or honest-reference proof is requested by this path.
The ordinary native PP commitment is rebuilt from its public coefficients and
salt stream and must exactly equal the independently derived CommonData cap.
The proof contains all five native INPUT openings and twelve FRI rounds, with
the exact outer/wrapper claim split and normal public PP openings.

The small tape case checks the full rejected digest, all contiguous retries,
duplicate index/row reuse and unused/gapped-draw rejection. The first heavy case
uses explicit public zero private-column algebra and a separately constructed
PP DEEP polynomial: genuine native PCS accepts, but the complete AIR receiver
rejects. Twelve omissions/mutations must also reject. This distinguishes the
PCS component gate from full AIR acceptance.

The second heavy case uses the actual joint V and whole-B samplers. The existing
bounded frame decoder and complete native `verify_batch` accept. All produced
and received RAW/FIELD/CAP/SAMPLE events agree: 277 accepted draws and seventeen
caps. The run had 192 unique input positions and 348377 ideal Gold cells. Ten
omission/mutation controls reject, including missing input rounds, changed AUX
next and quotient coordinates, wrapper claims, public PP salt and nonzero PoW.
The normal concrete SHA receiver rejects this research frame.

| Run | Cases | Harness time | Process wall | Sampled OS peak |
| --- | ---: | ---: | ---: | ---: |
| r821, exact raw tape and duplicate laws | 1 | 0.00 s | 29.6957 ms | 6,221,824 B |
| r822, genuine native PCS with AIR rejection | 1 | 1.56 s | 1574.3182 ms | 577,437,696 B |
| r823, complete public V/B to native Query receiver | 1 | 4.55 s | 4574.4771 ms | 604,524,544 B |

All three used the optimized build r819, executable SHA256
`2F6DDA25ABCB981EB502FDF8E5A09C29E677CF274DA49F6841E337ACD6471818`.
Source/image pins matched before and after; no observer faults or cleanup
actions occurred. Strict Clippy r818 passed after explicitly discarding the
unused AIR challenge in the deliberately PCS-only test receiver. Heavy cases
ran with exact names and `--ignored`, reporting one passed and zero ignored.
The existing 120-second/1792-MiB held-process limits were unchanged.

Acceptance here uses an explicitly programmable research oracle. It checks
native assembly and verification, not soundness under programmable hashes,
adaptive privacy, concrete SHA security, production admission or SQL latency.

## Two fresh Query frames in one prior-state dictionary

The owning opt-in shared-session test constructs two complete public V/B frames
with one fixed complete Expected, one shared Programmer dictionary and one
query-only Receiver. Each proof has an independent full raw64-byte FS tape,
sampled before either frame is made, and distinct owned V/B/opaque/FRI streams.
The first attempt's Inputs, PP trees, V/B and native proof allocations are dropped
before the second attempt; only immutable frame bytes and its full walk survive.

Both complete bounded receiver calls agree with their entire produced walks,
including raw prefixes, all raw64 rejection/retry digests, 277 accepted samples
and seventeen caps each. The first immutable frame replays after the second
producer has added cells. A planter then reconstructs its first native draw
prefix and changes only digest byte63, keeping the Gold candidate unchanged.
The exact named programming-conflict panic occurs outside the receiver guard.
Both old frames replay afterwards through the same dictionary and receiver,
without overwriting, replacing the dictionary, regenerating a proof or resampling.
Normal concrete-SHA facades reject both research frames.

The private cfg(test) PUBLIC SHA observer records actual update bytes and actual
SHA results at the selected Query/DATA profile and Expected, dense wire profile
and public-PP stream sites. Normal builds retain the original SHA types. Capture
is synchronous on the calling thread, clears on unwind, and bounds each input
to 1 MiB, all inputs to 16 MiB and completed calls to 4096. Its unit case compares
both SHA algorithms with their actual unwrapped results and tests panic cleanup.

The complete test independently recomputes every observed digest, requires raw
namespace disjointness from proof LEAF/NODE/FS, and compares exact deduplicated
algorithm/input/result manifests across the two productions. All four selected
SHA256 and three SHA512 helper-family prefixes must actually occur. Initial
Expected construction recorded eleven calls/six distinct cells; each production
recorded fourteen calls/five distinct cells, including all three public-PP labels.

| Run | Cases | Harness time | Process wall | Sampled OS peak |
| --- | ---: | ---: | ---: | ---: |
| r845, actual SHA observation and unwind cleanup | 1 | 0.00 s | 12.1538 ms | 6,025,216 B |
| r846, two native frames, old replay, conflict and helper inventory | 1 | 8.03 s | 8033.0309 ms | 709,300,224 B |

Both use optimized build r844, executable SHA256
`890724DA075E1C451491E3B3A27A20F392A14DCDBED6F7C2B710E386B4EDA6B9`.
The existing 120-second/1792-MiB held-process limits and Rayon8 were unchanged;
source/image pins matched and no observer fault or cleanup occurred. The ignored
heavy case ran explicitly with its exact name and reported one passed/zero ignored.
Strict Clippy r843 passed. Independent source review found no blocking defect.

This is finite selected synchronous PUBLIC preprocessing with restricted
proof-MMCS/FS ROM. The suite profile, geometry/graph/request helpers and arbitrary
worker calls remain outside this capture. It is not a single global all-string
SHA ROM or a complete helper inventory. PIT challenge randomness remains a
separate soundness question. Two-session replay does not establish arbitrary
adaptive auxiliary-information composition, all-five-family simulation,
ideal-cell/PRG security, concrete cryptography, admission or full SQL latency.

## Remaining work

The fixed-coin trace/AUX residues, correlated quotient fiber, whole-B sampler,
opaque input trees and final native frame assembly now compose in an accepting
research receiver without an original private `Prepared` or honest witness.
This executable path does not establish causal oracle composition or adaptive
privacy across sessions and all five proof families.
The source helpers use their concrete public SHA implementations outside this
regression dictionary; complete shared-helper ROM simulation is not claimed.
Conditional privacy additionally needs its explicit calibrated prior-state,
auxiliary-information, ideal-cell/PRG, abort and oracle-coupling premises.
Soundness, concrete cryptography and the application bindings are separate.

These durations include research checks and are not full SQL latency. No network,
fresh agreed head, finalized lock or complete 500-ms result is established.

## Shared research-hash owner regression

The former local Query RO/config/opaque modules now have one private cfg(test)
[program owner](../research_hash/README.md). Query imports that exact owner and
selects its closed421/425 layout; DATA opaque checks select517/415. No raw
namespace, seed/parameter, AIR, public PP, codec, normal config or admission
contract changed. Old measurements above retain their historical source paths.

Clippy r888/build r889 passed, followed by eight shared/native opaque cases r890,
the existing Query tape check r891 and the existing complete two-frame Query
gate r892. All10 selected cases passed with zero ignored. The heavy Query gate
took8.81s harness/8817.2222ms process and OS peak709193728B, including two fresh
productions, receives/replays, conflict rejection and normal SHA rejections.
It is not a full SQL latency measurement. The shared owner records the exact
executable, unchanged120s/1792MiB observer, remaining model and DATA-frame boundary.

## Mixed Query/DATA prior-state regression

The [mixed gate](../research_hash/MIXED-SESSIONS.md) now runs complete Query and
DATA research frames in one retained raw-input dictionary. Native acceptance,
entire walk equality, foreign-header rejection, normal-SHA rejection, a named
full raw-tail conflict and old-frame replay passed in r912. The moved Query
factory and original two-Query test body retain their operations; its affected
native gate r913 and raw-tape parser r914 also passed.

Build r911/Clippy r910 and normal/requirements checks r915/r916 passed. Mixed
time was9.62s harness/9636.3207ms process, OS peak1041694720B with both true PP
histories retained. This is a research multi-frame regression, not full SQL or
production crypto assessment. The linked record owns exact image, helper,
resource and measurement scopes.
