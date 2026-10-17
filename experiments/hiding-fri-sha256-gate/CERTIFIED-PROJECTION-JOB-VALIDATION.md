# Certified BFV projection job validation

Observed on 2026-10-17. This is a nonaccepting, bounded experiment connecting the
existing lock-return formation certificate to a real ciphertext-only public
projection on an independent `dcs-peer`. It does not enable live SQL acceptance.

## Verified boundary

The client compiler opens the existing 144-field `C_plan` from the exact SQL,
nonce, projection, predicate, lock strength/wait policy, row window and independently
owned transaction metadata. A sealed capability retains that exact typed producer.
An independently valid foreign projection under the same request cannot replace it.

Before request creation or network I/O, `prepare` verifies the complete canonical
Source/Lock or actual StateLease/Lock path, returned encoding, KeyTransform, five
ordered Basis certificates and signed-integer formation proof. The exact complete
ciphertext enters the existing BFV public-product request. The worker receives
public parameters/setup and encrypted input, with no secret decryption key,
plaintext rows, source witness or fabricated arithmetic.

The final arithmetic proof is verified before restoring the encrypted response.
Client completion decrypts the real output and checks all 8192 slots. The full
request32, parent, typed target and formation public values belong to the sealed
input composite; the existing arithmetic wire binds QueryId16, heads, full setup
identity, public projection and complete ciphertext. These scopes remain distinct.

## Actual validation

Toolchain: Rust 1.99.0, Windows x86_64 MSVC, release profile,
`-C target-cpu=native`, Cargo jobs 2 and Rayon threads 2. Inherited Rust/DCS/build
profile overrides were cleared; Cargo used the local cache with `--locked --offline`.
The separate daemon was built from unchanged owning inputs at parent `4768e134`.
No external proof-kernel directory was installed; its actual backend was `avx512`.

| Gate | Actual result |
| --- | --- |
| Final dependency graph | 211 packages; all original 142 identities/checksums retained; all 69 additions match the root lock |
| Root workspace lock and 54 pinned SDK source anchors | Unchanged |
| Formatting, release build, test compilation, all-target strict Clippy | Passed |
| Compiled test discovery | 241 unique names, exactly the old 235 plus six new cases |
| Existing numeric reports | All 23 complete ordered JSON outputs exactly match the returned-formation baseline |
| New owning cases | Six passed, each selected exactly once; each reports 1 passed and 240 filtered |
| Affected existing controls | Four passed, each selected exactly once |
| Independent-process CLI | Passed once; actual encrypted result, verified proof, client completion and peer exit 0 |
| Requirements mirror | Exact match; both requirement documents unchanged |

The six new cases cover compiler-field/projection binding, a genuinely valid
foreign plan, independent full-context mismatches, missing/swapped/foreign
prerequisites, actual TLS/physical-custody corruption, and the actual cold
certificate/cache/StateLease path with a fresh query. The four existing controls
cover parsed lock semantics against `transaction-state`, bounded-window rejection,
exact query identity and integer residual bounds. Existing 235 test bodies remain
unchanged; their earlier full-suite result is recorded in
[the baseline report](LOCK-RETURNED-BFV-VALIDATION.md). This change did not rerun
all 241 test bodies.

| Observation | Outer elapsed ms | Samples | Max sampled working set bytes | Max sampled private bytes |
| --- | ---: | ---: | ---: | ---: |
| Six new + four existing cases, sum / maxima across separate processes | 277780.7754 | 2550 | 1295339520 | 1317744640 |
| One independent-process CLI | 57412.6091 | 527 | 1280610304 | 1302724608 |

The first row sums elapsed times, not concurrent memory. Maximum sampled OS peak
working sets equal the working-set maxima in this table. Sampling was nominally
100 ms; actual maximum gaps were 115.0643 ms for the selected tests and 113.4134 ms
for the CLI. The 1792 MiB soft observation fuse and samples are not hard memory
bounds. Test-thread TLS fixtures are within their test PID. **CLI samples exclude
the independent daemon RAM**; no aggregate or peer-process memory result is claimed.

The CLI's inner timer was 57079.3364 ms. It starts after fixture/key/setup creation
and includes prerequisite proving/admission, child/bootstrap/Probe/Store, setup
installation and proved RPC, verification/restoration, all-slot client completion,
shutdown and output-drain joins. The outer timer also covers fixture creation and
process lifetime. Neither is an interactive SQL latency benchmark; no fixed
500 ms limit applies. The client PID was 374244, the distinct peer PID was 18484,
its exit code was 0, and the restored encrypted response was 446812 bytes.

R1 release and test compilation succeeded, but strict Clippy rejected constant-size
`chunks_exact` and an unnecessary `drop` of a test witness. No R1 test bodies or
numeric gates ran. R2 used `as_chunks` and a lexical witness scope, preserving all
arithmetic/AIR/profile parameters. Its fresh target and all successful gates are
the evidence reported here; R1 sources, logs and binaries remain preserved locally.

## Reproduction and evidence

Build `dcs-peer` from the root workspace and this leaf from its own manifest with
the pinned toolchain and flags above. Compile tests with `cargo test --no-run` and
run `cargo clippy --all-targets -- -D warnings`, using `--release --locked --offline`
and the leaf manifest for each command. Select the owning test names with the
compiled test executable's `--exact <name> --test-threads=1`; discovery lists all
six new names under `opening::locking::formation::job::tests` and
`opening::state::locking::certified_job_tests`. The honest process invocation is:

```powershell
./hiding-fri-source-primitives.exe prove certified-projection-job E:/absolute/path/dcs-peer.exe
```

The peer path must be absolute and is checked before fixture creation. The hidden
Windows child uses the existing bounded Bootstrap v2 frame and TLS endpoint,
verifies loopback/identity and a Probe PID equal to the owned child, and keeps one
stdin supervisor writer. Normal completion uses Shutdown, close, wait and reader
joins. The existing EOF supervisor and kill/join cleanup were source-reviewed;
this observation exercised normal completion, not a forced-parent-termination test.
Endpoint receive is bounded after the synchronous bootstrap write; it is not a
whole-start deadline. Logs retain at most 64 KiB per stream. Normal daemon backend
stderr is retained separately from the empty outer CLI stderr.

Immutable local evidence (ignored, not committed) lives in
`.local/certified-projection-job-validation-r2`,
`.local/certified-projection-daemon-build-r1` and
`.local/certified-projection-job-observations-r2`. The final source SHA-256 is
`CDCCE6F06BA2D7361373BB1C8BB58B0C5D8884C12EE0470CA23276E7A1A9B059`;
Focused receipt SHA-256 is
`47D8AE338B1783C3BDCE7D226E02BD563574D433D5FDA650EDA05FF40C852D24`;
independent-process receipt SHA-256 is
`47FAC0A1954B735082778157BF82A7F8BCA41AA4566685C1B7729E6D8A7F5544`.

## Remaining requirements

All old individual-relation security reports are unchanged; this is not a proof
of composed 128-bit security. Only the final public-product worker is
ciphertext-only. The upstream bounded Source/Lock/Encoding/Formation witnesses are
still owner-local; they are not peer-only encrypted predicate/selection execution.
Projection is public in the current BFV wire. Owner/key authority, evaluation-key
consistency, entropy, fresh agreed heads, decentralized finality, writer fencing,
MVCC, full PostgreSQL, compact expansion and whole-peer resource targets remain
open. The next arithmetic dependency for encrypted predicates is a complete exact
ciphertext multiplication/relinearization proof, including scaling and key switching.
No signature, checksum, TLS identity, successful decryption or fixture equality
substitutes for a required computation/completeness proof.
