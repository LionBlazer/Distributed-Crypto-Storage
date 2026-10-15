# BFV addition proof experiment

Opt-in Plonky3 0.8.0 research consumer. It executes and proves one actual encrypted
BFV indexed amount addition over every component of the unchanged N8192/Q218
profile: 81,920 canonical NTT residues. It has its own Cargo workspace and lockfile;
no production crate depends on it.

`prove` owns addition, carry generation and serialized proof creation. `verify`
accepts the caller's trusted exact canonical request, the claimed encrypted output
and a proof frame capped at 1 MiB. It rejects missing/trailing/noncanonical proof
encodings, derives its own full public preprocessing commitment, and verifies the
STARK without executing addition. Only successful verification constructs the
private-field `CheckedAddition`, which exposes the two checked byte-array digests.
It is arithmetic evidence, never an accepted SQL result or permission to write.

The AIR enforces a Boolean carry and `a + b - c - q * carry = 0` for every residue.
The verifier independently checks `0 <= a,b,c < q < 2^44`; the integer expression
cannot wrap the Goldilocks field. Eight independent residue equations share each
row: 8 carry columns and 32 public columns, retaining all 81,920 residues. Zero rows
pad the trace to 2^14. Exact input/output
SHA-256 digests, including the original request binding, enter the public transcript.
The verifier never accepts a prover-supplied preprocessing key.

Proof decoding uses a recursive Serde adapter over the unchanged Postcard SDK
format. Before invoking any sequence consumer (including `Vec`'s reservation),
it requires a known length of at most 4,096 elements and charges a shared budget
of 1,048,576 sequence slots. Tuples, fixed arrays and nested containers also count;
map entries charge both a key and a value. Unknown lengths are rejected. These
are decoder structure limits for this fixed profile, not a whole-process RAM
claim. A violation returns `ProofResourceLimit`, before public preprocessing or
cryptographic verification. In particular, a sub-MiB frame cannot first reserve
hundreds of thousands of empty quotient-chunk vectors and only then fail shape
validation. The real full-profile proof tests exercise these same limits.

Parameters are identical in the CLI and tests: Goldilocks degree-5 extension,
standard Poseidon2 width 12, FRI blowup 8, 192 queries, binary folding, no grinding.
The SDK's proven-security model must report at least 128 bits in both decoding
regimes. This model calculation is not a production security audit.

Direct project dependencies are [bfv-linear-circuit](../../crates/bfv-linear-circuit/README.md)
(canonical encrypted arithmetic) and [bfv-query-core](../../crates/bfv-query-core/README.md)
(real BFV owner/evaluator adapters used by the benchmark and public test fixtures).
The CLI generates fresh keys in memory, encrypts public fixture records, proves the
actual peer-side addition, verifies serialized proof, and only then reconstructs
and decrypts the result. It writes no keys, proofs or participant data to disk.

From the repository root, with two compilation/prover threads:

```powershell
$env:CARGO_BUILD_JOBS = '2'
$env:RAYON_NUM_THREADS = '2'
cargo test --release --locked --manifest-path experiments/bfv-addition-proof/Cargo.toml -- --test-threads=1
cargo run --release --locked --manifest-path experiments/bfv-addition-proof/Cargo.toml
```

The boundary tests reuse one genuine full-profile proof and reject corruption,
truncation, missing/trailing/oversized frames, a changed final output residue,
omitted output data, and a rebound request identity in both matching headers.

The test-only direct dependency [compact-query](../../crates/compact-query/README.md)
uses its BFV feature with TFHE disabled. `compact_selection_boundary` creates a real
compact encrypted table and owner-built encrypted index, authenticates the complete
242-row exact range selection, and bridges the unchanged `PreparedUpdate::request()`
to the arithmetic prover/verifier. It retains the opaque preparation throughout;
there is no plaintext reconstruction of the proof inputs or call to owner-local
`apply` as a substitute for verification. The same proof is rejected for a fresh
pending operation, a different delta and different actual data/index heads, even
when the claimed output's binding header is rebound to match the new request.
Selection was already authenticated owner-side under the existing index-build
contract; this test supplies no independently proven SQL-completeness marker,
agreed/current head or live mutation acceptance.

Measure the **whole** operation. The CLI reports independent verifier public
preprocessing, cryptographic verification, their sum and full decoding-inclusive
verification separately. Milliseconds for the final verifier call alone do not
establish the query latency target. Process-wide RAM requires an external process
measurement; this executable does not label buffer sizes as peak RAM.

Default builds remain portable. To measure optional CPU-specific vectorization on
the current computer, use a separate target cache and record the CPU and flags:

```powershell
$env:RUSTFLAGS = '-C target-cpu=native'
$env:CARGO_TARGET_DIR = '.local/target-bfv-addition-native'
cargo run --release --locked --manifest-path experiments/bfv-addition-proof/Cargo.toml
```

Such binaries may require that CPU's instruction set. Results from this optional
build are separate from portable/default timings and are not a SQL latency SLA.

This proof does not establish authenticated SQL selection completeness, query
authorization, agreement on a database head, freshness, crash-safe mutation or
permissionless consensus. The live client's hard missing-proof/freshness gates
remain unchanged. The bound fixture heads are explicitly public opaque test bytes,
not fabricated consensus certificates. SELECT and INSERT are not implemented here.
