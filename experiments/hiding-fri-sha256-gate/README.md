# Hiding-FRI SHA-256 compression gate

Status: experimentally validated for this fixed public compression fixture. The
release build, strict Clippy, both 128-bit SDK security reports and all ten serial
tests passed. One separate observed process proved and verified the fixture; this
is not a SQL, private-source, ZK or production resource-compliance result. Exact
identities, failed initial checks and observation limits are in [VALIDATION.md](VALIDATION.md).
This standalone workspace has no production consumers and does not change the
root workspace or its default members.

The gate composes the published `p3-sha256-air =0.8.0` compression AIR with the
installed Plonky3 0.8.0 hiding backend. The published archive's VCS identifier is
`a21e3ed42905040ad49c519e402f018381c12d0c`, matching the other pinned P3 crates.
It proves one public SHA-256 compression, repeated into exactly 512 rows to meet
an explicit fixed masking budget. Repetition does not establish chaining, SHA
padding, AEAD opening, CSTORE source consistency, BFV formation, SQL completeness,
row locks or finality. Synthetic primitive fixtures are public test inputs, never
SQL answers. These tests cannot empirically establish witness secrecy or ZK.

## Ownership and entry point

`src/main.rs` owns a local CLI with `security` and `prove` modes. `statement.rs`
owns public block/state/output inputs and a domain-separated identity covering
those inputs, the request identity and the complete fixed profile. `air.rs`
binds all those values through AIR constraints and actual public values.
`backend.rs` owns configuration, both numerical security reports, conservative
array accounting, proving and verification. All interfaces are crate-private.
There is no proof-byte encoder, decoder, external proof input, network endpoint,
acceptance marker or production dependency. SDK proof objects remain in process.

Direct dependencies are the pinned P3 crates, RustCrypto SHA-256 as an independent
compression oracle, and Rand's OS-seeded CSPRNG. There are no project-crate
runtime dependencies. The relevant neighboring contracts are
[private source proofs](../../docs/private-lock-source-proof.md),
[current public arithmetic](../../crates/bfv-query-proof/README.md) and
[the next source relation](SOURCE-RELATION.md).

## Fixed candidate configuration

- Goldilocks base field; degree-five extension; 319-bit extension-field floor.
- Poseidon2 Goldilocks width 12, rate 8, four-element digest; stated hash
  collision-resistance assumption 128 bits, as an experimental model parameter.
- Hiding MMCS for both input and FRI trees, cap height zero, four Goldilocks salt
  elements. Main-MMCS, FRI-MMCS and polynomial masking use independently
  OS-seeded `StdRng` instances. SDK clones fork fresh seeds rather than copy RNG
  state. No deterministic seed or testing preset is used, including in tests.
- Hiding FRI: blowup 8, 192 queries, five random codewords, binary folding,
  terminal log degree zero, no grinding. No preprocessing, lookups, periodic
  columns, next-row access or auxiliary witness commitments.
- Exact trace: 512 rows by 7,728 columns. Each main column opens at one point,
  giving the pinned hiding budget `512 >= 2 * (192 + 5) = 394`.

`StarkSecurityParams::from_air` inspects the complete wrapper and original
512-row domain, with `OpeningShape::hiding(5)`. The numerical report then uses
post-ZK `degree_bits=10`, matching the actual committed proof. It includes the
actual quotient chunks and masking/opening columns. The normal CLI/Backend path
requires both proven unique-decoding and list-decoding reports to reach 128 before
allocating its full SHA trace/proof. Direct primitive/oracle/adversarial test
fixtures may construct public traces before their helper's security gate; run the
test suite only after the independent security-stage review. Verification checks
the fixed proof height and repeats that security gate.
The CLI prints both reports even when the candidate fails its target.

The report is evidence under the pinned calculator, hash and random-oracle models;
it is not a production security certification, a proof of ZK composition or an
approval to place private owner data into this experiment. An insufficient bound
must reject: adjusting parameters requires source review, never a silent fallback.
See the pinned [security adapter](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/uni-stark/src/security.rs),
[hiding PCS](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/fri/src/hiding_pcs.rs),
[hiding MMCS](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/merkle-tree/src/hiding_mmcs.rs)
and [SHA AIR](https://github.com/Plonky3/Plonky3/blob/a21e3ed42905040ad49c519e402f018381c12d0c/sha256-air/src/lib.rs).

## Resource gate and later validation

For 8-byte Goldilocks values the original trace payload is 31,653,888 bytes.
Hiding expands the main matrix to `2 * 512 * (7728 + 5)`, or 63,348,736 bytes.
Its blowup-8 dense main LDE alone is 506,789,888 bytes (483.3125 MiB). These are
separate array sizes, not an additive peak estimate or a whole-process bound.
Quotient work, SDK allocations/copies, DFT scratch, tree salts/nodes, proof storage,
thread stacks and allocator overhead remain unmeasured. No reserve is selected
from secret data; all geometry is fixed. Masking also does not guarantee zeroization.

After source review and a coordinated validation window, generate/review the
standalone lockfile, then use the actual release commands from the repository root:

```powershell
cargo build --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
cargo test --release --locked --no-run --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml
cargo clippy --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml --all-targets -- -D warnings
cargo run --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- security
```

Only after the numerical bounds and external process-memory plan are reviewed,
run the proof-bearing suite in its own coordinated window:

```powershell
cargo test --release --locked --manifest-path experiments/hiding-fri-sha256-gate/Cargo.toml -- --test-threads=1
```

The first numerical run must record both bounds, constraints, quotient chunks,
opening counts and source/lock/toolchain identity. A separate fresh process may
then run `prove`, with CPU threads fixed and an external Windows observer recording
peak working set/private memory, elapsed lifetime, exit status and artifact hashes.
Do not equate the printed proving interval with whole-process or SQL latency.
Reaching the RAM target requires actual full-process observations; no 500-ms,
production privacy or resource-compliance claim follows from this gate.

Release tests include a real proof and independent compression checks; changed
input/output/request identity, proof height and randomization; rebuilt malicious
proofs with a wrong claimed output for the same genuine input, an internally valid
alternate input/state in the last padding row, and a corrupted internal SHA schedule
bit; inadequate masking/codeword budgets; reuse through cloned private prover data;
and independently forked configuration RNGs. The valid alternate rows are first
checked against the unwrapped upstream SHA AIR. Rebuilt-proof tests invoke the raw
SDK prover under the claimed public statement, rather than replay an old proof.
They use release mode because SDK debug builds assert invalid trace constraints
before producing the malicious proof.
