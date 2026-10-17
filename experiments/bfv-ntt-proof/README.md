# Public NTT stage proof experiment

This separate consumer proves one complete degree-8192 transform in the pinned
native `fhe-math` ordering: Forward from natural PowerBasis to the SDK's NTT order,
or Inverse from that order to PowerBasis, including the final N^-1 normalization.
Each fixed basis index 0..9 selects one of the existing Q5||P5 moduli. This stage
cannot become a production `CheckedOperation`, a full MulRelin proof or a live SQL
permit.

Status: validated arithmetic experiment. Strict Clippy, actual SDK parity and
security analysis for all 20 fixed cases, all 15 owning tests and four measured
CLI proof/verification examples passed. See [validation and measurements](VALIDATION.md).

| Dependency | Role |
| --- | --- |
| [bfv-ntt-circuit](../../crates/bfv-ntt-circuit/README.md) | Fixed native roots/routing, full intermediate certificate, canonical codec and optional public AIR |
| [bounded-postcard](../../crates/bounded-postcard/README.md) | Per-call bounded nested SDK proof decoding |
| [bfv-arithmetic-stark](../../crates/bfv-arithmetic-stark/README.md) | Shared fixed linked configuration and actual AIR security-floor analysis |
| Plonky3 0.8.0 | Linked Goldilocks/Poseidon2 public-preprocessing STARK |

`backend` delegates the exact linked configuration and AIR analysis to
`bfv-arithmetic-stark`: extension degree 5, blowup 8 and 192 queries, with no
loader, SDK fork or private-data cache. `BoundAir` delegates
the circuit's complete evaluator and preprocessing and adds eight public words
for the independent consumer profile. Actual SDK analysis must establish both
individual-relation security bounds at least 128 before any proof execution.
Array byte counts are structural estimates, not RSS or whole-peer resource bounds.

`proof` owns generation, the stage-only checked marker and the independent verifier
path. Verification checks the entire trusted input/output and canonical public
auxiliary, reconstructs its own fixed-routing preprocessing commitment and checks
the genuine SDK proof. It never runs an NTT, butterfly or quotient calculation.
The proof transcript binds the complete request/output/auxiliary digests and the
exact direction, basis, native root/order, inverse normalization and configuration.

The new frame is capped at 16 MiB; the RNS experiment's 8 MiB and production 2 MiB
caps are unchanged. The full auxiliary alone is about 4.8/5.2 MB for 13/14 layers.
Every SDK sequence has a 4096-element limit and shares a 2,097,152-slot decoding
budget. Binary Goldilocks values charge their eight byte-array slots as well as
the parent slot; the initial one-million-slot candidate rejected legitimate full
proofs. The new NTT-only budget follows the fixed proof shape and changes its
profile digest. Existing RNS and production budgets remain unchanged. These are
decoder/container limits, not measured memory guarantees.

The owning oracle calls the actual feature-selected native `NttOperator` for all
8192 coefficients in both directions and all ten bases. The SDK impulse also
opens the deterministic primitive root and N^-1. Actual Cargo metadata must confirm
`fhe-math` has no tfhe-ntt backend feature; a transitive crate's presence alone says
nothing about which operator is selected.

All 20 genuine serialized stage proofs are an unignored owning case. It generates,
verifies and drops each proof sequentially. Negative examples retain only four
public representative fixtures (Q0/P4, both directions), never all 20 proofs.
Canonical forgeries rebuild output hashes and final-stage equality before the
integer AIR rejects a wrong last butterfly, root/order or inverse normalization.
Other examples exercise intermediate routing, quotients/carries, canonical ranges,
foreign genuine stages, attacker-selected AIR/preprocessing and nested decoder caps.
All those tests passed. A separate resource regression pins the eight binary
byte-array slots charged for each Goldilocks field element.

After reviewed offline dependency resolution, from the repository root:

```powershell
$ErrorActionPreference = 'Stop'
$manifest = 'experiments/bfv-ntt-proof/Cargo.toml'
function Invoke-CheckedCargo([string[]] $Arguments) {
    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Cargo failed: $LASTEXITCODE" }
}
Invoke-CheckedCargo @('build','--release','--locked','--offline','--manifest-path',$manifest)
Invoke-CheckedCargo @('test','--release','--locked','--offline','--manifest-path',$manifest,'--no-run')
Invoke-CheckedCargo @('clippy','--release','--locked','--offline','--manifest-path',$manifest,'--all-targets','--','-D','warnings')
# Analyze all 20 fixed combinations before any oracle/trace/proof invocation.
foreach ($direction in @('forward','inverse')) {
    foreach ($basis in 0..9) {
        Invoke-CheckedCargo @('run','--release','--locked','--offline','--manifest-path',$manifest,'--','security',$direction,"$basis")
    }
}
Invoke-CheckedCargo @('test','--release','--locked','--offline','--manifest-path',$manifest,'--lib','tests::all8192_coefficients_match_the_actual_native_sdk_in_both_directions_and_all_ten_bases','--','--exact','--test-threads=1')
Invoke-CheckedCargo @('test','--release','--locked','--offline','--manifest-path',$manifest,'--lib','tests::native_sdk_impulse_opens_the_exact_deterministic_root_and_inverse_normalization','--','--exact','--test-threads=1')
# Then observe Q0/P4 both directions before the complete all-20 owning suite.
foreach ($direction in @('forward','inverse')) {
    foreach ($basis in @(0,9)) {
        Invoke-CheckedCargo @('run','--release','--locked','--offline','--manifest-path',$manifest,'--','prove',$direction,"$basis")
    }
}
Invoke-CheckedCargo @('test','--release','--locked','--offline','--manifest-path',$manifest,'--','--test-threads=1')
```

The CLI fixture is explicitly PUBLIC NONSECRET. The proving timer covers stage
arithmetic/certificate creation, preprocessing and SDK proof/frame encoding;
verification covers bounded decoding, independent preprocessing and actual SDK
verification. Initial security reporting and fixture creation are outside those
inner timers. The validation report separately records owned-process observations
and their sampling limits; these are single arithmetic-stage measurements.

A valid transform stage does not link different ciphertext components, RNS
extension/scaling, multiplication, relinearization/key switching or SQL source and
plan proofs. Key authority, freshness, decentralized agreement and production
answer acceptance remain separately required. No composed 128-bit or practical SQL
latency guarantee is established.

The shared-backend extraction is SOURCE ONLY pending ROOT validation. The linked
reports above retain the actual pre-extraction builds and measurements.
