# Owned AIR and public schedule reuse

This local experiment retains the exact public AIR inside the Backend that
analyzed it. Proving and verification reuse that AIR after the existing exact
kind/public-value guards. A changed request is rejected before its witness
factory runs. Configuration, RNG seeds, security gates and SDK verification
remain unchanged.

Opening and Selection AIRs lazily retain their existing 512-by-512 public
one-hot schedule in a per-instance `OnceLock`. The SDK receives borrowed
columns. No witness, prover data, RNG stream or proof-dependent `zeta` data is
cached. Each initialized table retains 2,097,152 payload bytes plus allocation
overhead. This change does not eliminate SDK symbolic analysis, constraint
layout, periodic interpolation, PCS/FRI/Merkle verification or OOD checks.
Composite proving can keep both source and Selection Backends alive, hence two
tables. Composite verification creates fresh Backends, each with its own table;
this change does not share analyzed contexts between independent Backends.

## Validation

Native Windows MSVC Rust/Cargo 1.99.0, release, `-C target-cpu=native`, two Cargo
jobs and two Rayon threads; locked/offline dependencies. The previous measured
target and outputs were preserved; this change used a fresh target.

- Release build, test compilation and strict all-target Clippy completed with
  exit code zero.
- All eleven actual CLI security reports matched the preceding revision field
  for field, including both decoding bounds, geometry and allocation estimates.
- Genuine Selection and Packed source proofs passed actual verification.
- All 86 tests passed once in 574.35 s: zero failed, ignored or filtered.
  The external process duration was 574426.5794 ms.

The new behavior test builds one real HChaCha proof, verifies it twice and
observes one AIR construction for the bound Backend. Changing the request then
fails proving before the witness callback and fails verification. Existing
raw-SDK forgery/profile rejection tests remain in the complete suite.

Local retained evidence is bound to these SHA-256 identities (generated logs,
proofs and executables are not repository files):

| Evidence | SHA-256 |
| --- | --- |
| Source snapshot, parent `0c8367f` | `F862D0B44EE0F9B3A4198EAE908AA0B2F5769B8AA98D44AE6AD76247BBB164A2` |
| CLI executable | `AAC0998033E6CF133391D2F4F088CB1402D9FEED8D862B2109F6D7E82AA47765` |
| Test executable | `8FFF081B93A3F5A9D39F3D83A9067042FF0D74051641999CAC9849522AEF7DE6` |
| Eleven-report receipt | `E6BF6FB3D48D426527A2185E27514BEA4ADBB3D039CA8DC672E037EF381833A2` |
| Full-suite receipt | `159375C5F3130FF1216F69896C68E300B63D952DA5D72010C97CC53A11B264C0` |

The source snapshot predates the final documentation link and this report; all
compiled Rust and dependency inputs remained exact. The initial compile driver
failed while collecting PE metadata after all three successful native commands
(it attempted UTF-8 decoding). Collection was repaired without rebuilding or
rerunning those commands; their original exit codes and log hashes were checked.

## Observed components

One invocation per mode, not a latency distribution or a causal speedup claim:

| Experimental CLI mode | Proving ms | Verification ms |
| --- | ---: | ---: |
| Selection composite | 7183.0496 | 1418.3566 |
| Packed canonical source | 1779.8048 | 391.8567 |

Selection proving includes the old canonical source Backend, source proof and
verification, then the Selection Backend and proof. Its verification includes
fresh Backends and both proofs. Packed setup/security/fixture auditing are
outside its proving timer; trace generation and STARK proving are inside.
Verification uses the same in-memory bound Backend. These scopes match the
preceding experiment and exclude codec, network, FHE query evaluation and SQL.

The former single observations were 5671.2797/1484.5861 ms for Selection and
2521.0821/560.8781 ms for Packed. The mixed movement does not establish a general
performance improvement. A complete SQL operation at 500 ms is not established.

An external observer requested 100 ms waits and sampled working/private/OS peak
working-set counters. Its 1792 MiB threshold is a sampled soft abort condition,
not an allocator limit or a lifetime RAM guarantee. Actual intervals can be
longer than requested. The full suite produced 2747 samples, from 167.475 to 574390.092 ms.
Intervals ranged from 150.015 to 592.116 ms (mean 209.112388 ms). Maximum sampled
working set and sampled OS peak were 1,002,741,760 bytes; private bytes reached
1,007,296,512. The child exited zero without abort or observer exception.

## Remaining boundary

This is an internal nonaccepting proof experiment. It adds no network SQL
acceptance, PostgreSQL operation, FHE formation proof, private row-lock protocol,
fresh agreed head or composition-wide 128-bit security result. Required live
proof/freshness rejection remains unchanged. The prior
[Selection/Packed validation](SELECTION-PACKED-VALIDATION.md) describes those
relations and their outstanding limits.
