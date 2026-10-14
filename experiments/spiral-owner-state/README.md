# Spiral owner-state recovery experiment

A small reusable owner-only backup boundary for the pinned Spiral SDK used by
[the private-BFV pipeline](../../docs/experiment-private-bfv-index.md). It keeps
its 32-byte secret seed in an opaque, zeroizing **336-byte** envelope and binds the
original public setup, domain, exact parameters, SDK and RNG contract. It changes
no SDK source or cryptographic parameters.

`OwnerState::generate(params, domain)` returns `KeySetup { owner, client,
public_wire }`. `owner.encode_secret_for_experiment()` returns a secret owner-only
buffer. `OwnerState::restore(params, expected_domain, image, original_public_wire)`
returns `Restored { owner, client, public }`. Generate/restore use a fresh SDK
`Client::init`, so seed regeneration starts from zero matrices. `profile_params()`
is the exact 512-record, 8192-byte profile used by the pipeline.

The original **6,029,344-byte public setup must be retained** and is counted once.
`generate_keys_from_seed` regenerates both secret keys, then uses fresh entropy for
public setup; it cannot reproduce that setup. Restoration calls only
`generate_secret_keys_from_seed` and decodes the retained public setup after all
length, domain, parameter, pinned-contract and SHA-256 gates pass. Query generation
continues using fresh SDK entropy on every call.

| Direct dependency | Responsibility |
| --- | --- |
| Pinned `spiral-rs` | Keys, parameters, query/response protocol, server evaluation |
| Exact `rand` / `rand_chacha` | Constrain the SDK's supported secret shuffle |
| `getrandom` | Fresh owner seed |
| `sha2` | Bind public setup and identify corruption of trusted owner state |
| `zeroize` | Wipe the wrapper's owned seed/envelope buffers on drop |
| `serde_json` | Probe result, with no secret bytes |

The secret image is not encrypted or authenticated by this module. Its checksum
only detects corruption; confidential authenticated backup storage and a trusted
expected owner domain remain caller responsibilities. A malicious replacement of
the entire trusted image is outside this boundary. Never send the owner image to
peers, log it, or commit it. The fixture entry point accepts only intentionally
public non-secret test seeds. SDK client private allocations and SDK seed copies
are not zeroized by this wrapper. SDK public-wire integers use native byte order;
this experiment accepts only little-endian 64-bit processes and the pinned lock.
It does not promise cross-version or cross-architecture recovery.

The Gaussian CDF is public, regenerated from pinned width 6.4, and does not sample
the secret keys. Keys use three fixed-weight ternary polynomials (256 `+1` and 256
`-1` coefficients each). Native client state, CDF, parameter tables, process/TLS
and allocator overhead remain RAM, separately from the canonical owner image.
The probe reports public-field capacity/inline counts and secret-payload formulas;
these are not whole-process RAM measurements.

Validated: seven focused contract tests plus one real restored-client private-PIR
integration test pass; strict Clippy passes for this package. No timing or security
level is inferred. Set `RAYON_NUM_THREADS=8` to reproduce the recorded probe.

Prepare the ignored local package from a clean SDK checkout at
`fdb7206517c249603b0c91b65f1f29f95272107c`:

```powershell
./experiments/spiral-owner-state/run.ps1 -SdkDirectory <pinned-sdk> -Mode prepare
# The reviewed Cargo.lock is supplied beside this README.
./experiments/spiral-owner-state/run.ps1 -SdkDirectory <pinned-sdk> -Cargo <cargo> -Mode check
./experiments/spiral-owner-state/run.ps1 -SdkDirectory <pinned-sdk> -Cargo <cargo> -Mode probe
```

`-CargoHome` and `-TargetDirectory` allow project-local shared caches. The check runs
focused contract tests, one real private-PIR restored-client probe, and strict
Clippy. The public fixture contains distinct first/middle/last records. It requires the
SDK decode buffer to contain exactly the 8192-byte payload plus 32 zero guard
bytes, then compares the complete bounded payload. A controlled
wrong seed must return an unequal record. This is an owner oracle check, not PIR
response authentication; the composed pipeline still needs its existing
Merkle/AEAD/root checks. No files containing keys or owner images are written.
See [the accounting and validation report](../../docs/experiment-spiral-owner-state.md).
