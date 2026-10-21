# Protected Gold owner validation

Executed on 2026-10-21, Windows x86_64/MSVC Rust 1.99 release, opt3,
`-C target-cpu=native`, two Cargo jobs/two Rayon threads. The optional `gold-owner` family is
mathematical client/worker code; normal Session SQL acceptance is not enabled.
Its DATA expectation is public metadata, not authenticated Source admission.

## Executed owning boundary

The release library test target was built with
`cargo test --release --offline --locked -p bfv-query-core --features gold-owner --lib --no-run --message-format=json`.
The exact resulting executable then ran `gold:: --nocapture --test-threads=1`.
All four cases passed in 0.26s, without ignored cases:

- Actual SDK query encryption and ciphertext-only worker multiplication, full
  public arithmetic verification before owner decryption, then an independent
  full 4096-coefficient plaintext oracle. Damaged evidence and a foreign call
  reject; honest completion after the damaged attempt succeeds on the same input.
- Destroy the original Owner/origin, import the actual key again, authenticate
  custody and reopen the exact original QueryCt. Original bytes remain identical;
  the restored query genuinely evaluates and decrypts. AEAD, record identity,
  independently expected mask and allocation limits reject tampering.
- Repaired authenticated records with a canonical Q1 tail corruption or a wrong
  mask still reject with the concrete private-equation Arithmetic error. They
  pass the public ciphertext parser and AEAD layer first.
- Wrong actual SDK secret, Cs salt, fixed parameter profile or DATA key binding
  reject. Public request trailing bytes and oversized frames reject.

Fixtures are explicitly public/nonsecret. Public parameter setup is shared;
keys and private scopes are fresh per case. The worker receives ciphertexts only.
No Source/Formation proof fixture, accepted-DATA factory, simulated result,
alternate verifier, saved success flag or re-encryption recovery is used.

## Local measurements

One honest operation, excluding fixture/key/DATA setup, measured 76.316ms from
origination through complete conditional verification and full-ring decryption:

| Included part | Time |
| --- | ---: |
| Owner origination, including actual SDK query encryption |0.955ms|
| Public evaluator construction, actual SDK multiplication and certificate |41.431ms|
| Owner complete arithmetic check and 4096-coefficient decryption |33.760ms|

The overall interval also includes public request serialization/decoding and
association work between those parts. The request was 123580 bytes and conditional
certificate 1737899 bytes. A separate cold Owner import plus exact authenticated
origin restore/private equations took 13.053ms; custody was 123928 bytes. It excludes
filesystem I/O, durable WAL and rollback/exclusive-writer management.

The held test process lived 268.8554ms and consumed 0.25 CPU seconds. Fourteen 20ms
samples observed peak private bytes 21798912; the OS recorded peak working set
26865664 bytes. Its 120s/1792MiB test fuses did not fire, no cleanup kill occurred,
and it left no direct child. Sources and executable were pinned before/after.
The 3115008-byte executable SHA256 was
`7132572A1C47D5095603C683CD212C4E34CEBF110CE27DC700C9D512728987F7`.
These are local test-process observations, not whole-peer resource measurements.

## Compile and integration checks

Three actual compile-fail examples passed: private Owner key, private origin mask
and unavailable origin Clone. Strict all-target Clippy passed with `gold-owner`
and with all existing features together. Default all-target `cargo check` passed
without the new feature. Upper `registry200-proof` strict all-target Clippy passed
after the additive readonly `core_expected()` metadata getter. The dependency-free
`requirements_sync` test passed; both requirement copies retain the full 500ms target.

## Remaining complete-query obligations

These intervals exclude State/Role3/DATA admission proofs, the Cmd/lock proof,
transport, weighted finality, current-head verification, durable tickets and SQL
response assembly. No full-query speedup factor or <=500ms result is established.
The old distributed route has not been replaced by this module.

The lower product profile remains explicitly UNASSESSED under its conditional
[arithmetic/noise model](../../../bfv-unrelinearized-product/MODEL.md); actual
lattice estimation and composed security remain open. Source completeness,
authorization, freshness, locks and full PostgreSQL semantics require their own
closed composition. A checked/decrypted product or authenticated custody record
does not grant any of those authorities.
