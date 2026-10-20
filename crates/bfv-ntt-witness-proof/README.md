# N8192 NTT witness proof

This library owns the genuine public-arithmetic proof of one complete forward or
inverse NTT over one of the ten fixed Q5/P5 bases. It moves the existing
`BFVNTW01` implementation from the standalone experiment without changing its
domains, profile bytes, arithmetic, proof envelope, security floor or limits.

The proof is not hiding. A checked NTT stage proves neither ciphertext/key
provenance nor complete MulRelin, SQL completeness, authorization or freshness.

## Public contract and ownership

- `prove(&Request)` evaluates the sealed circuit certificate and creates the
  complete multi-AIR proof. `Generated` owns the output, encoded proof and timings.
- `verify(&Request, &Output, frame)` performs bounded canonical decoding,
  reconstructs all public routing/range/IO tables and its own VK, then verifies
  the actual proof. It accepts no prover-selected setup or auxiliary certificate
  and does not execute the NTT, quotient or carry evaluator.
- `CheckedNtt::matches` binds the complete canonical request/output through full
  SHA512 digests. `security_report()` borrows the actual verifier-rebuilt report
  retained after successful verification; callers cannot construct the marker.
- `analyze(&Request, &Output)` assesses the supplied canonical claim. It builds
  and commits actual public preprocessing, but creates no main trace or proof and
  evaluates no NTT. An analysis report alone does not verify the claim.
- `profile_digest(Direction, Basis)` and `direction_name` expose fixed public
  metadata. `SecurityReport`, `AirReport`, `PcsSchedule` and `Term` are public
  report data. Backend/configuration, SDK proof types and PK/VK stay private.

The verifier drops proving preprocessing before actual verification. Its work
still includes public table encoding and commitments; timings include that work.
The CLI and fixtures belong to the [standalone consumer](../../experiments/bfv-ntt-witness-proof/README.md).
Library fixtures and hostile AIR adapters compile only under `cfg(test)`.

## Fixed proof policy

`BFVNTW01` retains its exact 256-byte header, complete profile64, binding32,
direction/basis, representations, full request/output SHA512 digests and fixed
table counts. The complete frame cap is 16 MiB, a sequence is limited to 16,384
elements and the shared typed decode budget is 8 Mi elements. Canonical
reencoding, exact topology, bounded WHIR openings, trailing-byte rejection and
SDK panic rejection remain mandatory.

The backend retains Goldilocks EF5, full SHA512, collision cap256, zero PoW,
UniqueDecoding, phase target160 and actual complete individual-statement floor144.
No missing, nonfinite or below-floor SDK assessment is accepted. This is not a
composed-operation security claim or a whole-process memory bound.

## Direct dependencies

| Dependency | Responsibility |
| --- | --- |
| [bfv-ntt-circuit](../bfv-ntt-circuit/README.md), `multistark` | Canonical Request/Output, fixed arithmetic, public tables and witness layout |
| [bfv-multilinear-stark](../bfv-multilinear-stark/README.md) | Shared serial SHA512/WHIR configuration and complete SDK assessment |
| [bounded-postcard](../bounded-postcard/README.md) | Fresh caller-owned typed allocation budget |
| `vendor/p3-multi-stark`, exact 0.8.0 | Reviewed SDK setup/prove/verify implementation through an explicit path dependency |

The remaining pinned P3 crates provide AIR/symbolic interactions, sumcheck and
WHIR/Merkle data types; `serde`, `postcard` and `sha2` implement the fixed report,
wire and digest contracts. Native BFV SDK and hostile program helpers are dev
dependencies only. There is no dependency on an experiment, CLI or owner fixture.

## Owning verification

All thirteen existing tests move with the implementation, including the real SDK
all8192 oracle for all twenty direction/basis targets, twenty genuine proofs,
complete transcript binding, bounded codec failures and genuine weaker/foreign
programs that first verify under their own AIR/VK before honest rejection.
Only the report test's call site changes to supply its existing zero claim.

The owning command is `cargo test --release --locked --offline -p bfv-ntt-witness-proof --lib -- --test-threads=1`.
Historical measurements remain in the unchanged [validation report](../../experiments/bfv-ntt-witness-proof/VALIDATION.md);
they do not establish the performance or resource use of this extraction.

The [proof-library extraction validation](../../experiments/bfv-mul-relin-proof/LIBRARY-EXTRACTION-VALIDATION.md) records the current
relocation, owning native tests and preserved proof policy.


### Sequential hash implementation parity

The ignored owning test
`tests::hash_parity::one_public_ntt_preserves_complete_proof_preprocessing_and_transcript`
uses one deterministic PUBLIC NONSECRET forward N8192/basis0 request. It calls
production `prove` and `verify`, checks all 8192 output coefficients against the
native SDK, and rejects a decoded/reencoded genuine proof after a semantic
sumcheck mutation. Existing genuine tests are unchanged.

A bounded test-only capture reconstructs the actual public preprocessing PCS
commitment, records all eight words of its Merkle root, and replays the genuine
SDK verifier with a named challenger to finalize its 64-byte state digest.
It drops each extra proving codeword before verification. It adds no production
API, profile, randomness, thread, timeout or security-policy change. `p3-commit`
is a pinned dev dependency solely for the actual PCS commitment trait.

To compare two hash implementations, run the same test sequentially before and
after replacing only the hash implementation. Use the same release/native build
configuration and exact sources for everything else. For example, in PowerShell
from the workspace root (create the ignored `.local` parent first):

```powershell
$env:DCS_NTT_HASH_PARITY_EXPORT = (Join-Path (Get-Location) '.local/ntt-hash-baseline')
Remove-Item Env:DCS_NTT_HASH_PARITY_BASELINE -ErrorAction SilentlyContinue
cargo test --release --offline --locked -p bfv-ntt-witness-proof --lib tests::hash_parity::one_public_ntt_preserves_complete_proof_preprocessing_and_transcript -- --exact --ignored --test-threads=1 --nocapture
# Import the separately reviewed hash implementation, then build and run again.
$env:DCS_NTT_HASH_PARITY_BASELINE = $env:DCS_NTT_HASH_PARITY_EXPORT
$env:DCS_NTT_HASH_PARITY_EXPORT = (Join-Path (Get-Location) '.local/ntt-hash-buffered')
cargo test --release --offline --locked -p bfv-ntt-witness-proof --lib tests::hash_parity::one_public_ntt_preserves_complete_proof_preprocessing_and_transcript -- --exact --ignored --test-threads=1 --nocapture
Remove-Item Env:DCS_NTT_HASH_PARITY_BASELINE, Env:DCS_NTT_HASH_PARITY_EXPORT
```

The optional environment paths must be absolute and inside this checkout's
ignored `.local`. The export directory and its seven files must be new. The
candidate reads bounded complete baseline files and fails on a missing file,
length difference or any byte difference. Artifacts contain the full canonical
request, output, profile, complete encoded proof, preprocessing root, finalized
verifier transcript and serialized actual security report. They contain no
credentials, secret keys or participant data and must not be committed. Without
these environment variables the ignored test still verifies the genuine claim
and rejection but writes no artifacts. Printed component timings are observations;
there is no speed assertion or claim of an end-to-end improvement.

The owning parity gate and canonical adapter tests passed; see the
[native observations](../../docs/hash-compatibility-validation.md). The tested
buffering candidate was not retained because complete-test timings showed no
stable gain. The production hash implementation, protocol and old tests remain
unchanged. `verifier-transcript.bin` stores the final challenger digest, not an
event log of transcript messages.
