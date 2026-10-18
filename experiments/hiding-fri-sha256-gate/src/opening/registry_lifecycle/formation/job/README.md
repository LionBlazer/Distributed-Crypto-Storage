# Registry200 certified ciphertext projection job

This validated experiment connects a complete Registry200 encoding and actual-owner
BFV formation to a real ciphertext-only public projection on an independent peer.
It creates no new AIR or proof profile, and grants no live SQL result, lock,
writer permission or agreed finality.

## Owned contracts

`mod.rs` owns sealed independent `Expected`/`Binding`, `prepare`, public-only
`Prepared`, raw `Received`, actual arithmetic verification and encrypted-response
restoration. The independent pins include full request32 separately from QueryId16,
exact SQL/nonce identity and compiled projection, complete Encoding PV136 including
Cenc, complete Source heads and packets, full original setup/owner anchor, Key PV33,
five ordered Basis claims, complete CT and complete formation PV44 including noise.
Projection is derived from the one existing Encoding metadata identity, not another
mutable cache. The storage AEAD C_key and BFV C_s remain different commitments.

`journal/projection_context.rs` binds the actual signed admitted Acquire body,
canonical Request200, one C_old-to-C_next CAS and both the pre-Acquire parent and
the accepted Acquire HeadRef. It reads the REAL Journal before I/O and after the
actual arithmetic proof. Both the policy-resolved state and conservative
best_validated tip must retain exact immutable Source/sticky enrollment/C_next,
Acquire ancestry and only Empty descendants. Exact(oldAcquire) is not current
ownership after End, and equal-root sibling forks do not establish ancestry.
The Journal is still a conditional local view, not proof of a globally freshest
network state. No caller boolean or receipt substitutes for this read.

`fixture.rs` owns explicitly PUBLIC NONSECRET signed histories and the original
actual Owner used for final client decryption. The handoff retains public request,
parameters and canonical arithmetic input only; it does not retain owner borrows,
private witnesses, Backends, traces or ten prerequisite proof frames. `Received`
contains an unverified reply so a delayed answer can be checked against a changed
real Journal before any encrypted result is exposed.

## Direct dependencies and execution

- [Formation](../README.md): actual Source/Lifecycle/Encoding, Key/five Basis and
  formation verification before request creation or I/O.
- [Registry200 Journal](../../journal/README.md): actual owner signatures, admitted
  control CAS and independent policy-resolved/validated states.
- [Shared peer lifecycle](../../../peer_process/README.md): one explicit daemon,
  TLS/PID/custody checks, bounded logs and EOF/Drop cleanup.
- [BFV query core](../../../../../../../crates/bfv-query-core/README.md): existing
  `PublicUpdateEvaluator` exact public-projection codec and original-Owner
  `decrypt_public_select_unverified_for_experiment` completion.
- [BFV arithmetic proof](../../../../../../../crates/bfv-query-proof/README.md):
  existing full canonical public-polynomial product proof and profile.

The only network job is the unchanged InstallSetup/Prove Select RPC. The peer
receives public setup, encrypted storage and the formed ciphertext/public column
projection. It receives no Source plaintext, private registry, BFV secret key or fixture
answer. `finish` verifies the actual exact product proof before restoring the
existing encrypted response. The public arithmetic wire does not independently
bind request32 or control parent; those require this freshly verified composite
and matching outer Expected. TLS, a signature or decryption is never a proof.

```powershell
hiding-fri-source-primitives.exe prove registry200-peer-projection E:/absolute/dcs-peer.exe
```

The alias is prove-only and requires an explicit checked executable; no new
security report is fabricated for unchanged math. The CLI checks before child
startup (Probe/Store), rechecks before InstallSetup/Prove, verifies the returned
operation, rechecks current control, restores ciphertext and decrypts with the
same original Owner. Only then does a separate public test oracle compare all
8192 slots. Normal completion exercises daemon EOF. Server-thread fixtures are
explicit unit/integration-test consumers, not a CLI fallback.

The one JSON stage is `verified_registry200_peer_projection`. `elapsed_ms` starts
before signed-history/proof generation and ends after original-Owner decryption
and EOF cleanup. `input_generation_and_admission_ms` ends before process startup;
`process_rpc_verification_decryption_and_eof_ms` includes startup/TLS/Store,
InstallSetup, actual peer FHE/proof, client verification/control reread, restoration,
decryption and EOF. Component sizes are reported individually. No file-spool I/O
or aggregate proof serialization is hidden in those timers.

## Limits and unresolved requirements

The existing peer/transport 64 MiB, Body 32 MiB and Journal 256 MiB limits remain.
Ten input proof components are verified locally and dropped before CLI I/O; they
are never sent as a 155 MiB aggregate. Public frames retained by negative tests
and real Journal bodies still count toward actual process memory. Actual process/daemon observations, adversarial checks and reproducible commands
are recorded in [executed validation](PEER-PROJECTION-VALIDATION.md). The full CLI
measured about 123 s in one run, including prerequisite generation. Sampled RAM
observations do not establish a hard resource bound.

The peer performs a genuine public-polynomial FHE projection. Private predicate,
selection completeness and bounded lock-witness construction remain owner-side;
this is not ciphertext-only peer SQL. Controller delegation, MVCC, writer fencing,
production fresh agreement, safe Journal compaction, a bounded remote component
stream and same-secret evaluation-key proofs for future ct-by-ct/relinearization
remain open. Existing individual proof floors do not imply composed 128-bit
security. Production storage-client LockingSelect stays a hard rejection.
