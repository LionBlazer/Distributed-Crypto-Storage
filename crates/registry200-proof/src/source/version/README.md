# Closed mathematical Source version certificate

This module owns a separate fixed StateCertificate prover/receiving verifier.
Its owning native and compile-fail gates passed; see [validation](VALIDATION.md).
It adds no cache, current-head lease, owner authorization, key-custody/BFV
Formation, query answer or SQL grant.
The old Canonical source(), Source producer and Source-first child APIs remain
unchanged and reject StateCertificate through their original policy.

Direct dependencies are the parent Source's single canonical-image parser,
packed AEAD/index AIR and guarded witness, compact-store's complete expected
heads/images, the private fixed backend, bfv-hiding-stark's fresh-OS configuration,
actual analytical/native verifier and bounded canonical codec, plus SHA256.
There is no experiment/fixture dependency in production.

`SourceVersionExpected::checked(images, independent_heads, C_key, C_state)` checks
both complete canonical encrypted images and exact fixed geometry before retaining
a private immutable Statement. It derives the EXACT existing consumer version tag:
SHA256(domain, preserved StateCertificate profile, each full length-prefixed image,
C_key). No caller request/tag or from-Statement factory exists. C_state is excluded
from the version ID to avoid a circular commitment; the actual proof still binds
that independently retained C_state and every other complete public value. The tag
alone is neither the full expectation nor a proof. C_key is the compact-storage
AEAD key commitment, not a BFV key commitment. Expected heads/key/state authority
and freshness remain the caller's separate responsibilities.

`prove` assesses the fixed packed width 7161/PV691 AIR before allocating its
private trace, uses the genuine SDK prover and canonical serializer, and returns
`UnverifiedStateCertificate` bytes/claim. It deliberately performs no self-verify
and creates no mathematical result. A malformed private witness can reach a real
native failure or yield an unverified proof that the receiver rejects. Production
consumers must retain their own expectation rather than trust the claim beside
remote evidence. Existing source::prove keeps its self-verification semantics.

`verify` performs fresh actual verification and only then creates move-only
`VerifiedSourceVersion` with private fields and a read-only complete expectation.
It retains no proof, SDK state/config, secret or verified flag. No such result is
serialized or restored. Each call coldly re-assesses the actual immutable AIR,
decodes and verifies the complete proof and drops all heavy objects on exit.
Public Expected clones are metadata only and cannot create this result.

The mathematical profile, equations, public values and raw proof encoding are
unchanged from the existing experimental StateCertificate. The receiving policy
uses the existing 20 MiB Source cap, sequence 16384/24 Mi total element budgets, fixed
hiding topology, canonical fields/reencoding and EOF. The backend retains actual
individual security/degree/chunk gates and fresh OS private randomness. None of
this establishes composed security, database version currentness or 500 ms latency.
A future query/data-version composition MUST define a separate reviewed profile,
application/G/Rules/WAL contract rather than relabel old proofs or checkpoints.

The four owning runtime tests share ONE explicitly PUBLIC compact-data/key fixture
and ONE honest proof byte allocation. They exercise the closed constructor and
legacy rejection, full receiving verification with genuine cryptographic context/
opening tampering and codec/cap/EOF failures, and a separate real wrong-private-key
native proving/verification failure. No live Owner, SDK configuration or verified
result is retained globally. Two compile-fail examples exercise actual private-field
construction and move-only behavior. Native test selection for Root:

```sh
cargo clippy --release --offline --locked -p registry200-proof --all-targets -- -D warnings
cargo test --release --offline --locked -p registry200-proof --lib source::version::tests:: -- --nocapture --test-threads=1
cargo test --release --offline --locked -p registry200-proof --doc source::version::VerifiedSourceVersion -- --test-threads=1
```

The four release tests passed in 7.00s. In release, the false-key case must
produce a real native argument and reach the receiving cryptographic verifier's
Verification error; a panic or generic Proving error is not a passing oracle.
The two private-field/clone examples and affected Canonical policy tests also
passed. Reusing a bounded public test prerequisite is not a production success
cache. Any future process restart must perform real verification again; file
existence, hash/AEAD checks,
public claims and old receipts cannot mint this mathematical result.


The actual [immutable DATA encoding consumer](../../two_lane_encoding/README.md#request-independent-immutable-version-data-encoding)
now freshly checks this certificate before proving or receiving its distinct
all-4096 encoding child. It uses the original State C_state opening and never
casts the version tag into the old canonical query q. That consumer still grants
no BFV ciphertext Formation, installed key, currentness or SQL capability.
