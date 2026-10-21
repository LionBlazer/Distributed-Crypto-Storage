# Public unrelinearized product certificate experiment

This executable investigates a smaller public arithmetic certificate for one real
N4096/Q2/P2 BFV product. It implements no Source, hidden-program, encryption-key,
authorization, database, lock, freshness or SQL acceptance. Its concrete
Fiat–Shamir/security composition, lattice parameters and full-domain noise
correctness remain unassessed. Successful arithmetic checks are not presented as
an accepted DCS proof or completion of the 500 ms query target.

The direct dependencies are pinned `fhe`/`fhe-traits` for the actual public SDK
fixture, `ethnum`/`num-bigint`/`num-traits` for exact integer scaling certificates,
`sha2` for the full transcript, `rand` for fresh fixture encryption, `zeroize` for
plaintext cleanup and `serde_json` for observations. Test-only `fhe-math` and
`ndarray` compare the exact scaler against the upstream implementation. There
is no library API or production consumer. Default workspace members stay core.

The private boundary is split by responsibility:

- `statement` parses complete canonical unseeded SDK endpoint bytes without an
  NTT, seed expansion or query evaluation. No witness chooses its own expected
  inputs. The owner supplies the original four component polynomials.
- `scale` owns exact Extend2To4/Scale4To2 constants, prover arithmetic and a
  separate integer-certificate checker. Every coefficient, rounding interval,
  reduction equation and original Q copy is mandatory.
- `pit` constructs ordinary degree<2N convolution quotients. Its checker tests
  all three BFV component equations in all four residue fields, using eighteen
  points per field. It evaluates polynomials; it performs no NTT or SDK product.
- `modular` implements bounded Montgomery arithmetic for the public checker.
  Horner accumulators and coefficients stay in the ordinary residue domain;
  only each common evaluation point is converted. The independent prover keeps
  its original integer-remainder convolution.
- `certificate` owns the only complete checking path: fixed bounded codec,
  endpoint association, all seven scaler certificates and the full transcript.
  Challenges derive from those SAME complete canonical bytes before checking.
- `fixture` generates explicitly public nonsecret four-row data and an encrypted
  private truth table. Its result comes from a genuine SDK multiplication; no
  expected plaintext answer is an execution fallback. Its client completion
  deserializes and decrypts the actual output, then compares all 4096 decoded
  coefficients with an independent public full-ring oracle. The private client
  key is never passed to the certificate producer or checker.

All internal product and quotient coefficients are public functions of already
public encrypted operands. No plaintext, predicate mask or secret key is put
in the certificate. This does not make the separate Source/Formation proofs
unnecessary; those are outside the implemented relation.

For each basis, a false fixed product relation gives a nonzero polynomial of
degree at most 8190. The fixed-witness root bound and the concrete full-message
Fiat–Shamir instantiation must be distinguished. The latter needs an independent
quantitative security review including oracle/grinding queries; hashes alone
are never arithmetic acceptance. The executable deliberately reports security
and SQL flags as false. [SOUNDNESS.md](SOUNDNESS.md) separates the algebraic
argument from the unassessed cryptographic assumptions.
[PARAMETERS.md](PARAMETERS.md) records the conditional fixed-pair noise analysis
and the unresolved confidentiality and SDK-rounding assessment.

```sh
cargo clippy --release --offline --locked -p bfv-unrelinearized-certificate --all-targets -- -D warnings
cargo test --release --offline --locked -p bfv-unrelinearized-certificate -- --test-threads=1
cargo run --release --offline --locked -p bfv-unrelinearized-certificate -- --show-profile
cargo run --release --offline --locked -p bfv-unrelinearized-certificate -- --public-fixture
cargo run --release --offline --locked -p bfv-unrelinearized-certificate -- --private-formation-fixture
```

Default execution reports metadata only. The explicit public fixture measures
fresh encryption, the actual SDK product, certificate construction and a fresh
complete arithmetic check and actual client decryption. Real network, agreed
head, Source proofs, client SQL
completion and durable storage costs must be measured separately before any
claim about complete queries. [VALIDATION.md](VALIDATION.md) records the owning
tests and one local native observation, with those exclusions explicit.

The separate [private Goldilocks witness candidate](src/gold_formation/README.md)
is owner-only pre-proving arithmetic. Explicit `--private-formation-fixture`
derives/checks bounded shared-secret/error/quotient witnesses from real SDK
ciphertexts and the SAME original guarded plaintext buffers, and reports no key
or witness values. All19 arithmetic tests and strict Clippy passed; the
[private diagnostic observation](src/gold_formation/VALIDATION.md) took13.7364ms
including SDK preparation/product. Cryptographic Formation, Source/SQL authority
and the500ms complete-query target remain open. The public certificate profile and
`--public-fixture` protocol are unchanged. The client fixture retains two extra
guarded4096-word inputs; logical buffer counts do not establish process RSS.
