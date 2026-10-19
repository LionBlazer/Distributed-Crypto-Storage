# Owner key and proof-epoch recovery

The [Core owner-state capability](../crates/bfv-query-core/src/owner_state/README.md)
encrypts the actual generated BFV secret, salted anchor opening and Ready epoch
opening under an externally custodied owner wrapping key. Restore requires the
independently retained full original setup, scope, record identity, authentic
anchor and complete Key33. It reopens both commitments and genuinely verifies
the original Key proof; it never rerandomizes a supposedly restored epoch.

The secret record has a fixed 8208-byte private payload. Exact degree, reserved
fields and all 8192 signed CBD coefficients are validated before the SDK receives
an internally generated official protobuf. AEAD authenticates the public role,
scope, record identity, full setup SHA256/SHA512, anchor and all Key33. Bounded
parsing alone supplies no authentication. Owned private buffers are guarded;
SDK/parser, native field/FFT/trace scratch and caller copies have no total erasure
guarantee. No plaintext secret getter was added.

## Actual native gate

```sh
cargo test --release --offline --locked -p bfv-query-core -p bfv-key-transform --features bfv-query-core/formation-proofs -- --test-threads=1
```

The complete run passed **132 runtime tests and 35 compile-fail contracts**:
six Key primitive cases, 92 Core unit cases, 34 integration cases and the Core
ownership contracts. The new runtime cases establish:

- Old ciphertext decrypts at every coefficient after the original Owner is dropped.
- Wrong authority, setup, rotation bytes, scope, record, role and anchor are rejected.
- Tampering, truncation, trailing bytes and resource/canonical-field aliases reject.
- Even authenticated malformed private coefficients reject before SDK decoding.
- The restored input salt opens the original Cs; an authenticated wrong salt fails.
- After the original Owner/anchor/epoch are destroyed, the restored full Key33
  produces five new Basis proofs and a Formation proof which a fresh public setup
  verifies. Wrong output salt, full Key33 and a genuinely damaged proof reject.
- The primitive's owned-evidence constructor retains exact original bytes only
  after genuine verification; a canonically repaired damaged trace commitment
  fails the actual cryptographic verifier.

There are six new runtime test functions in total. All existing generation/proof tests also
passed. All-target formation checking, key-only/default checking, strict Clippy
and workspace formatting passed. The requirements mirror matched.

The sole lock-file change adds existing locked `chacha20poly1305` 0.10.1 and
`prost` 0.14.4 as optional Core direct dependencies enabled by `key-proofs`.
No package/version, proof equation, profile or frame cap changed. An initial
locked check stopped before compilation until those new edges were resolved
offline; `owner-state-check-r2` is the successful imported-candidate check.
Three strict-Clippy suggestions were applied before the frozen native run.

## Scope and measurements

The full command took 821.282s, including 1m14s compilation. Key runtime took
15.33s, Core unit runtime 717.24s, eight integration executables 10.50s in total,
and the Core compile-fail contracts 3.43s. These are suite observations, not
per-operation recovery latency or distributed SQL timing.

The Windows observer retained 5820 samples across Cargo and ten actual test
executables, with maximum sampling gap 550.522ms. Maximum sampled and OS-peak
working set was 1,439,559,680 bytes; maximum sampled private bytes were
1,500,364,800. Neither the 1792MiB per-process soft fuse nor the 1800s runner
budget triggered. This does not certify whole-peer or concurrent-operation RAM.

The frozen 1461-file source manifest SHA256 is
`67AA51FCC8D3AE55E707162934759DE65C03C050231253D447155E03A71AF4FB`.
All raw hashes matched after the run, before this documentation update. Parent
commit was `f3f895f6dc15725ce165a77abe0ad90e2b995e6f`. Ignored receipts are in
`.local/private-peer-native-r1/owner-state-tests-r1/`. Stdout SHA256 is
`24E9A3AEFACC12DE1D51A8C7F3A4B98CF7A597C8E5B4CE28D5503A961EC08D6F`;
stderr SHA256 is
`80391E2FE4F35556A415D10B557A778A3B3A262C1A9ADAD3E200E4B071F6D5AA`.
Generated keys, witnesses, ciphertexts and receipts are not committed.

This provides authenticated custody of an owner-generated key pair, not a new
public evaluation-key same-secret theorem. It provides no atomic file writer,
OS keystore, password KDF or rollback protection. An old authentic snapshot is
still cryptographically valid. Source Ckey/salt, database signing authority,
controller/Registry openings, pending exact signed bytes and staged state still
need a durable owner store and reconciliation with a genuinely verified finalized
joint decision. Full SQL admission and recovery remain incomplete.
