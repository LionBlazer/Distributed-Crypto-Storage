# Peer transport

TLS 1.3 mutual authentication and bounded framing over TCP, using pinned rustls
0.23.45 with ring. Two explicit trust models share the same credential and framing
contracts:

- `Connector::new` and `Acceptor::new` use the caller's configured CA. This remains
  an explicit diagnostic/private-network mode; it does not establish open admission.
- `Connector::permissionless` and `Acceptor::permissionless` admit independently
  generated, valid self-signed participant identities without an enrollment CA.
  The connector verifies the exact `Endpoint` certificate SHA-256 fingerprint
  inside the TLS handshake, before sending its own authentication credential.
  The acceptor requires a client credential and genuine proof of key possession.

Permissionless verification delegates certificate checks to the standard WebPKI
verifiers with the presented certificate as its only trust anchor and no
intermediates. The resulting one-certificate path must have a valid self-signature,
matching issuer/subject, current validity and appropriate key usage. Server
credentials must also contain the service SAN `dcs-peer`; dual-role peers should
specify DigitalSignature plus ServerAuth and ClientAuth EKUs. This SAN is a protocol
service label, not a claim of authority over public DNS. A CA-issued leaf does not
become self-signed by being added as its own trust anchor and is rejected here.

TLS CertificateVerify signatures are checked by rustls/ring's actual
`verify_tls13_signature` implementation for both roles. The custom trust adapters
return WebPKI's actual validation result; they never manufacture a verification
assertion. Both constructors check that the private key matches the certificate.
TLS 1.2, certificate chains in permissionless mode, anonymous clients and plaintext
fallbacks are excluded. Permissionless session resumption/tickets are disabled so
every connection repeats its identity pin and key-possession checks. The historical
CA connector also retains its exact endpoint pin check after the handshake.

`Identity` owns one endpoint's TLS credential, wipes its private PKCS#8 bytes on
drop and has no Debug implementation. It is distinct from owner FHE/AEAD keys.
Identity generation and endpoint discovery belong to the calling application.
An endpoint pin must identify the peer the caller intends to contact; accepting a
random discovered identity does not authenticate a network's history or defend
against eclipse attacks. Transport admission grants no SQL write permission, proof
acceptance, resource weight or consensus vote. One participant can generate many
keys; the separate version journal must resist that with validated resource weight.
Certificate rotation changes the exact identity fingerprint and requires endpoint
rediscovery. Certificate time checks depend on the local clock and are unrelated
to agreed database-version freshness. No global trust store is read or changed.

`read_frame` and `write_frame` use versioned framing and a 64 MiB cap. The declared
length is checked before payload allocation. Connections have a two-second connect
timeout and 15-second read/write timeouts. These are transport bounds, not a
proof of a whole-process RAM or latency target. Windows accepted sockets are
explicitly returned to blocking mode before the TLS handshake.

There are no direct project dependencies, GUI, process supervision or database
operations. The [peer runtime](../peer-runtime/README.md) consumes this contract.
Real loopback TLS tests cover independently self-signed participants, wrong endpoint
pins, damaged certificate signatures, mismatched keys, valid certificates paired
with hostile handshake signing keys, validity/name/usage rejection and unchanged
CA-mode authentication. Test credentials are generated in memory only.

The upstream [verifier contract](https://docs.rs/rustls/latest/rustls/client/danger/trait.ServerCertVerifier.html)
distinguishes certificate acceptance from handshake signature verification;
[TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3) defines the
CertificateVerify key-possession step. The implementation was checked against the
pinned local rustls/WebPKI source, including WebPKI's signed-chain verification.

```sh
cargo test --release --locked --offline -p peer-transport -- --test-threads=1
cargo clippy --release --locked --offline -p peer-transport --all-targets -- -D warnings
```
