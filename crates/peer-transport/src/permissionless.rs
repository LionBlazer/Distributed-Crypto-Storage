//! Self-signed identity admission with ordinary WebPKI and TLS signature checks.
//! A new identity is not a vote, a storage permission or a computation proof.
use super::*;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, verify_tls13_signature},
    pki_types::UnixTime,
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::{CertifiedKey, SingleCertAndKey},
};

fn self_signed_roots(certificate: &CertificateDer<'_>) -> Result<Arc<RootCertStore>, TlsError> {
    let mut anchors = RootCertStore::empty();
    anchors.add(certificate.clone())?;
    Ok(Arc::new(anchors))
}

fn no_intermediates(intermediates: &[CertificateDer<'_>]) -> Result<(), TlsError> {
    if !intermediates.is_empty() {
        return Err(TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer,
        ));
    }
    Ok(())
}

fn verify_self_signed_client(
    provider: &Arc<CryptoProvider>,
    certificate: &CertificateDer<'_>,
    now: UnixTime,
) -> Result<ClientCertVerified, TlsError> {
    // This certificate is its own ONLY trust anchor. WebPKI still builds and
    // verifies the one-certificate signed path, issuer/subject, validity and EKU.
    // A CA-signed leaf does not become self-signed just by putting it in this store.
    let verifier = WebPkiClientVerifier::builder_with_provider(
        self_signed_roots(certificate)?,
        provider.clone(),
    )
    .build()
    .map_err(|error| TlsError::General(error.to_string()))?;
    verifier.verify_client_cert(certificate, &[], now)
}

#[derive(Debug)]
struct PinnedSelfSignedServer {
    provider: Arc<CryptoProvider>,
    expected_identity: [u8; 32],
}
impl ServerCertVerifier for PinnedSelfSignedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        no_intermediates(intermediates)?;
        if fingerprint(end_entity.as_ref()) != self.expected_identity {
            return Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        let verifier = WebPkiServerVerifier::builder_with_provider(
            self_signed_roots(end_entity)?,
            self.provider.clone(),
        )
        .build()
        .map_err(|error| TlsError::General(error.to_string()))?;
        verifier.verify_server_cert(end_entity, &[], server_name, ocsp_response, now)
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("Only TLS 1.3 is supported".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct OpenSelfSignedClients {
    provider: Arc<CryptoProvider>,
}
impl ClientCertVerifier for OpenSelfSignedClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        no_intermediates(intermediates)?;
        verify_self_signed_client(&self.provider, end_entity, now)
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("Only TLS 1.3 is supported".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl Connector {
    /// Any participant may generate its own valid self-signed identity. The exact
    /// server certificate identity is pinned by each Endpoint before TLS completes.
    /// No central authority, invited membership or TLS verification bypass is used.
    pub fn permissionless(identity: &Identity) -> io::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let certificate = CertificateDer::from(identity.certificate.clone());
        verify_self_signed_client(&provider, &certificate, UnixTime::now())
            .map_err(io::Error::other)?;
        let certified = CertifiedKey::from_der(vec![certificate], key(identity), &provider)
            .map_err(io::Error::other)?;
        // Ring exposes the public key: reject unknown consistency as well as mismatch.
        certified.keys_match().map_err(io::Error::other)?;
        Ok(Self {
            mode: ConnectorMode::Permissionless {
                provider,
                identity: Arc::new(certified),
            },
        })
    }

    pub(super) fn client_config(&self, endpoint: &Endpoint) -> io::Result<Arc<ClientConfig>> {
        match &self.mode {
            ConnectorMode::Authority(config) => Ok(config.clone()),
            ConnectorMode::Permissionless { provider, identity } => {
                let mut config = ClientConfig::builder_with_provider(provider.clone())
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(io::Error::other)?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(PinnedSelfSignedServer {
                        provider: provider.clone(),
                        expected_identity: endpoint.identity,
                    }))
                    .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(identity.clone())));
                // Every connection checks the requested identity and proves key possession.
                config.resumption = rustls::client::Resumption::disabled();
                Ok(Arc::new(config))
            }
        }
    }
}

impl Acceptor {
    /// Requires genuine mutually authenticated TLS using independently self-signed
    /// participant identities. Admission does not grant database write authority.
    pub fn permissionless(identity: &Identity) -> io::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let certificate = CertificateDer::from(identity.certificate.clone());
        PinnedSelfSignedServer {
            provider: provider.clone(),
            expected_identity: identity.fingerprint(),
        }
        .verify_server_cert(
            &certificate,
            &[],
            &ServerName::try_from("dcs-peer").map_err(io::Error::other)?,
            &[],
            UnixTime::now(),
        )
        .map_err(io::Error::other)?;
        let certified = CertifiedKey::from_der(vec![certificate], key(identity), &provider)
            .map_err(io::Error::other)?;
        certified.keys_match().map_err(io::Error::other)?;
        let mut config = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_client_cert_verifier(Arc::new(OpenSelfSignedClients { provider }))
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
        config.send_tls13_tickets = 0;
        Ok(Self {
            config: Arc::new(config),
        })
    }
}
