//! TLS 1.3 mutual authentication, endpoint pinning and bounded byte frames.
//! Identity admission is caller policy; this transport does not establish consensus.
#![forbid(unsafe_code)]

mod cancellation;
mod deadline;
mod permissionless;
pub use cancellation::{Cancellation, RequestControl, RequestScope};
pub use deadline::ConnectionDeadline;

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroize;

pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
pub const IO_TIMEOUT: Duration = Duration::from_secs(15);
const MAGIC: &[u8; 8] = b"DCSNET01";

/// Secret TLS credential. Only bootstrap through private IPC/secret storage.
#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub certificate: Vec<u8>,
    pub private_key_pkcs8: Vec<u8>,
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.private_key_pkcs8.zeroize();
    }
}
impl Identity {
    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint(&self.certificate)
    }
}
pub fn fingerprint(certificate: &[u8]) -> [u8; 32] {
    Sha256::digest(certificate).into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub address: SocketAddr,
    pub identity: [u8; 32],
}

/// Clones share immutable TLS credential/configuration handles, never an application or FHE key.
#[derive(Clone)]
pub struct Connector {
    mode: ConnectorMode,
}
#[derive(Clone)]
enum ConnectorMode {
    Authority(Arc<ClientConfig>),
    Permissionless {
        provider: Arc<rustls::crypto::CryptoProvider>,
        identity: Arc<rustls::sign::CertifiedKey>,
    },
}
#[derive(Clone)]
pub struct Acceptor {
    config: Arc<ServerConfig>,
}
/// Server-side TLS stream after endpoint authentication. Authentication itself
/// supplies no application, computation or agreement authority.
pub type AcceptedConnection = StreamOwned<ServerConnection, TcpStream>;
/// A TLS stream whose local socket is interrupted when its operation is cancelled.
pub struct CancellableConnection {
    stream: StreamOwned<ClientConnection, TcpStream>,
    _registration: Option<cancellation::Registration>,
}
impl Read for CancellableConnection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.read(bytes)
    }
}
impl CancellableConnection {
    /// Own an absolute budget in addition to the socket's inactivity timeout.
    pub fn deadline(&self, budget: Duration) -> io::Result<ConnectionDeadline> {
        ConnectionDeadline::new(&self.stream.sock, budget)
    }
    /// Set explicit operation I/O budgets after the bounded TLS handshake.
    /// Cancellation still interrupts the registered underlying socket.
    pub fn set_io_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.stream.sock.set_read_timeout(Some(timeout))?;
        self.stream.sock.set_write_timeout(Some(timeout))
    }
}
impl Write for CancellableConnection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
fn roots(authority: &[u8]) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(authority.to_vec()))
        .map_err(io::Error::other)?;
    Ok(roots)
}
fn key(identity: &Identity) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(identity.private_key_pkcs8.clone()).into()
}
impl Connector {
    pub fn new(identity: &Identity, authority: &[u8]) -> io::Result<Self> {
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(io::Error::other)?
                .with_root_certificates(roots(authority)?)
                .with_client_auth_cert(
                    vec![CertificateDer::from(identity.certificate.clone())],
                    key(identity),
                )
                .map_err(io::Error::other)?;
        Ok(Self {
            mode: ConnectorMode::Authority(Arc::new(config)),
        })
    }
    pub fn connect(
        &self,
        endpoint: &Endpoint,
    ) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
        self.connect_inner(endpoint, None)
            .map(|connection| connection.stream)
    }
    pub fn connect_cancellable(
        &self,
        endpoint: &Endpoint,
        cancellation: Option<&Cancellation>,
    ) -> io::Result<CancellableConnection> {
        self.connect_inner(endpoint, cancellation)
    }
    fn connect_inner(
        &self,
        endpoint: &Endpoint,
        cancellation: Option<&Cancellation>,
    ) -> io::Result<CancellableConnection> {
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        let mut socket = TcpStream::connect_timeout(&endpoint.address, Duration::from_secs(2))?;
        let registration = cancellation
            .map(|token| token.register(&socket))
            .transpose()?;
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
        socket.set_nodelay(true)?;
        let handshake_deadline = ConnectionDeadline::new(&socket, IO_TIMEOUT)?;
        let mut connection = ClientConnection::new(
            self.client_config(endpoint)?,
            ServerName::try_from("dcs-peer").map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        while connection.is_handshaking() {
            connection.complete_io(&mut socket)?;
        }
        let cert = connection
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| io::Error::other("Missing peer certificate"))?;
        if fingerprint(cert.as_ref()) != endpoint.identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Peer certificate does not match the configured endpoint",
            ));
        }
        drop(handshake_deadline);
        Ok(CancellableConnection {
            stream: StreamOwned::new(connection, socket),
            _registration: registration,
        })
    }
}
impl Acceptor {
    pub fn new(identity: &Identity, authority: &[u8]) -> io::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots(authority)?),
            provider.clone(),
        )
        .build()
        .map_err(io::Error::other)?;
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from(identity.certificate.clone())],
                key(identity),
            )
            .map_err(io::Error::other)?;
        Ok(Self {
            config: Arc::new(config),
        })
    }
    pub fn accept(
        &self,
        mut socket: TcpStream,
    ) -> io::Result<([u8; 32], StreamOwned<ServerConnection, TcpStream>)> {
        // Windows accepted sockets inherit the listener's nonblocking flag.
        socket.set_nonblocking(false)?;
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
        let handshake_deadline = ConnectionDeadline::new(&socket, IO_TIMEOUT)?;
        socket.set_nodelay(true)?;
        let mut connection =
            ServerConnection::new(self.config.clone()).map_err(io::Error::other)?;
        while connection.is_handshaking() {
            connection.complete_io(&mut socket)?;
        }
        let cert = connection
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| io::Error::other("Client authentication is required"))?;
        let identity = fingerprint(cert.as_ref());
        drop(handshake_deadline);
        Ok((identity, StreamOwned::new(connection, socket)))
    }
}

/// The declared length is checked before allocation or reading a payload.
pub fn read_frame(reader: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 16];
    reader.read_exact(&mut header)?;
    if &header[..8] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unsupported transport version",
        ));
    }
    let length = u64::from_be_bytes(header[8..].try_into().unwrap());
    if length > limit.min(MAX_FRAME_BYTES) as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Frame exceeds the configured bound",
        ));
    }
    let mut bytes = vec![0u8; length as usize];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
pub fn write_frame(writer: &mut impl Write, bytes: &[u8], limit: usize) -> io::Result<()> {
    if bytes.len() > limit.min(MAX_FRAME_BYTES) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Frame exceeds the configured bound",
        ));
    }
    writer.write_all(MAGIC)?;
    writer.write_all(&(bytes.len() as u64).to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hostile_lengths_are_rejected_before_any_body_is_read() {
        let mut input = MAGIC.to_vec();
        input.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            read_frame(&mut input.as_slice(), 1024).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn truncated_and_unknown_version_frames_never_produce_a_payload() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"ciphertext", 1024).unwrap();
        assert_eq!(
            read_frame(&mut wire.as_slice(), 1024).unwrap(),
            b"ciphertext"
        );
        wire.pop();
        assert!(read_frame(&mut wire.as_slice(), 1024).is_err());
        wire[0] ^= 1;
        assert!(read_frame(&mut wire.as_slice(), 1024).is_err());
    }
}
