//! Public non-secret identities are generated afresh; no key material is persisted.
use peer_transport::{Acceptor, Connector, Endpoint, Identity, read_frame, write_frame};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use std::{io, net::TcpListener, sync::Arc, thread};

fn params() -> CertificateParams {
    let mut params = CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params
}
fn self_signed() -> Identity {
    let key = KeyPair::generate().unwrap();
    let cert = params().self_signed(&key).unwrap();
    Identity {
        certificate: cert.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}
fn damaged_signature(identity: &Identity) -> Identity {
    let mut certificate = identity.certificate.clone();
    *certificate.last_mut().unwrap() ^= 1;
    Identity {
        certificate,
        private_key_pkcs8: identity.private_key_pkcs8.clone(),
    }
}
fn server(
    acceptor: Acceptor,
    identity: [u8; 32],
) -> (Endpoint, thread::JoinHandle<io::Result<[u8; 32]>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = Endpoint {
        address: listener.local_addr().unwrap(),
        identity,
    };
    let task = thread::spawn(move || {
        let (socket, _) = listener.accept()?;
        let (identity, mut stream) = acceptor.accept(socket)?;
        let message = read_frame(&mut stream, 1024)?;
        write_frame(&mut stream, &message, 1024)?;
        Ok(identity)
    });
    (endpoint, task)
}

#[test]
fn independent_self_signed_participants_exchange_real_mutually_authenticated_tls_frames() {
    let first = self_signed();
    let second = self_signed();
    assert_ne!(first.fingerprint(), second.fingerprint());
    let acceptor = Acceptor::permissionless(&first).unwrap();
    let connector = Connector::permissionless(&second).unwrap();
    let (endpoint, task) = server(acceptor, first.fingerprint());

    let mut connection = connector.connect(&endpoint).unwrap();
    write_frame(&mut connection, b"encrypted operation", 1024).unwrap();
    let received = read_frame(&mut connection, 1024).unwrap();

    assert_eq!(received, b"encrypted operation");
    assert_eq!(task.join().unwrap().unwrap(), second.fingerprint());
}

#[test]
fn another_valid_self_signed_server_cannot_impersonate_the_pinned_endpoint() {
    let actual = self_signed();
    let expected = self_signed();
    let client = self_signed();
    let connector = Connector::permissionless(&client).unwrap();
    let (mut endpoint, task) = server(
        Acceptor::permissionless(&actual).unwrap(),
        actual.fingerprint(),
    );
    endpoint.identity = expected.fingerprint();

    assert!(connector.connect(&endpoint).is_err());
    assert!(task.join().unwrap().is_err());
}

#[test]
fn a_matching_certificate_pin_does_not_authorize_a_damaged_certificate_signature() {
    let valid = self_signed();
    let damaged = damaged_signature(&valid);
    let client = self_signed();
    // The historical CA constructor configures credentials without claiming they
    // are self-signed. It lets this test deliver a hostile certificate over real TLS.
    let acceptor = Acceptor::new(&damaged, &client.certificate).unwrap();
    let connector = Connector::permissionless(&client).unwrap();
    let (endpoint, task) = server(acceptor, damaged.fingerprint());

    assert!(connector.connect(&endpoint).is_err());
    assert!(task.join().unwrap().is_err());
}

#[test]
fn open_admission_still_rejects_a_clients_invalid_self_signature() {
    let server_identity = self_signed();
    let client = damaged_signature(&self_signed());
    let acceptor = Acceptor::permissionless(&server_identity).unwrap();
    let connector = Connector::new(&client, &server_identity.certificate).unwrap();
    let (endpoint, task) = server(acceptor, server_identity.fingerprint());

    // A TLS1.3 client can finish its side before receiving the server's client-auth
    // rejection. No application request/response is accepted in either case.
    if let Ok(mut stream) = connector.connect(&endpoint) {
        let sent = write_frame(&mut stream, b"untrusted", 1024);
        assert!(sent.is_err() || read_frame(&mut stream, 1024).is_err());
    }
    assert!(task.join().unwrap().is_err());
}

#[test]
fn a_certificate_cannot_be_paired_with_another_participants_private_key() {
    let first = self_signed();
    let second = self_signed();
    let mismatched = Identity {
        certificate: first.certificate.clone(),
        private_key_pkcs8: second.private_key_pkcs8.clone(),
    };

    assert!(Connector::permissionless(&mismatched).is_err());
    assert!(Acceptor::permissionless(&mismatched).is_err());
}

#[test]
fn a_valid_pinned_certificate_cannot_hide_a_handshake_signed_by_another_key() {
    use rustls::{
        ServerConfig, ServerConnection,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
        sign::{CertifiedKey, SingleCertAndKey},
    };
    let server_identity = self_signed();
    let wrong_signer = self_signed();
    let client = self_signed();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let wrong_key = provider
        .key_provider
        .load_private_key(PrivatePkcs8KeyDer::from(wrong_signer.private_key_pkcs8.clone()).into())
        .unwrap();
    // Malicious endpoint fixture: bypass only its OWN key/certificate consistency
    // builder check, then let the real connector verify the actual TLS signature.
    let credential = CertifiedKey::new(
        vec![CertificateDer::from(server_identity.certificate.clone())],
        wrong_key,
    );
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(credential)));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = Endpoint {
        address: listener.local_addr().unwrap(),
        identity: server_identity.fingerprint(),
    };
    let task = thread::spawn(move || -> io::Result<()> {
        let (mut socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(peer_transport::IO_TIMEOUT))?;
        socket.set_write_timeout(Some(peer_transport::IO_TIMEOUT))?;
        let mut connection = ServerConnection::new(Arc::new(config)).map_err(io::Error::other)?;
        while connection.is_handshaking() {
            connection.complete_io(&mut socket)?;
        }
        Ok(())
    });
    let connector = Connector::permissionless(&client).unwrap();

    assert!(connector.connect(&endpoint).is_err());
    assert!(task.join().unwrap().is_err());
}

#[test]
fn self_signed_client_admission_rejects_a_handshake_signed_by_another_key() {
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
        sign::{CertifiedKey, SingleCertAndKey},
    };
    let server_identity = self_signed();
    let client = self_signed();
    let wrong_signer = self_signed();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let wrong_key = provider
        .key_provider
        .load_private_key(PrivatePkcs8KeyDer::from(wrong_signer.private_key_pkcs8.clone()).into())
        .unwrap();
    let credential = CertifiedKey::new(
        vec![CertificateDer::from(client.certificate.clone())],
        wrong_key,
    );
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_identity.certificate.clone()))
        .unwrap();
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(credential)));
    let (endpoint, task) = server(
        Acceptor::permissionless(&server_identity).unwrap(),
        server_identity.fingerprint(),
    );
    let mut socket = std::net::TcpStream::connect(endpoint.address).unwrap();
    socket
        .set_read_timeout(Some(peer_transport::IO_TIMEOUT))
        .unwrap();
    socket
        .set_write_timeout(Some(peer_transport::IO_TIMEOUT))
        .unwrap();
    let mut connection =
        ClientConnection::new(Arc::new(config), ServerName::try_from("dcs-peer").unwrap()).unwrap();
    let handshake = (|| -> io::Result<()> {
        while connection.is_handshaking() {
            connection.complete_io(&mut socket)?;
        }
        Ok(())
    })();

    if handshake.is_ok() {
        let mut stream = StreamOwned::new(connection, socket);
        let sent = write_frame(&mut stream, b"untrusted", 1024);
        assert!(sent.is_err() || read_frame(&mut stream, 1024).is_err());
    }
    assert!(task.join().unwrap().is_err());
}

#[test]
fn malformed_expired_wrong_name_and_wrong_usage_credentials_are_rejected() {
    let malformed = Identity {
        certificate: b"not DER".to_vec(),
        private_key_pkcs8: vec![0; 32],
    };
    assert!(Connector::permissionless(&malformed).is_err());
    assert!(Acceptor::permissionless(&malformed).is_err());
    let key = KeyPair::generate().unwrap();
    let mut expired_params = params();
    expired_params.not_before = rcgen::date_time_ymd(2010, 1, 1);
    expired_params.not_after = rcgen::date_time_ymd(2011, 1, 1);
    let expired = Identity {
        certificate: expired_params.self_signed(&key).unwrap().der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    };
    assert!(Connector::permissionless(&expired).is_err());
    assert!(Acceptor::permissionless(&expired).is_err());
    let mut wrong_name = params();
    wrong_name.subject_alt_names = CertificateParams::new(vec!["another-service".into()])
        .unwrap()
        .subject_alt_names;
    let wrong_name = Identity {
        certificate: wrong_name.self_signed(&key).unwrap().der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    };
    assert!(Acceptor::permissionless(&wrong_name).is_err());
    let mut only_server = params();
    only_server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let only_server = Identity {
        certificate: only_server.self_signed(&key).unwrap().der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    };
    assert!(Connector::permissionless(&only_server).is_err());
}

#[test]
fn historical_ca_mode_remains_explicit_and_does_not_become_permissionless() {
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let issued = || {
        let key = KeyPair::generate().unwrap();
        Identity {
            certificate: params().signed_by(&key, &issuer).unwrap().der().to_vec(),
            private_key_pkcs8: key.serialize_der(),
        }
    };
    let server_identity = issued();
    let client = issued();
    assert!(Connector::permissionless(&client).is_err());
    assert!(Acceptor::permissionless(&server_identity).is_err());
    let connector = Connector::new(&client, ca.der()).unwrap();
    let acceptor = Acceptor::new(&server_identity, ca.der()).unwrap();
    let (endpoint, task) = server(acceptor, server_identity.fingerprint());

    let mut stream = connector.connect(&endpoint).unwrap();
    write_frame(&mut stream, b"explicit CA diagnostic", 1024).unwrap();

    assert_eq!(
        read_frame(&mut stream, 1024).unwrap(),
        b"explicit CA diagnostic"
    );
    assert_eq!(task.join().unwrap().unwrap(), client.fingerprint());
}

#[test]
fn cancelling_an_actual_tls_response_wait_finishes_before_server_release() -> io::Result<()> {
    held_tls_response_finishes_before_release(ResponseWaitStop::Cancellation)
}

#[test]
fn absolute_deadline_ends_an_idle_tls_response_wait_before_server_release() -> io::Result<()> {
    held_tls_response_finishes_before_release(ResponseWaitStop::Deadline)
}

#[test]
fn cancelling_a_tls_handshake_finishes_before_server_release() -> io::Result<()> {
    held_tls_response_finishes_before_release(ResponseWaitStop::Handshake)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseWaitStop {
    Cancellation,
    Deadline,
    Handshake,
}

fn held_tls_response_finishes_before_release(stop_by: ResponseWaitStop) -> io::Result<()> {
    use peer_transport::Cancellation;
    use std::io::Read;
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::{Duration, Instant},
    };

    const SETUP: Duration = Duration::from_secs(20);
    const INACTIVITY: Duration = Duration::from_secs(10);
    const CANCEL: Duration = Duration::from_secs(2);
    const REQUEST: &[u8] = b"PUBLIC TLS cancellation request";
    fn receive<T>(
        stage: &'static str,
        receiver: &mpsc::Receiver<T>,
        expires: Instant,
    ) -> io::Result<T> {
        let remaining = expires
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        receiver.recv_timeout(remaining).map_err(|error| {
            io::Error::new(
                match error {
                    mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
                    mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe,
                },
                stage,
            )
        })
    }
    fn joined<T>(result: thread::Result<T>) -> io::Result<T> {
        result.map_err(|_| io::Error::other("TLS cancellation test worker panicked"))
    }
    struct Release {
        sender: Option<mpsc::SyncSender<()>>,
        stop: Arc<AtomicBool>,
    }
    impl Drop for Release {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(sender) = self.sender.take() {
                let _ = sender.send(());
            }
        }
    }

    // Arrange genuine, fresh, non-secret TLS participants using the existing helper.
    let server_identity = self_signed();
    let client_identity = self_signed();
    let expected_client = client_identity.fingerprint();
    let acceptor = Acceptor::permissionless(&server_identity)?;
    let connector = Connector::permissionless(&client_identity)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = Endpoint {
        address: listener.local_addr()?,
        identity: server_identity.fingerprint(),
    };
    let cancellation = Cancellation::default();
    let observed = Instant::now();

    thread::scope(|scope| -> io::Result<()> {
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let (seen_sender, seen_receiver) = mpsc::sync_channel(1);
        let (reading_sender, reading_receiver) = mpsc::sync_channel(1);
        let (read_sender, read_receiver) = mpsc::sync_channel(1);
        let (cancel_sender, cancel_receiver) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let holding = Arc::new(AtomicBool::new(false));
        // INSIDE the scope, before worker owners: unwind releases the server
        // before thread::scope can perform any implicit joins.
        let release = Release {
            sender: Some(release_sender),
            stop: stop.clone(),
        };
        let server_holding = holding.clone();
        let server = scope.spawn(move || -> io::Result<()> {
            let expires = Instant::now() + SETUP;
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if stop.load(Ordering::Acquire) || Instant::now() >= expires {
                            return Err(io::Error::from(io::ErrorKind::TimedOut));
                        }
                        thread::park_timeout(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error),
                }
            };
            if stop_by == ResponseWaitStop::Handshake {
                socket.set_read_timeout(Some(INACTIVITY))?;
                // Observe an actual TLS ClientHello record beginning, then
                // deliberately send no ServerHello. This is no TLS-positive.
                let mut record_type = [0];
                socket.read_exact(&mut record_type)?;
                if record_type != [22] {
                    return Err(io::Error::other("Expected TLS handshake record"));
                }
                server_holding.store(true, Ordering::Release);
                seen_sender.send(()).map_err(io::Error::other)?;
                let held = release_receiver
                    .recv_timeout(INACTIVITY)
                    .map_err(io::Error::other);
                server_holding.store(false, Ordering::Release);
                held?;
                drop(socket);
                return Ok(());
            }
            let (identity, mut stream) = acceptor.accept(socket)?;
            stream.sock.set_read_timeout(Some(INACTIVITY))?;
            stream.sock.set_write_timeout(Some(INACTIVITY))?;
            if identity != expected_client || read_frame(&mut stream, 1024)? != REQUEST {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Real TLS request mismatch",
                ));
            }
            server_holding.store(true, Ordering::Release);
            eprintln!(
                "tls_cancel phase=server_holding elapsed_us={}",
                observed.elapsed().as_micros()
            );
            seen_sender.send(()).map_err(io::Error::other)?;
            // No response, close_notify, socket shutdown or stream drop until
            // this INDEPENDENT release (or the 10-second failure bound).
            let held = release_receiver
                .recv_timeout(INACTIVITY)
                .map_err(io::Error::other);
            server_holding.store(false, Ordering::Release);
            held?;
            Ok(())
        });
        let read_token = cancellation.clone();
        let mut reader = Some(scope.spawn(move || {
            let result = (|| -> io::Result<io::Result<Vec<u8>>> {
                if stop_by == ResponseWaitStop::Handshake {
                    reading_sender.send(()).map_err(io::Error::other)?;
                }
                let mut stream = connector.connect_cancellable(&endpoint, Some(&read_token))?;
                if stop_by == ResponseWaitStop::Handshake {
                    return Err(io::Error::other("Unanswered TLS handshake completed"));
                }
                stream.set_io_timeout(INACTIVITY)?;
                write_frame(&mut stream, REQUEST, 1024)?;
                let deadline = if stop_by == ResponseWaitStop::Deadline {
                    Some(stream.deadline(Duration::from_millis(100))?)
                } else {
                    None
                };
                // This announces intent to read, not proof that the scheduler
                // has entered the OS recv syscall. No sleep claims that proof.
                reading_sender.send(()).map_err(io::Error::other)?;
                eprintln!(
                    "tls_cancel phase=read_start elapsed_us={}",
                    observed.elapsed().as_micros()
                );
                let read = read_frame(&mut stream, 1024);
                eprintln!(
                    "tls_cancel phase=read_return error={:?} elapsed_us={}",
                    read.as_ref().err().map(io::Error::kind),
                    observed.elapsed().as_micros()
                );
                drop(deadline);
                drop(stream); // Include actual TLS/socket registration cleanup.
                eprintln!(
                    "tls_cancel phase=connection_dropped elapsed_us={}",
                    observed.elapsed().as_micros()
                );
                Ok(read)
            })();
            let _ = read_sender.send(result);
        }));
        let mut cancelling = None;
        let observation = (|| -> io::Result<()> {
            let setup_expires = Instant::now() + SETUP;
            receive("server receipt", &seen_receiver, setup_expires)?;
            receive("read intent", &reading_receiver, setup_expires)?;
            if !matches!(read_receiver.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                return Err(io::Error::other("Read finished before actual cancellation"));
            }
            if !holding.load(Ordering::Acquire) {
                return Err(io::Error::other("Server did not retain the response wait"));
            }

            // Act: cancel the SAME token registered by the real Connector.
            // One absolute observation budget covers BOTH completion signals
            // and actual joins; it is not renewed for the second receive.
            let expires = Instant::now() + CANCEL;
            if stop_by != ResponseWaitStop::Deadline {
                let cancel_token = cancellation.clone();
                cancelling = Some(scope.spawn(move || {
                    eprintln!(
                        "tls_cancel phase=cancel_start elapsed_us={}",
                        observed.elapsed().as_micros()
                    );
                    cancel_token.cancel();
                    eprintln!(
                        "tls_cancel phase=cancel_return elapsed_us={}",
                        observed.elapsed().as_micros()
                    );
                    let _ = cancel_sender.send(());
                }));
                receive("cancel return", &cancel_receiver, expires)?;
            }
            let result = receive("read and connection drop", &read_receiver, expires)?;
            let read = if stop_by == ResponseWaitStop::Handshake {
                match result {
                    Err(error) => Err(error),
                    Ok(_) => return Err(io::Error::other("Unanswered TLS handshake succeeded")),
                }
            } else {
                result?
            };
            match (stop_by, read) {
                (ResponseWaitStop::Deadline, Err(error))
                    if error.kind() == io::ErrorKind::TimedOut => {}
                (ResponseWaitStop::Cancellation | ResponseWaitStop::Handshake, Err(error))
                    if !matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                (_, Err(_)) => {
                    return Err(io::Error::other("Read did not report the requested stop"));
                }
                (_, Ok(_)) => return Err(io::Error::other("Server sent no response payload")),
            }
            if let Some(worker) = cancelling.take() {
                joined(worker.join())?;
            }
            joined(
                reader
                    .take()
                    .ok_or_else(|| io::Error::other("Missing read worker"))?
                    .join(),
            )?;
            if Instant::now() >= expires
                || cancellation.is_cancelled() != (stop_by != ResponseWaitStop::Deadline)
                || !holding.load(Ordering::Acquire)
            {
                return Err(io::Error::other(
                    "Cancellation did not finish before independent server release",
                ));
            }
            Ok(())
        })();

        // Always release first on failure; then join EVERY remaining worker.
        // No unwrap/early propagation can strand a held server on an error.
        eprintln!(
            "tls_cancel phase=server_release elapsed_us={}",
            observed.elapsed().as_micros()
        );
        drop(release);
        let reader_join = reader.map(|worker| joined(worker.join())).unwrap_or(Ok(()));
        let cancel_join = cancelling
            .map(|worker| joined(worker.join()))
            .unwrap_or(Ok(()));
        let server_join = joined(server.join());
        observation?;
        reader_join?;
        cancel_join?;
        server_join??;
        Ok(())
    })
}
