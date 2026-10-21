//! Shared actual dcs-peer child/TLS lifecycle for integration tests.
use peer_runtime::{Bootstrap, Connector, Endpoint, Identity, RemotePeer, Request, Response};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) fn identity() -> Identity {
    let mut params = CertificateParams::new(vec!["dcs-peer".into()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    Identity {
        certificate: certificate.der().to_vec(),
        private_key_pkcs8: key.serialize_der(),
    }
}

pub(crate) struct Process {
    child: Child,
    endpoint: Endpoint,
}
impl Process {
    pub fn start(owner: [u8; 32], id: u64) -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.local/network-tests")
            .join(format!(
                "private-product-{}-{id}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        let mut command = Command::new(env!("CARGO_BIN_EXE_dcs-peer"));
        let threads = std::env::var("DCS_TEST_PEER_THREADS").unwrap_or_else(|_| "2".into());
        assert!(threads.parse::<usize>().is_ok_and(|n| (1..=8).contains(&n)));
        command
            .args(["--state-dir", directory.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("RAYON_NUM_THREADS", threads);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().unwrap();
        let config = Bootstrap {
            identity: identity(),
            authority: vec![],
            owner,
            node_id: id,
            quota_bytes: 16 * 1024 * 1024,
            listen: "127.0.0.1:0".parse().unwrap(),
        };
        let secret = zeroize::Zeroizing::new(serde_json::to_vec(&config).unwrap());
        peer_transport::write_frame(&mut child.stdin.take().unwrap(), &secret, 64 * 1024).unwrap();
        drop(secret);
        drop(config);
        let stdout = child.stdout.take().unwrap();
        let (sent, received) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = sent.send(result);
        });
        let endpoint = match received.recv_timeout(Duration::from_secs(20)) {
            Ok(Ok(line)) => match serde_json::from_str(&line) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    panic!("Invalid daemon startup at {}: {error}", directory.display());
                }
            },
            other => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                panic!(
                    "Daemon startup failed at {}: {other:?}",
                    directory.display()
                );
            }
        };
        reader.join().unwrap();
        assert_ne!(child.id(), std::process::id());
        println!("private_product_peer_pid={}", child.id());
        Self { child, endpoint }
    }
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn remote(&self, connector: &Connector) -> RemotePeer {
        RemotePeer::new(self.endpoint.clone(), connector.clone())
    }
    pub fn finish(mut self, remote: &RemotePeer) {
        assert!(matches!(
            remote.call(Request::Shutdown).unwrap(),
            Response::Done
        ));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Peer did not shut down after stream cleanup"
            );
            std::thread::yield_now();
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
