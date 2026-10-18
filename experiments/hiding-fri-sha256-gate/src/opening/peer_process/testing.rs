//! TLS server-thread fixtures for owning protocol tests, never a live process fallback.
use super::{Error, OwnedDirectory, Result, identity};
use peer_runtime::{RemotePeer, Request, Response};
pub(in crate::opening) struct PublicPeer {
    server: peer_runtime::RunningServer,
    pub(in crate::opening) remote: RemotePeer,
    pub(in crate::opening) traces: std::sync::Arc<std::sync::Mutex<Vec<peer_runtime::Trace>>>,
    // Drop AFTER the stopped server releases its Store directory lock on Windows.
    _directory: OwnedDirectory,
}
impl PublicPeer {
    pub(in crate::opening) fn start(bundle: &peer_runtime::RawBundle) -> Result<Self> {
        use std::sync::{Arc, Mutex};
        let directory = OwnedDirectory::new()?;
        let owner = identity();
        let connector = peer_runtime::Connector::permissionless(&owner)?;
        let server = peer_runtime::PeerServer::bind(
            peer_runtime::Bootstrap {
                identity: identity(),
                authority: Vec::new(),
                owner: owner.fingerprint(),
                node_id: 1,
                quota_bytes: 64 * 1024 * 1024,
                listen: "127.0.0.1:0".parse().map_err(|_| Error::Binding)?,
            },
            &directory.peer_path(),
        )?
        .spawn()?;
        let traces = Arc::new(Mutex::new(Vec::new()));
        let observed = traces.clone();
        let remote =
            RemotePeer::new(server.endpoint.clone(), connector).with_trace(Arc::new(move |t| {
                if let Ok(mut traces) = observed.lock() {
                    traces.push(t);
                }
            }));
        let peer = Self {
            _directory: directory,
            server,
            remote,
            traces,
        };
        let expected = *bundle
            .target_version()
            .map_err(|_| Error::Binding)?
            .object();
        match peer.remote.call(Request::Store(bundle.clone()))? {
            Response::Stored(info) if info.id == expected => Ok(peer),
            _ => Err(Error::UnexpectedReply),
        }
    }
    pub(in crate::opening) fn last_request_id(&self) -> Result<u64> {
        self.traces
            .lock()
            .map_err(|_| Error::Binding)?
            .last()
            .map(|t| t.request_id)
            .ok_or(Error::Binding)
    }
}
impl PublicPeer {
    pub(in crate::opening) fn corrupt_index_tail(&self, object: [u8; 32]) -> Result<()> {
        use std::io::{Read, Seek, SeekFrom, Write};
        let name = object
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            + ".object2";
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self._directory.peer_path().join(name))?;
        file.seek(SeekFrom::End(-1))?;
        let mut byte = [0];
        file.read_exact(&mut byte)?;
        file.seek(SeekFrom::End(-1))?;
        file.write_all(&[byte[0] ^ 1])?;
        file.sync_all()?;
        Ok(())
    }
}

impl Drop for PublicPeer {
    fn drop(&mut self) {
        self.server.stop();
    }
}
