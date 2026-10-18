//! One explicitly named dcs-peer process, existing framed bootstrap and parent EOF lifetime.
pub(in crate::opening) use directory::OwnedDirectory;
pub(in crate::opening) use identity::identity;
mod directory;
mod identity;
#[cfg(test)]
mod testing;
use peer_runtime::{
    Bootstrap, Connector, Endpoint, RawBundle, RemotePeer, Request, Response, Trace,
};
use std::{
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
#[cfg(test)]
pub(in crate::opening) use testing::PublicPeer;
#[derive(Debug)]
pub(in crate::opening) enum Error {
    Binding,
    #[cfg(test)]
    UnexpectedReply,
    Io(io::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Binding => f.write_str("Invalid experiment peer process binding"),
            #[cfg(test)]
            Self::UnexpectedReply => f.write_str("Unexpected experiment peer reply"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
pub(in crate::opening) type Result<T> = std::result::Result<T, Error>;
const LOG_CAP: usize = 64 * 1024;
const ENDPOINT_CAP: u64 = 4096;

pub(in crate::opening) fn checked_executable(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || !path.is_file() {
        return Err(Error::Binding);
    }
    Ok(path.canonicalize()?)
}
struct Captured {
    bytes: Vec<u8>,
    total: u64,
}
fn capture(mut input: impl Read, mut bytes: Vec<u8>) -> io::Result<Captured> {
    let mut total = bytes.len() as u64;
    bytes.truncate(LOG_CAP);
    let mut buffer = [0u8; 4096];
    loop {
        let n = match input.read(&mut buffer) {
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if n == 0 {
            return Ok(Captured { bytes, total });
        }
        total = total.saturating_add(n as u64);
        bytes.extend_from_slice(&buffer[..n.min(LOG_CAP - bytes.len())]);
    }
}
/// Sole writer is Child.stdin; it is never cloned or handed to the daemon.
/// Hard owner termination closes it: existing daemon watch_parent exits even
/// during FHE. Before bootstrap, a closed pipe instead fails read_frame.
struct OwnedChild {
    child: Child,
    stdout: Option<JoinHandle<io::Result<Captured>>>,
    stderr: Option<JoinHandle<io::Result<Captured>>>,
}
pub(in crate::opening) struct Completion {
    pub(in crate::opening) code: i32,
    pub(in crate::opening) stdout: String,
    pub(in crate::opening) stderr: String,
}
impl OwnedChild {
    fn stop(&mut self) -> io::Result<(ExitStatus, bool, Captured, Captured)> {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut forced = false;
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                forced = true;
                self.child.kill()?;
                break self.child.wait()?;
            }
            thread::sleep(Duration::from_millis(10));
        };
        // Process is joined before the readers: its non-inherited pipe writers
        // are closed. Both drains retain at most LOG_CAP bytes, but count all.
        let take = |handle: &mut Option<JoinHandle<io::Result<Captured>>>| {
            handle
                .take()
                .ok_or_else(|| io::Error::other("Missing peer output reader"))?
                .join()
                .map_err(|_| io::Error::other("Peer output reader panicked"))?
        };
        let stdout = take(&mut self.stdout)?;
        let stderr = take(&mut self.stderr)?;
        Ok((status, forced, stdout, stderr))
    }
    fn failure(&mut self, error: impl std::fmt::Display) -> Error {
        let detail = match self.stop() {
            Ok((status, forced, out, err)) => format!(
                "{error}; peer={status}; forced={forced}; stdout({}B)={}; stderr({}B)={}",
                out.total,
                String::from_utf8_lossy(&out.bytes),
                err.total,
                String::from_utf8_lossy(&err.bytes)
            ),
            Err(stop) => format!("{error}; peer cleanup: {stop}"),
        };
        Error::Io(io::Error::other(detail))
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        // No error path or unwinding can leave this owned daemon running. The
        // existing EOF supervisor also covers forced termination of THIS owner.
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.stdout.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr.take() {
            let _ = reader.join();
        }
    }
}
/// Client process supervisor only; peer receives public/encrypted request bytes.
pub(in crate::opening) struct ProcessPeer {
    child: OwnedChild,
    pub(in crate::opening) remote: RemotePeer,
    traces: Arc<Mutex<Vec<Trace>>>,
    // Last field drops after the child has released every file/Store lock.
    _directory: OwnedDirectory,
    owner: peer_transport::Identity,
    quota: u64,
}
impl ProcessPeer {
    pub(in crate::opening) fn start(executable: &Path, bundle: &RawBundle) -> Result<Self> {
        let mut peer = Self::spawn(executable, 64 * 1024 * 1024)?;
        let object = *bundle
            .target_version()
            .map_err(|_| Error::Binding)?
            .object();
        match peer.remote.call(Request::Store(bundle.clone())) {
            Ok(Response::Stored(info)) if info.id == object => Ok(peer),
            Ok(_) => Err(peer.child.failure("Unexpected peer Store reply")),
            Err(error) => Err(peer.child.failure(error)),
        }
    }

    /// Spawn-only control consumer: no dummy object or BFV setup is installed.
    pub(in crate::opening) fn spawn(executable: &Path, quota: u64) -> Result<Self> {
        Self::spawn_in(executable, OwnedDirectory::new()?, identity(), quota)
    }
    fn spawn_in(
        executable: &Path,
        directory: OwnedDirectory,
        owner: peer_transport::Identity,
        quota: u64,
    ) -> Result<Self> {
        let executable = checked_executable(executable)?;
        let connector = Connector::permissionless(&owner)?;
        let config = Bootstrap {
            identity: identity(),
            authority: Vec::new(),
            owner: owner.fingerprint(),
            node_id: 1,
            quota_bytes: quota,
            listen: "127.0.0.1:0".parse().map_err(|_| Error::Binding)?,
        };
        let expected_peer = config.identity.fingerprint();
        let bootstrap =
            zeroize::Zeroizing::new(serde_json::to_vec(&config).map_err(io::Error::other)?);
        if bootstrap.len() > 64 * 1024 {
            return Err(Error::Binding);
        }
        drop(config);
        let mut command = Command::new(executable);
        command
            .arg("--state-dir")
            .arg(directory.peer_path())
            .arg("--exit-on-stdin-close")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("RAYON_NUM_THREADS", "2");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        let mut child = OwnedChild {
            child: command.spawn()?,
            stdout: None,
            stderr: None,
        };
        let stdout = child.child.stdout.take().ok_or(Error::Binding)?;
        let stderr = child.child.stderr.take().ok_or(Error::Binding)?;
        let (tx, rx) = mpsc::channel();
        child.stdout = Some(thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = Vec::new();
            let result = (|| {
                Read::take(&mut reader, ENDPOINT_CAP + 1).read_until(b'\n', &mut line)?;
                if line.len() as u64 > ENDPOINT_CAP || !line.ends_with(b"\n") {
                    return Err(io::Error::other("Missing/bounded peer endpoint line"));
                }
                serde_json::from_slice::<Endpoint>(&line).map_err(io::Error::other)
            })();
            let _ = tx.send(result);
            capture(reader, line)
        }));
        child.stderr = Some(thread::spawn(move || capture(stderr, Vec::new())));
        let bootstrap_result = peer_transport::write_frame(
            child.child.stdin.as_mut().ok_or(Error::Binding)?,
            &bootstrap,
            64 * 1024,
        );
        drop(bootstrap); // This private IPC contains TLS material only, never FHE secrets.
        if let Err(error) = bootstrap_result {
            return Err(child.failure(error));
        }
        let endpoint = match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(endpoint)) => endpoint,
            Ok(Err(error)) => return Err(child.failure(error)),
            Err(error) => return Err(child.failure(error)),
        };
        if endpoint.identity != expected_peer
            || !endpoint.address.ip().is_loopback()
            || endpoint.address.port() == 0
        {
            return Err(child.failure("Unexpected peer endpoint/identity"));
        }
        let traces = Arc::new(Mutex::new(Vec::new()));
        let observed = traces.clone();
        let remote = RemotePeer::new(endpoint, connector).with_trace(Arc::new(move |trace| {
            if let Ok(mut rows) = observed.lock() {
                rows.push(trace);
            }
        }));
        let mut peer = Self {
            child,
            remote,
            traces,
            _directory: directory,
            owner,
            quota,
        };
        match peer.remote.call(Request::Probe) {
            Ok(Response::Alive { node_id: 1, pid })
                if pid == peer.pid() && pid != std::process::id() => {}
            Ok(_) => return Err(peer.child.failure("Unexpected peer Probe reply/PID")),
            Err(error) => return Err(peer.child.failure(error)),
        }
        Ok(peer)
    }
    /// Reopens the same participant directory only after its owned process exited.
    pub(in crate::opening) fn restart(mut self, executable: &Path) -> Result<Self> {
        if self.child.child.try_wait()?.is_none() {
            return Err(Error::Binding);
        }
        let Self {
            child,
            remote: _,
            traces: _,
            _directory,
            owner,
            quota,
        } = self;
        drop(child);
        Self::spawn_in(executable, _directory, owner, quota)
    }
    pub(in crate::opening) fn pid(&self) -> u32 {
        self.child.child.id()
    }
    /// Completed application-frame observations; TLS/OS framing is outside this count.
    pub(in crate::opening) fn observed_io(&self) -> Result<(u64, u64)> {
        let traces = self.traces.lock().map_err(|_| Error::Binding)?;
        Ok(traces.iter().fold((0, 0), |(a, b), t| {
            (a + t.request_bytes, b + t.response_bytes)
        }))
    }
    pub(in crate::opening) fn last_request_id(&self) -> Result<u64> {
        self.traces
            .lock()
            .map_err(|_| Error::Binding)?
            .last()
            .map(|row| row.request_id)
            .ok_or(Error::Binding)
    }
    pub(in crate::opening) fn finish(&mut self) -> Result<Completion> {
        match self.remote.call(Request::Shutdown) {
            Ok(Response::Done) => {}
            Ok(_) => return Err(self.child.failure("Unexpected peer Shutdown reply")),
            Err(error) => return Err(self.child.failure(error)),
        }
        self.wait_for_exit()
    }
    /// End the owned daemon through the existing sole-stdin EOF contract.
    pub(in crate::opening) fn finish_on_eof(&mut self) -> Result<Completion> {
        self.wait_for_exit()
    }
    fn wait_for_exit(&mut self) -> Result<Completion> {
        let (status, forced, out, err) = self.child.stop()?;
        if forced || !status.success() || out.total > LOG_CAP as u64 || err.total > LOG_CAP as u64 {
            return Err(Error::Io(io::Error::other(format!(
                "Peer completion {status}; forced={forced}; stdout({}B)={}; stderr({}B)={}",
                out.total,
                String::from_utf8_lossy(&out.bytes),
                err.total,
                String::from_utf8_lossy(&err.bytes)
            ))));
        }
        Ok(Completion {
            code: status.code().ok_or(Error::Binding)?,
            stdout: String::from_utf8_lossy(&out.bytes).into_owned(),
            stderr: String::from_utf8_lossy(&err.bytes).into_owned(),
        })
    }
}
