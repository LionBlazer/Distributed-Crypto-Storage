//! Reusable test-local OS supervision only. No Source fixture or key accessor.
//! Owning tests supply independently pinned private IPC and the explicit binary.
use peer_runtime::{
    Bootstrap, Endpoint, joint_participant::JointParticipantReady, participant::ParticipantInstall,
};
use std::{
    io::{self, BufRead, BufReader, Read},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

struct ChildOwner {
    child: Child,
    input: Option<ChildStdin>,
}
impl ChildOwner {
    fn finish(&mut self) -> io::Result<()> {
        drop(self.input.take());
        let end = Instant::now() + peer_runtime::finality::JOINT_OPERATION_BUDGET;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other(format!("Peer exited {status}")))
                };
            }
            if Instant::now() >= end {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Joined peer shutdown did not finish",
                ));
            }
            std::thread::park_timeout(Duration::from_millis(20));
        }
    }
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        drop(self.input.take());
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
pub(crate) struct Process {
    owned: ChildOwner,
    ready: JointParticipantReady,
}
// The same source is included by the owning storage-client full-Acquire gate;
// this control-only target does not launch an unnecessary FHE child.
#[allow(dead_code)]
pub(crate) struct StorageProcess {
    owned: ChildOwner,
    endpoint: Endpoint,
}
fn launch(
    executable: &Path,
    args: &[&std::ffi::OsStr],
    frames: &[&[u8]],
) -> io::Result<(ChildOwner, String)> {
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .env("RAYON_NUM_THREADS", "2");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn()?;
    let input = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("Missing child stdin"))?;
    let mut owned = ChildOwner {
        child,
        input: Some(input),
    };
    // Limits are test IPC bounds only; the actual daemon parses exact roles.
    for (index, bytes) in frames.iter().enumerate() {
        let cap = match index {
            0 => 64 * 1024,
            1 => work_finality::MAX_GENESIS_BYTES,
            2 => 716,
            3 => 896,
            4 => 136,
            _ => protocol_storage::MAX_BLOB_BYTES as usize,
        };
        peer_transport::write_frame(owned.input.as_mut().unwrap(), bytes, cap)?;
    }
    let stdout = owned
        .child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Missing child stdout"))?;
    let (sent, received) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout.take(64 * 1024 + 1))
            .read_line(&mut line)
            .and_then(|_| {
                if line.len() > 64 * 1024 || !line.ends_with('\n') {
                    Err(io::Error::other("Unbounded or truncated Ready"))
                } else {
                    Ok(line)
                }
            });
        let _ = sent.send(result);
    });
    let line = match received.recv_timeout(peer_runtime::finality::JOINT_OPERATION_BUDGET) {
        Ok(result) => result,
        Err(e) => {
            drop(owned.input.take());
            let _ = owned.child.kill();
            let _ = owned.child.wait();
            let _ = reader.join();
            return Err(io::Error::other(e));
        }
    }?;
    reader
        .join()
        .map_err(|_| io::Error::other("Ready reader panicked"))?;
    if owned.child.id() == std::process::id() {
        return Err(io::Error::other("Expected independent child process"));
    }
    Ok((owned, line))
}
impl Process {
    pub(crate) fn start_joint(
        executable: &Path,
        directory: &Path,
        install: ParticipantInstall,
        frames: &[&[u8]],
    ) -> io::Result<Self> {
        let mode = match install {
            ParticipantInstall::New => "new",
            ParticipantInstall::Existing => "existing",
        };
        if matches!(install, ParticipantInstall::New) && !(6..=7).contains(&frames.len())
            || matches!(install, ParticipantInstall::Existing) && frames.len() != 5
        {
            return Err(io::Error::other("Invalid test bootstrap frame count"));
        }
        let args = [
            std::ffi::OsStr::new("--participant-joint-finality"),
            std::ffi::OsStr::new(mode),
            directory.as_os_str(),
        ];
        let (owned, line) = launch(executable, &args, frames)?;
        let ready = serde_json::from_str(&line).map_err(io::Error::other)?;
        let process = Self { owned, ready };
        if process.ready.pid != process.owned.child.id() {
            return Err(io::Error::other("Ready PID differs from actual child"));
        }
        Ok(process)
    }
    pub(crate) fn ready(&self) -> &JointParticipantReady {
        &self.ready
    }
    pub(crate) fn endpoint(&self) -> &Endpoint {
        &self.ready.endpoint
    }
    pub(crate) fn pid(&self) -> u32 {
        self.owned.child.id()
    }
    pub(crate) fn finish(mut self) -> io::Result<()> {
        self.owned.finish()
    }
    #[allow(dead_code)]
    pub(crate) fn start_storage(
        executable: &Path,
        directory: &Path,
        bootstrap: &Bootstrap,
    ) -> io::Result<StorageProcess> {
        let bytes =
            zeroize::Zeroizing::new(serde_json::to_vec(bootstrap).map_err(io::Error::other)?);
        let args = [
            std::ffi::OsStr::new("--state-dir"),
            directory.as_os_str(),
            std::ffi::OsStr::new("--exit-on-stdin-close"),
        ];
        let (owned, line) = launch(executable, &args, &[bytes.as_slice()])?;
        let endpoint = serde_json::from_str(&line).map_err(io::Error::other)?;
        Ok(StorageProcess { owned, endpoint })
    }
}
#[allow(dead_code)]
impl StorageProcess {
    pub(crate) fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    pub(crate) fn pid(&self) -> u32 {
        self.owned.child.id()
    }
    pub(crate) fn finish(mut self) -> io::Result<()> {
        self.owned.finish()
    }
}
