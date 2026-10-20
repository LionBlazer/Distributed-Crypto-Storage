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

// Owner-only unit-test subprocesses use a different bounded IPC grammar from
// dcs-peer. No private owner frame is ever sent to Process::start_joint.
#[allow(dead_code)]
pub(crate) struct OwnerProcess {
    owned: ChildOwner,
    reports: mpsc::Receiver<io::Result<Vec<u8>>>,
    reader: Option<std::thread::JoinHandle<io::Result<()>>>,
}
enum OwnerAuthorityFrame {
    Control,
    Acquire,
}

// Host A: initial inventory, four fixed phase reports, final inventory. This
// finite test-only bound allows a complete burst while the supervisor is idle.
const MAX_OWNER_REPORTS: usize = 6;

fn read_owner_reports(
    stdout: impl Read,
    sender: mpsc::SyncSender<io::Result<Vec<u8>>>,
) -> io::Result<()> {
    let mut stdout = BufReader::new(stdout);
    let mut prelude_bytes = 0usize;
    let mut reports = 0usize;
    loop {
        // libtest prefixes bounded text. Only this exact marker introduces a
        // public binary frame. Payloads retain their original 64-KiB cap.
        let mut line = Vec::new();
        let n = stdout
            .by_ref()
            .take(64 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(());
        }
        if n > 64 * 1024 || !line.ends_with(b"\n") {
            return Err(io::Error::other("Unbounded owner report prelude"));
        }
        prelude_bytes = prelude_bytes
            .checked_add(n)
            .ok_or_else(|| io::Error::other("Owner prelude overflow"))?;
        if prelude_bytes > 64 * 1024 {
            return Err(io::Error::other("Owner prelude limit"));
        }
        if line.ends_with(b"DCS-OWNER-PUBLIC-REPORT-01\n") {
            reports += 1;
            if reports > MAX_OWNER_REPORTS {
                return Err(io::Error::other("Unexpected owner report count"));
            }
            let bytes = peer_transport::read_frame(&mut stdout, 64 * 1024)?;
            sender
                .try_send(Ok(bytes))
                .map_err(|_| io::Error::other("Unexpected owner report count"))?;
        }
    }
}

fn require_reports_drained(reports: &mpsc::Receiver<io::Result<Vec<u8>>>) -> io::Result<()> {
    match reports.try_recv() {
        Err(mpsc::TryRecvError::Disconnected | mpsc::TryRecvError::Empty) => Ok(()),
        Ok(_) => Err(io::Error::other("Unexpected trailing owner report")),
    }
}

impl OwnerAuthorityFrame {
    fn bytes(&self) -> usize {
        match self {
            Self::Control => 128,
            Self::Acquire => 160,
        }
    }
}
#[allow(dead_code)]
impl OwnerProcess {
    pub(crate) fn start(executable: &Path, worker: &str, frames: [&[u8]; 5]) -> io::Result<Self> {
        Self::start_owned(executable, worker, frames, OwnerAuthorityFrame::Control)
    }
    /// Distinct test-only bootstrap: Source/Core/Vault/signing/capsule authorities.
    /// The old Control entry remains exactly 128 bytes, never an optional tail.
    pub(crate) fn start_acquire(
        executable: &Path,
        worker: &str,
        frames: [&[u8]; 5],
    ) -> io::Result<Self> {
        Self::start_owned(executable, worker, frames, OwnerAuthorityFrame::Acquire)
    }
    fn start_owned(
        executable: &Path,
        worker: &str,
        frames: [&[u8]; 5],
        authority: OwnerAuthorityFrame,
    ) -> io::Result<Self> {
        if frames[1].len() != authority.bytes() {
            return Err(io::Error::other(
                "Exact private owner authority frame required",
            ));
        }
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                worker,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
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
            .ok_or_else(|| io::Error::other("Missing owner stdin"))?;
        let mut owned = ChildOwner {
            child,
            input: Some(input),
        };
        for (bytes, cap) in frames.into_iter().zip([
            64 * 1024,
            authority.bytes(),
            64 * 1024,
            work_finality::MAX_GENESIS_BYTES,
            64 * 1024,
        ]) {
            peer_transport::write_frame(owned.input.as_mut().unwrap(), bytes, cap)?;
        }
        let stdout = owned
            .child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("Missing owner stdout"))?;
        let (sender, reports) = mpsc::sync_channel(MAX_OWNER_REPORTS);
        let reader = std::thread::spawn(move || read_owner_reports(stdout, sender));
        Ok(Self {
            owned,
            reports,
            reader: Some(reader),
        })
    }
    pub(crate) fn pid(&self) -> u32 {
        self.owned.child.id()
    }
    pub(crate) fn send_endpoints(&mut self, bytes: &[u8]) -> io::Result<()> {
        peer_transport::write_frame(
            self.owned
                .input
                .as_mut()
                .ok_or_else(|| io::Error::other("Closed owner IPC"))?,
            bytes,
            64 * 1024,
        )
    }
    pub(crate) fn public_report(&self) -> io::Result<Vec<u8>> {
        self.reports
            .recv_timeout(peer_runtime::finality::JOINT_OPERATION_BUDGET)
            .map_err(io::Error::other)?
    }
    pub(crate) fn finish(mut self) -> io::Result<()> {
        let process = self.owned.finish();
        if process.is_err() {
            drop(self.owned.input.take());
            let _ = self.owned.child.kill();
            let _ = self.owned.child.wait();
        }
        let reader = self
            .reader
            .take()
            .unwrap()
            .join()
            .map_err(|_| io::Error::other("Owner stdout reader panicked"))?;
        process.and(reader)?;
        require_reports_drained(&self.reports)
    }
}
impl Drop for OwnerProcess {
    fn drop(&mut self) {
        drop(self.owned.input.take());
        if self.owned.child.try_wait().ok().flatten().is_none() {
            let _ = self.owned.child.kill();
        }
        let _ = self.owned.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
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

// Progress is a distinct trusted-IPC installation. This supervisor owns only
// process lifecycle and bounded frames; it never creates proofs or a roster.
#[allow(dead_code)]
pub(crate) struct ProgressProcess {
    owned: ChildOwner,
    ready: peer_runtime::progress_participant::ProgressParticipantReady,
}
#[allow(dead_code)]
impl ProgressProcess {
    pub(crate) fn start(
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
            return Err(io::Error::other(
                "Invalid Progress test bootstrap frame count",
            ));
        }
        let args = [
            std::ffi::OsStr::new("--participant-progress-finality"),
            std::ffi::OsStr::new(mode),
            directory.as_os_str(),
        ];
        let (owned, line) = launch(executable, &args, frames)?;
        let ready = serde_json::from_str(&line).map_err(io::Error::other)?;
        let process = Self { owned, ready };
        if process.ready.pid != process.owned.child.id() {
            return Err(io::Error::other(
                "Progress Ready PID differs from actual child",
            ));
        }
        Ok(process)
    }
    pub(crate) fn ready(&self) -> &peer_runtime::progress_participant::ProgressParticipantReady {
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
}

#[cfg(test)]
mod owner_report_tests {
    use super::*;

    fn script(count: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for i in 0..count {
            bytes.extend_from_slice(b"DCS-OWNER-PUBLIC-REPORT-01\n");
            peer_transport::write_frame(&mut bytes, &[i as u8], 64 * 1024).unwrap();
        }
        bytes
    }

    #[test]
    fn complete_report_burst_is_bounded_without_requiring_receiver_scheduling() {
        let (sender, receiver) = mpsc::sync_channel(MAX_OWNER_REPORTS);
        // Join the actual framed reader BEFORE receiving anything: the old
        // two-slot queue failed this valid finite script on its third report.
        let reader = std::thread::spawn(move || read_owner_reports(script(6).as_slice(), sender));
        reader.join().unwrap().unwrap();
        for i in 0..6 {
            assert_eq!(receiver.try_recv().unwrap().unwrap(), [i]);
        }
        require_reports_drained(&receiver).unwrap();
    }

    #[test]
    fn report_count_is_bounded_even_if_the_channel_has_spare_capacity() {
        let (sender, receiver) = mpsc::sync_channel(MAX_OWNER_REPORTS + 1);
        assert!(read_owner_reports(script(7).as_slice(), sender).is_err());
        for i in 0..6 {
            assert_eq!(receiver.try_recv().unwrap().unwrap(), [i]);
        }
        require_reports_drained(&receiver).unwrap();
    }

    #[test]
    fn joined_reader_cannot_hide_a_trailing_framed_report() {
        let (sender, receiver) = mpsc::sync_channel(MAX_OWNER_REPORTS);
        read_owner_reports(script(3).as_slice(), sender).unwrap();
        assert_eq!(receiver.try_recv().unwrap().unwrap(), [0]);
        assert_eq!(receiver.try_recv().unwrap().unwrap(), [1]);
        assert!(require_reports_drained(&receiver).is_err());
    }
}
