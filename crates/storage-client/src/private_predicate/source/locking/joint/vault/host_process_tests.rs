//! SOURCE-ONLY seven-OS Host v3 gate. Logical clients are not SQL sockets.
//! Public initial rows/participant keys are NONSECRET test fixtures.
use super::acquire::{AcquireEndpoints, phase};
use super::*;
use peer_runtime::Bootstrap;

const WORKER_HOST: &str = "private_predicate::source::locking::joint::vault::process_tests::host::owner_host_process_worker";
pub(super) const CLIENT_A: [u8; 32] = [0x10; 32];
pub(super) const CLIENT_B: [u8; 32] = [0x20; 32];
pub(super) const SQL_A: &str =
    "SELECT age, amount FROM records WHERE age IN (0,255) LIMIT 1 FOR UPDATE SKIP LOCKED";
pub(super) const SQL_B: &str =
    "SELECT age, amount FROM records WHERE age IN (0,255) LIMIT 1 OFFSET 1 FOR UPDATE SKIP LOCKED";
pub(super) const BEGIN_A_QC: u8 = 0;
pub(super) const BEGIN_B_BLOCK: u8 = 1;
pub(super) const BEGIN_B_QC: u8 = 2;
pub(super) const FIRST_BLOCK: u8 = 3;
pub(super) const FIRST_QC: u8 = 4;
pub(super) const PENDING_BLOCK: u8 = 5;
pub(super) const PENDING_CURSOR: u8 = 6;

fn host_role_cap(role: u8) -> io::Result<usize> {
    match role {
        BEGIN_A_QC | BEGIN_B_QC | FIRST_QC => Ok(registry200_finality::joint::MAX_CHECKPOINT_BYTES),
        BEGIN_B_BLOCK | FIRST_BLOCK | PENDING_BLOCK => Ok(BLOCK_CAP),
        PENDING_CURSOR => Ok(72),
        _ => Err(io::Error::other("Unknown Host custody role")),
    }
}
fn host_role_id(role: u8) -> [u8; 32] {
    Sha256::digest(
        [
            b"DCS/test-owner-Host-restart-custody/v3".as_slice(),
            &[role],
        ]
        .concat(),
    )
    .into()
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct HostInventory {
    pub(super) base: Inventory,
    pub(super) extra: Vec<Pin>,
}
impl HostInventory {
    pub(super) fn validate(&self, initial: bool) -> io::Result<()> {
        self.base.validate(if initial { 16 } else { 19 })?;
        require(
            self.extra.len() == if initial { 0 } else { 7 },
            "Host fixed extra role count",
        )?;
        for (i, pin) in self.extra.iter().enumerate() {
            require(
                pin.role as usize == i
                    && pin.bytes > 0
                    && pin.bytes <= host_role_cap(pin.role)? as u64,
                "Host extra order/cap",
            )?;
        }
        Ok(())
    }
    pub(super) fn persist(
        &mut self,
        quota: &ParticipantQuota,
        role: u8,
        bytes: &[u8],
    ) -> io::Result<()> {
        require(
            role as usize == self.extra.len()
                && !bytes.is_empty()
                && bytes.len() <= host_role_cap(role)?,
            "Host custody order/cap",
        )?;
        write_custody(
            quota,
            &quota.control_file(host_role_id(role), ControlFile::Metadata),
            bytes,
        )?;
        self.extra.push(Pin {
            role,
            bytes: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        });
        Ok(())
    }
    pub(super) fn read(&self, root: &Path, role: u8) -> io::Result<Vec<u8>> {
        let pin = self
            .extra
            .get(role as usize)
            .ok_or_else(|| io::Error::other("Missing Host custody role"))?;
        require(
            pin.role == role && pin.bytes > 0 && pin.bytes <= host_role_cap(role)? as u64,
            "Host read role/cap",
        )?;
        let name = host_role_id(role)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let path = root.join("control").join(format!("{name}.meta"));
        let metadata = fs::symlink_metadata(&path)?;
        require(
            metadata.file_type().is_file() && metadata.len() == pin.bytes,
            "Host custody type/extent",
        )?;
        let mut file = File::open(path)?;
        let mut bytes = Vec::with_capacity(pin.bytes as usize);
        Read::by_ref(&mut file)
            .take(pin.bytes + 1)
            .read_to_end(&mut bytes)?;
        require(
            bytes.len() as u64 == pin.bytes
                && <[u8; 32]>::from(Sha256::digest(&bytes)) == pin.sha256,
            "Host custody hash/EOF",
        )?;
        Ok(bytes)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostConfig {
    pub(super) version: u16,
    pub(super) role: u8,
    pub(super) root: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostReport {
    pub(super) version: u16,
    pub(super) stage: u8,
    pub(super) pid: u32,
    pub(super) inventory: HostInventory,
    pub(super) header: [u8; 32],
    pub(super) body: [u8; 32],
    pub(super) key: [u8; 32],
    pub(super) generation: u64,
    pub(super) invocation: [u8; 32],
    pub(super) request: [u8; 32],
    pub(super) first_invocation: [u8; 32],
    pub(super) first_request: [u8; 32],
    pub(super) first_record: u64,
    pub(super) rows: usize,
}
pub(super) fn report_host(report: &HostReport) -> io::Result<()> {
    write_report(&checked(serde_json::to_vec(report))?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum HostPhase {
    BeginsCompleted,
    FirstCompleted,
    SecondFheRecorded,
    SecondCatalogRestored,
    Restored,
    SecondCompleted,
    Ended,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostProgress {
    version: u16,
    pid: u32,
    phase: HostPhase,
}
pub(super) fn report_progress(phase: HostPhase) -> io::Result<()> {
    write_report(&checked(serde_json::to_vec(&HostProgress {
        version: 3,
        pid: std::process::id(),
        phase,
    }))?)
}
fn require_progress(bytes: &[u8], pid: u32, expected: HostPhase) -> io::Result<()> {
    let progress: HostProgress = checked(serde_json::from_slice(bytes))?;
    require(
        progress.version == 3 && progress.pid == pid && progress.phase == expected,
        "Exact bounded ordered Host progress",
    )
}
fn wait_progress(
    owner: &os_process::OwnerProcess,
    pid: u32,
    phases: &[HostPhase],
) -> io::Result<()> {
    // One existing operation budget per FIXED expected phase. Unsolicited,
    // duplicate or reordered reports fail; no arbitrary heartbeat resets it.
    // The supervisor still requires the complete final result and joined PIDs.
    for &expected in phases {
        require_progress(&owner.public_report()?, pid, expected)?;
    }
    Ok(())
}

#[test]
fn progress_reports_require_the_expected_owner_and_phase_without_extensions() {
    let first = br#"{"version":3,"pid":41,"phase":"BeginsCompleted"}"#;
    require_progress(first, 41, HostPhase::BeginsCompleted).unwrap();
    assert!(require_progress(first, 42, HostPhase::BeginsCompleted).is_err());
    assert!(require_progress(first, 41, HostPhase::FirstCompleted).is_err());
    for invalid in [
        br#"{"version":2,"pid":41,"phase":"BeginsCompleted"}"#.as_slice(),
        br#"{"version":3,"pid":41,"phase":"heartbeat"}"#.as_slice(),
        br#"{"version":3,"pid":41,"phase":"FirstFheRecorded"}"#.as_slice(),
        br#"{"version":3,"pid":41,"phase":"FirstCatalogRestored"}"#.as_slice(),
        br#"{"version":3,"pid":41,"phase":"BeginsCompleted","extra":1}"#.as_slice(),
        br#"{"version":3,"pid":41}"#.as_slice(),
    ] {
        assert!(require_progress(invalid, 41, HostPhase::BeginsCompleted).is_err());
    }
}

#[test]
#[ignore = "Subprocess entry only; explicit Host-v3 config and exact160 private authority frame"]
fn owner_host_process_worker() {
    process_worker::run_host().expect("Actual Host owner subprocess failed");
}

#[test]
#[ignore = "Actual four validators + OS FHE + owner A/B; two logical clients SAME principal; requires DCS_PEER_EXE"]
fn seven_os_host_clients_skip_locked_recover_exact_second_call_and_prepaid_ack() {
    let started = Instant::now();
    let directory = fixture::Directory::new();
    let mut validators = Vec::new();
    let mut fhe = None;
    let result = (|| -> io::Result<()> {
        let exe = PathBuf::from(
            std::env::var_os("DCS_PEER_EXE")
                .ok_or_else(|| io::Error::other("DCS_PEER_EXE required"))?,
        );
        require(
            exe.is_absolute() && exe.is_file(),
            "Explicit actual dcs-peer executable required",
        )?;
        let worker_exe = std::env::current_exe()?;
        let authority = Zeroizing::new(fresh::<160>()?);
        let owner_tls = fixture::identity();
        let tls = Zeroizing::new(checked(serde_json::to_vec(&owner_tls))?);
        let work_bytes = checked(work()?.encode())?;
        let root = directory.path("Host-owner-private");
        let config = checked(serde_json::to_vec(&HostConfig {
            version: 3,
            role: 1,
            root: root.clone(),
        }))?;
        // The existing strict160 launcher owns the same five authorities. No
        // new key transport, optional tail, child process or peer protocol.
        let mut a = os_process::OwnerProcess::start_acquire(
            &worker_exe,
            WORKER_HOST,
            [
                &config,
                authority.as_slice(),
                tls.as_slice(),
                &work_bytes,
                b"null",
            ],
        )?;
        let a_pid = a.pid();
        require(a_pid != std::process::id(), "Host A separate PID")?;
        let initial: HostReport = checked(serde_json::from_slice(&a.public_report()?))?;
        initial.inventory.validate(true)?;
        require(
            initial.version == 3
                && initial.stage == 1
                && initial.pid == a_pid
                && initial.generation == 0
                && initial.invocation == [0; 32]
                && initial.request == [0; 32]
                && initial.first_invocation == [0; 32]
                && initial.first_request == [0; 32]
                && initial.first_record == 0
                && initial.rows == 0,
            "Host initial public report",
        )?;
        let binding = binding(&initial.inventory.base, &root)?;
        let signer = SigningKey::from_bytes(authority[96..128].try_into().unwrap());
        require(
            binding.journal_genesis().owner == signer.verifying_key().to_bytes()
                && initial.inventory.base.read(&root, WORK)? == work_bytes,
            "Independent Host DB/Work pins",
        )?;
        let boot = checked(CandidateBlock::decode(
            &initial.inventory.base.read(&root, BOOT_BLOCK)?,
        ))?;
        let key: [u8; 32] = Sha256::digest(initial.inventory.base.read(&root, KEY)?).into();
        require(
            initial.header == boot.header().id()
                && initial.body == version_journal::hash(boot.body())
                && initial.key == key,
            "Initial real Bootstrap/Key",
        )?;
        let setup = initial.inventory.base.read(&root, SETUP)?;
        require(
            <[u8; 32]>::from(Sha256::digest(&setup))
                == binding.application_descriptor().full_setup_id(),
            "Original setup identity",
        )?;
        let endpoints = start_validators(
            &exe,
            &directory,
            &binding,
            &owner_tls,
            &setup,
            &mut validators,
        )?;
        let storage = os_process::Process::start_storage(
            &exe,
            &directory.path("Host-FHE-peer"),
            &Bootstrap {
                identity: fixture::identity(),
                authority: vec![],
                owner: owner_tls.fingerprint(),
                node_id: 210,
                quota_bytes: 16 * 1024 * 1024,
                listen: "127.0.0.1:0".parse().unwrap(),
            },
        )?;
        let fhe_pid = storage.pid();
        eprintln!("Actual Host FHE pid={fhe_pid}");
        let fhe_endpoint = storage.endpoint().clone();
        fhe = Some(storage);
        require(
            fhe_pid != a_pid
                && fhe_pid != std::process::id()
                && validators
                    .iter()
                    .all(|p| p.pid() != a_pid && p.pid() != fhe_pid),
            "Separate four validators, FHE and A",
        )?;
        let endpoint_bytes = checked(serde_json::to_vec(&AcquireEndpoints {
            validators: endpoints,
            fhe: fhe_endpoint,
        }))?;
        a.send_endpoints(&endpoint_bytes)?;
        wait_progress(
            &a,
            a_pid,
            &[
                HostPhase::BeginsCompleted,
                HostPhase::FirstCompleted,
                HostPhase::SecondFheRecorded,
                HostPhase::SecondCatalogRestored,
            ],
        )?;
        let saved: HostReport = checked(serde_json::from_slice(&a.public_report()?))?;
        a.finish()?;
        phase(started, "Host-owner-A-joined");
        saved.inventory.validate(false)?;
        require(
            saved.version == 3
                && saved.stage == 2
                && saved.pid == a_pid
                && saved.generation == 3
                && saved.rows == 1
                && saved.inventory.base.files[..16] == initial.inventory.base.files[..]
                && saved.key == key
                && saved.invocation != [0; 32]
                && saved.first_invocation != [0; 32]
                && saved.invocation != saved.first_invocation
                && saved.request != saved.first_request
                && saved.first_record > 0,
            "A saved second original call AFTER actual first Acquire completion",
        )?;
        let exact = checked(CandidateBlock::decode(
            &saved.inventory.read(&root, PENDING_BLOCK)?,
        ))?;
        require(
            exact.header().id() == saved.header
                && version_journal::hash(exact.body()) == saved.body,
            "Exact second signed candidate",
        )?;
        let cursor = saved.inventory.read(&root, PENDING_CURSOR)?;
        require(
            cursor[..8] == 3u64.to_le_bytes() && cursor[8..40] == saved.invocation,
            "A exits before G4 completion",
        )?;
        // No live Owner, pending, result or evaluator survives into owner B.
        fhe.take().unwrap().finish()?;
        let config = checked(serde_json::to_vec(&HostConfig {
            version: 3,
            role: 2,
            root: root.clone(),
        }))?;
        let original_report = checked(serde_json::to_vec(&saved))?;
        let mut b = os_process::OwnerProcess::start_acquire(
            &worker_exe,
            WORKER_HOST,
            [
                &config,
                authority.as_slice(),
                tls.as_slice(),
                &work_bytes,
                &original_report,
            ],
        )?;
        let b_pid = b.pid();
        require(
            b_pid != a_pid
                && b_pid != fhe_pid
                && b_pid != std::process::id()
                && validators.iter().all(|p| p.pid() != b_pid),
            "Fresh Host B PID after A/FHE join",
        )?;
        b.send_endpoints(&endpoint_bytes)?;
        wait_progress(
            &b,
            b_pid,
            &[
                HostPhase::Restored,
                HostPhase::SecondCompleted,
                HostPhase::Ended,
            ],
        )?;
        let final_report: HostReport = checked(serde_json::from_slice(&b.public_report()?))?;
        b.finish()?;
        phase(started, "Host-owner-B-joined");
        require(
            final_report.version == 3
                && final_report.stage == 3
                && final_report.pid == b_pid
                && final_report.inventory == saved.inventory
                && final_report.generation == 6
                && final_report.key == key
                && final_report.invocation == saved.invocation
                && final_report.request == saved.request
                && final_report.first_invocation == saved.first_invocation
                && final_report.first_request == saved.first_request
                && final_report.first_record == saved.first_record
                && final_report.rows == 0
                && final_report.header != saved.header,
            "Two original Host calls, G4 empty reply, G5/G6 End and strict reopen",
        )?;
        let quota = checked(ParticipantQuota::open_existing(
            &root,
            NAMESPACE,
            fixture::CAPACITY,
        ))?;
        require(
            checked(quota.usage())?.control_bytes() > 0,
            "Final same accounted participant namespace",
        )?;
        drop(quota);
        Ok(())
    })();
    let stopped_fhe = fhe.map(os_process::StorageProcess::finish);
    let stopped = validators
        .into_iter()
        .map(os_process::Process::finish)
        .collect::<Vec<_>>();
    if let Some(result) = stopped_fhe {
        result.expect("Actual FHE child joined cleanup");
    }
    for result in stopped {
        result.expect("Actual validator joined cleanup");
    }
    result.expect("Actual seven-OS Host v3 same-principal contention/restart gate");
}
