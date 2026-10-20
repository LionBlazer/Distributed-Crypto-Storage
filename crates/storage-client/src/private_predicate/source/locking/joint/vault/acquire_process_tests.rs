//! Four validators + actual FHE + sequential A/B; native record: ACQUIRE-PROCESS.md.
//! All ingest rows/participant keys are explicitly PUBLIC NONSECRET fixtures.
use super::*;
use peer_runtime::Bootstrap;
const WORKER_ACQUIRE: &str = "private_predicate::source::locking::joint::vault::process_tests::acquire::owner_acquire_process_worker";
pub(super) const RECOVERY_ID: [u8; 32] = [0xd7; 32];
// Different test-custody namespace; the old Control roles/grammar stay intact.
pub(super) const BEGIN_CERT: u8 = 0;
pub(super) const ACQUIRE_BODY: u8 = 1;
pub(super) const ACQUIRE_CURSOR: u8 = 2;
fn extra_cap(role: u8) -> io::Result<usize> {
    match role {
        BEGIN_CERT => Ok(registry200_finality::joint::MAX_CHECKPOINT_BYTES),
        ACQUIRE_BODY => Ok(BLOCK_CAP),
        ACQUIRE_CURSOR => Ok(72),
        _ => Err(io::Error::other("Unknown Acquire custody role")),
    }
}
fn extra_id(role: u8) -> [u8; 32] {
    Sha256::digest(
        [
            b"DCS/test-owner-Acquire-restart-custody/v2".as_slice(),
            &[role],
        ]
        .concat(),
    )
    .into()
}
fn extra_path(root: &Path, role: u8) -> PathBuf {
    let name = extra_id(role)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    root.join("control").join(format!("{name}.meta"))
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct AcquireInventory {
    pub(super) base: Inventory,
    pub(super) extra: Vec<Pin>,
}
impl AcquireInventory {
    pub(super) fn validate(&self, initial: bool) -> io::Result<()> {
        self.base.validate(if initial { 16 } else { 19 })?;
        require(
            self.extra.len() == if initial { 0 } else { 3 },
            "Acquire fixed extra role count",
        )?;
        for (i, pin) in self.extra.iter().enumerate() {
            require(
                pin.role as usize == i && pin.bytes > 0 && pin.bytes <= extra_cap(pin.role)? as u64,
                "Acquire fixed extra order/cap",
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
                && bytes.len() <= extra_cap(role)?,
            "Acquire custody order/cap",
        )?;
        let path = quota.control_file(extra_id(role), ControlFile::Metadata);
        write_custody(quota, &path, bytes)?;
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
            .ok_or_else(|| io::Error::other("Missing Acquire custody role"))?;
        require(
            pin.role == role && pin.bytes > 0 && pin.bytes <= extra_cap(role)? as u64,
            "Acquire read role/cap",
        )?;
        let path = extra_path(root, role);
        let metadata = fs::symlink_metadata(&path)?;
        require(
            metadata.file_type().is_file() && metadata.len() == pin.bytes,
            "Acquire custody type/extent",
        )?;
        let mut file = File::open(path)?;
        let mut bytes = Vec::with_capacity(pin.bytes as usize);
        Read::by_ref(&mut file)
            .take(pin.bytes + 1)
            .read_to_end(&mut bytes)?;
        require(
            bytes.len() as u64 == pin.bytes
                && <[u8; 32]>::from(Sha256::digest(&bytes)) == pin.sha256,
            "Acquire custody hash/EOF",
        )?;
        Ok(bytes)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcquireConfig {
    pub(super) version: u16,
    pub(super) role: u8,
    pub(super) root: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcquireEndpoints {
    pub(super) validators: Vec<Endpoint>,
    pub(super) fhe: Endpoint,
}
impl AcquireEndpoints {
    pub(super) fn validate(&self) -> io::Result<()> {
        require(
            self.validators.len() == 4
                && self
                    .validators
                    .iter()
                    .map(|e| e.address)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == 4
                && self
                    .validators
                    .iter()
                    .all(|e| e.address != self.fhe.address),
            "Four validators and a separate FHE endpoint",
        )
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcquireReport {
    pub(super) version: u16,
    pub(super) stage: u8,
    pub(super) pid: u32,
    pub(super) inventory: AcquireInventory,
    pub(super) header: [u8; 32],
    pub(super) body: [u8; 32],
    pub(super) key: [u8; 32],
    pub(super) generation: u64,
    pub(super) invocation: [u8; 32],
    pub(super) request: [u8; 32],
    pub(super) rows: usize,
}
pub(super) fn report_acquire(value: &AcquireReport) -> io::Result<()> {
    write_report(&checked(serde_json::to_vec(value))?)
}
pub(super) fn phase(started: Instant, stage: &'static str) {
    eprintln!(
        "Acquire process pid={} phase={} elapsed_ms={:.3}",
        std::process::id(),
        stage,
        started.elapsed().as_secs_f64() * 1000.
    );
}

// Extends only the fixed Acquire manifest upload with the existing canonical
// catalog roles. Every body/selector/BlobId is checked again by the real server.
pub(super) fn upload_acquire(
    client: &JointFinalityClient,
    block: &CandidateBlock,
    ingress: &JointEvidenceIngress,
    binding: &JointBinding,
) -> io::Result<()> {
    upload(client, block, ingress, binding)?;
    let Body::Transition(body) = checked(Body::decode(
        block.body(),
        &binding.journal_genesis().profile,
    ))?
    else {
        return Err(io::Error::other("Actual Acquire transition required"));
    };
    let manifest = checked(Manifest::decode(&body.proof))?;
    require(
        manifest.lane() == registry200_joint::Lane::Acquire,
        "Acquire catalog lane",
    )?;
    let catalog = checked(bfv_product_evidence::CatalogId::from_blob(
        manifest
            .references()
            .find(|r| r.role() == registry200_joint::ManifestRole::ProductCatalog)
            .ok_or_else(|| io::Error::other("Missing catalog role"))?
            .blob_id(),
    ))?;
    let claim = checked(ingress.catalog_claim(catalog))?;
    for reference in claim.references() {
        let bytes = checked(ingress.read_public_blob(reference.blob_id(), reference.byte_cap()))?;
        let selector = checked(ProofBlobSelector::catalog(
            reference.role(),
            reference.ordinal(),
        ))?;
        until(
            || match client.put_proof_blob(block, selector, reference.blob_id(), &bytes) {
                Ok(()) => Ok(Some(())),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::NotConnected
                    ) =>
                {
                    Ok(None)
                }
                Err(e) => Err(e),
            },
        )?;
    }
    Ok(())
}

#[test]
#[ignore = "Subprocess entry only; requires explicit bounded Acquire-v2 private IPC"]
fn owner_acquire_process_worker() {
    process_worker::run_acquire().expect("Actual Acquire owner subprocess failed");
}

#[test]
#[ignore = "Actual four validators + OS FHE + sequential owner A/B; requires DCS_PEER_EXE; no local QC"]
fn seven_os_processes_recover_original_durable_acquire_then_finalize_end() {
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
        let root = directory.path("Acquire-owner-private");
        let config = checked(serde_json::to_vec(&AcquireConfig {
            version: 2,
            role: 1,
            root: root.clone(),
        }))?;
        let mut a = os_process::OwnerProcess::start_acquire(
            &worker_exe,
            WORKER_ACQUIRE,
            [
                &config,
                authority.as_slice(),
                tls.as_slice(),
                &work_bytes,
                b"null",
            ],
        )?;
        let a_pid = a.pid();
        require(a_pid != std::process::id(), "Owner A separate actual PID")?;
        let prepared: AcquireReport = checked(serde_json::from_slice(&a.public_report()?))?;
        prepared.inventory.validate(true)?;
        require(
            prepared.version == 2
                && prepared.stage == 1
                && prepared.pid == a_pid
                && prepared.invocation == [0; 32]
                && prepared.request == [0; 32],
            "Acquire A initial report",
        )?;
        let binding = binding(&prepared.inventory.base, &root)?;
        let db_signer = SigningKey::from_bytes(authority[96..128].try_into().unwrap());
        require(
            binding.journal_genesis().owner == db_signer.verifying_key().to_bytes()
                && prepared.inventory.base.read(&root, WORK)? == work_bytes,
            "Independent original DB/Work pins",
        )?;
        let boot = checked(CandidateBlock::decode(
            &prepared.inventory.base.read(&root, BOOT_BLOCK)?,
        ))?;
        let key: [u8; 32] = Sha256::digest(prepared.inventory.base.read(&root, KEY)?).into();
        require(
            boot.header().id() == prepared.header
                && version_journal::hash(boot.body()) == prepared.body
                && prepared.key == key,
            "Original Bootstrap/key report pins",
        )?;
        let setup = prepared.inventory.base.read(&root, SETUP)?;
        require(
            <[u8; 32]>::from(Sha256::digest(&setup))
                == binding.application_descriptor().full_setup_id(),
            "Complete original setup",
        )?;
        let endpoints = start_validators(
            &exe,
            &directory,
            &binding,
            &owner_tls,
            &setup,
            &mut validators,
        )?;
        let bootstrap = Bootstrap {
            identity: fixture::identity(),
            authority: vec![],
            owner: owner_tls.fingerprint(),
            node_id: 209,
            quota_bytes: 16 * 1024 * 1024,
            listen: "127.0.0.1:0".parse().unwrap(),
        };
        let storage = os_process::Process::start_storage(
            &exe,
            &directory.path("Acquire-FHE-peer"),
            &bootstrap,
        )?;
        let fhe_pid = storage.pid();
        let fhe_endpoint = storage.endpoint().clone();
        fhe = Some(storage);
        require(
            fhe_pid != a_pid
                && fhe_pid != std::process::id()
                && validators
                    .iter()
                    .all(|p| p.pid() != fhe_pid && p.pid() != a_pid),
            "Five distinct peer PIDs separated from owner A",
        )?;
        let public_endpoints = checked(serde_json::to_vec(&AcquireEndpoints {
            validators: endpoints.clone(),
            fhe: fhe_endpoint,
        }))?;
        a.send_endpoints(&public_endpoints)?;
        let saved: AcquireReport = checked(serde_json::from_slice(&a.public_report()?))?;
        a.finish()?; // Join owner and stdout BEFORE any owner B capability exists.
        phase(started, "owner-A-joined");
        saved.inventory.validate(false)?;
        require(
            saved.version == 2
                && saved.stage == 2
                && saved.pid == a_pid
                && saved.generation == 1
                && saved.invocation != [0; 32]
                && saved.inventory.base.files[..16] == prepared.inventory.base.files[..]
                && saved.inventory.base.binding == binding.id()
                && saved.key == key,
            "A saved original pending Acquire and prefix",
        )?;
        let pending = checked(CandidateBlock::decode(
            &saved.inventory.read(&root, ACQUIRE_BODY)?,
        ))?;
        require(
            pending.header().id() == saved.header
                && version_journal::hash(pending.body()) == saved.body,
            "Exact original signed Acquire",
        )?;
        let cursor = saved.inventory.read(&root, ACQUIRE_CURSOR)?;
        require(
            cursor[..8] == 1u64.to_le_bytes() && cursor[8..40] == saved.invocation,
            "A exits BEFORE private Acquire CAS",
        )?;
        // The FHE prover also exits: B must use original public evidence and its
        // restored Owner, never a surviving pending/result inside that process.
        fhe.take().unwrap().finish()?;
        let config = checked(serde_json::to_vec(&AcquireConfig {
            version: 2,
            role: 2,
            root: root.clone(),
        }))?;
        let inventory = checked(serde_json::to_vec(&saved.inventory))?;
        let mut b = os_process::OwnerProcess::start_acquire(
            &worker_exe,
            WORKER_ACQUIRE,
            [
                &config,
                authority.as_slice(),
                tls.as_slice(),
                &work_bytes,
                &inventory,
            ],
        )?;
        let b_pid = b.pid();
        require(
            b_pid != a_pid
                && b_pid != fhe_pid
                && b_pid != std::process::id()
                && validators.iter().all(|p| p.pid() != b_pid),
            "Owner B fresh PID after A join",
        )?;
        b.send_endpoints(&public_endpoints)?;
        let completed: AcquireReport = checked(serde_json::from_slice(&b.public_report()?))?;
        b.finish()?;
        phase(started, "owner-B-joined");
        require(
            completed.version == 2
                && completed.stage == 3
                && completed.pid == b_pid
                && completed.inventory == saved.inventory
                && completed.key == key
                && completed.generation == 3
                && completed.invocation == saved.invocation
                && completed.request == saved.request
                && completed.rows == 1
                && completed.header != saved.header,
            "B original restored invocation + durable Acquire/End",
        )?;
        let quota = checked(ParticipantQuota::open_existing(
            &root,
            NAMESPACE,
            fixture::CAPACITY,
        ))?;
        require(
            checked(quota.usage())?.control_bytes() > 0,
            "Actual final accounted namespace",
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
    result.expect("Actual seven-OS durable Acquire restart gate");
}
