//! Opt-in PUBLIC NONSECRET test-artifact custody, not proof/application acceptance.
//! No owner private state or mutable journal files enter this collector.
use super::super::{Config, operation::Operation};
use super::process_fixture::Network;
use bfv_product_evidence::{CatalogId, MAX_CATALOG_BYTES};
use peer_runtime::{RequestControl, finality::ProgressFinalityClient};
use protocol_storage::BlobId;
use registry200_finality::progress::{
    Binding, Candidate, CandidateBlock, Checkpoint, VerifiedParent,
};
use registry200_joint::progress::{
    Application, Lane, Manifest, ManifestRole, ProgressEvidenceIngress, Request,
};
use registry200_journal::Control;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use version_journal::{Body, HeadRef, Journal, ShardState};
use work_finality::consensus::{Context, Decision, MAX_RECORD_BYTES, Rules};

const MAX_BLOBS: usize = 148;
const MAX_FILES: usize = 162;
const MAX_TOTAL: u64 = 1024 * 1024 * 1024;
const MAX_BLOB: usize = 32 * 1024 * 1024;
const MAX_SETUP: u64 = 64 * 1024 * 1024;
const MAX_BODY: usize = 64 * 1024;
const MAX_MANIFEST: usize = 128 * 1024;
const COMPLETE_BYTES: usize = 65;
const ENV: &str = "DCS_PROGRESS_PUBLIC_CAPTURE_DIR";
// Independent PUBLIC fixture parameter, pinned by process_fixture.rs SourceSpec.
const PUBLIC_NETWORK: [u8; 32] = [0x3a; 32];

// The caller checks this BEFORE extracting even the completed-parent metadata.
// No environment mutation or differently named observer-scrub bypass exists.
pub(super) fn requested_path() -> Option<OsString> {
    std::env::var_os(ENV)
}
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn checked<T>(value: Result<T, impl std::fmt::Display>) -> io::Result<T> {
    value.map_err(|error| invalid(error.to_string()))
}
fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}
fn manifest_role(role: ManifestRole) -> &'static str {
    match role {
        ManifestRole::Source => "source",
        ManifestRole::Bootstrap803 => "bootstrap803",
        ManifestRole::Control815 => "control815",
        ManifestRole::ProductCatalog => "product-catalog",
        ManifestRole::Predicate896 => "predicate896",
    }
}
fn check_time(expires: Instant) -> io::Result<()> {
    if Instant::now() >= expires {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "public capture deadline",
        ))
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct Limits {
    files: usize,
    bytes: u64,
}
impl Limits {
    fn add(&mut self, bytes: u64) -> io::Result<()> {
        let files = self
            .files
            .checked_add(1)
            .ok_or_else(|| invalid("file count overflow"))?;
        let total = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("output size overflow"))?;
        require(
            files <= MAX_FILES && total <= MAX_TOTAL,
            "public artifact output limit",
        )?;
        self.files = files;
        self.bytes = total;
        Ok(())
    }
}
struct Part {
    cap: usize,
    uses: Vec<Value>,
}
#[derive(Default)]
struct Closure {
    parts: BTreeMap<BlobId, Part>,
}
impl Closure {
    fn add(&mut self, id: BlobId, cap: usize, role: Value) -> io::Result<()> {
        let cap = cap.min(MAX_BLOB);
        require(
            id.bytes() != 0 && id.bytes() <= cap as u64,
            "reference exceeds its role cap",
        )?;
        if let Some(part) = self.parts.get_mut(&id) {
            part.cap = part.cap.min(cap);
            part.uses.push(role);
        } else {
            require(self.parts.len() < MAX_BLOBS, "public CAS count limit")?;
            self.parts.insert(
                id,
                Part {
                    cap,
                    uses: vec![role],
                },
            );
        }
        Ok(())
    }
    fn bytes(&self) -> io::Result<u64> {
        self.parts.keys().try_fold(0_u64, |sum, id| {
            sum.checked_add(id.bytes())
                .filter(|n| *n <= MAX_TOTAL)
                .ok_or_else(|| invalid("public CAS aggregate limit"))
        })
    }
}

// Every filename is internal constant/decimal/hex, never manifest-supplied input.
struct Writer {
    root: PathBuf,
    limits: Limits,
    files: Vec<Value>,
    expires: Instant,
}
impl Writer {
    fn new(target: &Path, expires: Instant) -> io::Result<Self> {
        check_time(expires)?;
        require(target.is_absolute(), "capture target must be absolute")?;
        let parent = target
            .parent()
            .ok_or_else(|| invalid("capture parent missing"))?;
        let name = target
            .file_name()
            .ok_or_else(|| invalid("capture directory name missing"))?;
        let parent = fs::canonicalize(parent)?;
        require(
            parent.file_name().is_some_and(|n| n == ".local"),
            "capture must be directly inside a canonical existing .local",
        )?;
        let root = parent.join(name);
        fs::create_dir(&root)?; // atomic existing-target refusal, never create_dir_all
        fs::create_dir(root.join("blobs"))?;
        Ok(Self {
            root,
            limits: Limits::default(),
            files: Vec::new(),
            expires,
        })
    }
    fn write(&mut self, name: &str, bytes: &[u8], cap: usize) -> io::Result<()> {
        check_time(self.expires)?;
        require(
            !bytes.is_empty() && bytes.len() <= cap,
            "public file extent limit",
        )?;
        self.limits.add(bytes.len() as u64)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(self.root.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        check_time(self.expires)?;
        self.files
            .push(json!({"file":name,"bytes":bytes.len(),"sha256":hex(&Sha256::digest(bytes))}));
        Ok(())
    }
    fn blob(&mut self, id: BlobId, part: &Part, bytes: &[u8]) -> io::Result<()> {
        require(
            id.bytes() <= part.cap.min(MAX_BLOB) as u64,
            "blob role limit",
        )?;
        require(
            bytes.len() as u64 == id.bytes()
                && <[u8; 32]>::from(Sha256::digest(bytes)) == *id.sha256(),
            "public blob length/hash mismatch",
        )?;
        let name = format!("blobs/{}-{:016x}.blob", hex(id.sha256()), id.bytes());
        self.write(&name, bytes, part.cap)?;
        self.files.last_mut().expect("just written public file")["roles"] = json!(part.uses);
        Ok(())
    }
    fn finish(mut self, mut manifest: Value) -> io::Result<()> {
        check_time(self.expires)?;
        manifest["payload_files"] = json!(self.files);
        manifest["payload_bytes"] = json!(self.limits.bytes);
        manifest["payload_file_count"] = json!(self.limits.files);
        let bytes = checked(serde_json::to_vec_pretty(&manifest))?;
        require(bytes.len() <= MAX_MANIFEST, "capture manifest cap")?;
        // Both terminal files are prepaid BEFORE either is published.
        let mut complete = Limits {
            files: self.limits.files,
            bytes: self.limits.bytes,
        };
        complete.add(bytes.len() as u64)?;
        complete.add(COMPLETE_BYTES as u64)?;
        let marker = format!("{}\n", hex(&Sha256::digest(&bytes)));
        self.write("manifest.json", &bytes, MAX_MANIFEST)?;
        self.write("COMPLETE", marker.as_bytes(), COMPLETE_BYTES)?;
        Ok(())
    }
}

// Reuse the existing operation-owned bounded cancellation/join scope. No extra
// native work, verifier, participant store or timeout policy is installed here.
pub(super) fn capture(
    target: &Path,
    binding: &Binding,
    completed: &VerifiedParent,
    ingress: &ProgressEvidenceIngress,
    network: &Network,
) -> io::Result<()> {
    let started = Instant::now();
    let expires = started
        .checked_add(super::BUDGET)
        .ok_or_else(|| invalid("capture deadline overflow"))?;
    require(
        completed.binding_id() == binding.id()
            && completed.application_descriptor().encode()
                == binding.application_descriptor().encode()
            && completed.slot() == 4
            && completed.head().height == 4
            && ingress.application_id() == binding.application_descriptor().id(),
        "capture requires actual product1 completed parent",
    )?;
    let mut writer = Writer::new(target, expires)?;
    let config = checked(Config::new(
        network.connector.clone(),
        network.endpoints.clone(),
        network.fhe.clone(),
        1,
    ))?;
    let control = RequestControl::default();
    let operation = Operation::new(
        &config,
        binding,
        &control,
        expires.saturating_duration_since(Instant::now()),
    )?;
    let result = collect(
        binding,
        completed,
        ingress,
        &operation,
        &mut writer,
        expires,
    );
    let joined = operation.finish();
    let manifest = result?;
    joined?;
    writer.finish(manifest)?;
    eprintln!(
        "progress_combined4 public_capture=complete elapsed_ms={}",
        started.elapsed().as_millis()
    );
    Ok(())
}

fn rules(binding: &Binding) -> io::Result<Value> {
    let application = registry200_finality::progress::durable_profile_digest();
    let value_bytes = registry200_finality::progress::CANDIDATE_BYTES as u32;
    let reconstructed = checked(Rules::multi_slot(
        application,
        value_bytes,
        32,
        [180_000; 3],
        1000,
        MAX_RECORD_BYTES as u64,
    ))?;
    require(
        &reconstructed == binding.rules(),
        "capture fixture Rules mismatch",
    )?;
    Ok(
        json!({"constructor":"multi_slot","application":hex(&application),"value_bytes":value_bytes,"max_round":32,"timeouts_ms":[180000,180000,180000],"timeout_delta_ms":1000,"wal_bytes":MAX_RECORD_BYTES,"id":hex(reconstructed.id().as_bytes())}),
    )
}
struct Frame {
    qc: Checkpoint,
    block: CandidateBlock,
    decision: Decision,
}
fn fetch(
    binding: &Binding,
    context: &Context,
    clients: &[ProgressFinalityClient],
    expires: Instant,
) -> io::Result<Frame> {
    loop {
        check_time(expires)?;
        for client in clients {
            check_time(expires)?;
            let qc = match client.checkpoint_after(context.slot() - 1) {
                Ok(Some(qc)) => qc,
                Ok(None) => continue,
                Err(e) if retryable(&e) => continue,
                Err(e) => return Err(e),
            };
            let expected = checked(Candidate::for_context(
                binding,
                context,
                qc.candidate().header().clone(),
            ))?;
            require(
                qc.candidate().encode() == expected.encode(),
                "foreign historical checkpoint",
            )?;
            let decision =
                checked(context.verify_commit(&expected.encode(), qc.round(), qc.certificate()))?;
            match client.candidate_block(expected.header().id()) {
                Ok(block) => {
                    require(
                        block.header() == expected.header(),
                        "checkpoint/block Header mismatch",
                    )?;
                    return Ok(Frame {
                        qc,
                        block,
                        decision,
                    });
                }
                Err(e) if retryable(&e) => {}
                Err(e) => return Err(e),
            }
        }
        check_time(expires)?;
        std::thread::park_timeout(
            Duration::from_millis(20).min(expires.saturating_duration_since(Instant::now())),
        );
    }
}
fn retryable(error: &io::Error) -> bool {
    // InvalidData/permission/auth/canonical errors are deliberately hard errors.
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}
fn collect(
    binding: &Binding,
    completed: &VerifiedParent,
    ingress: &ProgressEvidenceIngress,
    operation: &Operation,
    writer: &mut Writer,
    expires: Instant,
) -> io::Result<Value> {
    let rules = rules(binding)?;
    let genesis = binding.journal_genesis();
    let g = checked(genesis.id())?;
    let application = checked(Application::new(
        binding.application_descriptor().clone(),
        genesis,
    ))?;
    let spec = application.source_spec();
    require(
        spec.network == PUBLIC_NETWORK
            && binding.work_genesis().seed().domain()
                == binding.rules().seed_domain(PUBLIC_NETWORK),
        "capture public fixture network mismatch",
    )?;
    let mut headers = checked(Journal::new(genesis.clone()))?;
    let mut head = headers.genesis_head();
    let mut shards = genesis.initial_shards.clone();
    let mut context = binding.initial_context().clone();
    let mut closure = Closure::default();
    let mut slots = Vec::new();
    let mut catalog = None;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    for slot in 1..=4 {
        check_time(expires)?;
        let Frame {
            qc,
            block,
            decision,
        } = fetch(binding, &context, &operation.clients, expires)?;
        let header = block.header();
        require(
            qc.candidate().slot() == slot
                && header.parent == head.block
                && header.genesis == g
                && header.height
                    == head
                        .height
                        .checked_add(1)
                        .ok_or_else(|| invalid("height overflow"))?,
            "capture header lineage mismatch",
        )?;
        let _ = checked(headers.import_header(header.clone(), now))?; // real header-only PoW/target/time checks; NEVER import_body
        require(
            block.body().len() <= MAX_BODY
                && header.body_hash == version_journal::hash(block.body()),
            "Body extent/hash mismatch",
        )?;
        let body = checked(Body::decode(block.body(), &genesis.profile))?;
        require(
            checked(body.encode(&genesis.profile))? == block.body(),
            "noncanonical Body",
        )?;
        let Body::Transition(t) = body else {
            return Err(invalid("capture prefix requires four actual transitions"));
        };
        checked(t.check_authorization(&genesis.owner, g))?;
        let request = checked(Request::decode(&t.request))?;
        let manifest = checked(Manifest::decode(&t.proof))?;
        let lane = match slot {
            1 => Lane::Bootstrap,
            2 | 3 => Lane::Control,
            4 => Lane::Predicate,
            _ => unreachable!(),
        };
        let canonical = checked(Request::new(&application, lane, request.inner().clone()))?;
        require(
            request.lane() == lane
                && manifest.lane() == lane
                && checked(canonical.encode())? == t.request
                && request.inner().parent == head.block
                && request.inner().genesis == g
                && t.parent == head.block,
            "prefix Request/Manifest binding mismatch",
        )?;
        let old_heads = checked(spec.control(&shards))?;
        let old = checked(Control::decode(spec, old_heads))?;
        require(
            match old {
                Control::Pending => slot == 1,
                Control::Active { enrollment, .. } => {
                    slot != 1 && enrollment == request.inner().enrollment
                }
            },
            "prefix enrollment/control mismatch",
        )?;
        let next = Control::Active {
            enrollment: request.inner().enrollment,
            registry: manifest.next_root(),
        };
        require(
            t.updates.len() == 1
                && t.updates[0].id == spec.control_id
                && t.updates[0].old == old_heads
                && t.updates[0].new == next.heads(spec),
            "prefix shard update mismatch",
        )?;
        let index = shards
            .iter()
            .position(|s| s.id == spec.control_id)
            .ok_or_else(|| invalid("missing control shard"))?;
        shards[index] = ShardState {
            id: spec.control_id,
            heads: t.updates[0].new,
        };
        require(
            version_journal::state_root(&shards) == header.state_root,
            "prefix state root mismatch",
        )?;
        for reference in manifest.references() {
            closure.add(reference.blob_id(), reference.byte_cap(), json!({"kind":"manifest","slot":slot,"role":manifest_role(reference.role()),"ordinal":reference.ordinal()}))?;
            if reference.role() == ManifestRole::ProductCatalog {
                require(catalog.is_none(), "multiple product catalogs")?;
                catalog = Some(checked(CatalogId::from_blob(reference.blob_id()))?);
            }
        }
        let next_context = checked(context.after_decision(&decision))?;
        slots.push(json!({"slot":slot,"context":hex(&context.id()),"next_context":hex(&next_context.id()),"decision":hex(&decision.semantic_id()),"header":hex(&header.id()),"body_sha256":hex(&header.body_hash),"state_root":hex(&header.state_root)}));
        head = HeadRef {
            genesis: g,
            database: genesis.database,
            block: header.id(),
            height: header.height,
            state_root: header.state_root,
        };
        if slot == 4 {
            require(
                head == completed.head()
                    && decision.semantic_id() == completed.decision_id()
                    && next == completed.control(),
                "archive target differs from actual completed owner",
            )?;
        }
        writer.write(
            &format!("slot-{slot}.block"),
            &block.encode(),
            8 + version_journal::HEADER_BYTES + 4 + MAX_BODY,
        )?;
        writer.write(
            &format!("slot-{slot}.qc"),
            &qc.encode(),
            registry200_finality::progress::MAX_CHECKPOINT_BYTES,
        )?;
        context = next_context;
    }
    check_time(expires)?;
    let catalog = catalog.ok_or_else(|| invalid("product catalog missing"))?;
    require(
        catalog.blob_id().bytes() <= MAX_CATALOG_BYTES as u64,
        "catalog metadata cap",
    )?;
    let claim = checked(ingress.catalog_claim(catalog))?;
    let setup = binding.setup_claim();
    require(
        setup.application_id() == application.id()
            && claim.setup_parts() == setup.parts()
            && claim.setup_bytes() == setup.bytes()
            && setup.bytes() <= MAX_SETUP,
        "original setup/catalog mismatch",
    )?;
    for reference in claim.references() {
        closure.add(
            reference.blob_id(),
            reference.byte_cap(),
            json!({"kind":"catalog","role":reference.role(),"ordinal":reference.ordinal()}),
        )?;
    }
    let work = checked(binding.work_genesis().encode())?;
    let journal = checked(genesis.encode())?;
    let descriptor = binding.application_descriptor().encode();
    let setup_claim = setup.encode();
    writer.write("work-genesis.bin", &work, 1024 * 1024)?;
    writer.write("journal-genesis.bin", &journal, 2 * 1024 * 1024)?;
    writer.write(
        "descriptor.bin",
        &descriptor,
        registry200_joint::progress::DESCRIPTOR_BYTES,
    )?;
    writer.write(
        "setup-claim.bin",
        &setup_claim,
        registry200_joint::progress::MAX_SETUP_CLAIM_BYTES,
    )?;
    drop((work, journal, descriptor, setup_claim));
    let projected = writer
        .limits
        .bytes
        .checked_add(closure.bytes()?)
        .and_then(|n| n.checked_add(MAX_MANIFEST as u64 + COMPLETE_BYTES as u64))
        .ok_or_else(|| invalid("output total overflow"))?;
    require(
        projected <= MAX_TOTAL && writer.limits.files + closure.parts.len() + 2 <= MAX_FILES,
        "full capture output limit",
    )?;
    // Read original setup parts FIRST in canonical order; one <=32MiB buffer.
    // Stream both whole setup hashes, not just chunk/claim equality.
    let mut order = Vec::with_capacity(closure.parts.len());
    for id in setup.parts() {
        if !order.contains(id) {
            order.push(*id);
        }
    }
    order.extend(
        closure
            .parts
            .keys()
            .filter(|id| !setup.parts().contains(id))
            .copied(),
    );
    let mut setup256 = Sha256::new();
    let mut setup512 = Sha512::new();
    let mut setup_bytes = 0_u64;
    for id in order {
        check_time(expires)?;
        let part = closure
            .parts
            .get(&id)
            .ok_or_else(|| invalid("setup outside catalog closure"))?;
        let bytes = checked(ingress.read_public_blob(id, part.cap))?; // existing bounded hash+exact-EOF reader
        check_time(expires)?;
        writer.blob(id, part, &bytes)?;
        // At most two setup chunks; equal chunks still contribute TWICE to the
        // canonical complete-setup hash, but occupy one CAS output file.
        for _ in setup.parts().iter().filter(|part| **part == id) {
            setup256.update(&bytes);
            setup512.update(&bytes);
            setup_bytes = setup_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| invalid("setup size overflow"))?;
        }
    }
    require(
        setup_bytes == setup.bytes()
            && <[u8; 32]>::from(setup256.finalize())
                == binding.application_descriptor().full_setup_id()
            && <[u8; 64]>::from(setup512.finalize())
                == binding.application_descriptor().full_setup_digest(),
        "full original setup SHA256/SHA512 mismatch",
    )?;
    Ok(
        json!({"format":"DCS-PROGRESS-PUBLIC-CAPTURE-1","untrusted":true,"public_network":hex(&PUBLIC_NETWORK),"rules":rules,"binding":hex(&binding.id()),"application":hex(&application.id()),"work_genesis":hex(&binding.work_genesis().id()),"journal_genesis":hex(&g),"source_object":hex(&binding.application_descriptor().source_object()),"full_setup_sha256":hex(&binding.application_descriptor().full_setup_id()),"full_setup_sha512":hex(&binding.application_descriptor().full_setup_digest()),"setup_bytes":setup.bytes(),"catalog":{"sha256":hex(catalog.blob_id().sha256()),"bytes":catalog.blob_id().bytes(),"graph_identity":hex(&claim.graph_identity())},"slots":slots,"target_slot":4,"target_decision":hex(&completed.decision_id()),"limits":{"blobs":MAX_BLOBS,"files":MAX_FILES,"total_bytes":MAX_TOTAL,"blob_bytes":MAX_BLOB,"setup_bytes":MAX_SETUP},"claim":"public artifact prefix only; all application proofs must be freshly verified on replay; target QC is reference-only, never preseed target acceptance"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct PublicDirectory {
        root: PathBuf,
        parent: PathBuf,
    }
    impl PublicDirectory {
        fn new() -> Self {
            let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
            let root = parent.join(format!(
                "dcs-public-capture-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap(); // exclusive creation of this unique child
            let root = fs::canonicalize(root).unwrap();
            assert!(root.is_absolute());
            assert_eq!(root.parent(), Some(parent.as_path()));
            fs::create_dir(root.join(".local")).unwrap();
            Self { root, parent }
        }
        fn target(&self) -> PathBuf {
            self.root.join(".local/capture")
        }
    }
    impl Drop for PublicDirectory {
        fn drop(&mut self) {
            let resolved = fs::canonicalize(&self.root).unwrap();
            assert!(resolved.is_absolute());
            assert_eq!(resolved, self.root);
            assert_eq!(resolved.parent(), Some(self.parent.as_path()));
            fs::remove_dir_all(&resolved).unwrap();
        }
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }
    fn raw_id(bytes: &[u8]) -> BlobId {
        BlobId::new(Sha256::digest(bytes).into(), bytes.len() as u64).unwrap()
    }
    #[test]
    fn untrusted_closure_deduplicates_but_enforces_each_role_count_and_total() {
        let id = raw_id(b"untrusted public IO fixture");
        let mut c = Closure::default();
        c.add(id, MAX_BLOB, json!({"role":1})).unwrap();
        c.add(id, id.bytes() as usize, json!({"role":2})).unwrap();
        assert_eq!(c.parts.len(), 1);
        assert_eq!(c.bytes().unwrap(), id.bytes());
        assert_eq!(c.parts[&id].uses.len(), 2);
        assert!(
            c.add(id, id.bytes() as usize - 1, json!({"role":3}))
                .is_err()
        );
        for i in 1..MAX_BLOBS {
            c.add(
                BlobId::new(Sha256::digest(i.to_le_bytes()).into(), 1).unwrap(),
                1,
                json!({"role":0}),
            )
            .unwrap();
        }
        assert!(c.add(raw_id(b"one too many"), MAX_BLOB, json!({})).is_err());
        let mut many = Closure::default();
        for i in 0_u64..33 {
            many.add(
                BlobId::new(Sha256::digest(i.to_le_bytes()).into(), MAX_BLOB as u64).unwrap(),
                MAX_BLOB,
                json!({}),
            )
            .unwrap();
        }
        assert!(many.bytes().is_err());
        let mut limits = Limits {
            files: MAX_FILES,
            bytes: 0,
        };
        assert!(limits.add(1).is_err());
        assert_eq!(limits.files, MAX_FILES);
        let mut limits = Limits {
            files: 0,
            bytes: u64::MAX,
        };
        assert!(limits.add(1).is_err());
        assert_eq!(limits.bytes, u64::MAX);
    }
    #[test]
    fn public_writer_refuses_reuse_corrupt_extent_and_write_failure_without_complete() {
        let directory = PublicDirectory::new();
        let target = directory.target();
        let mut writer = Writer::new(&target, deadline()).unwrap();
        assert!(Writer::new(&target, deadline()).is_err());
        let bytes = b"untrusted bytes, no cryptographic positive";
        let id = raw_id(bytes);
        let part = Part {
            cap: MAX_BLOB,
            uses: vec![json!({"untrusted":true})],
        };
        assert!(writer.blob(id, &part, &bytes[..bytes.len() - 1]).is_err());
        assert!(writer.blob(id, &part, &vec![0; bytes.len()]).is_err());
        assert!(!target.join("COMPLETE").exists());
        writer.blob(id, &part, bytes).unwrap();
        assert!(writer.blob(id, &part, bytes).is_err()); // actual CreateNew refusal
        assert!(writer.write("missing/file", bytes, MAX_BLOB).is_err()); // actual IO error
        assert!(!target.join("manifest.json").exists());
        assert!(!target.join("COMPLETE").exists());
        assert_eq!(
            fs::read(target.join(format!(
                "blobs/{}-{:016x}.blob",
                hex(id.sha256()),
                id.bytes()
            )))
            .unwrap(),
            bytes
        );
    }
    #[test]
    fn complete_is_only_synced_manifest_hash_and_deadline_failure_never_completes() {
        let directory = PublicDirectory::new();
        let target = directory.target();
        let mut writer = Writer::new(&target, deadline()).unwrap();
        writer.write("public.bin", b"untrusted", 32).unwrap();
        writer.finish(json!({"untrusted":true})).unwrap();
        let manifest = fs::read(target.join("manifest.json")).unwrap();
        assert_eq!(
            fs::read(target.join("COMPLETE")).unwrap(),
            format!("{}\n", hex(&Sha256::digest(&manifest))).as_bytes()
        );
        assert!(Writer::new(Path::new("relative"), deadline()).is_err());
        let other = directory.root.join(".local/expired");
        assert!(Writer::new(&other, Instant::now()).is_err());
        assert!(!other.exists());
        let no_manifest = directory.root.join(".local/oversize");
        let writer = Writer::new(&no_manifest, deadline()).unwrap();
        assert!(
            writer
                .finish(json!({"raw":"x".repeat(MAX_MANIFEST)}))
                .is_err()
        );
        assert!(!no_manifest.join("COMPLETE").exists());
    }
}
