//! Test-local UNTRUSTED public capture loading. Hashes and decoded metadata are
//! never computation/finality authority. Actual cold verification runs in peers.
use bfv_product_evidence::{CatalogId, MAX_CATALOG_BYTES, ProductStore};
use peer_runtime::finality::ProgressProofBlobSelector;
use protocol_storage::{BlobId, ParticipantQuota};
use registry200_finality::{
    CandidateBlock,
    progress::{Binding, CANDIDATE_BYTES, Candidate, Checkpoint, durable_profile_digest},
};
use registry200_joint::progress::{
    Application, Descriptor, Lane, Manifest, ManifestRole, Request, SetupClaim,
};
use registry200_journal::Control;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use version_journal::{Body, HeadRef, Journal, ShardState};
use work_finality::consensus::{Context, MAX_RECORD_BYTES, Rules};

// Independent Root-local INVOCATION receipt, not a value read from the archive.
pub(super) const INVOCATION_SHA256: &str =
    "D15F621FD6CDA810946528B8F3B504E1DC47DF35822C0B6B9B662AA098CCE8B0";
const MAX_MANIFEST: usize = 128 * 1024;
const MAX_BLOB: usize = 32 * 1024 * 1024;
const MAX_TOTAL: u64 = 1024 * 1024 * 1024;
const MAX_FILES: usize = 162;
const MAX_BLOBS: usize = 148;
const MAX_BODY: usize = 64 * 1024;
const PUBLIC_NETWORK: [u8; 32] = [0x3a; 32];

pub(super) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
pub(super) fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(invalid(message)) }
}
pub(super) fn checked<T>(value: Result<T, impl std::fmt::Display>) -> io::Result<T> {
    value.map_err(|e| invalid(e.to_string()))
}
pub(super) fn deadline(expires: Instant) -> io::Result<()> {
    if Instant::now() >= expires {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Public replay operation expired",
        ))
    } else {
        Ok(())
    }
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest<const N: usize>(value: &Value) -> io::Result<[u8; N]> {
    decode_hex(text(value)?)
}
pub(super) fn decode_hex<const N: usize>(value: &str) -> io::Result<[u8; N]> {
    require(
        value.len() == N * 2 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid digest",
    )?;
    let mut result = [0; N];
    for (index, out) in result.iter_mut().enumerate() {
        *out = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid("Invalid hex"))?;
    }
    Ok(result)
}
fn text(value: &Value) -> io::Result<&str> {
    value.as_str().ok_or_else(|| invalid("Expected string"))
}
fn number(value: &Value) -> io::Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| invalid("Expected unsigned integer"))
}
fn closed(value: &Value, keys: &[&str]) -> io::Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("Expected object"))?;
    require(
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)),
        "Unexpected JSON fields",
    )
}
fn array(value: &Value, limit: usize) -> io::Result<&[Value]> {
    let value = value.as_array().ok_or_else(|| invalid("Expected array"))?;
    require(value.len() <= limit, "Too many entries")?;
    Ok(value)
}
fn no_redirect(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        !metadata.file_type().is_symlink() && metadata.file_attributes() & 0x400 == 0
    }
    #[cfg(not(windows))]
    {
        !metadata.file_type().is_symlink()
    }
}
fn directory(path: &Path) -> io::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_dir() && no_redirect(&metadata),
        "Archive directory redirect/type",
    )?;
    fs::canonicalize(path)
}
fn open_regular(path: &Path, bytes: u64, cap: usize) -> io::Result<File> {
    require(
        bytes != 0 && bytes <= cap as u64,
        "File extent exceeds role cap",
    )?;
    let before = fs::symlink_metadata(path)?;
    require(
        before.is_file() && no_redirect(&before) && before.len() == bytes,
        "File type/extent/redirect",
    )?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    let actual = file.metadata()?;
    require(
        actual.is_file() && no_redirect(&actual) && actual.len() == bytes,
        "Opened file changed type/extent",
    )?;
    Ok(file)
}
fn read_extent(path: &Path, bytes: u64, cap: usize) -> io::Result<Vec<u8>> {
    let mut file = open_regular(path, bytes, cap)?;
    let mut out = vec![0; usize::try_from(bytes).map_err(|_| invalid("File size conversion"))?];
    file.read_exact(&mut out)?;
    let mut tail = [0];
    require(
        file.read(&mut tail)? == 0 && file.metadata()?.len() == bytes,
        "Trailing/changed extent",
    )?;
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FilePin {
    bytes: u64,
    sha256: [u8; 32],
}
fn check_manifest(bytes: &[u8], complete: &[u8], expected: [u8; 32]) -> io::Result<()> {
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    require(
        hash == expected,
        "Manifest differs from independent invocation pin",
    )?;
    require(
        complete == format!("{}\n", hex(&hash)).as_bytes(),
        "Missing/invalid COMPLETE",
    )?;
    Ok(())
}
fn fixed_cap(name: &str) -> Option<usize> {
    match name {
        "descriptor.bin" => Some(896),
        "journal-genesis.bin" => Some(716),
        "setup-claim.bin" => Some(136),
        "work-genesis.bin" => Some(work_finality::MAX_GENESIS_BYTES.min(1024 * 1024)),
        "slot-1.block" | "slot-2.block" | "slot-3.block" | "slot-4.block" => {
            Some(8 + version_journal::HEADER_BYTES + 4 + MAX_BODY)
        }
        "slot-1.qc" | "slot-2.qc" | "slot-3.qc" | "slot-4.qc" => {
            Some(registry200_finality::progress::MAX_CHECKPOINT_BYTES)
        }
        _ => None,
    }
}
fn blob_name(id: BlobId) -> String {
    format!("blobs/{}-{:016x}.blob", hex(id.sha256()), id.bytes())
}
fn blob_from_name(name: &str) -> io::Result<BlobId> {
    let name = name
        .strip_prefix("blobs/")
        .and_then(|s| s.strip_suffix(".blob"))
        .ok_or_else(|| invalid("Not an internal CAS filename"))?;
    require(
        name.is_ascii() && name.len() == 81 && name.as_bytes()[64] == b'-',
        "Invalid CAS filename",
    )?;
    let hash = decode_hex::<32>(&name[..64])?;
    require(name[..64] == hex(&hash), "Noncanonical CAS hex")?;
    let size = u64::from_str_radix(&name[65..], 16).map_err(|_| invalid("Invalid CAS extent"))?;
    let id = checked(BlobId::new(hash, size))?;
    require(
        blob_name(id) == format!("blobs/{name}.blob"),
        "Noncanonical CAS extent",
    )?;
    Ok(id)
}
fn inventory(value: &Value, roles: bool) -> io::Result<BTreeMap<String, FilePin>> {
    let values = array(value, MAX_FILES - 2)?;
    let mut out = BTreeMap::new();
    let mut total = 0_u64;
    for value in values {
        if roles && value.get("roles").is_some() {
            closed(value, &["file", "bytes", "sha256", "roles"])?;
            let _ = array(&value["roles"], 160)?;
        } else {
            closed(value, &["file", "bytes", "sha256"])?;
        }
        let name = text(&value["file"])?;
        let bytes = number(&value["bytes"])?;
        let cap = if let Some(cap) = fixed_cap(name) {
            cap
        } else {
            let id = blob_from_name(name)?;
            require(id.bytes() == bytes, "CAS name/extent mismatch")?;
            MAX_BLOB
        };
        require(
            bytes != 0 && bytes <= cap as u64,
            "Declared file exceeds cap",
        )?;
        let pin = FilePin {
            bytes,
            sha256: digest(&value["sha256"])?,
        };
        total = total
            .checked_add(bytes)
            .filter(|n| *n <= MAX_TOTAL)
            .ok_or_else(|| invalid("Capture total exceeded"))?;
        require(
            out.insert(name.to_owned(), pin).is_none(),
            "Duplicate archive filename",
        )?;
    }
    Ok(out)
}

#[derive(Clone, Copy)]
pub(super) struct Upload {
    pub selector: ProgressProofBlobSelector,
    pub id: BlobId,
    pub cap: usize,
}
pub(super) struct Prefix {
    pub block: CandidateBlock,
    pub checkpoint: Checkpoint,
    pub context: Context,
    pub decision: [u8; 32],
    pub uploads: Vec<Upload>,
}
// Deliberately has NO target Checkpoint. Only prefix1..3 expose one for transport.
pub(super) struct Target {
    pub block: CandidateBlock,
    pub context: Context,
    pub decision: [u8; 32],
    pub uploads: Vec<Upload>,
}
pub(super) struct Archive {
    root: PathBuf,
    files: BTreeMap<String, FilePin>,
    pub binding: Binding,
    pub prefix: [Prefix; 3],
    pub target: Target,
}
impl Archive {
    fn read(&self, name: &str, cap: usize) -> io::Result<Vec<u8>> {
        let pin = self
            .files
            .get(name)
            .ok_or_else(|| invalid("File absent from pinned closure"))?;
        let path = self.root.join(name);
        // Only internal fixed names / canonical CAS names enter this method.
        let bytes = read_extent(&path, pin.bytes, cap)?;
        require(
            <[u8; 32]>::from(Sha256::digest(&bytes)) == pin.sha256,
            "Changed public file hash",
        )?;
        Ok(bytes)
    }
    pub fn read_blob(&self, id: BlobId, cap: usize) -> io::Result<Vec<u8>> {
        require(
            id.bytes() <= cap.min(MAX_BLOB) as u64,
            "Read exceeds canonical role cap",
        )?;
        let bytes = self.read(&blob_name(id), cap.min(MAX_BLOB))?;
        require(
            <[u8; 32]>::from(Sha256::digest(&bytes)) == *id.sha256(),
            "Blob identity mismatch",
        )?;
        Ok(bytes)
    }
    pub fn setup_parts(&self) -> io::Result<Vec<Vec<u8>>> {
        self.binding
            .setup_claim()
            .parts()
            .iter()
            .map(|id| self.read_blob(*id, MAX_BLOB))
            .collect()
    }
}

struct Part {
    cap: usize,
    roles: Vec<Value>,
}
fn add(parts: &mut BTreeMap<BlobId, Part>, id: BlobId, cap: usize, role: Value) -> io::Result<()> {
    require(
        id.bytes() != 0 && id.bytes() <= cap.min(MAX_BLOB) as u64,
        "Canonical reference cap",
    )?;
    if let Some(part) = parts.get_mut(&id) {
        require(!part.roles.contains(&role), "Duplicate canonical role")?;
        part.cap = part.cap.min(cap);
        part.roles.push(role);
    } else {
        require(parts.len() < MAX_BLOBS, "Too many canonical blobs")?;
        parts.insert(
            id,
            Part {
                cap,
                roles: vec![role],
            },
        );
    }
    Ok(())
}
fn role_name(role: ManifestRole) -> &'static str {
    match role {
        ManifestRole::Source => "source",
        ManifestRole::Bootstrap803 => "bootstrap803",
        ManifestRole::Control815 => "control815",
        ManifestRole::ProductCatalog => "product-catalog",
        ManifestRole::Predicate896 => "predicate896",
    }
}
fn read_pinned(
    root: &Path,
    files: &BTreeMap<String, FilePin>,
    name: &str,
    cap: usize,
) -> io::Result<Vec<u8>> {
    let pin = files
        .get(name)
        .ok_or_else(|| invalid("Required public file missing"))?;
    let bytes = read_extent(&root.join(name), pin.bytes, cap)?;
    require(
        <[u8; 32]>::from(Sha256::digest(&bytes)) == pin.sha256,
        "Public file hash mismatch",
    )?;
    Ok(bytes)
}
fn scan_layout(root: &Path, expected: &BTreeSet<String>, expires: Instant) -> io::Result<()> {
    deadline(expires)?;
    let blobs = directory(&root.join("blobs"))?;
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        deadline(expires)?;
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("Non-UTF8 archive name"))?;
        if name == "blobs" {
            continue;
        }
        require(expected.contains(&name), "Unexpected archive filename")?;
        require(
            entry.file_type()?.is_file(),
            "Unexpected archive directory/type",
        )?;
        require(
            actual.insert(name) && actual.len() <= expected.len(),
            "Duplicate/unbounded archive inventory",
        )?;
    }
    for entry in fs::read_dir(blobs)? {
        deadline(expires)?;
        let entry = entry?;
        let name = format!(
            "blobs/{}",
            entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("Non-UTF8 blob filename"))?
        );
        require(expected.contains(&name), "Unexpected archive filename")?;
        require(entry.file_type()?.is_file(), "Unexpected blob child/type")?;
        require(
            actual.insert(name) && actual.len() <= expected.len(),
            "Duplicate/unbounded archive inventory",
        )?;
    }
    require(actual == *expected, "Missing archive files")
}
fn require_setup_hashes(
    root: &Path,
    files: &BTreeMap<String, FilePin>,
    ids: &[BlobId],
    expected_bytes: u64,
    expected256: [u8; 32],
    expected512: [u8; 64],
) -> io::Result<()> {
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut size = 0_u64;
    for id in ids {
        let raw = read_pinned(root, files, &blob_name(*id), MAX_BLOB)?;
        require(
            <[u8; 32]>::from(Sha256::digest(&raw)) == *id.sha256(),
            "Setup chunk identity",
        )?;
        sha256.update(&raw);
        sha512.update(&raw);
        size = size
            .checked_add(raw.len() as u64)
            .ok_or_else(|| invalid("Setup count overflow"))?;
    } // ORDER and repeated ids remain in the logical stream, irrespective of CAS dedup.
    require(
        size == expected_bytes
            && <[u8; 32]>::from(sha256.finalize()) == expected256
            && <[u8; 64]>::from(sha512.finalize()) == expected512,
        "Full original setup hashes",
    )
}
fn rules_json(binding: &Binding) -> Value {
    json!({"constructor":"multi_slot","id":hex(binding.rules().id().as_bytes()),
        "application":hex(&durable_profile_digest()),"value_bytes":CANDIDATE_BYTES,
        "max_round":32,"timeouts_ms":[180000,180000,180000],
        "timeout_delta_ms":1000,"wal_bytes":MAX_RECORD_BYTES})
}
pub(super) fn load(
    root: &Path,
    pin_file: &Path,
    operator_digest: [u8; 32],
    scratch: &Path,
) -> io::Result<Archive> {
    require(
        operator_digest == decode_hex(INVOCATION_SHA256)?,
        "Wrong independent invocation receipt",
    )?;
    let expires = Instant::now() + peer_runtime::finality::PROGRESS_OPERATION_BUDGET;
    let root = directory(root)?;
    let pin_len = fs::symlink_metadata(pin_file)?.len();
    let pin_bytes = read_extent(pin_file, pin_len, MAX_MANIFEST)?;
    require(
        <[u8; 32]>::from(Sha256::digest(&pin_bytes)) == operator_digest,
        "Independent PinSpec RAW digest mismatch",
    )?;
    let pins: Value = checked(serde_json::from_slice(&pin_bytes))?;
    closed(
        &pins,
        &[
            "format",
            "utc",
            "scope",
            "source_receipt_sha256",
            "all_original_source_hashes_exact_now",
            "observer_result_sha256",
            "pipeline_sha256",
            "capture_manifest_sha256",
            "metadata",
            "application",
            "binding",
            "journal_genesis",
            "work_genesis",
            "rules",
            "public_network",
            "source_object",
            "full_setup_sha256",
            "full_setup_sha512",
            "setup_bytes",
            "slots",
            "target_decision",
            "target_QC_policy",
            "all_payloads",
        ],
    )?;
    require(
        text(&pins["format"])? == "ROOT-LOCAL-PRODUCT1-CAPTURE-INVOCATION-PINS-1",
        "Wrong invocation format",
    )?;
    let manifest_len = fs::symlink_metadata(root.join("manifest.json"))?.len();
    let bytes = read_extent(&root.join("manifest.json"), manifest_len, MAX_MANIFEST)?;
    let complete = read_extent(&root.join("COMPLETE"), 65, 65)?;
    check_manifest(&bytes, &complete, digest(&pins["capture_manifest_sha256"])?)?;
    let manifest: Value = checked(serde_json::from_slice(&bytes))?;
    closed(
        &manifest,
        &[
            "application",
            "binding",
            "catalog",
            "claim",
            "format",
            "full_setup_sha256",
            "full_setup_sha512",
            "journal_genesis",
            "limits",
            "payload_bytes",
            "payload_file_count",
            "payload_files",
            "public_network",
            "rules",
            "setup_bytes",
            "slots",
            "source_object",
            "target_decision",
            "target_slot",
            "untrusted",
            "work_genesis",
        ],
    )?;
    require(
        text(&manifest["format"])? == "DCS-PROGRESS-PUBLIC-CAPTURE-1"
            && number(&manifest["target_slot"])? == 4,
        "Wrong public capture format/target",
    )?;
    // Self-declared 'untrusted' and 'claim' prose never authorizes anything.
    require(
        manifest["limits"]
            == json!({"blob_bytes":MAX_BLOB,"blobs":MAX_BLOBS,
        "files":MAX_FILES,"setup_bytes":64*1024*1024_u64,"total_bytes":MAX_TOTAL}),
        "Capture limit mismatch",
    )?;
    let files = inventory(&manifest["payload_files"], true)?;
    require(
        files == inventory(&pins["all_payloads"], false)?,
        "Manifest inventory differs from independent RAW pins",
    )?;
    let total: u64 = files.values().map(|p| p.bytes).sum();
    require(
        number(&manifest["payload_bytes"])? == total
            && number(&manifest["payload_file_count"])? == files.len() as u64
            && files.len() + 2 <= MAX_FILES
            && total + bytes.len() as u64 + 65 <= MAX_TOTAL,
        "Capture total/count mismatch",
    )?;
    let mut expected_names: BTreeSet<_> = files.keys().cloned().collect();
    expected_names.extend(["manifest.json".into(), "COMPLETE".into()]);
    scan_layout(&root, &expected_names, expires)?;

    let descriptor_bytes = read_pinned(&root, &files, "descriptor.bin", 896)?;
    require(descriptor_bytes.len() == 896, "Descriptor size")?;
    let descriptor = checked(Descriptor::decode(&descriptor_bytes))?;
    let work_bytes = read_pinned(
        &root,
        &files,
        "work-genesis.bin",
        work_finality::MAX_GENESIS_BYTES.min(1024 * 1024),
    )?;
    let work = checked(work_finality::Genesis::decode(
        &work_bytes,
        digest(&pins["work_genesis"])?,
    ))?;
    require(checked(work.encode())? == work_bytes, "Noncanonical Work")?;
    let journal_bytes = read_pinned(&root, &files, "journal-genesis.bin", 716)?;
    require(
        journal_bytes.len() == 716,
        "Exactly two Journal shards required",
    )?;
    let genesis = checked(version_journal::Genesis::decode(&journal_bytes))?;
    require(
        checked(genesis.encode())? == journal_bytes,
        "Noncanonical Journal",
    )?;
    let setup_bytes = read_pinned(&root, &files, "setup-claim.bin", 136)?;
    let setup = checked(SetupClaim::decode(&setup_bytes))?;
    require(setup.encode() == setup_bytes, "Noncanonical SetupClaim")?;
    let rules = checked(Rules::multi_slot(
        durable_profile_digest(),
        CANDIDATE_BYTES as u32,
        32,
        [180000; 3],
        1000,
        MAX_RECORD_BYTES as u64,
    ))?;
    let binding = checked(Binding::for_durable(
        PUBLIC_NETWORK,
        rules,
        work,
        genesis,
        descriptor,
        setup,
    ))?;
    let application = checked(Application::new(
        binding.application_descriptor().clone(),
        binding.journal_genesis(),
    ))?;
    let spec = application.source_spec();
    for key in [
        "application",
        "binding",
        "journal_genesis",
        "work_genesis",
        "public_network",
        "source_object",
        "full_setup_sha256",
        "full_setup_sha512",
        "setup_bytes",
        "rules",
        "slots",
        "target_decision",
    ] {
        require(
            manifest[key] == pins[key],
            "Capture association differs from independent invocation",
        )?;
    }
    require(
        binding.id() == digest(&pins["binding"])?
            && application.id() == digest(&pins["application"])?
            && checked(binding.journal_genesis().id())? == digest(&pins["journal_genesis"])?
            && binding.application_descriptor().source_object() == digest(&pins["source_object"])?
            && binding.application_descriptor().full_setup_id()
                == digest(&pins["full_setup_sha256"])?
            && binding.application_descriptor().full_setup_digest()
                == digest(&pins["full_setup_sha512"])?
            && binding.setup_claim().bytes() == number(&pins["setup_bytes"])?
            && spec.network == PUBLIC_NETWORK
            && digest::<32>(&pins["public_network"])? == PUBLIC_NETWORK
            && binding.work_genesis().seed().domain()
                == binding.rules().seed_domain(PUBLIC_NETWORK)
            && rules_json(&binding) == pins["rules"],
        "Independent descriptor/Rules/Work/Setup pins",
    )?;
    let mut keys: Vec<_> = (1..=4)
        .map(|n| {
            ed25519_dalek::SigningKey::from_bytes(&[n; 32])
                .verifying_key()
                .to_bytes()
        })
        .collect();
    keys.sort();
    let roster = binding.work_genesis().initial_set().validators();
    require(
        roster.len() == 4
            && roster
                .iter()
                .zip(keys)
                .all(|(v, k)| v.public_key() == k && v.work_units() > 0),
        "Not the independently pinned PUBLIC four-fixture weighted roster",
    )?;
    // The independently RAW-pinned Work encoding binds the actual weights, not
    // merely four ids. Context::verify_commit below uses those verified weights.
    let genesis = binding.journal_genesis();
    let g = checked(genesis.id())?;
    let mut headers = checked(Journal::new(genesis.clone()))?;
    let mut head = headers.genesis_head();
    let mut shards = genesis.initial_shards.clone();
    let mut context = binding.initial_context().clone();
    let mut prefix = Vec::new();
    let mut target = None;
    let mut parts = BTreeMap::new();
    let mut slots = Vec::new();
    let mut catalog = None;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    for slot in 1..=4 {
        deadline(expires)?;
        let raw = read_pinned(
            &root,
            &files,
            &format!("slot-{slot}.block"),
            8 + version_journal::HEADER_BYTES + 4 + MAX_BODY,
        )?;
        let block = checked(CandidateBlock::decode(&raw))?;
        require(block.encode() == raw, "Noncanonical candidate export")?;
        let raw = read_pinned(
            &root,
            &files,
            &format!("slot-{slot}.qc"),
            registry200_finality::progress::MAX_CHECKPOINT_BYTES,
        )?;
        let qc = checked(Checkpoint::decode(&raw))?;
        require(qc.encode() == raw, "Noncanonical checkpoint export")?;
        let candidate = checked(Candidate::for_context(
            &binding,
            &context,
            block.header().clone(),
        ))?;
        require(
            qc.candidate() == &candidate,
            "Whole captured Candidate mismatch",
        )?;
        let decision =
            checked(context.verify_commit(&candidate.encode(), qc.round(), qc.certificate()))?;
        let header = block.header();
        require(
            header.genesis == g
                && header.parent == head.block
                && header.height
                    == head
                        .height
                        .checked_add(1)
                        .ok_or_else(|| invalid("Height overflow"))?,
            "Header lineage mismatch",
        )?;
        let _ = checked(headers.import_header(header.clone(), now))?;
        require(
            header.body_hash == version_journal::hash(block.body()),
            "Header/Body hash mismatch",
        )?;
        let body = checked(Body::decode(block.body(), &genesis.profile))?;
        require(
            checked(body.encode(&genesis.profile))? == block.body(),
            "Noncanonical Body",
        )?;
        let Body::Transition(t) = body else {
            return Err(invalid("Only original transitions are captured"));
        };
        checked(t.check_authorization(&genesis.owner, g))?;
        let request = checked(Request::decode(&t.request))?;
        let manifest = checked(Manifest::decode(&t.proof))?;
        let lane = match slot {
            1 => Lane::Bootstrap,
            2 | 3 => Lane::Control,
            _ => Lane::Predicate,
        };
        let canonical = checked(Request::new(&application, lane, request.inner().clone()))?;
        require(
            request.lane() == lane
                && manifest.lane() == lane
                && checked(canonical.encode())? == t.request
                && request.inner().parent == head.block
                && request.inner().genesis == g
                && t.parent == head.block,
            "Original Request/Manifest binding",
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
            "Original enrollment/control binding",
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
            "Original shard CAS",
        )?;
        let index = shards
            .iter()
            .position(|s| s.id == spec.control_id)
            .ok_or_else(|| invalid("Control shard missing"))?;
        shards[index] = ShardState {
            id: spec.control_id,
            heads: t.updates[0].new,
        };
        require(
            version_journal::state_root(&shards) == header.state_root,
            "Original shard root",
        )?;
        let mut uploads = Vec::new();
        for r in manifest.references() {
            add(
                &mut parts,
                r.blob_id(),
                r.byte_cap(),
                json!({"kind":"manifest","slot":slot,"role":role_name(r.role()),"ordinal":r.ordinal()}),
            )?;
            uploads.push(Upload {
                selector: ProgressProofBlobSelector::manifest(r.ordinal() as u16)?,
                id: r.blob_id(),
                cap: r.byte_cap(),
            });
            if r.role() == ManifestRole::ProductCatalog {
                require(catalog.is_none(), "Duplicate catalog")?;
                catalog = Some(checked(CatalogId::from_blob(r.blob_id()))?);
            }
        }
        let next_context = checked(context.after_decision(&decision))?;
        slots.push(
            json!({"slot":slot,"context":hex(&context.id()),"next_context":hex(&next_context.id()),
            "decision":hex(&decision.semantic_id()),"header":hex(&header.id()),
            "body_sha256":hex(&header.body_hash),"state_root":hex(&header.state_root)}),
        );
        head = HeadRef {
            genesis: g,
            database: genesis.database,
            block: header.id(),
            height: header.height,
            state_root: header.state_root,
        };
        if slot <= 3 {
            prefix.push(Prefix {
                block,
                checkpoint: qc,
                context: context.clone(),
                decision: decision.semantic_id(),
                uploads,
            });
        } else {
            require(
                decision.semantic_id() == digest(&pins["target_decision"])?,
                "Wrong target semantic decision",
            )?;
            // QC4 is reference-only and is discarded here, before any child exists.
            drop(qc);
            target = Some(Target {
                block,
                context: context.clone(),
                decision: decision.semantic_id(),
                uploads,
            });
        }
        context = next_context;
    }
    require(
        json!(slots) == pins["slots"],
        "Context/Header/Body/decision prefix mismatch",
    )?;
    let catalog = catalog.ok_or_else(|| invalid("Missing canonical catalog"))?;
    let raw = read_pinned(
        &root,
        &files,
        &blob_name(catalog.blob_id()),
        MAX_CATALOG_BYTES,
    )?;
    let quota = checked(ParticipantQuota::create_new(
        scratch.join("catalog-parser"),
        [0x86; 32],
        1024 * 1024,
    ))?;
    let mut store = checked(ProductStore::open(quota.depot_budget()))?;
    require(
        checked(store.retain_public_blob(&raw))? == catalog.blob_id(),
        "Catalog retention identity",
    )?;
    drop(raw);
    let claim = checked(store.catalog_claim(catalog))?;
    let setup = binding.setup_claim();
    require(
        claim.setup_parts() == setup.parts()
            && claim.setup_bytes() == setup.bytes()
            && setup.application_id() == application.id(),
        "Catalog/setup association",
    )?;
    closed(&manifest["catalog"], &["bytes", "graph_identity", "sha256"])?;
    require(
        number(&manifest["catalog"]["bytes"])? == catalog.blob_id().bytes()
            && digest::<32>(&manifest["catalog"]["sha256"])? == *catalog.blob_id().sha256()
            && digest::<64>(&manifest["catalog"]["graph_identity"])? == claim.graph_identity(),
        "Catalog metadata binding",
    )?;
    let target_frame = target.as_mut().ok_or_else(|| invalid("Missing target"))?;
    for r in claim.references() {
        add(
            &mut parts,
            r.blob_id(),
            r.byte_cap(),
            json!({"kind":"catalog","role":r.role(),"ordinal":r.ordinal()}),
        )?;
        target_frame.uploads.push(Upload {
            selector: ProgressProofBlobSelector::catalog(r.role(), r.ordinal())?,
            id: r.blob_id(),
            cap: r.byte_cap(),
        });
    }
    drop(claim);
    drop(store);
    drop(quota); // no metadata depot/gate across RPC
    let mut required: BTreeSet<String> = [
        "descriptor.bin",
        "work-genesis.bin",
        "journal-genesis.bin",
        "setup-claim.bin",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for slot in 1..=4 {
        required.insert(format!("slot-{slot}.block"));
        required.insert(format!("slot-{slot}.qc"));
    }
    required.extend(parts.keys().map(|id| blob_name(*id)));
    require(
        required == files.keys().cloned().collect(),
        "Archive differs from canonical complete role closure",
    )?;
    let mut metadata = BTreeMap::new();
    for v in array(&manifest["payload_files"], MAX_FILES - 2)? {
        metadata.insert(text(&v["file"])?, v);
    }
    for (id, part) in &parts {
        require(
            metadata[blob_name(*id).as_str()]["roles"] == json!(part.roles),
            "Role/order metadata mismatch",
        )?;
    }
    // Full fresh bounded hash+EOF audit of ALL originals, without retaining proof vectors.
    for (name, pin) in &files {
        deadline(expires)?;
        let cap = if let Some(cap) = fixed_cap(name) {
            cap
        } else {
            parts[&blob_from_name(name)?].cap
        };
        let mut file = open_regular(&root.join(name), pin.bytes, cap)?;
        let mut hash = Sha256::new();
        let mut count = 0_u64;
        let mut buffer = [0; 64 * 1024];
        loop {
            deadline(expires)?;
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            count = count
                .checked_add(n as u64)
                .ok_or_else(|| invalid("Read count overflow"))?;
            require(count <= pin.bytes, "Trailing public bytes")?;
            hash.update(&buffer[..n]);
        }
        require(
            count == pin.bytes
                && <[u8; 32]>::from(hash.finalize()) == pin.sha256
                && file.metadata()?.len() == pin.bytes,
            "Full public original hash/EOF",
        )?;
    }
    require_setup_hashes(
        &root,
        &files,
        binding.setup_claim().parts(),
        binding.setup_claim().bytes(),
        binding.application_descriptor().full_setup_id(),
        binding.application_descriptor().full_setup_digest(),
    )?;
    let target = target.take().ok_or_else(|| invalid("Missing target"))?;
    deadline(expires)?;
    Ok(Archive {
        root,
        files,
        binding,
        prefix: prefix
            .try_into()
            .map_err(|_| invalid("Exactly three prefix slots"))?,
        target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repaired_complete_cannot_replace_independent_manifest_pin() {
        let expected = Sha256::digest(b"original").into();
        let changed = b"changed";
        let repaired = format!("{}\n", hex(&Sha256::digest(changed)));
        let error = check_manifest(changed, repaired.as_bytes(), expected).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("independent invocation"));
    }
    #[test]
    fn inventory_rejects_traversal_duplicates_and_overcap_extents() {
        for name in [
            "../outside",
            "blobs/../../outside",
            "/absolute",
            "slot-5.qc",
        ] {
            assert!(
                inventory(
                    &json!([{"file":name,"bytes":1,"sha256":hex(&[1;32])}]),
                    false
                )
                .is_err()
            );
        }
        let item = json!({"file":"descriptor.bin","bytes":896,"sha256":hex(&[1;32])});
        assert!(
            inventory(&json!([item.clone(), item]), false)
                .unwrap_err()
                .to_string()
                .contains("Duplicate")
        );
        assert!(
            inventory(
                &json!([{"file":"descriptor.bin","bytes":897,"sha256":hex(&[1;32])}]),
                false
            )
            .unwrap_err()
            .to_string()
            .contains("cap")
        );
    }
    #[test]
    fn catalog_file_names_require_exact_hash_extent_spelling() {
        let id = BlobId::new([0xab; 32], 8).unwrap();
        let canonical = blob_name(id);
        for name in [
            canonical.to_uppercase(),
            canonical.replace("0000000000000008", "8"),
            canonical.replace("-0000000000000008", "-0000000000000000"),
        ] {
            assert!(blob_from_name(&name).is_err(), "{name}");
        }
    }
}

#[cfg(test)]
mod io_tests {
    use super::*;
    use crate::network::Directory;
    fn end() -> Instant {
        Instant::now() + peer_runtime::finality::PROGRESS_OPERATION_BUDGET
    }
    #[test]
    fn extra_file_and_expired_scan_stop_before_unbounded_inventory_growth() {
        let dir = Directory::new().unwrap();
        fs::create_dir(dir.path().join("blobs")).unwrap();
        fs::write(dir.path().join("unexpected"), b"PUBLIC TEST BYTES").unwrap();
        let expected = BTreeSet::from(["manifest.json".to_owned()]);
        let e = scan_layout(dir.path(), &expected, end()).unwrap_err();
        assert!(e.to_string().contains("Unexpected archive filename"));
        let e = scan_layout(dir.path(), &expected, Instant::now()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        dir.finish().unwrap();
    }
    #[test]
    fn changed_extent_nonregular_and_changed_hash_reject_actual_file_reads() {
        let dir = Directory::new().unwrap();
        let path = dir.path().join("descriptor.bin");
        fs::write(&path, b"ABCD").unwrap();
        assert!(
            read_extent(&path, 4, 3)
                .unwrap_err()
                .to_string()
                .contains("role cap")
        );
        fs::write(&path, b"ABCDE").unwrap();
        assert!(
            read_extent(&path, 4, 4)
                .unwrap_err()
                .to_string()
                .contains("extent")
        );
        fs::write(&path, b"ABCE").unwrap();
        let pins = BTreeMap::from([(
            "descriptor.bin".into(),
            FilePin {
                bytes: 4,
                sha256: Sha256::digest(b"ABCD").into(),
            },
        )]);
        assert!(
            read_pinned(dir.path(), &pins, "descriptor.bin", 4)
                .unwrap_err()
                .to_string()
                .contains("hash mismatch")
        );
        fs::create_dir(dir.path().join("not-file")).unwrap();
        assert!(read_extent(&dir.path().join("not-file"), 4, 4).is_err());
        dir.finish().unwrap();
    }
    #[test]
    fn setup_stream_rejects_deduplication_reordering_and_either_wrong_digest() {
        let dir = Directory::new().unwrap();
        fs::create_dir(dir.path().join("blobs")).unwrap();
        let mut files = BTreeMap::new();
        let mut ids = Vec::new();
        for bytes in [b"PUBLIC-A".as_slice(), b"PUBLIC-B".as_slice()] {
            let hash = Sha256::digest(bytes).into();
            let id = BlobId::new(hash, bytes.len() as u64).unwrap();
            let name = blob_name(id);
            fs::write(dir.path().join(&name), bytes).unwrap();
            files.insert(
                name,
                FilePin {
                    bytes: id.bytes(),
                    sha256: hash,
                },
            );
            ids.push(id);
        }
        // Tiny ordinary hash-stream inputs only: not a fake accepted SetupClaim,
        // application proof, full archive, SQL answer or two-chunk geometry test.
        let pair = b"PUBLIC-APUBLIC-B";
        let reverse256 = Sha256::digest(b"PUBLIC-BPUBLIC-A").into();
        let full256 = Sha256::digest(pair).into();
        let full512 = Sha512::digest(pair).into();
        require_setup_hashes(dir.path(), &files, &ids, 16, full256, full512).unwrap();
        let e =
            require_setup_hashes(dir.path(), &files, &ids, 16, reverse256, full512).unwrap_err();
        assert!(e.to_string().contains("Full original setup hashes"));
        assert!(
            require_setup_hashes(
                dir.path(),
                &files,
                &ids,
                16,
                full256,
                Sha512::digest(b"PUBLIC-BPUBLIC-A").into()
            )
            .is_err()
        );
        assert!(
            require_setup_hashes(
                dir.path(),
                &files,
                &[ids[0], ids[0]],
                8,
                Sha256::digest(b"PUBLIC-A").into(),
                Sha512::digest(b"PUBLIC-A").into()
            )
            .is_err()
        );
        dir.finish().unwrap();
    }
}
