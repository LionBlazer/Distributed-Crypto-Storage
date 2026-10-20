//! Four real validators and two sequential owner PIDs; native owning gate passed.
//! Public ingest fixtures are not SQL answers. No local QC is assembled here.
use super::*;
use crate::private_predicate::source::locking::joint::tests::{
    full_acquire_fixture as fixture, os_process,
};
use crate::private_predicate::{
    EncryptedSourceState, SourceOwner, SourceStateAuthority, SourceStateIdentity,
};
use bfv_query_core::{
    EncryptedOwnerState, Geometry, KeyScope, MAX_OWNER_STATE_BYTES, Owner, OwnerStateAuthority,
    OwnerStateIdentity, PublicSetup,
};
use compact_query::{PlainRow, ReadHeads, RowIds, TableId};
use ed25519_dalek::SigningKey;
use p3_field::PrimeField64;
use peer_runtime::{
    Connector, Endpoint, Identity, RawBundle,
    finality::{JointFinalityClient, ProofBlobSelector},
    participant::ParticipantInstall,
};
use protocol_storage::{ControlFile, ParticipantQuota};
use registry200_finality::{
    CandidateBlock,
    joint::{JointBinding, JointCheckpoint, JointHistory},
};
use registry200_joint::{Descriptor, JointDepot, JointEvidenceIngress, Manifest, SetupClaim};
use registry200_journal::{Application as SourceSpec, ApplicationDescriptor, Control};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use version_journal::{
    AuthorizedTransition, Body, Genesis, Header, ProtocolProfile, ShardUpdate, Target,
};
use work_finality::{
    Genesis as WorkGenesis, Limits as WorkLimits, NetworkSeed, WorkTicket,
    consensus::{Context, MAX_RECORD_BYTES, Rules},
};

#[path = "acquire_process_tests.rs"]
mod acquire;
#[path = "host_process_tests.rs"]
mod host;
#[path = "process_observation.rs"]
mod observation;
#[path = "process_worker.rs"]
mod process_worker;
use observation::{Kind as RpcKind, Observation, until};

const WORKER: &str =
    "private_predicate::source::locking::joint::vault::process_tests::owner_process_worker";
const NAMESPACE: [u8; 32] = [0xb6; 32];
const NETWORK: [u8; 32] = [0x3a; 32];
const TABLE: [u8; 32] = [0x19; 32];
const DATABASE: [u8; 16] = [0x21; 16];
const DOMAIN: [u8; 16] = [0x88; 16];
const VAULT_ID: [u8; 32] = [0x81; 32];
const SOURCE_ID: [u8; 32] = [0x82; 32];
const CORE_ID: [u8; 32] = [0x83; 32];
const WAIT: Duration = Duration::from_secs(1800);
const PUBLIC_JSON: usize = 64 * 1024;
const BUNDLE_CAP: usize = 1024 * 1024;
const BLOCK_CAP: usize = 8 + version_journal::HEADER_BYTES + 4 + OWNER_VAULT_MAX_BODY_BYTES;
// Fixed test custody roles. All are public bytes or already encrypted records;
// no authority key, SK, plaintext bank or salt is stored beside this namespace.
const WORK: u8 = 0;
const JOURNAL: u8 = 1;
const DESCRIPTOR: u8 = 2;
const SETUP_CLAIM: u8 = 3;
const SETUP: u8 = 4;
const BUNDLE: u8 = 5;
const TABLE_ID: u8 = 6;
const ANCHOR: u8 = 7;
const KEY: u8 = 8;
const KEY33: u8 = 9;
const CKEY: u8 = 10;
const SOURCE_STATE: u8 = 11;
const OWNER_STATE: u8 = 12;
const ANCHOR_STATE: u8 = 13;
const EPOCH_STATE: u8 = 14;
const BOOT_BLOCK: u8 = 15;
const BOOT_QC: u8 = 16;
const BEGIN_BLOCK: u8 = 17;
const CURSOR: u8 = 18;

fn checked<T, E: core::fmt::Debug>(result: core::result::Result<T, E>) -> io::Result<T> {
    result.map_err(|e| io::Error::other(format!("{e:?}")))
}
fn require(ok: bool, message: &'static str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn fresh<const N: usize>() -> io::Result<[u8; N]> {
    let mut v = [0; N];
    checked(getrandom::getrandom(&mut v))?;
    Ok(v)
}
fn rules() -> io::Result<Rules> {
    checked(Rules::multi_slot(
        registry200_finality::joint::durable_profile_digest(),
        registry200_finality::joint::CANDIDATE_BYTES as u32,
        32,
        fixture::TIMEOUTS,
        fixture::DELTA,
        MAX_RECORD_BYTES as u64,
    ))
}
fn work() -> io::Result<WorkGenesis> {
    let rules = rules()?;
    let seed = checked(NetworkSeed::new(
        rules.seed_domain(NETWORK),
        [10; 32],
        [255; 32],
        checked(WorkLimits::new(16, 4))?,
    ))?;
    let tickets = fixture::signers()
        .iter()
        .map(|key| checked(WorkTicket::sign(&seed.bootstrap_election(), key, 0)))
        .collect::<io::Result<Vec<_>>>()?;
    checked(WorkGenesis::from_bootstrap(seed, tickets))
}
fn role_cap(role: u8) -> io::Result<usize> {
    Ok(match role {
        WORK => work_finality::MAX_GENESIS_BYTES,
        JOURNAL => 716,
        DESCRIPTOR => 896,
        SETUP_CLAIM => 136,
        SETUP => registry200_joint::MAX_SETUP_BYTES,
        BUNDLE => BUNDLE_CAP,
        TABLE_ID | CKEY => 32,
        ANCHOR => 140,
        KEY => bfv_key_transform::HEADER_BYTES + bfv_key_transform::MAX_PROOF_BYTES,
        KEY33 => 33 * 8,
        SOURCE_STATE => 488,
        OWNER_STATE => 8848,
        ANCHOR_STATE => 688,
        EPOCH_STATE => MAX_OWNER_STATE_BYTES,
        BOOT_BLOCK | BEGIN_BLOCK => BLOCK_CAP,
        BOOT_QC => registry200_finality::joint::MAX_CHECKPOINT_BYTES,
        CURSOR => 72,
        _ => return Err(io::Error::other("Unknown fixed owner custody role")),
    })
}
fn file_path(root: &Path, role: u8) -> PathBuf {
    let id = Sha256::digest([b"DCS/test-owner-restart-custody/v1".as_slice(), &[role]].concat());
    let name = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
    root.join("control").join(format!("{name}.meta"))
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Pin {
    role: u8,
    bytes: u64,
    sha256: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Inventory {
    files: Vec<Pin>,
    binding: [u8; 32],
    work: [u8; 32],
    journal: [u8; 32],
}
impl Inventory {
    fn validate(&self, count: usize) -> io::Result<()> {
        require(
            self.files.len() == count && matches!(count, 16 | 19),
            "Owner inventory count",
        )?;
        for (i, p) in self.files.iter().enumerate() {
            require(
                p.role as usize == i && p.bytes > 0 && p.bytes <= role_cap(p.role)? as u64,
                "Owner inventory order/cap",
            )?;
        }
        Ok(())
    }
    fn read(&self, root: &Path, role: u8) -> io::Result<Vec<u8>> {
        let pin = self
            .files
            .get(role as usize)
            .ok_or_else(|| io::Error::other("Missing fixed inventory role"))?;
        require(
            pin.role == role && pin.bytes <= role_cap(role)? as u64,
            "Owner role cap",
        )?;
        let path = file_path(root, role);
        let meta = fs::symlink_metadata(&path)?;
        require(
            meta.file_type().is_file() && meta.len() == pin.bytes,
            "Owner custody extent/type",
        )?;
        let mut file = File::open(path)?;
        let mut bytes = Vec::with_capacity(pin.bytes as usize);
        Read::by_ref(&mut file)
            .take(pin.bytes + 1)
            .read_to_end(&mut bytes)?;
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        require(
            bytes.len() as u64 == pin.bytes && actual == pin.sha256,
            "Owner custody hash/EOF",
        )?;
        Ok(bytes)
    }
}
fn persist(
    quota: &ParticipantQuota,
    inventory: &mut Inventory,
    role: u8,
    bytes: &[u8],
) -> io::Result<()> {
    require(
        role as usize == inventory.files.len()
            && !bytes.is_empty()
            && bytes.len() <= role_cap(role)?,
        "Owner custody fixed role/size",
    )?;
    let id: [u8; 32] =
        Sha256::digest([b"DCS/test-owner-restart-custody/v1".as_slice(), &[role]].concat()).into();
    let path = quota.control_file(id, ControlFile::Metadata);
    write_custody(quota, &path, bytes)?;
    inventory.files.push(Pin {
        role,
        bytes: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    });
    Ok(())
}
// One actual writer shared by both closed test inventories. Each caller first
// enforces its own fixed role/cap; no serializer, bank or proof authority here.
fn write_custody(quota: &ParticipantQuota, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let budget = quota.control_budget();
    let mut permit = checked(budget.preflight_file(path, bytes.len() as u64))?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    file.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::WouldBlock,
            "Owner custody file already locked",
        ),
        fs::TryLockError::Error(error) => error,
    })?;
    let charge = checked(permit.register_file())?;
    let written = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        require(
            file.metadata()?.len() == bytes.len() as u64,
            "Owner custody final extent",
        )
    })();
    if let Err(error) = written {
        charge.mark_io_failed();
        return Err(error);
    }
    drop(file);
    drop(charge);
    drop(permit);
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u16,
    role: u8,
    root: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    version: u16,
    stage: u8,
    pid: u32,
    inventory: Inventory,
    header: [u8; 32],
    body: [u8; 32],
    key: [u8; 32],
    generation: u64,
}
fn report(value: &Report) -> io::Result<()> {
    let bytes = checked(serde_json::to_vec(value))?;
    write_report(&bytes)
}
fn write_report(bytes: &[u8]) -> io::Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    out.write_all(b"\nDCS-OWNER-PUBLIC-REPORT-01\n")?;
    peer_transport::write_frame(&mut out, bytes, PUBLIC_JSON)?;
    out.flush()
}
fn binding(inventory: &Inventory, root: &Path) -> io::Result<JointBinding> {
    let work = checked(WorkGenesis::decode(
        &inventory.read(root, WORK)?,
        inventory.work,
    ))?;
    let journal = checked(Genesis::decode(&inventory.read(root, JOURNAL)?))?;
    require(
        checked(journal.id())? == inventory.journal,
        "Independent Journal genesis",
    )?;
    let result = checked(JointBinding::for_durable(
        NETWORK,
        rules()?,
        work,
        journal,
        checked(Descriptor::decode(&inventory.read(root, DESCRIPTOR)?))?,
        checked(SetupClaim::decode(&inventory.read(root, SETUP_CLAIM)?))?,
    ))?;
    require(
        result.id() == inventory.binding,
        "Independent Joint binding",
    )?;
    Ok(result)
}
fn fetched<'a>(
    bundle: &'a RawBundle,
    heads: &'a ReadHeads,
) -> io::Result<crate::private_predicate::FetchedSource<'a>> {
    Ok(crate::private_predicate::FetchedSource {
        object: *checked(bundle.target_version())?.object(),
        bundle,
        heads,
    })
}
fn heads(bundle: &RawBundle, table: &[u8]) -> io::Result<ReadHeads> {
    let limits = compact_store::Limits::default();
    let data = checked(compact_store::Commitment::decode(&bundle.data_head, limits))?;
    let index = checked(compact_query::decode_index_head(
        &bundle.index_head,
        data.layout().row_count,
    ))?;
    checked(ReadHeads::new(
        checked(TableId::from_bytes(checked(table.try_into())?))?,
        &data,
        &index,
        limits,
    ))
}
fn scope() -> KeyScope {
    KeyScope {
        database: DATABASE,
        bfv_key_domain: DOMAIN,
        epoch: 1,
    }
}
fn core_identity() -> OwnerStateIdentity {
    OwnerStateIdentity {
        scope: scope(),
        record_id: CORE_ID,
    }
}
fn pins(binding: &JointBinding) -> io::Result<OwnerVaultPins> {
    Ok(OwnerVaultPins::new(
        binding.clone(),
        checked(OwnerVaultIdentity::new(VAULT_ID))?,
    ))
}
fn cursor_bytes(cursor: OwnerVaultCursor) -> [u8; 72] {
    let mut bytes = [0; 72];
    bytes[..8].copy_from_slice(&cursor.generation().to_le_bytes());
    bytes[8..40].copy_from_slice(&cursor.pending_id());
    bytes[40..].copy_from_slice(&cursor.digest());
    bytes
}
fn key_bytes(statement: &bfv_key_transform::Statement) -> Vec<u8> {
    statement
        .public_values()
        .iter()
        .flat_map(|v| v.as_canonical_u64().to_le_bytes())
        .collect()
}
fn transition(
    binding: &JointBinding,
    parent: version_journal::HeadRef,
    request: JointRequest,
    manifest: Manifest,
    old: Control,
    signer: &SigningKey,
) -> io::Result<CandidateBlock> {
    let spec = checked(binding.application_descriptor().source_spec())?;
    let next = Control::Active {
        enrollment: request.inner().enrollment,
        registry: manifest.next_root(),
    };
    let mut body = AuthorizedTransition {
        parent: parent.block,
        request: checked(request.encode())?,
        updates: vec![ShardUpdate {
            id: spec.control_id,
            old: old.heads(&spec),
            new: next.heads(&spec),
        }],
        proof: manifest.encode(),
        owner_signature: [0; 64],
    };
    body.sign(parent.genesis, signer);
    let bytes = checked(Body::Transition(body).encode(&binding.journal_genesis().profile))?;
    let mut shards = spec.initial_shards();
    shards
        .iter_mut()
        .find(|s| s.id == spec.control_id)
        .ok_or_else(|| io::Error::other("Missing Control shard"))?
        .heads = next.heads(&spec);
    let mut header = Header {
        genesis: parent.genesis,
        parent: parent.block,
        height: parent.height + 1,
        timestamp: 1001 + parent.height,
        target: Target([255; 32]),
        body_hash: version_journal::hash(&bytes),
        state_root: version_journal::state_root(&shards),
        nonce: 0,
    };
    checked(header.mine(1))?;
    checked(CandidateBlock::new(header, bytes))
}
fn upload(
    client: &JointFinalityClient,
    peer: usize,
    block: &CandidateBlock,
    ingress: &JointEvidenceIngress,
    binding: &JointBinding,
) -> io::Result<()> {
    let Body::Transition(body) = checked(Body::decode(
        block.body(),
        &binding.journal_genesis().profile,
    ))?
    else {
        return Err(io::Error::other("Control transition required"));
    };
    for reference in checked(Manifest::decode(&body.proof))?.references() {
        let bytes = checked(ingress.read_public_blob(reference.blob_id(), reference.byte_cap()))?;
        until(
            Observation::new(RpcKind::Manifest, peer, reference.ordinal(), bytes.len()),
            || {
                client
                    .put_proof_blob(
                        block,
                        checked(ProofBlobSelector::manifest(
                            reference.ordinal().try_into().map_err(io::Error::other)?,
                        ))?,
                        reference.blob_id(),
                        &bytes,
                    )
                    .map(|()| Some(()))
            },
        )?;
    }
    Ok(())
}
fn submit(clients: &[JointFinalityClient], block: &CandidateBlock) -> io::Result<()> {
    require(clients.len() == 4, "Four actual validators required")?;
    submit_subset(clients, block)
}
fn submit_subset(clients: &[JointFinalityClient], block: &CandidateBlock) -> io::Result<()> {
    require(
        (1..=4).contains(&clients.len()),
        "One to four actual validators required for catch-up",
    )?;
    std::thread::scope(|scope| {
        let workers = clients
            .iter()
            .enumerate()
            .map(|(peer, client)| {
                scope.spawn(move || {
                    until(
                        Observation::new(RpcKind::Submit, peer, 0, block.body().len()),
                        || client.submit(block).map(|()| Some(())),
                    )
                })
            })
            .collect::<Vec<_>>();
        let results = workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| io::Error::other("Submit worker panic"))
                    .and_then(|r| r)
            })
            .collect::<Vec<_>>();
        for result in results {
            result?;
        }
        Ok(())
    })
}
fn checkpoints(
    clients: &[JointFinalityClient],
    binding: &JointBinding,
    context: &Context,
    block: &CandidateBlock,
) -> io::Result<Vec<JointCheckpoint>> {
    let mut result = Vec::with_capacity(4);
    let mut decision = None;
    for (peer, client) in clients.iter().enumerate() {
        let qc = until(Observation::new(RpcKind::Checkpoint, peer, 0, 0), || {
            client.checkpoint_after(context.slot() - 1)
        })?;
        require(
            qc.candidate().header() == block.header() && qc.candidate().slot() == context.slot(),
            "QC exact original candidate",
        )?;
        let actual =
            checked(context.verify_commit(&qc.candidate().encode(), qc.round(), qc.certificate()))?;
        let semantic = actual.semantic_id();
        require(
            decision.is_none_or(|prior| prior == semantic),
            "QC semantic decision differs",
        )?;
        decision = Some(semantic);
        let fetched = until(
            Observation::new(RpcKind::Body, peer, 0, block.body().len()),
            || client.candidate_block(block.header().id()).map(Some),
        )?;
        require(
            fetched.encode() == block.encode(),
            "Actual peer saved different signed Body",
        )?;
        require(
            qc.candidate().encode()
                == checked(registry200_finality::joint::JointCandidate::for_context(
                    binding,
                    context,
                    block.header().clone(),
                ))?
                .encode(),
            "QC current binding/parent context",
        )?;
        result.push(qc);
    }
    Ok(result)
}
fn next_context(context: &Context, qc: &JointCheckpoint) -> io::Result<Context> {
    let decision =
        checked(context.verify_commit(&qc.candidate().encode(), qc.round(), qc.certificate()))?;
    checked(context.after_decision(&decision))
}
fn clients(
    endpoints: &[Endpoint],
    identity: &Identity,
    binding: &JointBinding,
) -> io::Result<Vec<JointFinalityClient>> {
    require(
        endpoints.len() == 4
            && endpoints
                .iter()
                .map(|v| v.address)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == 4,
        "Four distinct endpoint addresses",
    )?;
    let connector = Connector::permissionless(identity)?;
    Ok(endpoints
        .iter()
        .cloned()
        .map(|endpoint| JointFinalityClient::new(connector.clone(), endpoint, binding))
        .collect())
}
fn start_validators(
    exe: &Path,
    directory: &fixture::Directory,
    binding: &JointBinding,
    owner: &Identity,
    setup: &[u8],
    processes: &mut Vec<os_process::Process>,
) -> io::Result<Vec<Endpoint>> {
    let identities = (0..4).map(|_| fixture::identity()).collect::<Vec<_>>();
    let mut sockets = (0..4)
        .map(|_| TcpListener::bind("127.0.0.1:0").map(Some))
        .collect::<io::Result<Vec<_>>>()?;
    let endpoints = sockets
        .iter()
        .zip(&identities)
        .map(|(socket, id)| {
            Ok(Endpoint {
                address: socket.as_ref().unwrap().local_addr()?,
                identity: id.fingerprint(),
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let signers = fixture::signers();
    let work = checked(binding.work_genesis().encode())?;
    let journal = checked(binding.journal_genesis().encode())?;
    let descriptor = binding.application_descriptor().encode();
    let claim = binding.setup_claim().encode();
    for i in 0..4 {
        let neighbors = endpoints
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, v)| v.clone())
            .collect::<Vec<_>>();
        let config = Zeroizing::new(checked(serde_json::to_vec(&serde_json::json!({
            "version":1,"kind":"registry200-joint-participant-finality-v1","identity":identities[i],"authority":[],
            "owner":owner.fingerprint(),"listen":endpoints[i].address,"neighbors":neighbors,"namespace":NAMESPACE,"capacity":fixture::CAPACITY,
            "work_genesis":binding.work_genesis().id(),"journal_genesis":checked(binding.journal_genesis().id())?,"binding":binding.id(),
            "rules":{"max_round":32,"timeouts_ms":fixture::TIMEOUTS,"timeout_delta_ms":fixture::DELTA,"wal_bytes":MAX_RECORD_BYTES as u64},"signer":signers[i].to_bytes().to_vec()
        })))?);
        let mut frames = vec![
            config.as_slice(),
            work.as_slice(),
            journal.as_slice(),
            descriptor.as_slice(),
            claim.as_slice(),
        ];
        frames.extend(setup.chunks(protocol_storage::MAX_BLOB_BYTES as usize));
        drop(sockets[i].take());
        let process = os_process::Process::start_joint(
            exe,
            &directory.path(&format!("validator-{i}")),
            ParticipantInstall::New,
            &frames,
        )?;
        let good = process.ready().version == 1
            && process.ready().binding == binding.id()
            && process.ready().namespace == NAMESPACE
            && process.ready().profile
                == peer_runtime::joint_participant::joint_participant_host_profile_digest()
            && process.endpoint() == &endpoints[i];
        eprintln!("Actual validator peer={i} pid={}", process.pid());
        processes.push(process);
        require(
            good,
            "Actual validator Ready differs from independent install",
        )?;
    }
    require(
        processes
            .iter()
            .map(|p| p.pid())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == 4,
        "Four unique actual peer PIDs",
    )?;
    Ok(endpoints)
}

/// This ignored entry point ALWAYS parses the authenticated test's bounded
/// private stdin. Invoking it manually without valid input is an error.
#[test]
#[ignore = "Subprocess entry only; requires the fixed bounded owner IPC grammar"]
fn owner_process_worker() {
    process_worker::run().expect("Actual owner subprocess failed");
}

#[test]
#[ignore = "Actual four dcs-peer validators plus sequential owner A/B restart; requires DCS_PEER_EXE"]
fn six_os_processes_restore_original_owner_epoch_and_complete_only_the_saved_control_intent() {
    let directory = fixture::Directory::new();
    let mut validators = Vec::new();
    // Actual child RAII owners join even if an assertion/library call unwinds.
    // Normal error handling below finishes every child before asserting success.
    let result = (|| -> io::Result<()> {
        let exe = PathBuf::from(
            std::env::var_os("DCS_PEER_EXE")
                .ok_or_else(|| io::Error::other("DCS_PEER_EXE required"))?,
        );
        require(
            exe.is_absolute() && exe.is_file(),
            "Actual dcs-peer executable required",
        )?;
        let worker_exe = std::env::current_exe()?;
        let authority = Zeroizing::new(fresh::<128>()?);
        let owner_tls = fixture::identity();
        let tls = Zeroizing::new(checked(serde_json::to_vec(&owner_tls))?);
        let work = checked(work()?.encode())?;
        let root = directory.path("owner-private");
        let config = checked(serde_json::to_vec(&Config {
            version: 1,
            role: 1,
            root: root.clone(),
        }))?;
        let mut a = os_process::OwnerProcess::start(
            &worker_exe,
            WORKER,
            [
                &config,
                authority.as_slice(),
                tls.as_slice(),
                &work,
                b"null",
            ],
        )?;
        let a_pid = a.pid();
        require(
            a_pid != std::process::id(),
            "A must be an actual distinct process",
        )?;
        let prepared: Report = checked(serde_json::from_slice(&a.public_report()?))?;
        prepared.inventory.validate(16)?;
        require(
            prepared.version == 1 && prepared.stage == 1 && prepared.pid == a_pid,
            "Owner A initial report",
        )?;
        let binding = binding(&prepared.inventory, &root)?;
        let db_signer = SigningKey::from_bytes(authority[96..128].try_into().unwrap());
        require(
            binding.journal_genesis().owner == db_signer.verifying_key().to_bytes()
                && prepared.inventory.read(&root, WORK)? == work,
            "Supervisor's independent owner/Work pins",
        )?;
        let original_boot = checked(CandidateBlock::decode(
            &prepared.inventory.read(&root, BOOT_BLOCK)?,
        ))?;
        let original_key: [u8; 32] = Sha256::digest(prepared.inventory.read(&root, KEY)?).into();
        require(
            original_boot.header().id() == prepared.header
                && version_journal::hash(original_boot.body()) == prepared.body
                && original_key == prepared.key,
            "A original public Bootstrap/Key pins",
        )?;
        let setup = prepared.inventory.read(&root, SETUP)?;
        let setup_digest: [u8; 32] = Sha256::digest(&setup).into();
        require(
            setup_digest == binding.application_descriptor().full_setup_id(),
            "Full original public setup pin",
        )?;
        let endpoints = start_validators(
            &exe,
            &directory,
            &binding,
            &owner_tls,
            &setup,
            &mut validators,
        )?;
        require(
            validators.iter().all(|p| p.pid() != a_pid),
            "Owner/validator PID separation",
        )?;
        a.send_endpoints(&checked(serde_json::to_vec(&endpoints))?)?;
        let submitted: Report = checked(serde_json::from_slice(&a.public_report()?))?;
        // Joining A and its stdout thread precedes creating ANY B capability.
        a.finish()?;
        submitted.inventory.validate(19)?;
        require(
            submitted.version == 1
                && submitted.stage == 2
                && submitted.pid == a_pid
                && submitted.generation == 0
                && submitted.inventory.files[..16] == prepared.inventory.files[..]
                && submitted.inventory.binding == binding.id(),
            "A exact saved public inventory",
        )?;
        let begin = checked(CandidateBlock::decode(
            &submitted.inventory.read(&root, BEGIN_BLOCK)?,
        ))?;
        require(
            begin.header().id() == submitted.header
                && version_journal::hash(begin.body()) == submitted.body,
            "A saved signed Begin",
        )?;
        let saved_cursor = submitted.inventory.read(&root, CURSOR)?;
        require(
            saved_cursor[..8] == 0u64.to_le_bytes(),
            "A exits before private completion",
        )?;
        let config = checked(serde_json::to_vec(&Config {
            version: 1,
            role: 2,
            root: root.clone(),
        }))?;
        let inventory = checked(serde_json::to_vec(&submitted.inventory))?;
        let mut b = os_process::OwnerProcess::start(
            &worker_exe,
            WORKER,
            [
                &config,
                authority.as_slice(),
                tls.as_slice(),
                &work,
                &inventory,
            ],
        )?;
        let b_pid = b.pid();
        require(
            b_pid != a_pid
                && b_pid != std::process::id()
                && validators.iter().all(|p| p.pid() != b_pid),
            "B must be a fresh independent owner PID",
        )?;
        b.send_endpoints(&checked(serde_json::to_vec(&endpoints))?)?;
        let completed: Report = checked(serde_json::from_slice(&b.public_report()?))?;
        b.finish()?;
        require(
            completed.version == 1
                && completed.stage == 3
                && completed.pid == b_pid
                && completed.inventory == submitted.inventory
                && completed.key == prepared.key
                && completed.generation == 2
                && completed.header != submitted.header,
            "B actual original-key restore and Begin/End completions",
        )?;
        // No live owner/depot descendants remain when independently reopening.
        let quota = checked(ParticipantQuota::open_existing(
            &root,
            NAMESPACE,
            fixture::CAPACITY,
        ))?;
        require(
            checked(quota.usage())?.control_bytes() > 0,
            "Reopen actual accounted owner files",
        )?;
        drop(quota);
        Ok(())
    })();
    let shutdown = validators
        .into_iter()
        .map(os_process::Process::finish)
        .collect::<Vec<_>>();
    for stopped in shutdown {
        stopped.expect("Actual validator joined cleanup");
    }
    result.expect("Actual two-owner/four-validator recovery gate");
}
