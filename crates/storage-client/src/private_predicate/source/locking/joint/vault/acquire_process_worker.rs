//! Actual owner A/B bodies; no local consensus certificates or inherited owner.
//! A prepares once; B restores the original bounded encrypted owner records.
use super::super::acquire::{
    ACQUIRE_BODY, ACQUIRE_CURSOR, AcquireConfig, AcquireEndpoints, AcquireInventory, AcquireReport,
    BEGIN_CERT, RECOVERY_ID, phase, report_acquire, upload_acquire,
};
use super::*;
use peer_runtime::{RemotePeer, Request, Response};

#[path = "host_process_worker.rs"]
mod host_worker;
pub(super) fn run_host() -> io::Result<()> {
    host_worker::run()
}

struct AcquireAuthorities {
    base: Authorities,
    capsule: JointRecoveryKey,
}
impl AcquireAuthorities {
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        require(
            bytes.len() == 160,
            "Exactly five external Acquire authorities required",
        )?;
        Ok(Self {
            base: Authorities::decode(&bytes[..128])?,
            capsule: JointRecoveryKey::new(Zeroizing::new(bytes[128..].try_into().unwrap())),
        })
    }
}

pub(super) fn run() -> io::Result<()> {
    let input = std::io::stdin();
    let mut input = input.lock();
    let config: AcquireConfig = read_json(&mut input)?;
    require(
        config.version == 2 && matches!(config.role, 1 | 2) && config.root.is_absolute(),
        "Bounded Acquire-v2 role/root",
    )?;
    let private = Zeroizing::new(peer_transport::read_frame(&mut input, 160)?);
    let authorities = AcquireAuthorities::decode(&private)?;
    drop(private);
    let tls = Zeroizing::new(peer_transport::read_frame(&mut input, PUBLIC_JSON)?);
    let identity: Identity = checked(serde_json::from_slice(&tls))?;
    drop(tls);
    let original_work = peer_transport::read_frame(&mut input, work_finality::MAX_GENESIS_BYTES)?;
    let independent_work = work()?;
    require(
        original_work == checked(independent_work.encode())?,
        "Original independent WorkGenesis",
    )?;
    let inventory = peer_transport::read_frame(&mut input, PUBLIC_JSON)?;
    // Explicit scheduling owner. All local native work shares this one gate;
    // there is no dummy server, second ProductStore or new quota for a proof.
    let gate = peer_runtime::ProofGate::new();
    if config.role == 1 {
        require(
            inventory == b"null",
            "New Acquire owner cannot adopt a restored inventory",
        )?;
        owner_a(
            &config.root,
            &authorities,
            &identity,
            independent_work,
            &gate,
            &mut input,
        )
    } else {
        let inventory: AcquireInventory = checked(serde_json::from_slice(&inventory))?;
        inventory.validate(false)?;
        owner_b(
            &config.root,
            &authorities,
            &identity,
            &inventory,
            &gate,
            &mut input,
        )
    }
}

struct Originals {
    setup: PublicSetup,
    anchor: bfv_query_core::BfvKeyAnchor,
    key: bfv_key_transform::Statement,
    owner_identity: OwnerStateIdentity,
    owner_record: EncryptedOwnerState,
    anchor_record: EncryptedOwnerState,
    ready_record: EncryptedOwnerState,
    source_identity: SourceStateIdentity,
    source_record: EncryptedSourceState,
    recovery_identity: JointRecoveryIdentity,
}
impl Originals {
    fn material<'a>(&'a self, authority: &'a AcquireAuthorities) -> OwnerVaultAcquireMaterial<'a> {
        OwnerVaultAcquireMaterial {
            setup: &self.setup,
            anchor: &self.anchor,
            key: &self.key,
            owner_identity: &self.owner_identity,
            owner_authority: &authority.base.core,
            owner_record: &self.owner_record,
            anchor_record: &self.anchor_record,
            ready_record: &self.ready_record,
            source_identity: &self.source_identity,
            source_authority: &authority.base.source,
            source_record: &self.source_record,
            recovery_identity: &self.recovery_identity,
            recovery_key: &authority.capsule,
        }
    }
}

// A borrowed inventory writer, not an owner/secret serialization API. It uses
// the SAME original nineteen role ids, extents and precharged custody writer.
struct InitialCustody<'a> {
    setup: &'a PublicSetup,
    anchor: &'a bfv_query_core::BfvKeyAnchor,
    key: &'a bfv_key_transform::Statement,
    key_proof: &'a [u8],
    source: &'a EncryptedSourceState,
    owner: &'a EncryptedOwnerState,
    anchor_state: &'a EncryptedOwnerState,
    ready: &'a EncryptedOwnerState,
}
fn persist_originals(
    quota: &ParticipantQuota,
    inventory: &mut Inventory,
    binding: &JointBinding,
    bundle: &RawBundle,
    boot: &CandidateBlock,
    ckey: [u8; 32],
    original: InitialCustody<'_>,
) -> io::Result<()> {
    persist(
        quota,
        inventory,
        WORK,
        &checked(binding.work_genesis().encode())?,
    )?;
    persist(
        quota,
        inventory,
        JOURNAL,
        &checked(binding.journal_genesis().encode())?,
    )?;
    persist(
        quota,
        inventory,
        DESCRIPTOR,
        &binding.application_descriptor().encode(),
    )?;
    persist(
        quota,
        inventory,
        SETUP_CLAIM,
        &binding.setup_claim().encode(),
    )?;
    persist(
        quota,
        inventory,
        SETUP,
        &checked(original.setup.to_bytes())?,
    )?;
    persist(
        quota,
        inventory,
        BUNDLE,
        &checked(serde_json::to_vec(bundle))?,
    )?;
    persist(quota, inventory, TABLE_ID, &TABLE)?;
    persist(
        quota,
        inventory,
        ANCHOR,
        &checked(original.anchor.encode_claim())?,
    )?;
    persist(quota, inventory, KEY, original.key_proof)?;
    persist(quota, inventory, KEY33, &key_bytes(original.key))?;
    persist(quota, inventory, CKEY, &ckey)?;
    persist(quota, inventory, SOURCE_STATE, original.source.as_bytes())?;
    persist(quota, inventory, OWNER_STATE, original.owner.as_bytes())?;
    persist(
        quota,
        inventory,
        ANCHOR_STATE,
        original.anchor_state.as_bytes(),
    )?;
    persist(quota, inventory, EPOCH_STATE, original.ready.as_bytes())?;
    persist(quota, inventory, BOOT_BLOCK, &boot.encode())?;
    inventory.validate(16)
}

fn owner_a(
    root: &Path,
    authority: &AcquireAuthorities,
    identity: &Identity,
    work: WorkGenesis,
    gate: &peer_runtime::ProofGate,
    input: &mut impl Read,
) -> io::Result<()> {
    let started = Instant::now();
    let (source, bundle, heads) = new_source()?;
    let permit = checked(gate.try_acquire())?;
    let (owner, setup) = checked(Owner::generate(Geometry::Rows16))?;
    let handle = checked(owner.key_anchor(&setup, scope()))?;
    let anchor = handle.public_anchor().clone();
    let mut epoch = checked(handle.proof_epoch(&setup))?;
    checked(epoch.prove_key())?;
    let key_proof = checked(epoch.key_evidence())?;
    let checked_key = checked(setup.verify_key_transform(&anchor, key_proof.as_bytes()))?;
    let key_digest = Sha256::digest(key_proof.as_bytes()).into();
    let key_statement = checked_key.statement().clone();
    let quota = checked(ParticipantQuota::create_new(
        root,
        NAMESPACE,
        fixture::CAPACITY,
    ))?;
    let binding = new_binding(
        &source,
        &bundle,
        &heads,
        KeyPremises {
            setup: &setup,
            anchor: &anchor,
            statement: &key_statement,
        },
        &quota,
        work,
        &authority.base.signer,
    )?;
    let mut inventory = AcquireInventory {
        base: Inventory {
            files: Vec::new(),
            binding: binding.id(),
            work: binding.work_genesis().id(),
            journal: checked(binding.journal_genesis().id())?,
        },
        extra: Vec::new(),
    };
    let depot = checked(JointDepot::open(quota.depot_budget()))?;
    let ingress = depot.ingress();
    let mut history = checked(JointHistory::new(binding.clone(), depot))?;
    let boot_parent = checked(history.bootstrap_parent())?;
    let prepared = checked(source.prepare_joint_bootstrap(
        fetched(&bundle, &heads)?,
        &binding,
        &boot_parent,
        Zeroizing::new(fixture::CONTROLLERS),
        fresh()?,
    ))?;
    let (request, life, boot_candidate) = prepared.into_parts();
    let next = registry200_proof::source::statement::encode_digest(life.statement().next);
    let ckey = registry200_proof::source::statement::encode_digest(
        life.statement().expected.source.key_commitment,
    );
    let pair = checked(ingress.retain_public_blob(life.as_bytes()))?;
    let expected = checked(boot_candidate.expectation(checked(Manifest::bootstrap(next, pair))?))?;
    let boot = transition(
        &binding,
        boot_parent.head(),
        request,
        checked(Manifest::bootstrap(next, pair))?,
        Control::Pending,
        &authority.base.signer,
    )?;
    drop(life);
    let source_identity = checked(SourceStateIdentity::new(SOURCE_ID, ckey))?;
    let owner_identity = core_identity();
    let source_record = checked(source.backup_private_state(
        &source_identity,
        fetched(&bundle, &heads)?,
        &authority.base.source,
    ))?;
    let owner_record =
        checked(owner.backup_private_state(&setup, &owner_identity, &authority.base.core))?;
    let anchor_record =
        checked(handle.backup_private_state(&setup, &owner_identity, &authority.base.core))?;
    let ready_record =
        checked(epoch.backup_ready_state(&setup, &owner_identity, &authority.base.core))?;
    require(
        source_record.as_bytes().len() == 488
            && owner_record.as_bytes().len() == 8848
            && anchor_record.as_bytes().len() == 688,
        "Original guarded encrypted record extents",
    )?;
    persist_originals(
        &quota,
        &mut inventory.base,
        &binding,
        &bundle,
        &boot,
        ckey,
        InitialCustody {
            setup: &setup,
            anchor: &anchor,
            key: &key_statement,
            key_proof: key_proof.as_bytes(),
            source: &source_record,
            owner: &owner_record,
            anchor_state: &anchor_record,
            ready: &ready_record,
        },
    )?;
    inventory.validate(true)?;
    report_acquire(&AcquireReport {
        version: 2,
        stage: 1,
        pid: std::process::id(),
        inventory: inventory.clone(),
        header: boot.header().id(),
        body: version_journal::hash(boot.body()),
        key: key_digest,
        generation: 0,
        invocation: [0; 32],
        request: [0; 32],
        rows: 0,
    })?;
    drop(epoch);
    drop(handle);
    drop(owner);
    let original = Originals {
        setup,
        anchor,
        key: key_statement,
        owner_identity,
        owner_record,
        anchor_record,
        ready_record,
        source_identity,
        source_record,
        recovery_identity: JointRecoveryIdentity::new(RECOVERY_ID),
    };
    drop(permit);
    let endpoints: AcquireEndpoints = read_json(input)?;
    endpoints.validate()?;
    let clients = clients(&endpoints.validators, identity, &binding)?;
    let remote = RemotePeer::new(endpoints.fhe, Connector::permissionless(identity)?);
    let object = *checked(bundle.target_version())?.object();
    require(
        matches!(remote.call(Request::Store(bundle.clone()))?, Response::Stored(info) if info.id == object),
        "Actual original encrypted Source stored by separate FHE peer",
    )?;
    require(
        matches!(
            remote.call(Request::InstallSetup(checked(original.setup.to_bytes())?))?,
            Response::Setup(_)
        ),
        "Actual original public setup installed on FHE peer",
    )?;
    for (peer, client) in clients.iter().enumerate() {
        upload(client, peer, &boot, &ingress, &binding)?;
    }
    submit(&clients, &boot)?;
    let boot_qcs = checkpoints(&clients, &binding, checked(history.context())?, &boot)?;
    phase(started, "A-Boot-four-QCs");
    let permit = checked(gate.try_acquire())?;
    let receipt = checked(history.apply_bootstrap(&boot_qcs[0], &boot, &expected))?;
    let opening = checked(boot_candidate.complete(receipt))?.into_opening();
    persist(&quota, &mut inventory.base, BOOT_QC, &boot_qcs[0].encode())?;
    drop(history);
    drop(ingress);
    let replay = [OwnerVaultReplay {
        checkpoint: &boot_qcs[0],
        block: &boot,
    }];
    let mut vault = checked(OwnerVault::create_new(
        &quota,
        pins(&binding)?,
        authority.base.vault(),
        &source,
        fetched(&bundle, &heads)?,
        &replay,
        opening,
    ))?;
    let draft = checked(vault.prepare_control(
        checked(vault.cursor())?,
        &source,
        fetched(&bundle, &heads)?,
        checked(control::JointControlIntent::begin(1, 1, fresh()?))?,
    ))?;
    let begin = transition(
        &binding,
        draft.parent().head(),
        checked(draft.request())?,
        checked(draft.manifest())?,
        draft.parent().control(),
        &authority.base.signer,
    )?;
    let begin_copy = checked(CandidateBlock::decode(&begin.encode()))?;
    let cursor = checked(vault.seal_body(checked(vault.cursor())?, begin))?;
    let ingress = checked(vault.evidence_ingress())?;
    drop(permit);
    for (peer, client) in clients.iter().enumerate() {
        upload(client, peer, &begin_copy, &ingress, &binding)?;
    }
    let submitted = checked(vault.submission(cursor))?;
    require(
        submitted.header() == begin_copy.header() && submitted.body() == begin_copy.body(),
        "Exact saved Begin bytes",
    )?;
    submit(&clients, &begin_copy)?;
    let after_boot = next_context(binding.initial_context(), &boot_qcs[0])?;
    let begin_qcs = checkpoints(&clients, &binding, &after_boot, &begin_copy)?;
    phase(started, "A-Begin-four-QCs");
    let permit = checked(gate.try_acquire())?;
    let completed =
        checked(vault.complete_control(cursor, &source, fetched(&bundle, &heads)?, &begin_qcs[0]))?;
    require(
        completed.outcome() == control::JointControlOutcome::Begun,
        "Real network Begin QC completes actual actor",
    )?;
    let cursor = checked(vault.acknowledge(completed.cursor()))?;
    require(cursor.generation() == 1, "Begin one durable generation")?;
    persist(
        &quota,
        &mut inventory.base,
        BEGIN_BLOCK,
        &begin_copy.encode(),
    )?;
    persist(&quota, &mut inventory.base, CURSOR, &cursor_bytes(cursor))?;
    inventory.persist(&quota, BEGIN_CERT, &begin_qcs[0].encode())?;
    const SQL: &str =
        "SELECT age, amount FROM records WHERE age IN (0, 255) LIMIT 1 FOR UPDATE SKIP LOCKED";
    // NEW invocation exactly once. The returned work is after ComputePrepared
    // fsync and terminal capacity reservation, before any public FHE work escapes.
    let work = match checked(vault.prepare_acquire(
        cursor,
        fetched(&bundle, &heads)?,
        &original.material(authority),
        SQL,
        1,
        1,
    ))? {
        OwnerVaultAcquirePreparation::Prepared(work) => *work,
        OwnerVaultAcquirePreparation::NonAdmitted(_) => {
            return Err(io::Error::other("Unexpected uncontended Acquire refusal"));
        }
    };
    require(
        checked(vault.phase())? == OwnerVaultPhase::AcquireComputePrepared,
        "Compute fsync before FHE escape",
    )?;
    let invocation = work.invocation_id();
    let cursor = work.cursor();
    phase(started, "A-ComputePrepared-fsynced");
    let request_digest = Sha256::digest(work.encrypted_request()).into();
    let (provenance, request, frames) = work.into_parts();
    let inputs = checked(bfv_mul_relin_proof::InputEvidence::from_frames(
        frames.each_ref().map(Vec::as_slice),
    ))?;
    let shared = ingress.recording_store();
    let recorded = remote.prove_private_product_recorded_shared(
        object,
        provenance,
        &request,
        &inputs,
        shared.clone(),
    )?;
    let (checked_product, catalog) = recorded.into_parts();
    drop(checked_product);
    drop(shared);
    drop(frames);
    drop(request);
    phase(started, "A-FHE-16-118-END-EOF-recorded");
    // save_catalog independently replays the real completed 16+118/END/EOF
    // catalog. No serialized marker or fixture result supplies this phase.
    let draft = checked(vault.save_acquire_catalog(
        cursor,
        catalog,
        fetched(&bundle, &heads)?,
        &original.material(authority),
    ))?;
    phase(started, "A-catalog-replayed-saved");
    let acquire = transition(
        &binding,
        draft.parent().head(),
        checked(draft.request())?,
        checked(draft.manifest())?,
        draft.parent().control(),
        &authority.base.signer,
    )?;
    let exact = checked(CandidateBlock::decode(&acquire.encode()))?;
    let cursor = checked(vault.seal_acquire_body(
        checked(vault.cursor())?,
        acquire,
        fetched(&bundle, &heads)?,
        &original.material(authority),
    ))?;
    phase(started, "A-BodyPrepared-fsynced");
    inventory.persist(&quota, ACQUIRE_BODY, &exact.encode())?;
    inventory.persist(&quota, ACQUIRE_CURSOR, &cursor_bytes(cursor))?;
    inventory.validate(false)?;
    let submitted = checked(vault.submission(cursor))?;
    require(
        submitted.header() == exact.header() && submitted.body() == exact.body(),
        "Acquire exact BodyPrepared bytes",
    )?;
    drop(permit);
    for (peer, client) in clients.iter().enumerate() {
        upload_acquire(client, peer, &exact, &ingress, &binding)?;
    }
    submit(&clients, &exact)?;
    phase(started, "A-four-network-ACKs-outcome-unknown");
    require(
        checked(vault.phase())? == OwnerVaultPhase::SubmittedUnknown
            && checked(vault.cursor())?.generation() == 1,
        "A exits after healthy upload ACKs before any Acquire completion",
    )?;
    // This is actual process loss of submission outcome, NOT injected lost fsync
    // acknowledgement. There is no Acquire QC or decrypted answer in A.
    drop(ingress);
    drop(vault);
    drop(quota);
    drop(source);
    drop(original);
    drop(remote);
    report_acquire(&AcquireReport {
        version: 2,
        stage: 2,
        pid: std::process::id(),
        inventory,
        header: exact.header().id(),
        body: version_journal::hash(exact.body()),
        key: key_digest,
        generation: 1,
        invocation,
        request: request_digest,
        rows: 0,
    })
}

// B authenticates the complete original setup and anchor/ALL33 BEFORE private
// restore. These are externally pinned encrypted records, not an SDK fixture.
fn read_originals(
    root: &Path,
    inventory: &Inventory,
    binding: &JointBinding,
) -> io::Result<(Originals, [u8; 32])> {
    let setup_bytes = inventory.read(root, SETUP)?;
    require(
        <[u8; 32]>::from(Sha256::digest(&setup_bytes))
            == binding.application_descriptor().full_setup_id()
            && <[u8; 64]>::from(Sha512::digest(&setup_bytes))
                == binding.application_descriptor().full_setup_digest(),
        "Complete original setup hashes BEFORE SDK decode",
    )?;
    let setup = checked(PublicSetup::from_bytes(&setup_bytes))?;
    drop(setup_bytes);
    let anchor = checked(setup.decode_key_anchor_claim(&inventory.read(root, ANCHOR)?))?;
    let key_bytes_original = inventory.read(root, KEY)?;
    let checked_key = checked(setup.verify_key_transform(&anchor, &key_bytes_original))?;
    require(
        key_bytes(checked_key.statement()) == inventory.read(root, KEY33)?,
        "ALL33 original Key values",
    )?;
    let key = checked_key.statement().clone();
    let key_digest = Sha256::digest(&key_bytes_original).into();
    drop(key_bytes_original);
    let spec = checked(binding.application_descriptor().source_spec())?;
    let checked_descriptor = checked(Descriptor::checked(
        checked(ApplicationDescriptor::from_application(&spec))?,
        binding.application_descriptor().source_object(),
        &setup,
        &anchor,
        &key,
    ))?;
    require(
        checked_descriptor.encode() == binding.application_descriptor().encode(),
        "Independent original complete descriptor",
    )?;
    let ckey = checked(inventory.read(root, CKEY)?.as_slice().try_into())?;
    Ok((
        Originals {
            setup,
            anchor,
            key,
            owner_identity: core_identity(),
            owner_record: checked(EncryptedOwnerState::from_bytes(
                &inventory.read(root, OWNER_STATE)?,
            ))?,
            anchor_record: checked(EncryptedOwnerState::from_bytes(
                &inventory.read(root, ANCHOR_STATE)?,
            ))?,
            ready_record: checked(EncryptedOwnerState::from_bytes(
                &inventory.read(root, EPOCH_STATE)?,
            ))?,
            source_identity: checked(SourceStateIdentity::new(SOURCE_ID, ckey))?,
            source_record: checked(EncryptedSourceState::from_bytes(
                &inventory.read(root, SOURCE_STATE)?,
            ))?,
            recovery_identity: JointRecoveryIdentity::new(RECOVERY_ID),
        },
        key_digest,
    ))
}
fn owner_b(
    root: &Path,
    authority: &AcquireAuthorities,
    identity: &Identity,
    inventory: &AcquireInventory,
    gate: &peer_runtime::ProofGate,
    input: &mut impl Read,
) -> io::Result<()> {
    let started = Instant::now();
    let quota = checked(ParticipantQuota::open_existing(
        root,
        NAMESPACE,
        fixture::CAPACITY,
    ))?;
    let permit = checked(gate.try_acquire())?;
    let binding = binding(&inventory.base, root)?;
    require(
        binding.journal_genesis().owner == authority.base.signer.verifying_key().to_bytes(),
        "Independent original DB signing authority",
    )?;
    let bundle: RawBundle = checked(serde_json::from_slice(&inventory.base.read(root, BUNDLE)?))?;
    let heads = heads(&bundle, &inventory.base.read(root, TABLE_ID)?)?;
    require(
        *checked(bundle.target_version())?.object()
            == binding.application_descriptor().source_object(),
        "Original Source object",
    )?;
    let (original, key_digest) = read_originals(root, &inventory.base, &binding)?;
    let source = checked(SourceOwner::restore_private_state(
        &original.source_identity,
        fetched(&bundle, &heads)?,
        &authority.base.source,
        &original.source_record,
    ))?;
    let boot = checked(CandidateBlock::decode(
        &inventory.base.read(root, BOOT_BLOCK)?,
    ))?;
    let boot_qc = checked(JointCheckpoint::decode(
        &inventory.base.read(root, BOOT_QC)?,
    ))?;
    let begin = checked(CandidateBlock::decode(
        &inventory.base.read(root, BEGIN_BLOCK)?,
    ))?;
    let begin_qc = checked(JointCheckpoint::decode(&inventory.read(root, BEGIN_CERT)?))?;
    let after_boot = next_context(binding.initial_context(), &boot_qc)?;
    require(
        begin_qc.candidate().header() == begin.header()
            && begin_qc.candidate().encode()
                == checked(registry200_finality::joint::JointCandidate::for_context(
                    &binding,
                    &after_boot,
                    begin.header().clone(),
                ))?
                .encode(),
        "Separately pinned actual Begin QC",
    )?;
    let after_begin = next_context(&after_boot, &begin_qc)?;
    let exact = checked(CandidateBlock::decode(&inventory.read(root, ACQUIRE_BODY)?))?;
    let saved_cursor = inventory.read(root, ACQUIRE_CURSOR)?;
    // Only Bootstrap is an external history prefix. The WAL must recheck Begin
    // and its QC itself before restoring the saved original Acquire capsule.
    let prefix = [OwnerVaultReplay {
        checkpoint: &boot_qc,
        block: &boot,
    }];
    let mut vault = checked(OwnerVault::open_existing_acquire(
        &quota,
        pins(&binding)?,
        authority.base.vault(),
        &source,
        fetched(&bundle, &heads)?,
        &prefix,
        &original.material(authority),
    ))?;
    let cursor = checked(vault.cursor())?;
    require(
        checked(vault.phase())? == OwnerVaultPhase::SubmittedUnknown
            && cursor.generation() == 1
            && cursor_bytes(cursor).as_slice() == saved_cursor,
        "Recovered exact original pending cursor",
    )?;
    let original_parent = version_journal::HeadRef {
        genesis: begin.header().genesis,
        database: binding.journal_genesis().database,
        block: begin.header().id(),
        height: begin.header().height,
        state_root: begin.header().state_root,
    };
    require(
        checked(vault.historical_parent())?.head() == original_parent
            && checked(vault.historical_parent())?.slot() == begin_qc.candidate().slot()
            && checked(vault.historical_parent())?.decision_id() == after_begin.previous_decision(),
        "Restored historical parent must be separately pinned Begin",
    )?;
    let retained_parent = checked(vault.historical_parent())?.clone();
    checked(vault.require_known_parent(&retained_parent, &after_begin))?;
    let pending = checked(vault.submission(cursor))?;
    require(
        pending.header() == exact.header() && pending.body() == exact.body(),
        "Original signed Acquire bytes BEFORE retry",
    )?;
    phase(started, "B-strict-Acquire-aware-reopen");
    let invocation = cursor.pending_id();
    let ingress = checked(vault.evidence_ingress())?;
    let Body::Transition(body) = checked(Body::decode(
        exact.body(),
        &binding.journal_genesis().profile,
    ))?
    else {
        return Err(io::Error::other("Original Acquire transition required"));
    };
    let manifest = checked(Manifest::decode(&body.proof))?;
    let catalog = checked(bfv_product_evidence::CatalogId::from_blob(
        manifest
            .references()
            .find(|r| r.role() == registry200_joint::ManifestRole::ProductCatalog)
            .ok_or_else(|| io::Error::other("Original catalog required"))?
            .blob_id(),
    ))?;
    let request_digest = *checked(ingress.catalog_claim(catalog))?.request().sha256();
    let endpoints: AcquireEndpoints = read_json(input)?;
    endpoints.validate()?;
    let clients = clients(&endpoints.validators, identity, &binding)?;
    drop(permit);
    // FIRST network operation after restore is the exact original submission.
    // The FHE process is already joined; no new query, nonce, proof or encryption.
    submit(&clients, &exact)?;
    phase(started, "B-original-submission-four-ACKs");
    let acquire_qcs = checkpoints(&clients, &binding, &after_begin, &exact)?;
    phase(started, "B-Acquire-four-QCs");
    let permit = checked(gate.try_acquire())?;
    // A genuine older QC cannot turn the pending request into a completed bank.
    require(
        vault
            .complete_acquire(
                cursor,
                fetched(&bundle, &heads)?,
                &original.material(authority),
                &begin_qc,
            )
            .is_err()
            && checked(vault.cursor())? == cursor,
        "Old Begin QC must not advance Acquire",
    )?;
    let completed = checked(vault.complete_acquire(
        cursor,
        fetched(&bundle, &heads)?,
        &original.material(authority),
        &acquire_qcs[0],
    ))?;
    require(
        completed.invocation_id() == invocation
            && completed.is_recovered_invocation()
            && completed.cursor().generation() == 2
            && completed.rows().len() == 1
            && completed.rows()[0].ordinal == 0
            && completed.rows()[0].age == Some(0)
            && completed.rows()[0].amount == Some(65535)
            && checked(vault.phase())? == OwnerVaultPhase::Completed,
        "Only actual FHE/QC completion yields historical original rows after G2 fsync",
    )?;
    let rows = completed.rows().len();
    phase(started, "B-original-invocation-completed-G2-fsynced");
    let cursor = checked(vault.acknowledge(completed.cursor()))?;
    drop(completed);
    require(
        vault
            .complete_acquire(
                cursor,
                fetched(&bundle, &heads)?,
                &original.material(authority),
                &acquire_qcs[0],
            )
            .is_err()
            && checked(vault.cursor())? == cursor,
        "Completed invocation cannot complete again",
    )?;
    let draft = checked(vault.prepare_control(
        cursor,
        &source,
        fetched(&bundle, &heads)?,
        checked(control::JointControlIntent::end(
            1,
            1,
            control::JointEndDisposition::Close,
            fresh()?,
        ))?,
    ))?;
    let end = transition(
        &binding,
        draft.parent().head(),
        checked(draft.request())?,
        checked(draft.manifest())?,
        draft.parent().control(),
        &authority.base.signer,
    )?;
    let exact_end = checked(CandidateBlock::decode(&end.encode()))?;
    let cursor = checked(vault.seal_body(cursor, end))?;
    let pending = checked(vault.submission(cursor))?;
    require(
        pending.header() == exact_end.header() && pending.body() == exact_end.body(),
        "Saved exact new End bytes",
    )?;
    drop(permit);
    for (peer, client) in clients.iter().enumerate() {
        upload(client, peer, &exact_end, &ingress, &binding)?;
    }
    submit(&clients, &exact_end)?;
    let after_acquire = next_context(&after_begin, &acquire_qcs[0])?;
    let end_qcs = checkpoints(&clients, &binding, &after_acquire, &exact_end)?;
    phase(started, "B-End-four-QCs");
    let permit = checked(gate.try_acquire())?;
    let completed =
        checked(vault.complete_control(cursor, &source, fetched(&bundle, &heads)?, &end_qcs[0]))?;
    require(
        completed.outcome() == control::JointControlOutcome::ClosedRegistry,
        "Actual End closes restored acquired actor",
    )?;
    let final_cursor = checked(vault.acknowledge(completed.cursor()))?;
    require(
        final_cursor.generation() == 3 && checked(vault.phase())? == OwnerVaultPhase::Idle,
        "Actual G3 End fsync",
    )?;
    phase(started, "B-End-G3-fsynced");
    drop(ingress);
    drop(vault);
    drop(quota);
    // A fresh exclusive ledger must replay Acquire with its ORIGINAL material
    // even though the final phase is Idle. Control-only open is not a substitute.
    let quota = checked(ParticipantQuota::open_existing(
        root,
        NAMESPACE,
        fixture::CAPACITY,
    ))?;
    let reopened = checked(OwnerVault::open_existing_acquire(
        &quota,
        pins(&binding)?,
        authority.base.vault(),
        &source,
        fetched(&bundle, &heads)?,
        &prefix,
        &original.material(authority),
    ))?;
    require(
        checked(reopened.phase())? == OwnerVaultPhase::Idle
            && checked(reopened.cursor())? == final_cursor
            && checked(reopened.historical_parent())?.head().block == exact_end.header().id(),
        "Strict Acquire-aware reopen retains G3 and exact End",
    )?;
    phase(started, "B-strict-final-reopen");
    drop(reopened);
    drop(quota);
    drop(source);
    drop(original);
    drop(permit);
    report_acquire(&AcquireReport {
        version: 2,
        stage: 3,
        pid: std::process::id(),
        inventory: inventory.clone(),
        header: exact_end.header().id(),
        body: version_journal::hash(exact_end.body()),
        key: key_digest,
        generation: 3,
        invocation,
        request: request_digest,
        rows,
    })
}
