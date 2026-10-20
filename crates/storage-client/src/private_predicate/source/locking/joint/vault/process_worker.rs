//! Actual owner-only subprocess body. No serialized or inherited Rust capability.
use super::*;
#[path = "acquire_process_worker.rs"]
mod acquire_worker;
pub(super) fn run_acquire() -> io::Result<()> {
    acquire_worker::run()
}
pub(super) fn run_host() -> io::Result<()> {
    acquire_worker::run_host()
}

struct Authorities {
    source: SourceStateAuthority,
    core: OwnerStateAuthority,
    vault: Zeroizing<[u8; 32]>,
    signer: SigningKey,
}
impl Authorities {
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        require(
            bytes.len() == 128,
            "Exactly four external owner authorities required",
        )?;
        Ok(Self {
            source: SourceStateAuthority::new(Zeroizing::new(bytes[..32].try_into().unwrap())),
            core: OwnerStateAuthority::new(Zeroizing::new(bytes[32..64].try_into().unwrap())),
            vault: Zeroizing::new(bytes[64..96].try_into().unwrap()),
            signer: SigningKey::from_bytes(bytes[96..128].try_into().unwrap()),
        })
    }
    fn vault(&self) -> OwnerVaultAuthority {
        OwnerVaultAuthority::new(Zeroizing::new(*self.vault))
    }
}
fn read_json<T: serde::de::DeserializeOwned>(reader: &mut impl Read) -> io::Result<T> {
    checked(serde_json::from_slice(&peer_transport::read_frame(
        reader,
        PUBLIC_JSON,
    )?))
}
pub(super) fn run() -> io::Result<()> {
    let input = std::io::stdin();
    let mut input = input.lock();
    let config: Config = read_json(&mut input)?;
    require(
        config.version == 1 && matches!(config.role, 1 | 2) && config.root.is_absolute(),
        "Bounded owner worker role/root",
    )?;
    // Never put these authorities in argv/env/reports, a fixture file or a peer.
    let private = Zeroizing::new(peer_transport::read_frame(&mut input, 128)?);
    let authorities = Authorities::decode(private.as_slice())?;
    drop(private);
    let tls_bytes = Zeroizing::new(peer_transport::read_frame(&mut input, PUBLIC_JSON)?);
    let identity: Identity = checked(serde_json::from_slice(tls_bytes.as_slice()))?;
    drop(tls_bytes);
    let work_bytes = peer_transport::read_frame(&mut input, work_finality::MAX_GENESIS_BYTES)?;
    let independent_work = work()?;
    require(
        work_bytes == checked(independent_work.encode())?,
        "Independent original WorkGenesis bytes",
    )?;
    let inventory_bytes = peer_transport::read_frame(&mut input, PUBLIC_JSON)?;
    // Exactly one owner-local resource gate per worker; no second store/server
    // is created merely to obtain a gate. Root supplies the public constructor.
    let gate = peer_runtime::ProofGate::new();
    if config.role == 1 {
        require(
            inventory_bytes == b"null",
            "New owner cannot adopt a restored inventory",
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
        let inventory: Inventory = checked(serde_json::from_slice(&inventory_bytes))?;
        inventory.validate(19)?;
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
struct KeyPremises<'a> {
    setup: &'a PublicSetup,
    anchor: &'a bfv_query_core::BfvKeyAnchor,
    statement: &'a bfv_key_transform::Statement,
}
fn new_binding(
    owner: &SourceOwner,
    bundle: &RawBundle,
    heads: &ReadHeads,
    key: KeyPremises<'_>,
    quota: &ParticipantQuota,
    work: WorkGenesis,
    signer: &SigningKey,
) -> io::Result<JointBinding> {
    let loaded = checked(owner.load(fetched(bundle, heads)?))?;
    let spec = checked(SourceSpec::new(NETWORK, 7, 8, &loaded.draft))?;
    let descriptor = checked(Descriptor::checked(
        checked(ApplicationDescriptor::from_application(&spec))?,
        *checked(bundle.target_version())?.object(),
        key.setup,
        key.anchor,
        key.statement,
    ))?;
    drop(loaded);
    let depot = checked(JointDepot::open(quota.depot_budget()))?;
    let claim = checked(depot.retain_setup(&descriptor, key.setup))?;
    drop(depot);
    let journal = Genesis {
        network_id: NETWORK,
        database: spec.database,
        owner: signer.verifying_key().to_bytes(),
        application_commitment: descriptor.id(),
        timestamp: 1000,
        profile: ProtocolProfile {
            initial_target: Target([255; 32]),
            pow_limit: Target([255; 32]),
            block_spacing_secs: 10,
            retarget_interval: 100,
            max_future_secs: 60,
            confirmation_depth: 1,
            max_headers: 16,
            max_shards: 2,
            max_updates: 1,
            max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
            max_request_bytes: registry200_joint::REQUEST_BYTES as u32,
            max_proof_bytes: registry200_joint::MANIFEST_BYTES as u32,
            max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
        },
        initial_shards: spec.initial_shards(),
    };
    checked(JointBinding::for_durable(
        NETWORK,
        rules()?,
        work,
        journal,
        descriptor,
        claim,
    ))
}
fn new_source() -> io::Result<(SourceOwner, RawBundle, ReadHeads)> {
    let source = checked(SourceOwner::new(
        DATABASE,
        [0x42; 16],
        Zeroizing::new(fresh()?),
    ))?;
    // These PUBLIC NONSECRET rows are initial ingest only. They never supply
    // an answer, control-bank preimage, completion or QC.
    let table = checked(source.seal_partition(
        &checked(TableId::from_bytes(TABLE))?,
        &[
            PlainRow {
                age: 0,
                amount: 65535,
            },
            PlainRow { age: 1, amount: 0 },
            PlainRow {
                age: 128,
                amount: 255,
            },
            PlainRow {
                age: 255,
                amount: 65534,
            },
        ],
        checked(RowIds::generate(4))?,
    ))?;
    let heads = table.read_heads();
    let bundle = checked(RawBundle::from_snapshots(
        table.snapshot(),
        table.encrypted_index(),
    ))?;
    drop(table);
    Ok((source, bundle, heads))
}
fn owner_a(
    root: &Path,
    authority: &Authorities,
    identity: &Identity,
    work: WorkGenesis,
    gate: &peer_runtime::ProofGate,
    input: &mut impl Read,
) -> io::Result<()> {
    let (source, bundle, heads) = new_source()?;
    let _permit = checked(gate.try_acquire())?;
    let (owner, setup) = checked(Owner::generate(Geometry::Rows16))?;
    let anchor_handle = checked(owner.key_anchor(&setup, scope()))?;
    let anchor = anchor_handle.public_anchor().clone();
    let mut epoch = checked(anchor_handle.proof_epoch(&setup))?;
    checked(epoch.prove_key())?;
    let key = epoch
        .key_evidence()
        .map_err(|e| io::Error::other(format!("{e:?}")))?;
    let checked_key = checked(setup.verify_key_transform(&anchor, key.as_bytes()))?;
    let key_digest: [u8; 32] = Sha256::digest(key.as_bytes()).into();
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
            statement: checked_key.statement(),
        },
        &quota,
        work,
        &authority.signer,
    )?;
    let mut inventory = Inventory {
        files: Vec::new(),
        binding: binding.id(),
        work: binding.work_genesis().id(),
        journal: checked(binding.journal_genesis().id())?,
    };
    let depot = checked(JointDepot::open(quota.depot_budget()))?;
    let ingress = depot.ingress();
    let mut history = checked(JointHistory::new(binding.clone(), depot))?;
    let bootstrap_parent = checked(history.bootstrap_parent())?;
    let prepared = checked(source.prepare_joint_bootstrap(
        fetched(&bundle, &heads)?,
        &binding,
        &bootstrap_parent,
        Zeroizing::new(fixture::CONTROLLERS),
        fresh()?,
    ))?;
    let (request, life, candidate) = prepared.into_parts();
    let next = registry200_proof::source::statement::encode_digest(life.statement().next);
    let ckey = registry200_proof::source::statement::encode_digest(
        life.statement().expected.source.key_commitment,
    );
    let pair = checked(ingress.retain_public_blob(life.as_bytes()))?;
    let manifest = checked(Manifest::bootstrap(next, pair))?;
    let expected = checked(candidate.expectation(checked(Manifest::bootstrap(next, pair))?))?;
    drop(life);
    let boot = transition(
        &binding,
        bootstrap_parent.head(),
        request,
        manifest,
        Control::Pending,
        &authority.signer,
    )?;
    let source_identity = checked(SourceStateIdentity::new(SOURCE_ID, ckey))?;
    let source_backup = checked(source.backup_private_state(
        &source_identity,
        fetched(&bundle, &heads)?,
        &authority.source,
    ))?;
    let owner_backup =
        checked(owner.backup_private_state(&setup, &core_identity(), &authority.core))?;
    let anchor_backup =
        checked(anchor_handle.backup_private_state(&setup, &core_identity(), &authority.core))?;
    let epoch_backup =
        checked(epoch.backup_ready_state(&setup, &core_identity(), &authority.core))?;
    require(
        source_backup.as_bytes().len() == 488
            && owner_backup.as_bytes().len() == 8848
            && anchor_backup.as_bytes().len() == 688,
        "Actual canonical encrypted owner record sizes",
    )?;
    persist(
        &quota,
        &mut inventory,
        WORK,
        &checked(binding.work_genesis().encode())?,
    )?;
    persist(
        &quota,
        &mut inventory,
        JOURNAL,
        &checked(binding.journal_genesis().encode())?,
    )?;
    persist(
        &quota,
        &mut inventory,
        DESCRIPTOR,
        &binding.application_descriptor().encode(),
    )?;
    persist(
        &quota,
        &mut inventory,
        SETUP_CLAIM,
        &binding.setup_claim().encode(),
    )?;
    persist(&quota, &mut inventory, SETUP, &checked(setup.to_bytes())?)?;
    persist(
        &quota,
        &mut inventory,
        BUNDLE,
        &checked(serde_json::to_vec(&bundle))?,
    )?;
    persist(&quota, &mut inventory, TABLE_ID, &TABLE)?;
    persist(
        &quota,
        &mut inventory,
        ANCHOR,
        &checked(anchor.encode_claim())?,
    )?;
    persist(&quota, &mut inventory, KEY, key.as_bytes())?;
    persist(
        &quota,
        &mut inventory,
        KEY33,
        &key_bytes(checked_key.statement()),
    )?;
    persist(&quota, &mut inventory, CKEY, &ckey)?;
    persist(
        &quota,
        &mut inventory,
        SOURCE_STATE,
        source_backup.as_bytes(),
    )?;
    persist(&quota, &mut inventory, OWNER_STATE, owner_backup.as_bytes())?;
    persist(
        &quota,
        &mut inventory,
        ANCHOR_STATE,
        anchor_backup.as_bytes(),
    )?;
    persist(&quota, &mut inventory, EPOCH_STATE, epoch_backup.as_bytes())?;
    persist(&quota, &mut inventory, BOOT_BLOCK, &boot.encode())?;
    inventory.validate(16)?;
    // All original secret owners still live only in A. Public inventory pins
    // leave A now and are returned independently to B through private IPC.
    report(&Report {
        version: 1,
        stage: 1,
        pid: std::process::id(),
        inventory: inventory.clone(),
        header: boot.header().id(),
        body: version_journal::hash(boot.body()),
        key: key_digest,
        generation: 0,
    })?;
    drop(epoch);
    drop(anchor_handle);
    drop(owner);
    drop(_permit);
    let endpoints: Vec<Endpoint> = read_json(input)?;
    let clients = clients(&endpoints, identity, &binding)?;
    for (peer, client) in clients.iter().enumerate() {
        upload(client, peer, &boot, &ingress, &binding)?;
    }
    submit(&clients, &boot)?;
    let qcs = checkpoints(
        &clients,
        &binding,
        history
            .context()
            .map_err(|e| io::Error::other(format!("{e:?}")))?,
        &boot,
    )?;
    let _permit = checked(gate.try_acquire())?;
    let receipt = checked(history.apply_bootstrap(&qcs[0], &boot, &expected))?;
    let opening = checked(candidate.complete(receipt))?.into_opening();
    persist(&quota, &mut inventory, BOOT_QC, &qcs[0].encode())?;
    // Closing the original depot owner is required before the SAME quota is
    // used by OwnerVault. No second store/ledger or generic parent is supplied.
    drop(history);
    drop(ingress);
    let replay = [OwnerVaultReplay {
        checkpoint: &qcs[0],
        block: &boot,
    }];
    let mut vault = checked(OwnerVault::create_new(
        &quota,
        pins(&binding)?,
        authority.vault(),
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
        &authority.signer,
    )?;
    let block = checked(CandidateBlock::decode(&begin.encode()))?;
    let cursor = checked(vault.seal_body(checked(vault.cursor())?, begin))?;
    persist(&quota, &mut inventory, BEGIN_BLOCK, &block.encode())?;
    persist(&quota, &mut inventory, CURSOR, &cursor_bytes(cursor))?;
    let ingress = checked(vault.evidence_ingress())?;
    drop(_permit);
    for (peer, client) in clients.iter().enumerate() {
        upload(client, peer, &block, &ingress, &binding)?;
    }
    let submitted = checked(vault.submission(cursor))?;
    require(
        submitted.header() == block.header()
            && submitted.body() == block.body()
            && submitted.cursor() == cursor,
        "Vault exact durable submission",
    )?;
    submit(&clients, &block)?;
    require(
        checked(vault.phase())? == OwnerVaultPhase::SubmittedUnknown
            && checked(vault.cursor())?.generation() == 0,
        "A must exit without completing Begin",
    )?;
    // No completion, saved successor bank or QC is manufactured by A.
    drop(ingress);
    drop(vault);
    drop(quota);
    drop(source);
    report(&Report {
        version: 1,
        stage: 2,
        pid: std::process::id(),
        inventory,
        header: block.header().id(),
        body: version_journal::hash(block.body()),
        key: key_digest,
        generation: 0,
    })
}
fn owner_b(
    root: &Path,
    authority: &Authorities,
    identity: &Identity,
    inventory: &Inventory,
    gate: &peer_runtime::ProofGate,
    input: &mut impl Read,
) -> io::Result<()> {
    // Root lock and complete disk accounting are reacquired in a fresh process.
    let quota = checked(ParticipantQuota::open_existing(
        root,
        NAMESPACE,
        fixture::CAPACITY,
    ))?;
    let _permit = checked(gate.try_acquire())?;
    let binding = binding(inventory, root)?;
    require(
        binding.journal_genesis().owner == authority.signer.verifying_key().to_bytes(),
        "Independent original DB signing authority",
    )?;
    let bundle: RawBundle = checked(serde_json::from_slice(&inventory.read(root, BUNDLE)?))?;
    let heads = heads(&bundle, &inventory.read(root, TABLE_ID)?)?;
    require(
        *checked(bundle.target_version())?.object()
            == binding.application_descriptor().source_object(),
        "Independent original Source object",
    )?;
    let ckey: [u8; 32] = checked(inventory.read(root, CKEY)?.as_slice().try_into())?;
    let source_identity = checked(SourceStateIdentity::new(SOURCE_ID, ckey))?;
    let source_record = checked(EncryptedSourceState::from_bytes(
        &inventory.read(root, SOURCE_STATE)?,
    ))?;
    let source = checked(SourceOwner::restore_private_state(
        &source_identity,
        fetched(&bundle, &heads)?,
        &authority.source,
        &source_record,
    ))?;
    let setup_bytes = inventory.read(root, SETUP)?;
    let setup_id: [u8; 32] = Sha256::digest(&setup_bytes).into();
    let setup_digest: [u8; 64] = Sha512::digest(&setup_bytes).into();
    require(
        setup_id == binding.application_descriptor().full_setup_id()
            && setup_digest == binding.application_descriptor().full_setup_digest(),
        "Full independent setup hashes BEFORE SDK decode",
    )?;
    let setup = checked(PublicSetup::from_bytes(&setup_bytes))?;
    drop(setup_bytes);
    let anchor = checked(setup.decode_key_anchor_claim(&inventory.read(root, ANCHOR)?))?;
    let key_frame = inventory.read(root, KEY)?;
    let key = checked(setup.verify_key_transform(&anchor, &key_frame))?;
    require(
        key_bytes(key.statement()) == inventory.read(root, KEY33)?,
        "All original 33 Key values independently match",
    )?;
    let spec = checked(binding.application_descriptor().source_spec())?;
    let descriptor = checked(Descriptor::checked(
        checked(ApplicationDescriptor::from_application(&spec))?,
        *checked(bundle.target_version())?.object(),
        &setup,
        &anchor,
        key.statement(),
    ))?;
    require(
        descriptor.encode() == binding.application_descriptor().encode(),
        "Full original setup/anchor/ALL33 descriptor",
    )?;
    let owner_record = checked(EncryptedOwnerState::from_bytes(
        &inventory.read(root, OWNER_STATE)?,
    ))?;
    let anchor_record = checked(EncryptedOwnerState::from_bytes(
        &inventory.read(root, ANCHOR_STATE)?,
    ))?;
    let epoch_record = checked(EncryptedOwnerState::from_bytes(
        &inventory.read(root, EPOCH_STATE)?,
    ))?;
    // Lexical restore. There is no generate/key_anchor/proof_epoch/prove_key on
    // this path, no fresh Ckey/anchor/output salt, and no deserialized seal.
    let owner = checked(Owner::restore_private_state(
        &setup,
        &core_identity(),
        &authority.core,
        &owner_record,
    ))?;
    let handle = checked(owner.restore_key_anchor(
        &setup,
        &anchor,
        &core_identity(),
        &authority.core,
        &anchor_record,
    ))?;
    let epoch = checked(handle.restore_ready_epoch(
        &setup,
        key.statement(),
        &core_identity(),
        &authority.core,
        &epoch_record,
    ))?;
    require(
        checked(epoch.key_evidence())?.as_bytes() == key_frame,
        "Restored Ready must retain EXACT original Key proof bytes",
    )?;
    let key_digest = Sha256::digest(&key_frame).into();
    drop(epoch);
    drop(handle);
    drop(owner);
    drop(_permit);
    let boot = checked(CandidateBlock::decode(&inventory.read(root, BOOT_BLOCK)?))?;
    let boot_qc = checked(JointCheckpoint::decode(&inventory.read(root, BOOT_QC)?))?;
    let begin = checked(CandidateBlock::decode(&inventory.read(root, BEGIN_BLOCK)?))?;
    let saved_cursor = inventory.read(root, CURSOR)?;
    let endpoints: Vec<Endpoint> = read_json(input)?;
    let clients = clients(&endpoints, identity, &binding)?;
    // Independently authenticate actual remote QCs; full mathematical replay
    // and the original private openings remain mandatory inside the Vault.
    let context = next_context(binding.initial_context(), &boot_qc)?;
    let qcs = checkpoints(&clients, &binding, &context, &begin)?;
    let _permit = checked(gate.try_acquire())?;
    let replay = [
        OwnerVaultReplay {
            checkpoint: &boot_qc,
            block: &boot,
        },
        OwnerVaultReplay {
            checkpoint: &qcs[0],
            block: &begin,
        },
    ];
    let mut vault = checked(OwnerVault::open_existing(
        &quota,
        pins(&binding)?,
        authority.vault(),
        &source,
        fetched(&bundle, &heads)?,
        &replay,
    ))?;
    require(
        checked(vault.phase())? == OwnerVaultPhase::SubmittedUnknown,
        "Restart must conservatively recover SubmittedUnknown",
    )?;
    let cursor = checked(vault.cursor())?;
    require(
        cursor_bytes(cursor).as_slice() == saved_cursor,
        "Restart changed generation/pending ID/digest",
    )?;
    let pending = checked(vault.submission(cursor))?;
    require(
        pending.header() == begin.header() && pending.body() == begin.body(),
        "Restart regenerated original signed request",
    )?;
    let completion =
        checked(vault.complete_control(cursor, &source, fetched(&bundle, &heads)?, &qcs[0]))?;
    require(
        completion.outcome() == control::JointControlOutcome::Begun
            && checked(vault.phase())? == OwnerVaultPhase::Completed,
        "Actual Begin completion must be durably published",
    )?;
    let cursor = checked(vault.acknowledge(completion.cursor()))?;
    require(
        cursor.generation() == 1,
        "Exactly one completed Begin generation",
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
        &authority.signer,
    )?;
    let end_copy = checked(CandidateBlock::decode(&end.encode()))?;
    let cursor = checked(vault.seal_body(cursor, end))?;
    let ingress = checked(vault.evidence_ingress())?;
    drop(_permit);
    for (peer, client) in clients.iter().enumerate() {
        upload(client, peer, &end_copy, &ingress, &binding)?;
    }
    // Returning the exact fsynced bytes precedes network submission.
    let pending = checked(vault.submission(cursor))?;
    require(
        pending.body() == end_copy.body(),
        "End exact durable submission",
    )?;
    submit(&clients, &end_copy)?;
    let after_begin = next_context(&context, &qcs[0])?;
    let end_qcs = checkpoints(&clients, &binding, &after_begin, &end_copy)?;
    let _permit = checked(gate.try_acquire())?;
    let completion =
        checked(vault.complete_control(cursor, &source, fetched(&bundle, &heads)?, &end_qcs[0]))?;
    require(
        completion.outcome() == control::JointControlOutcome::ClosedRegistry,
        "Actual End must close its exact Registry transaction",
    )?;
    let cursor = checked(vault.acknowledge(completion.cursor()))?;
    require(
        cursor.generation() == 2 && checked(vault.phase())? == OwnerVaultPhase::Idle,
        "Actual saved Begin/End generations",
    )?;
    drop(ingress);
    drop(vault);
    drop(quota);
    // A fresh exclusive ledger and WAL opener must recover both real completed
    // records. The external prefix supplies Bootstrap only; each later stored
    // QC is fully replayed from the WAL, never accepted as a receipt/cache.
    let quota = checked(ParticipantQuota::open_existing(
        root,
        NAMESPACE,
        fixture::CAPACITY,
    ))?;
    let prefix = [OwnerVaultReplay {
        checkpoint: &boot_qc,
        block: &boot,
    }];
    let reopened = checked(OwnerVault::open_existing(
        &quota,
        pins(&binding)?,
        authority.vault(),
        &source,
        fetched(&bundle, &heads)?,
        &prefix,
    ))?;
    require(
        checked(reopened.cursor())? == cursor
            && checked(reopened.phase())? == OwnerVaultPhase::Idle
            && checked(reopened.historical_parent())?.head().block == end_copy.header().id(),
        "Strict final WAL reopen must retain exact completed End bank",
    )?;
    drop(reopened);
    drop(quota);
    drop(source);
    drop(_permit);
    report(&Report {
        version: 1,
        stage: 3,
        pid: std::process::id(),
        inventory: inventory.clone(),
        header: end_copy.header().id(),
        body: version_journal::hash(end_copy.body()),
        key: key_digest,
        generation: cursor.generation(),
    })
}
