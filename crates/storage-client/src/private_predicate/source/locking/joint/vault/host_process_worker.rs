//! SOURCE-ONLY owner A/B bodies for two same-principal logical Host clients.
//! The existing Acquire child owns original guarded materials and strict160 IPC.
use super::super::super::host::{
    BEGIN_A_QC, BEGIN_B_BLOCK, BEGIN_B_QC, CLIENT_A, CLIENT_B, FIRST_BLOCK, FIRST_QC, HostConfig,
    HostInventory, HostPhase, HostReport, PENDING_BLOCK, PENDING_CURSOR, SQL_A, SQL_B, report_host,
    report_progress,
};
use super::*;
use crate::private_predicate::{
    JointSqlCall, JointSqlClientBinding, JointSqlHost, JointSqlHostPins, JointSqlNetworkConfig,
    JointSqlNetworkHost, JointSqlNetworkInput, JointSqlNetworkOutcome, JointSqlPreparation,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn run() -> io::Result<()> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let config: HostConfig = read_json(&mut input)?;
    require(
        config.version == 3 && matches!(config.role, 1 | 2) && config.root.is_absolute(),
        "Explicit Host-v3 worker role/root",
    )?;
    let private = Zeroizing::new(peer_transport::read_frame(&mut input, 160)?);
    let authority = AcquireAuthorities::decode(&private)?;
    drop(private);
    let tls = Zeroizing::new(peer_transport::read_frame(&mut input, PUBLIC_JSON)?);
    let identity: Identity = checked(serde_json::from_slice(&tls))?;
    drop(tls);
    let original_work = peer_transport::read_frame(&mut input, work_finality::MAX_GENESIS_BYTES)?;
    let independent_work = work()?;
    require(
        original_work == checked(independent_work.encode())?,
        "Independent original Host WorkGenesis",
    )?;
    let previous = peer_transport::read_frame(&mut input, PUBLIC_JSON)?;
    let gate = peer_runtime::ProofGate::new();
    if config.role == 1 {
        require(
            previous == b"null",
            "A cannot adopt a restored Host inventory",
        )?;
        owner_a(
            &config.root,
            &authority,
            &identity,
            independent_work,
            &gate,
            &mut input,
        )
    } else {
        let previous: HostReport = checked(serde_json::from_slice(&previous))?;
        previous.inventory.validate(false)?;
        require(
            previous.version == 3 && previous.stage == 2 && previous.generation == 3,
            "B requires A's bounded second-pending report",
        )?;
        owner_b(
            &config.root,
            &authority,
            &identity,
            &previous,
            &gate,
            &mut input,
        )
    }
}
fn host_pins(binding: &JointBinding) -> io::Result<JointSqlHostPins> {
    checked(JointSqlHostPins::new(
        binding.clone(),
        checked(OwnerVaultIdentity::new(VAULT_ID))?,
        [
            checked(JointSqlClientBinding::new(CLIENT_A, 1))?,
            checked(JointSqlClientBinding::new(CLIENT_B, 1))?,
        ],
    ))
}
fn call(
    host: &JointSqlHost,
    client: [u8; 32],
    sequence: u64,
    sql: &str,
) -> io::Result<JointSqlCall> {
    checked(host.call(&checked(host.client(client))?, sequence, sql))
}
fn wal_extent(root: &Path) -> io::Result<u64> {
    let paths = fs::read_dir(root.join("control"))?
        .map(|e| e.map(|e| e.path()))
        .collect::<io::Result<Vec<_>>>()?;
    let paths = paths
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "wal"))
        .collect::<Vec<_>>();
    require(paths.len() == 1, "One actual owner WAL")?;
    Ok(fs::metadata(&paths[0])?.len())
}
fn fill_reservation_slots(
    quota: &ParticipantQuota,
) -> io::Result<Vec<protocol_storage::Reservation>> {
    let budget = quota.control_budget();
    let mut leases = Vec::new();
    loop {
        match budget.reserve(0) {
            Ok(lease) => leases.push(lease),
            Err(protocol_storage::Error::ResourceLimit) => break,
            Err(error) => {
                return Err(io::Error::other(format!(
                    "Actual slot pressure failed: {error:?}"
                )));
            }
        }
    }
    require(!leases.is_empty(), "Actual reservation slots exhausted")?;
    Ok(leases)
}
// Owner permission and real branch mining metadata, not proof admission. The
// private test seam forwards to this Host's SAME live closed History. In
// particular, a real-clock driver block cannot be followed by fixture time.
fn mined_transition(
    host: &JointSqlHost,
    binding: &JointBinding,
    draft: &OwnerVaultDraft,
    signer: &SigningKey,
) -> io::Result<CandidateBlock> {
    let spec = checked(binding.application_descriptor().source_spec())?;
    let request = checked(draft.request())?;
    let manifest = checked(draft.manifest())?;
    let parent = draft.parent();
    let next = Control::Active {
        enrollment: request.inner().enrollment,
        registry: manifest.next_root(),
    };
    let mut transition = AuthorizedTransition {
        parent: parent.head().block,
        request: checked(request.encode())?,
        updates: vec![ShardUpdate {
            id: spec.control_id,
            old: parent.control().heads(&spec),
            new: next.heads(&spec),
        }],
        proof: manifest.encode(),
        owner_signature: [0; 64],
    };
    transition.sign(parent.head().genesis, signer);
    let body = Body::Transition(transition);
    let expires = Instant::now() + peer_runtime::finality::JOINT_OPERATION_BUDGET;
    let mut header = loop {
        require(Instant::now() < expires, "Real Host timestamp deadline")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::other("Host clock precedes UNIX epoch"))?
            .as_secs();
        match host.candidate_header_for_test(parent, &body, now) {
            Ok(header) => break header,
            Err(OwnerVaultError::Joint(registry200_finality::joint::Error::Journal(
                version_journal::Error::InvalidTimestamp,
            ))) => std::thread::park_timeout(Duration::from_millis(50)),
            Err(error) => return checked(Err(error)),
        }
    };
    checked(header.mine(4096))?;
    require(Instant::now() < expires, "Actual Host mining deadline")?;
    checked(CandidateBlock::new(
        header,
        checked(body.encode(&binding.journal_genesis().profile))?,
    ))
}
struct ControlNetwork<'a> {
    binding: &'a JointBinding,
    source: &'a SourceOwner,
    bundle: &'a RawBundle,
    heads: &'a ReadHeads,
    signer: &'a SigningKey,
    clients: &'a [JointFinalityClient],
    gate: &'a peer_runtime::ProofGate,
}
impl ControlNetwork<'_> {
    // Actual typed producer, signed Body, all uploads, four network QCs and
    // completion remain visible here. There is no local vote/QC assembler.
    fn finish(
        &self,
        host: &mut JointSqlHost,
        context: &mut Context,
        call: &JointSqlCall,
        outcome: control::JointControlOutcome,
        generation: u64,
    ) -> io::Result<(CandidateBlock, JointCheckpoint)> {
        let permit = checked(self.gate.try_acquire())?;
        let JointSqlPreparation::ControlDraft(draft) =
            checked(host.prepare_control(call, self.source, fetched(self.bundle, self.heads)?))?
        else {
            return Err(io::Error::other(
                "A new Host Control must produce real Source/Life/Kind",
            ));
        };
        let block = mined_transition(host, self.binding, &draft, self.signer)?;
        let exact = checked(CandidateBlock::decode(&block.encode()))?;
        let cursor = checked(host.seal_body(call, checked(host.cursor())?, block))?;
        let ingress = checked(host.evidence_ingress())?;
        let submitted = checked(host.submission(call, cursor))?;
        require(
            submitted.header() == exact.header() && submitted.body() == exact.body(),
            "Host saved exact Control Body",
        )?;
        drop(permit);
        for (peer, client) in self.clients.iter().enumerate() {
            upload(client, peer, &exact, &ingress, self.binding)?;
        }
        submit(self.clients, &exact)?;
        let qcs = checkpoints(self.clients, self.binding, context, &exact)?;
        let permit = checked(self.gate.try_acquire())?;
        let reply = checked(host.complete_control(
            call,
            cursor,
            self.source,
            fetched(self.bundle, self.heads)?,
            &qcs[0],
        ))?;
        require(
            reply.control_outcome() == Some(outcome),
            "Actual Host Control completion outcome",
        )?;
        let cursor = checked(host.acknowledge(call, checked(host.cursor())?))?;
        require(
            cursor.generation() == generation && checked(host.phase())? == OwnerVaultPhase::Idle,
            "Control bank/map/ACK generation",
        )?;
        *context = next_context(context, &qcs[0])?;
        drop(reply);
        drop(ingress);
        drop(permit);
        Ok((exact, qcs.into_iter().next().unwrap()))
    }
}
fn record(
    work: OwnerVaultAcquireWork,
    remote: &RemotePeer,
    ingress: &JointEvidenceIngress,
) -> io::Result<(bfv_product_evidence::CatalogId, [u8; 32], [u8; 32])> {
    let invocation = work.invocation_id();
    let object = work.object();
    let digest = Sha256::digest(work.encrypted_request()).into();
    let (provenance, request, frames) = work.into_parts();
    let inputs = checked(bfv_mul_relin_proof::InputEvidence::from_frames(
        frames.each_ref().map(Vec::as_slice),
    ))?;
    let store = ingress.recording_store();
    let recorded = remote.prove_private_product_recorded_shared(
        object,
        provenance,
        &request,
        &inputs,
        store.clone(),
    )?;
    let (checked_product, catalog) = recorded.into_parts();
    drop(checked_product);
    drop(store);
    drop(frames);
    drop(request);
    Ok((catalog, invocation, digest))
}
fn seal_acquire(
    host: &mut JointSqlHost,
    call: &JointSqlCall,
    draft: OwnerVaultDraft,
    network: &ControlNetwork<'_>,
    material: &OwnerVaultAcquireMaterial<'_>,
) -> io::Result<(CandidateBlock, OwnerVaultCursor)> {
    let started = Instant::now();
    eprintln!("Host seal Acquire pid={} event=start", std::process::id());
    let block = mined_transition(host, network.binding, &draft, network.signer)?;
    let exact = checked(CandidateBlock::decode(&block.encode()))?;
    let cursor = checked(host.seal_acquire_body(
        call,
        checked(host.cursor())?,
        block,
        fetched(network.bundle, network.heads)?,
        material,
    ))?;
    let submitted = checked(host.submission(call, cursor))?;
    require(
        submitted.header() == exact.header() && submitted.body() == exact.body(),
        "Exact Host Acquire Body before submission",
    )?;
    eprintln!(
        "Host seal Acquire pid={} event=sealed elapsed_ms={:.3}",
        std::process::id(),
        started.elapsed().as_secs_f64() * 1000.
    );
    Ok((exact, cursor))
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
    let evidence = checked(epoch.key_evidence())?;
    let checked_key = checked(setup.verify_key_transform(&anchor, evidence.as_bytes()))?;
    let key_digest = Sha256::digest(evidence.as_bytes()).into();
    let key = checked_key.statement().clone();
    let mut quota = checked(ParticipantQuota::create_new(
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
            statement: &key,
        },
        &quota,
        work,
        &authority.base.signer,
    )?;
    let mut inventory = HostInventory {
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
    let parent = checked(history.bootstrap_parent())?;
    let prepared = checked(source.prepare_joint_bootstrap(
        fetched(&bundle, &heads)?,
        &binding,
        &parent,
        Zeroizing::new(fixture::CONTROLLERS),
        fresh()?,
    ))?;
    let (request, life, candidate) = prepared.into_parts();
    let next = registry200_proof::source::statement::encode_digest(life.statement().next);
    let ckey = registry200_proof::source::statement::encode_digest(
        life.statement().expected.source.key_commitment,
    );
    let pair = checked(ingress.retain_public_blob(life.as_bytes()))?;
    let expected = checked(candidate.expectation(checked(Manifest::bootstrap(next, pair))?))?;
    let boot = transition(
        &binding,
        parent.head(),
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
            key: &key,
            key_proof: evidence.as_bytes(),
            source: &source_record,
            owner: &owner_record,
            anchor_state: &anchor_record,
            ready: &ready_record,
        },
    )?;
    inventory.validate(true)?;
    report_host(&HostReport {
        version: 3,
        stage: 1,
        pid: std::process::id(),
        inventory: inventory.clone(),
        header: boot.header().id(),
        body: version_journal::hash(boot.body()),
        key: key_digest,
        generation: 0,
        invocation: [0; 32],
        request: [0; 32],
        first_invocation: [0; 32],
        first_request: [0; 32],
        first_record: 0,
        rows: 0,
    })?;
    drop(epoch);
    drop(handle);
    drop(owner);
    let original = Originals {
        setup,
        anchor,
        key,
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
    let remote = RemotePeer::new(endpoints.fhe.clone(), Connector::permissionless(identity)?);
    let object = *checked(bundle.target_version())?.object();
    require(
        matches!(remote.call(Request::Store(bundle.clone()))?,Response::Stored(info)if info.id==object),
        "Actual encrypted Source stored by separate FHE peer",
    )?;
    require(
        matches!(
            remote.call(Request::InstallSetup(checked(original.setup.to_bytes())?))?,
            Response::Setup(_)
        ),
        "Actual original setup installed",
    )?;
    for (peer, client) in clients.iter().enumerate() {
        upload(client, peer, &boot, &ingress, &binding)?;
    }
    submit(&clients, &boot)?;
    let boot_qcs = checkpoints(&clients, &binding, checked(history.context())?, &boot)?;
    phase(started, "Host-A-Boot-four-QCs");
    let permit = checked(gate.try_acquire())?;
    let opening = checked(candidate.complete(checked(history.apply_bootstrap(
        &boot_qcs[0],
        &boot,
        &expected,
    ))?))?
    .into_opening();
    persist(&quota, &mut inventory.base, BOOT_QC, &boot_qcs[0].encode())?;
    drop(history);
    drop(ingress);
    let prefix = [OwnerVaultReplay {
        checkpoint: &boot_qcs[0],
        block: &boot,
    }];
    let mut host = checked(JointSqlHost::create_new(
        &quota,
        host_pins(&binding)?,
        authority.base.vault(),
        &source,
        fetched(&bundle, &heads)?,
        &prefix,
        opening,
    ))?;
    let mut context = next_context(binding.initial_context(), &boot_qcs[0])?;
    drop(permit);
    let network = ControlNetwork {
        binding: &binding,
        source: &source,
        bundle: &bundle,
        heads: &heads,
        signer: &authority.base.signer,
        clients: &clients,
        gate,
    };
    let begin_a = call(&host, CLIENT_A, 1, "BEGIN")?;
    let (begin_a_body, begin_a_qc) = network.finish(
        &mut host,
        &mut context,
        &begin_a,
        control::JointControlOutcome::Begun,
        1,
    )?;
    persist(
        &quota,
        &mut inventory.base,
        BEGIN_BLOCK,
        &begin_a_body.encode(),
    )?;
    persist(
        &quota,
        &mut inventory.base,
        CURSOR,
        &cursor_bytes(checked(host.cursor())?),
    )?;
    inventory.persist(&quota, BEGIN_A_QC, &begin_a_qc.encode())?;
    let begin_b = call(&host, CLIENT_B, 1, "BEGIN")?;
    let (begin_b_body, begin_b_qc) = network.finish(
        &mut host,
        &mut context,
        &begin_b,
        control::JointControlOutcome::Begun,
        2,
    )?;
    inventory.persist(&quota, BEGIN_B_BLOCK, &begin_b_body.encode())?;
    inventory.persist(&quota, BEGIN_B_QC, &begin_b_qc.encode())?;
    phase(started, "Host-A-Begin-A-B-four-QCs-G1-G2");
    report_progress(HostPhase::BeginsCompleted)?;

    // Refuse BEFORE original invocation/input16 can escape when five record
    // extents including ACK cannot be promised. No fake Source is needed.
    let acquire_a = call(&host, CLIENT_A, 2, SQL_A)?;
    let before = checked(host.cursor())?;
    let extent = wal_extent(root)?;
    let budget = quota.control_budget();
    let used = checked(budget.used())?;
    let pressure_bytes = protocol_storage::MAX_SHARED_BYTES
        .checked_sub(used)
        .and_then(|n| n.checked_sub(5 * OWNER_VAULT_MAX_RECORD_BYTES as u64))
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| io::Error::other("Fixture must leave five record extents"))?;
    let pressure = checked(budget.reserve(pressure_bytes))?;
    require(
        matches!(
            host.prepare_acquire(
                &acquire_a,
                SQL_A,
                &source,
                fetched(&bundle, &heads)?,
                &original.material(authority)
            ),
            Err(OwnerVaultError::Storage(
                protocol_storage::Error::ResourceLimit
            ))
        ) && checked(host.cursor())? == before
            && wal_extent(root)? == extent,
        "Five-record refusal leaves bank/cursor/WAL unchanged",
    )?;
    drop(pressure);
    drop(budget);
    // FIRST actual Acquire is owned end to end by the production driver. A
    // transport ACK, timeout or NeedsReopen is not substituted for its reply.
    let mut runner = checked(JointSqlNetworkHost::attach(
        host,
        authority.base.signer.clone(),
        checked(JointSqlNetworkConfig::new(
            Connector::permissionless(identity)?,
            endpoints.validators.clone(),
            endpoints.fhe.clone(),
            4096,
        ))?,
        gate.clone(),
    ))?;
    let material = original.material(authority);
    let driver_started = Instant::now();
    let JointSqlNetworkOutcome::Completed { cursor, reply } = checked(runner.execute(
        CLIENT_A,
        2,
        SQL_A,
        JointSqlNetworkInput {
            source: &source,
            fetched: fetched(&bundle, &heads)?,
            acquire: Some(&material),
        },
        peer_runtime::finality::JOINT_OPERATION_BUDGET,
    ))?
    else {
        return Err(io::Error::other(
            "Actual first driver Acquire did not complete",
        ));
    };
    phase(driver_started, "Host-A-production-driver-execute-completed");
    let first_invocation = reply.invocation_id();
    let rows = reply
        .rows()
        .ok_or_else(|| io::Error::other("First actual Acquire rows required"))?;
    require(
        reply.client_id() == CLIENT_A
            && reply.call_sequence() == 2
            && reply.invocation_id() == first_invocation
            && cursor.pending_id() == first_invocation
            && cursor.generation() == 3
            && checked(runner.cursor())? == cursor
            && rows.len() == 1
            && rows[0].ordinal == 0
            && rows[0].age == Some(0)
            && rows[0].amount == Some(65535),
        "First genuine FHE completion binds A's original call and row0",
    )?;
    let first_record = reply.completed_record_sequence();
    drop(reply);
    let slots = fill_reservation_slots(&quota)?;
    let cursor = checked(runner.acknowledge(CLIENT_A, 2, SQL_A, cursor))?;
    require(
        cursor.generation() == 3 && checked(runner.phase())? == OwnerVaultPhase::Idle,
        "First ACK uses prepaid fifth record with no free reservation slot",
    )?;
    drop(slots);
    host = runner.into_host();
    phase(
        started,
        "Host-A-production-driver-first-Acquire-G3-prepaid-ACK",
    );
    report_progress(HostPhase::FirstCompleted)?;
    let head = checked(host.historical_parent())?.head();
    let first = until(Observation::new(RpcKind::Body, 0, 0, 0), || {
        clients[0].candidate_block(head.block).map(Some)
    })?;
    require(
        first.header().id() == head.block
            && first.header().state_root == head.state_root
            && first.header().height == head.height,
        "Driver result associates the actual peer-retained signed Body",
    )?;
    let ingress = checked(host.evidence_ingress())?;
    let Body::Transition(body) = checked(Body::decode(
        first.body(),
        &binding.journal_genesis().profile,
    ))?
    else {
        return Err(io::Error::other(
            "Actual first driver Acquire Body required",
        ));
    };
    let manifest = checked(Manifest::decode(&body.proof))?;
    let catalog = checked(bfv_product_evidence::CatalogId::from_blob(
        manifest
            .references()
            .find(|r| r.role() == registry200_joint::ManifestRole::ProductCatalog)
            .ok_or_else(|| io::Error::other("Actual first product catalog required"))?
            .blob_id(),
    ))?;
    // Public metadata is not a proof receipt. The driver already checked this
    // exact operation; its retained original request identity is compared with
    // the SECOND independently prepared ciphertext below.
    let first_request = *checked(ingress.catalog_claim(catalog))?.request().sha256();
    // The production driver has already completed this exact operation. Avoid
    // asking a peer that finalized it to perform another fresh import replay.
    // A missing/unavailable observation still takes the original catch-up path.
    let expected = checked(registry200_finality::joint::JointCandidate::for_context(
        &binding,
        &context,
        first.header().clone(),
    ))?;
    let expected_decision = checked(host.historical_parent())?.decision_id();
    let previous_slot = context
        .slot()
        .checked_sub(1)
        .ok_or_else(|| io::Error::other("Original first Acquire slot required"))?;
    require(clients.len() == 4, "Four actual validators required")?;
    let mut missing = Vec::with_capacity(4);
    for (peer, client) in clients.iter().enumerate() {
        let checkpoint = super::super::super::observation::once(
            Observation::new(RpcKind::Checkpoint, peer, 0, 0),
            || client.checkpoint_after(previous_slot),
        )?;
        if let Some(qc) = checkpoint {
            require(
                qc.candidate().encode() == expected.encode(),
                "Probe QC exact binding, original context and whole candidate",
            )?;
            let decision = checked(context.verify_commit(
                &qc.candidate().encode(),
                qc.round(),
                qc.certificate(),
            ))?;
            require(
                decision.semantic_id() == expected_decision,
                "Probe QC is the driver's actual completed semantic decision",
            )?;
        } else {
            missing.push((peer, client.clone()));
        }
    }
    for (peer, client) in &missing {
        upload_acquire(client, *peer, &first, &ingress, &binding)?;
    }
    if !missing.is_empty() {
        let missing = missing
            .into_iter()
            .map(|(_, client)| client)
            .collect::<Vec<_>>();
        submit_subset(&missing, &first)?;
    }
    let first_qcs = checkpoints(&clients, &binding, &context, &first)?;
    context = next_context(&context, &first_qcs[0])?;
    require(
        checked(host.historical_parent())?.decision_id() == context.previous_decision(),
        "First completed parent is its actual semantic decision",
    )?;
    inventory.persist(&quota, FIRST_BLOCK, &first.encode())?;
    inventory.persist(&quota, FIRST_QC, &first_qcs[0].encode())?;
    phase(started, "Host-A-first-Acquire-four-QCs-G3-prepaid-ACK");
    drop(ingress);

    let acquire_b = call(&host, CLIENT_B, 2, SQL_B)?;
    let permit = checked(gate.try_acquire())?;
    let JointSqlPreparation::AcquireWork(work) = checked(host.prepare_acquire(
        &acquire_b,
        SQL_B,
        &source,
        fetched(&bundle, &heads)?,
        &original.material(authority),
    ))?
    else {
        return Err(io::Error::other(
            "Real held conflict SKIP/OFFSET must prepare second input16",
        ));
    };
    let second_compute = work.cursor();
    let altered = call(&host, CLIENT_B, 2, &format!("{SQL_B};"))?;
    require(
        host.prepare_acquire(
            &altered,
            &format!("{SQL_B};"),
            &source,
            fetched(&bundle, &heads)?,
            &original.material(authority),
        )
        .is_err()
            && checked(host.cursor())? == second_compute,
        "Changed exact SQL cannot replace pending intent",
    )?;
    let premature_end = call(&host, CLIENT_A, 3, "COMMIT")?;
    require(
        host.prepare_control(&premature_end, &source, fetched(&bundle, &heads)?)
            .is_err()
            && checked(host.cursor())? == second_compute,
        "Other logical client cannot overwrite global pending",
    )?;
    let ingress = checked(host.evidence_ingress())?;
    phase(
        started,
        "Host-A-second-Compute-fsynced-after-real-held-row0",
    );
    let (catalog, invocation, request) = record(*work, &remote, &ingress)?;
    require(
        invocation != first_invocation && request != first_request,
        "Second query has its own original invocation/ciphertext",
    )?;
    phase(started, "Host-A-second-FHE-16-118-END-EOF");
    report_progress(HostPhase::SecondFheRecorded)?;
    let draft = checked(host.save_acquire_catalog(
        &acquire_b,
        second_compute,
        catalog,
        fetched(&bundle, &heads)?,
        &original.material(authority),
    ))?;
    let request_pin = checked(checked(draft.request())?.encode())?;
    let manifest_pin = checked(draft.manifest())?.encode();
    let catalog_cursor = checked(host.cursor())?;
    require(
        catalog_cursor.pending_id() == invocation && catalog_cursor != second_compute,
        "Original catalog fsync advances exact cursor only",
    )?;
    drop(draft);
    drop(ingress);
    drop(host);
    drop(quota);
    drop(permit);
    // The SECOND genuine catalog is the local drop/reopen boundary. It retains
    // the first driver's completed operation and performs no third FHE or new
    // invocation. The later A/FHE-exit boundary still starts only after Body.
    quota = checked(ParticipantQuota::open_existing(
        root,
        NAMESPACE,
        fixture::CAPACITY,
    ))?;
    let permit = checked(gate.try_acquire())?;
    host = checked(JointSqlHost::open_existing_acquire(
        &quota,
        host_pins(&binding)?,
        authority.base.vault(),
        &source,
        fetched(&bundle, &heads)?,
        &prefix,
        &original.material(authority),
    ))?;
    require(
        checked(host.cursor())? == catalog_cursor
            && checked(host.phase())? == OwnerVaultPhase::AcquireComputePrepared,
        "Catalog-only exact full reopen",
    )?;
    require(
        matches!(checked(host.prepare_acquire(&acquire_b,SQL_B,&source,fetched(&bundle,&heads)?,&original.material(authority)))?,JointSqlPreparation::ExistingPending(cursor)if cursor==catalog_cursor),
        "Catalog retry does not re-encrypt or prove",
    )?;
    require(
        host.acquire_draft(&acquire_b, second_compute).is_err(),
        "Pre-catalog cursor cannot recover signing metadata",
    )?;
    let wrong = call(&host, CLIENT_A, 3, SQL_A)?;
    require(
        host.acquire_draft(&wrong, catalog_cursor).is_err(),
        "Other client cannot recover second signing draft",
    )?;
    let draft = checked(host.acquire_draft(&acquire_b, catalog_cursor))?;
    require(
        checked(checked(draft.request())?.encode())? == request_pin
            && checked(draft.manifest())?.encode() == manifest_pin,
        "R2 wrapper returns exact original request/catalog/roots",
    )?;
    phase(
        started,
        "Host-A-second-catalog-only-full-reopen-original-draft",
    );
    report_progress(HostPhase::SecondCatalogRestored)?;
    let (exact, cursor) = seal_acquire(
        &mut host,
        &acquire_b,
        draft,
        &network,
        &original.material(authority),
    )?;
    inventory.persist(&quota, PENDING_BLOCK, &exact.encode())?;
    inventory.persist(&quota, PENDING_CURSOR, &cursor_bytes(cursor))?;
    inventory.validate(false)?;
    let ingress = checked(host.evidence_ingress())?;
    drop(permit);
    for (peer, client) in clients.iter().enumerate() {
        upload_acquire(client, peer, &exact, &ingress, &binding)?;
    }
    submit(&clients, &exact)?;
    require(
        checked(host.phase())? == OwnerVaultPhase::SubmittedUnknown
            && checked(host.cursor())?.generation() == 3,
        "A exits before second Acquire completion G4",
    )?;
    phase(
        started,
        "Host-A-second-Body-fsynced-four-ACKs-outcome-unknown",
    );
    drop(ingress);
    drop(host);
    drop(quota);
    drop(source);
    drop(original);
    drop(remote);
    // The supervisor joins A and the FHE child before launching B. No current
    // lease or literal lost-fsync-ACK is claimed by this healthy seal boundary.
    report_host(&HostReport {
        version: 3,
        stage: 2,
        pid: std::process::id(),
        inventory,
        header: exact.header().id(),
        body: version_journal::hash(exact.body()),
        key: key_digest,
        generation: 3,
        invocation,
        request,
        first_invocation,
        first_request,
        first_record,
        rows: 1,
    })
}

fn advance(
    context: &Context,
    binding: &JointBinding,
    block: &CandidateBlock,
    qc: &JointCheckpoint,
) -> io::Result<Context> {
    require(
        qc.candidate().header() == block.header()
            && qc.candidate().encode()
                == checked(registry200_finality::joint::JointCandidate::for_context(
                    binding,
                    context,
                    block.header().clone(),
                ))?
                .encode(),
        "Independent exact prefix candidate/context",
    )?;
    next_context(context, qc)
}
fn owner_b(
    root: &Path,
    authority: &AcquireAuthorities,
    identity: &Identity,
    previous: &HostReport,
    gate: &peer_runtime::ProofGate,
    input: &mut impl Read,
) -> io::Result<()> {
    let started = Instant::now();
    let inventory = &previous.inventory;
    let quota = checked(ParticipantQuota::open_existing(
        root,
        NAMESPACE,
        fixture::CAPACITY,
    ))?;
    let permit = checked(gate.try_acquire())?;
    let binding = binding(&inventory.base, root)?;
    require(
        binding.journal_genesis().owner == authority.base.signer.verifying_key().to_bytes(),
        "Original independent DB signer",
    )?;
    let bundle: RawBundle = checked(serde_json::from_slice(&inventory.base.read(root, BUNDLE)?))?;
    let heads = heads(&bundle, &inventory.base.read(root, TABLE_ID)?)?;
    let (original, key_digest) = read_originals(root, &inventory.base, &binding)?;
    require(key_digest == previous.key, "Original Key proof inventory")?;
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
    let begin_a = checked(CandidateBlock::decode(
        &inventory.base.read(root, BEGIN_BLOCK)?,
    ))?;
    let begin_a_qc = checked(JointCheckpoint::decode(&inventory.read(root, BEGIN_A_QC)?))?;
    let begin_b = checked(CandidateBlock::decode(
        &inventory.read(root, BEGIN_B_BLOCK)?,
    ))?;
    let begin_b_qc = checked(JointCheckpoint::decode(&inventory.read(root, BEGIN_B_QC)?))?;
    let first = checked(CandidateBlock::decode(&inventory.read(root, FIRST_BLOCK)?))?;
    let first_qc = checked(JointCheckpoint::decode(&inventory.read(root, FIRST_QC)?))?;
    let after_boot = advance(binding.initial_context(), &binding, &boot, &boot_qc)?;
    let after_a = advance(&after_boot, &binding, &begin_a, &begin_a_qc)?;
    let after_b = advance(&after_a, &binding, &begin_b, &begin_b_qc)?;
    let mut context = advance(&after_b, &binding, &first, &first_qc)?;
    let exact = checked(CandidateBlock::decode(
        &inventory.read(root, PENDING_BLOCK)?,
    ))?;
    require(
        exact.header().id() == previous.header
            && version_journal::hash(exact.body()) == previous.body,
        "Independently retained second signed Body",
    )?;
    let saved_cursor = inventory.read(root, PENDING_CURSOR)?;
    let prefix = [OwnerVaultReplay {
        checkpoint: &boot_qc,
        block: &boot,
    }];
    // Only Bootstrap is externally replayed. The same WAL must itself reverify
    // both Begin QCs and first full Acquire before opening second private state.
    let mut host = checked(JointSqlHost::open_existing_acquire(
        &quota,
        host_pins(&binding)?,
        authority.base.vault(),
        &source,
        fetched(&bundle, &heads)?,
        &prefix,
        &original.material(authority),
    ))?;
    let cursor = checked(host.cursor())?;
    require(
        checked(host.phase())? == OwnerVaultPhase::SubmittedUnknown
            && cursor.generation() == 3
            && cursor.pending_id() == previous.invocation
            && cursor_bytes(cursor).as_slice() == saved_cursor,
        "Exact pending second-call cursor and G3 on fresh owner",
    )?;
    let head = version_journal::HeadRef {
        genesis: first.header().genesis,
        database: binding.journal_genesis().database,
        block: first.header().id(),
        height: first.header().height,
        state_root: first.header().state_root,
    };
    require(
        checked(host.historical_parent())?.head() == head
            && checked(host.historical_parent())?.slot() == first_qc.candidate().slot()
            && checked(host.historical_parent())?.decision_id() == context.previous_decision(),
        "Original full parent/context remains first actual Acquire",
    )?;
    let retained = checked(host.historical_parent())?.clone();
    checked(host.require_known_parent(&retained, &context))?;
    let acquire_b = call(&host, CLIENT_B, 2, SQL_B)?;
    require(
        matches!(checked(host.prepare_acquire(&acquire_b,SQL_B,&source,fetched(&bundle,&heads)?,&original.material(authority)))?,JointSqlPreparation::ExistingPending(actual)if actual==cursor),
        "Same logical call resumes exact pending without new compute",
    )?;
    let acquire_a = call(&host, CLIENT_A, 2, SQL_A)?;
    require(
        host.submission(&acquire_a, cursor).is_err(),
        "Wrong client cannot submit B's pending candidate",
    )?;
    let pending = checked(host.submission(&acquire_b, cursor))?;
    require(
        pending.header() == exact.header() && pending.body() == exact.body(),
        "Restored original signed Body BEFORE first retry",
    )?;
    let ingress = checked(host.evidence_ingress())?;
    let Body::Transition(body) = checked(Body::decode(
        exact.body(),
        &binding.journal_genesis().profile,
    ))?
    else {
        return Err(io::Error::other("Saved actual Acquire transition required"));
    };
    let manifest = checked(Manifest::decode(&body.proof))?;
    let catalog = checked(bfv_product_evidence::CatalogId::from_blob(
        manifest
            .references()
            .find(|r| r.role() == registry200_joint::ManifestRole::ProductCatalog)
            .ok_or_else(|| io::Error::other("Saved product catalog required"))?
            .blob_id(),
    ))?;
    require(
        *checked(ingress.catalog_claim(catalog))?.request().sha256() == previous.request,
        "Exact original encrypted request identity",
    )?;
    phase(started, "Host-B-strict-full-Acquire-aware-reopen");
    report_progress(HostPhase::Restored)?;
    let endpoints: AcquireEndpoints = read_json(input)?;
    endpoints.validate()?;
    let clients = clients(&endpoints.validators, identity, &binding)?;
    drop(permit);
    // FIRST network operation after restore is immutable second-call retry.
    // The FHE peer has been joined; no new product can be generated by B.
    submit(&clients, &exact)?;
    phase(started, "Host-B-original-second-submission-four-ACKs");
    let qcs = checkpoints(&clients, &binding, &context, &exact)?;
    phase(started, "Host-B-second-Acquire-four-QCs");
    let permit = checked(gate.try_acquire())?;
    require(
        matches!(
            host.complete_acquire(
                &acquire_b,
                cursor,
                fetched(&bundle, &heads)?,
                &original.material(authority),
                &first_qc,
            ),
            Err(OwnerVaultError::Joint(
                registry200_finality::joint::Error::Context
            ))
        ) && checked(host.cursor())? == cursor,
        "Genuine first Acquire QC cannot complete second call",
    )?;
    let reply = checked(host.complete_acquire(
        &acquire_b,
        cursor,
        fetched(&bundle, &heads)?,
        &original.material(authority),
        &qcs[0],
    ))?;
    require(
        reply.client_id() == CLIENT_B
            && reply.call_sequence() == 2
            && reply.invocation_id() == previous.invocation
            && reply.rows().is_some_and(|rows| rows.is_empty())
            && reply.completed_record_sequence()
                == previous
                    .first_record
                    .checked_add(5)
                    .ok_or_else(|| io::Error::other("Record sequence overflow"))?
            && checked(host.cursor())?.generation() == 4,
        "Actual original B call skips held row0 before OFFSET consumes row3; G4 fsync before empty rows",
    )?;
    drop(reply);
    let slots = fill_reservation_slots(&quota)?;
    let completed_cursor = checked(host.cursor())?;
    let cursor = checked(host.acknowledge(&acquire_b, completed_cursor))?;
    require(
        cursor.generation() == 4 && checked(host.phase())? == OwnerVaultPhase::Idle,
        "Recovered second call prepaid fifth ACK with all slots occupied",
    )?;
    drop(slots);
    require(
        host.complete_acquire(
            &acquire_b,
            completed_cursor,
            fetched(&bundle, &heads)?,
            &original.material(authority),
            &qcs[0],
        )
        .is_err()
            && checked(host.cursor())? == cursor,
        "Stale completion CAS cannot advance G4 twice",
    )?;
    let first_reply = checked(host.take_recovered_reply(&acquire_a))?;
    require(
        first_reply.client_id() == CLIENT_A
            && first_reply.call_sequence() == 2
            && first_reply.invocation_id() == previous.first_invocation
            && first_reply
                .rows()
                .is_some_and(|rows| rows.len() == 1 && rows[0].ordinal == 0),
        "Fresh forward replay preserves OTHER same-principal client's original response",
    )?;
    drop(first_reply);
    require(
        matches!(
            host.take_recovered_reply(&acquire_a),
            Err(OwnerVaultError::RecoveryRequired)
        ),
        "Historical response consumed once per full open",
    )?;
    context = next_context(&context, &qcs[0])?;
    drop(permit);
    phase(started, "Host-B-original-empty-result-G4-and-prepaid-ACK");
    report_progress(HostPhase::SecondCompleted)?;
    let network = ControlNetwork {
        binding: &binding,
        source: &source,
        bundle: &bundle,
        heads: &heads,
        signer: &authority.base.signer,
        clients: &clients,
        gate,
    };
    let end_a = call(&host, CLIENT_A, 3, "COMMIT")?;
    network.finish(
        &mut host,
        &mut context,
        &end_a,
        control::JointControlOutcome::ClosedRegistry,
        5,
    )?;
    let end_b = call(&host, CLIENT_B, 3, "ROLLBACK")?;
    let (final_body, _) = network.finish(
        &mut host,
        &mut context,
        &end_b,
        control::JointControlOutcome::AbortedRegistry,
        6,
    )?;
    let final_cursor = checked(host.cursor())?;
    phase(started, "Host-B-COMMIT-A-ROLLBACK-B-four-QCs-G5-G6");
    report_progress(HostPhase::Ended)?;
    drop(ingress);
    drop(host);
    drop(quota);
    let quota = checked(ParticipantQuota::open_existing(
        root,
        NAMESPACE,
        fixture::CAPACITY,
    ))?;
    let permit = checked(gate.try_acquire())?;
    let mut reopened = checked(JointSqlHost::open_existing_acquire(
        &quota,
        host_pins(&binding)?,
        authority.base.vault(),
        &source,
        fetched(&bundle, &heads)?,
        &prefix,
        &original.material(authority),
    ))?;
    require(
        checked(reopened.phase())? == OwnerVaultPhase::Idle
            && checked(reopened.cursor())? == final_cursor
            && checked(reopened.historical_parent())?.head().block == final_body.header().id(),
        "Strict final v3 reopen restores exact G6/End parent",
    )?;
    let end_b = call(&reopened, CLIENT_B, 3, "ROLLBACK")?;
    require(
        checked(reopened.take_recovered_reply(&end_b))?.control_outcome()
            == Some(control::JointControlOutcome::AbortedRegistry),
        "ACK retains actual original B End reply",
    )?;
    let old = call(&reopened, CLIENT_B, 2, SQL_B)?;
    require(
        reopened
            .prepare_acquire(
                &old,
                SQL_B,
                &source,
                fetched(&bundle, &heads)?,
                &original.material(authority),
            )
            .is_err(),
        "Overwritten lower client call cannot become a new query",
    )?;
    phase(started, "Host-B-final-strict-reopen-G6");
    drop(reopened);
    drop(quota);
    drop(source);
    drop(original);
    drop(permit);
    report_host(&HostReport {
        version: 3,
        stage: 3,
        pid: std::process::id(),
        inventory: inventory.clone(),
        header: final_body.header().id(),
        body: version_journal::hash(final_body.body()),
        key: key_digest,
        generation: 6,
        invocation: previous.invocation,
        request: previous.request,
        first_invocation: previous.first_invocation,
        first_request: previous.first_request,
        first_record: previous.first_record,
        rows: 0,
    })
}
