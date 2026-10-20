//! PUBLIC NONSECRET custody and actual five-child lifecycle. No local QC builder.
use super::*;
use bfv_query_core::{Geometry, KeyScope};
use compact_query::{PlainRow, ReadHeads, RowIds, TableId};
use p3_field::PrimeCharacteristicRing;
use peer_runtime::{Bootstrap as PeerBootstrap, Identity, RawBundle, Response};
use registry200_joint::progress::{Lane, Request};
use registry200_journal::{
    Application as SourceSpec, ApplicationDescriptor, Control, Operation, intent_query,
};
use registry200_proof::{
    Val,
    admission::CanonicalSource,
    registry_progress::{self as core, BootstrapWitness},
    source::{self, statement as ss},
};
use std::{net::TcpListener, path::Path, time::Instant};
use version_journal::{AuthorizedTransition, Body, Genesis, ProtocolProfile, ShardUpdate, Target};
use work_finality::{
    Genesis as WorkGenesis, Limits as WorkLimits, NetworkSeed, WorkTicket,
    consensus::{MAX_RECORD_BYTES, Rules},
};

pub(super) const CAPACITY: u64 = 10_000_000_000;
pub(super) struct Fixture {
    pub binding: Binding,
    pub setup: PublicSetup,
    anchor: BfvKeyAnchor,
    key: bfv_key_transform::Statement,
    owner_identity: OwnerStateIdentity,
    owner_authority: OwnerStateAuthority,
    owner_record: EncryptedOwnerState,
    anchor_record: EncryptedOwnerState,
    ready_record: EncryptedOwnerState,
    source_identity: SourceStateIdentity,
    source_authority: SourceStateAuthority,
    source_record: EncryptedSourceState,
    bundle: RawBundle,
    heads: ReadHeads,
    object: [u8; 32],
}
pub(super) struct Boot {
    pub history: History,
    pub ingress: ProgressEvidenceIngress,
    pub block: CandidateBlock,
    pub salts: [[u64; 4]; 2],
}
impl Fixture {
    pub fn new(dir: &fixture::Directory) -> (Self, ParticipantQuota, Boot) {
        let started = Instant::now();
        let source_owner =
            SourceOwner::new([0x21; 16], [0x42; 16], Zeroizing::new([0x63; 32])).unwrap();
        let table = source_owner
            .seal_partition(
                &TableId::from_bytes([0x19; 32]).unwrap(),
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
                RowIds::generate(4).unwrap(),
            )
            .unwrap();
        let heads = table.read_heads();
        let bundle = RawBundle::from_snapshots(table.snapshot(), table.encrypted_index()).unwrap();
        let object = *bundle.target_version().unwrap().object();
        drop(table);
        let fetched = || FetchedSource {
            object,
            bundle: &bundle,
            heads: &heads,
        };
        let loaded = source_owner.load(fetched()).unwrap();
        let (owner, setup) = BfvOwner::generate(Geometry::Rows16).unwrap();
        let owner_authority = OwnerStateAuthority::new(Zeroizing::new([0xa2; 32]));
        let (anchor, key, owner_identity, owner_record, anchor_record, ready_record) = {
            let handle = owner
                .key_anchor(
                    &setup,
                    KeyScope {
                        database: [0x21; 16],
                        bfv_key_domain: [0x88; 16],
                        epoch: 1,
                    },
                )
                .unwrap();
            let anchor = handle.public_anchor().clone();
            let id = OwnerStateIdentity {
                scope: anchor.scope().clone(),
                record_id: [0xa1; 32],
            };
            let mut epoch = handle.proof_epoch(&setup).unwrap();
            epoch.prove_key().unwrap();
            let key = setup
                .verify_key_transform(&anchor, epoch.key_evidence().unwrap().as_bytes())
                .unwrap()
                .statement()
                .clone();
            let records = (
                owner
                    .backup_private_state(&setup, &id, &owner_authority)
                    .unwrap(),
                handle
                    .backup_private_state(&setup, &id, &owner_authority)
                    .unwrap(),
                epoch
                    .backup_ready_state(&setup, &id, &owner_authority)
                    .unwrap(),
            );
            (anchor, key, id, records.0, records.1, records.2)
        };
        let source_identity =
            SourceStateIdentity::new([0xa3; 32], ss::encode_digest(loaded.draft.key_commitment))
                .unwrap();
        let source_authority = SourceStateAuthority::new(Zeroizing::new([0xa4; 32]));
        let source_record = source_owner
            .backup_private_state(&source_identity, fetched(), &source_authority)
            .unwrap();
        drop(owner);
        eprintln!(
            "progress_fixture phase=custody_done elapsed_ms={}",
            started.elapsed().as_millis()
        );
        let quota = protocol_storage::ParticipantQuota::create_new(
            dir.path("participant"),
            [0x29; 32],
            10_000_000_000,
        )
        .unwrap();
        let spec = SourceSpec::new([0x3a; 32], 7, 8, &loaded.draft).unwrap();
        let descriptor = Descriptor::checked(
            ApplicationDescriptor::from_application(&spec).unwrap(),
            object,
            &setup,
            &anchor,
            &key,
        )
        .unwrap();
        let depot = ProgressDepot::open(quota.depot_budget(), &descriptor).unwrap();
        let claim = depot.retain_setup(&setup).unwrap();
        let signer = SigningKey::from_bytes(&[0x5b; 32]);
        let g = Genesis {
            network_id: spec.network,
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
                max_headers: 32,
                max_shards: 2,
                max_updates: 1,
                max_body_bytes: version_journal::MAX_BODY_BYTES as u32,
                max_request_bytes: registry200_joint::progress::REQUEST_BYTES as u32,
                max_proof_bytes: registry200_joint::progress::MANIFEST_BYTES as u32,
                max_journal_bytes: version_journal::MAX_JOURNAL_BYTES,
            },
            initial_shards: spec.initial_shards(),
        };
        let rules = Rules::multi_slot(
            registry200_finality::progress::durable_profile_digest(),
            registry200_finality::progress::CANDIDATE_BYTES as u32,
            32,
            [180_000; 3],
            1_000,
            MAX_RECORD_BYTES as u64,
        )
        .unwrap();
        let seed = NetworkSeed::new(
            rules.seed_domain(spec.network),
            [10; 32],
            [255; 32],
            WorkLimits::new(16, 4).unwrap(),
        )
        .unwrap();
        let tickets = fixture::signers()
            .iter()
            .map(|k| WorkTicket::sign(&seed.bootstrap_election(), k, 0).unwrap())
            .collect();
        let binding = Binding::for_durable(
            spec.network,
            rules,
            WorkGenesis::from_bootstrap(seed, tickets).unwrap(),
            g,
            descriptor,
            claim,
        )
        .unwrap();
        let app = app(&binding).unwrap();
        let ingress = depot.ingress();
        let history = registry200_finality::progress::History::new(binding.clone(), depot).unwrap();
        let clients = [
            ClientBinding::new([0x61; 32], 1).unwrap(),
            ClientBinding::new([0x62; 32], 2).unwrap(),
        ];
        let controllers = [[0x41; 32], [0x42; 32]];
        let pins = || {
            Pins::new(
                binding.clone(),
                [0x63; 32],
                clients,
                Zeroizing::new(controllers),
            )
            .unwrap()
        };
        let salts = [[11, 12, 13, 14], [21, 22, 23, 24]];
        let empty = Bank {
            state: Zeroizing::new(State::default()),
            controllers: Zeroizing::new(controllers),
            enroll_salt: Zeroizing::new(salts[0]),
            registry_salt: Zeroizing::new(salts[1]),
        };
        let parent = history.bootstrap_parent().unwrap().head();
        let (enrollment, _) = empty
            .root(
                &pins(),
                parent.block,
                &loaded.draft,
                &loaded.plain.as_slice().try_into().unwrap(),
            )
            .unwrap();
        let nonce = [0xb1; 32];
        let mut source = loaded.draft.clone();
        source.request = intent_query(
            app.source_spec(),
            app.genesis(),
            parent.block,
            nonce,
            enrollment,
            Operation::Bootstrap,
        );
        source.open_commitment = source::commitment::digest(&source::commitment::opening_fields(
            &source,
            [Val::from_u64(31); 4],
            &loaded.plain,
        ));
        let canonical = CanonicalSource::checked_claim(&source).unwrap();
        let source_proof = source::prove(
            &canonical,
            &source_owner.source_witness([Val::from_u64(31); 4], &loaded.originals),
        )
        .unwrap();
        let expected =
            core::BootstrapExpected::new(&canonical, app.genesis(), parent.block, enrollment)
                .unwrap();
        let witness = BootstrapWitness::new(
            &expected,
            Zeroizing::new(loaded.plain.as_slice().try_into().unwrap()),
            Zeroizing::new(controllers),
            Zeroizing::new([[31; 4], salts[0], salts[1]]),
        )
        .unwrap();
        let proof = core::prove_bootstrap(&expected, &witness, source_proof.as_bytes()).unwrap();
        let manifest = Manifest::bootstrap(
            proof.statement().next(),
            ingress.retain_public_blob(source_proof.as_bytes()).unwrap(),
            ingress.retain_public_blob(&proof.into_parts().1).unwrap(),
        )
        .unwrap();
        let request = Request::new(
            &app,
            Lane::Bootstrap,
            registry200_journal::Request {
                operation: Operation::Bootstrap,
                genesis: app.genesis(),
                parent: parent.block,
                application: app.source_spec().id(),
                nonce,
                query: source.request,
                enrollment,
                opening: ss::encode_digest(source.open_commitment),
                command: [0; 32],
                packets: source.packets,
            },
        )
        .unwrap();
        let mut t = AuthorizedTransition {
            parent: parent.block,
            request: request.encode().unwrap(),
            proof: manifest.encode(),
            updates: vec![ShardUpdate {
                id: app.source_spec().control_id,
                old: Control::Pending.heads(app.source_spec()),
                new: Control::Active {
                    enrollment,
                    registry: manifest.next_root(),
                }
                .heads(app.source_spec()),
            }],
            owner_signature: [0; 64],
        };
        t.sign(app.genesis(), &signer);
        let body = Body::Transition(t);
        let mut header = history.candidate_header(&body, 1001, 2000).unwrap();
        header.mine(16).unwrap();
        let boot = registry200_finality::CandidateBlock::new(
            header,
            body.encode(&binding.journal_genesis().profile).unwrap(),
        )
        .unwrap();

        eprintln!(
            "progress_fixture phase=bootstrap_proof_done elapsed_ms={}",
            started.elapsed().as_millis()
        );
        let f = Self {
            binding,
            setup,
            anchor,
            key,
            owner_identity,
            owner_authority,
            owner_record,
            anchor_record,
            ready_record,
            source_identity,
            source_authority,
            source_record,
            bundle,
            heads,
            object,
        };
        (
            f,
            quota,
            Boot {
                history,
                ingress,
                block: boot,
                salts,
            },
        )
    }
    pub fn material(&self) -> Material<'_> {
        Material {
            setup: &self.setup,
            anchor: &self.anchor,
            key: &self.key,
            owner_identity: &self.owner_identity,
            owner_authority: &self.owner_authority,
            owner_record: &self.owner_record,
            anchor_record: &self.anchor_record,
            ready_record: &self.ready_record,
            source_identity: &self.source_identity,
            source_authority: &self.source_authority,
            source_record: &self.source_record,
        }
    }
    pub fn fetched(&self) -> FetchedSource<'_> {
        FetchedSource {
            object: self.object,
            bundle: &self.bundle,
            heads: &self.heads,
        }
    }
    pub fn pins(&self) -> Pins {
        Pins::new(
            self.binding.clone(),
            [0x63; 32],
            [
                ClientBinding::new(A, 1).unwrap(),
                ClientBinding::new(B, 2).unwrap(),
            ],
            Zeroizing::new([[0x41; 32], [0x42; 32]]),
        )
        .unwrap()
    }
}
pub(super) fn authority() -> Authority {
    Authority::new(Zeroizing::new([0x91; 32]))
}
pub(super) fn owner_signer() -> SigningKey {
    SigningKey::from_bytes(&[0x5b; 32])
}

pub(super) struct Network {
    validators: Vec<os_process::ProgressProcess>,
    storage: os_process::StorageProcess,
    pub connector: Connector,
    pub endpoints: Vec<Endpoint>,
    pub fhe: Endpoint,
}
impl Network {
    pub fn start(f: &Fixture, dir: &fixture::Directory, executable: &Path) -> Self {
        let owner_tls = fixture::identity();
        let connector = Connector::permissionless(&owner_tls).unwrap();
        let identities: Vec<Identity> = (0..4).map(|_| fixture::identity()).collect();
        let reservations: Vec<_> = (0..4)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let endpoints: Vec<_> = identities
            .iter()
            .zip(&reservations)
            .map(|(identity, listener)| Endpoint {
                address: listener.local_addr().unwrap(),
                identity: identity.fingerprint(),
            })
            .collect();
        drop(reservations);
        let setup = f.setup.to_bytes().unwrap();
        let signers = fixture::signers();
        let mut validators = Vec::new();
        for i in 0..4 {
            let neighbors: Vec<_> = endpoints
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, e)| e.clone())
                .collect();
            let namespace = [0x91 + i as u8; 32];
            let config=Zeroizing::new(serde_json::to_vec(&serde_json::json!({"version":2,"kind":"registry208-progress-participant-finality-v2","identity":identities[i],"authority":[],"owner":owner_tls.fingerprint(),"listen":endpoints[i].address,"neighbors":neighbors,"namespace":namespace,"capacity":CAPACITY,"work_genesis":f.binding.work_genesis().id(),"journal_genesis":f.binding.journal_genesis().id().unwrap(),"binding":f.binding.id(),"rules":{"max_round":32,"timeouts_ms":[180000,180000,180000],"timeout_delta_ms":1000,"wal_bytes":MAX_RECORD_BYTES},"signer":signers[i].to_bytes()})).unwrap());
            let work = f.binding.work_genesis().encode().unwrap();
            let journal = f.binding.journal_genesis().encode().unwrap();
            let descriptor = f.binding.application_descriptor().encode();
            let claim = f.binding.setup_claim().encode();
            let mut frames = vec![
                config.as_slice(),
                work.as_slice(),
                journal.as_slice(),
                descriptor.as_slice(),
                claim.as_slice(),
            ];
            frames.extend(setup.chunks(protocol_storage::MAX_BLOB_BYTES as usize));
            let node = os_process::ProgressProcess::start(
                executable,
                &dir.path(&format!("validator{i}")),
                peer_runtime::participant::ParticipantInstall::New,
                &frames,
            )
            .unwrap();
            assert_eq!(node.ready().version, 2);
            assert_eq!(
                node.ready().profile,
                peer_runtime::progress_participant::progress_participant_host_profile_digest()
            );
            assert_eq!(node.ready().binding, f.binding.id());
            assert_eq!(node.ready().namespace, namespace);
            assert_eq!(node.endpoint(), &endpoints[i]);
            eprintln!("progress_fixture validator={i} pid={}", node.pid());
            validators.push(node);
        }
        let storage = os_process::Process::start_storage(
            executable,
            &dir.path("actual-fhe-peer"),
            &PeerBootstrap {
                identity: fixture::identity(),
                authority: vec![],
                owner: owner_tls.fingerprint(),
                node_id: 207,
                quota_bytes: 16 * 1024 * 1024,
                listen: "127.0.0.1:0".parse().unwrap(),
            },
        )
        .unwrap();
        let fhe = storage.endpoint().clone();
        let remote = RemotePeer::new(fhe.clone(), connector.clone());
        assert!(
            matches!(remote.call(peer_runtime::Request::Store(f.bundle.clone())).unwrap(),Response::Stored(info) if info.id==f.object)
        );
        assert!(matches!(
            remote
                .call(peer_runtime::Request::InstallSetup(setup))
                .unwrap(),
            Response::Setup(_)
        ));
        let mut pids: Vec<_> = validators
            .iter()
            .map(os_process::ProgressProcess::pid)
            .collect();
        pids.push(storage.pid());
        assert!(pids.iter().all(|p| *p != std::process::id()));
        pids.sort_unstable();
        pids.dedup();
        assert_eq!(pids.len(), 5);
        eprintln!(
            "progress_fixture fhe_pid={} actual_children=5",
            storage.pid()
        );
        Self {
            validators,
            storage,
            connector,
            endpoints,
            fhe,
        }
    }
    pub fn config(&self) -> Config {
        Config::new(
            self.connector.clone(),
            self.endpoints.clone(),
            self.fhe.clone(),
            16,
        )
        .unwrap()
    }
    fn clients(&self, binding: &Binding) -> Vec<peer_runtime::finality::ProgressFinalityClient> {
        self.endpoints
            .iter()
            .map(|e| {
                peer_runtime::finality::ProgressFinalityClient::new(
                    self.connector.clone(),
                    e.clone(),
                    binding,
                )
            })
            .collect()
    }
    pub fn bootstrap(&self, binding: &Binding, boot: &Boot) -> Checkpoint {
        use peer_runtime::finality::{ProgressFinalityClient, ProgressProofBlobSelector};
        let started = Instant::now();
        let Body::Transition(t) =
            Body::decode(boot.block.body(), &binding.journal_genesis().profile).unwrap()
        else {
            panic!("actual bootstrap transition required")
        };
        let manifest = Manifest::decode(&t.proof).unwrap();
        let clients = self.clients(binding);
        let foreign = ProgressFinalityClient::new(
            Connector::permissionless(&fixture::identity()).unwrap(),
            self.endpoints[0].clone(),
            binding,
        );
        let reference = manifest.references().next().unwrap();
        let bytes = boot
            .ingress
            .read_public_blob(reference.blob_id(), reference.byte_cap())
            .unwrap();
        let denied = foreign
            .put_proof_blob(
                &boot.block,
                ProgressProofBlobSelector::manifest(0).unwrap(),
                reference.blob_id(),
                &bytes,
            )
            .unwrap_err();
        assert_eq!(denied.kind(), io::ErrorKind::InvalidData);
        let mut wrong = self.endpoints[0].clone();
        wrong.identity[0] ^= 1;
        assert!(
            ProgressFinalityClient::new(self.connector.clone(), wrong, binding)
                .observed_slot()
                .is_err()
        );
        drop(bytes);
        for reference in manifest.references() {
            let bytes = boot
                .ingress
                .read_public_blob(reference.blob_id(), reference.byte_cap())
                .unwrap();
            retry(started, || {
                clients[0].put_proof_blob(
                    &boot.block,
                    ProgressProofBlobSelector::manifest(reference.ordinal().try_into().unwrap())
                        .unwrap(),
                    reference.blob_id(),
                    &bytes,
                )
            });
        }
        eprintln!(
            "progress_fixture phase=bootstrap_upload_done elapsed_ms={}",
            started.elapsed().as_millis()
        );
        for client in &clients {
            retry(started, || client.submit(&boot.block));
        }
        let expected = registry200_finality::progress::Candidate::for_context(
            binding,
            boot.history.context().unwrap(),
            boot.block.header().clone(),
        )
        .unwrap();
        loop {
            bounded(started);
            for client in &clients {
                bounded(started);
                match client.checkpoint_after(0) {
                    Ok(Some(qc)) => {
                        assert_eq!(qc.candidate().encode(), expected.encode());
                        boot.history
                            .context()
                            .unwrap()
                            .verify_commit(&expected.encode(), qc.round(), qc.certificate())
                            .unwrap();
                        eprintln!(
                            "progress_fixture phase=bootstrap_valid_qc elapsed_ms={}",
                            started.elapsed().as_millis()
                        );
                        return qc;
                    }
                    Ok(None) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("actual Bootstrap checkpoint failed: {e}"),
                }
            }
            std::thread::park_timeout(Duration::from_millis(50));
        }
    }
    pub fn operation(
        &self,
        binding: &Binding,
        parent: &registry200_finality::progress::VerifiedParent,
    ) -> (Request, Manifest) {
        let started = Instant::now();
        loop {
            bounded(started);
            for (peer, client) in self.clients(binding).iter().enumerate() {
                bounded(started);
                match client.candidate_block(parent.head().block) {
                    Ok(block) => {
                        assert_eq!(block.header().id(), parent.head().block);
                        assert_eq!(
                            block.header().body_hash,
                            version_journal::hash(block.body())
                        );
                        let Body::Transition(t) =
                            Body::decode(block.body(), &binding.journal_genesis().profile).unwrap()
                        else {
                            panic!("own actual transition required")
                        };
                        t.check_authorization(
                            &binding.journal_genesis().owner,
                            binding.journal_genesis().id().unwrap(),
                        )
                        .unwrap();
                        return (
                            Request::decode(&t.request).unwrap(),
                            Manifest::decode(&t.proof).unwrap(),
                        );
                    }
                    Err(e) => {
                        // A laggard may reject a missing candidate even after
                        // another peer supplied a valid QC. An RPC error proves
                        // no absence or validity; try the other configured peers
                        // under this same deadline. Every returned block still
                        // passes all checks above before its bytes are used.
                        eprintln!(
                            "progress_fixture phase=parked_body_unavailable peer={} error_kind={:?} elapsed_ms={}",
                            peer,
                            e.kind(),
                            started.elapsed().as_millis()
                        );
                    }
                }
            }
            std::thread::park_timeout(Duration::from_millis(50));
        }
    }
    pub fn finish(self) {
        for validator in self.validators {
            validator.finish().unwrap();
        }
        self.storage.finish().unwrap();
    }
}
fn bounded(started: Instant) {
    assert!(
        started.elapsed() < peer_runtime::finality::PROGRESS_OPERATION_BUDGET,
        "fixed bootstrap/observation deadline expired; never renew a budget"
    );
}
fn retry(started: Instant, mut f: impl FnMut() -> io::Result<()>) {
    loop {
        bounded(started);
        match f() {
            Ok(()) => return,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::park_timeout(Duration::from_millis(50))
            }
            Err(e) => panic!("actual bootstrap I/O rejected: {e}"),
        }
    }
}
