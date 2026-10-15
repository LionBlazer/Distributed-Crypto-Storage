use super::*;
use crate::{JobVerifier, JournalBlock, MAX_JOB_BYTES, ProofReply};
use version_journal::{Body, DurableJournal, Genesis, Header};

pub(super) struct Network {
    pub(super) journal: DurableJournal,
    verifier: Arc<JobVerifier>,
    mining: BTreeMap<[u8; 32], u64>,
}
struct ProofPermit<'a>(&'a AtomicBool);
impl<'a> ProofPermit<'a> {
    fn acquire(busy: &'a AtomicBool) -> Result<Self, RemoteError> {
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RemoteError::Busy)?;
        Ok(Self(busy))
    }
}
impl Drop for ProofPermit<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
struct DiskReservation {
    shared: Arc<Shared>,
    bytes: u64,
}
impl DiskReservation {
    fn new(shared: &Arc<Shared>, bytes: u64) -> Result<Self, RemoteError> {
        shared
            .state
            .lock()
            .map_err(io_error)?
            .store
            .reserve(bytes)?;
        Ok(Self {
            shared: shared.clone(),
            bytes,
        })
    }
}
impl Drop for DiskReservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.store.release(self.bytes);
        }
    }
}
fn crypto(error: impl std::fmt::Display) -> RemoteError {
    RemoteError::Cryptography(error.to_string())
}
fn seconds() -> u64 {
    now() / 1000
}
fn get_network(shared: &Arc<Shared>, id: [u8; 32]) -> Result<Arc<Mutex<Network>>, RemoteError> {
    shared
        .state
        .lock()
        .map_err(io_error)?
        .journals
        .get(&id)
        .cloned()
        .ok_or(RemoteError::NotFound)
}

pub(super) fn dispatch(shared: &Arc<Shared>, request: Request) -> Result<Response, RemoteError> {
    match request {
        Request::InstallSetup(bytes) => {
            let id: [u8; 32] = Sha256::digest(&bytes).into();
            {
                let state = shared.state.lock().map_err(io_error)?;
                if state.setups.contains_key(&id) {
                    return Ok(Response::Setup(id));
                }
                if state.setups.len() >= 2 {
                    return Err(RemoteError::ResourceLimit);
                }
            }
            let _permit = ProofPermit::acquire(&shared.proof_busy)?;
            let public = PublicSetup::from_bytes(&bytes).map_err(crypto)?;
            let verifier = Arc::new(JobVerifier::new(
                public.update_parameters().map_err(crypto)?,
            )?);
            let setup = Arc::new(Setup {
                public,
                legacy: Mutex::new(None),
                verifier,
                bytes: bytes.len(),
            });
            let mut state = shared.state.lock().map_err(io_error)?;
            if state.setups.len() >= 2 && !state.setups.contains_key(&id) {
                return Err(RemoteError::ResourceLimit);
            }
            state.setups.insert(id, setup);
            Ok(Response::Setup(id))
        }
        Request::Evaluate {
            object,
            setup,
            operation,
            ciphertext,
        } => {
            let _permit = ProofPermit::acquire(&shared.proof_busy)?;
            let setup = {
                let mut state = shared.state.lock().map_err(io_error)?;
                state.store.get(&object)?;
                state
                    .setups
                    .get(&setup)
                    .cloned()
                    .ok_or(RemoteError::NotFound)?
            };
            let evaluator = {
                let mut legacy = setup.legacy.lock().map_err(io_error)?;
                if legacy.is_none() {
                    *legacy = Some(Arc::new(
                        PeerEvaluator::from_public_setup(&setup.public).map_err(crypto)?,
                    ));
                }
                legacy.as_ref().ok_or(RemoteError::Integrity)?.clone()
            };
            let output = match operation {
                Operation::Aggregate => evaluator
                    .evaluate_exact_index_aggregate_for_experiment(&ciphertext)
                    .map(|v| v.output),
                Operation::Select => evaluator
                    .evaluate_indexed_select_for_experiment(&ciphertext)
                    .map(|v| v.output),
                Operation::Insert => evaluator
                    .evaluate_indexed_insert_for_experiment(&ciphertext)
                    .map(|v| v.output),
                Operation::Update => evaluator
                    .evaluate_indexed_update(&ciphertext)
                    .map(|v| v.output),
            }
            .map_err(crypto)?;
            Ok(Response::UnverifiedCiphertext(output))
        }
        Request::InitJournal { genesis, setup } => {
            let _permit = ProofPermit::acquire(&shared.proof_busy)?;
            let genesis = Genesis::decode(&genesis).map_err(crypto)?;
            if genesis.initial_shards.len() > crate::MAX_JOBS {
                return Err(RemoteError::ResourceLimit);
            }
            let network = genesis.id().map_err(crypto)?;
            let (path, verifier) = {
                let mut state = shared.state.lock().map_err(io_error)?;
                let verifier = state
                    .setups
                    .get(&setup)
                    .ok_or(RemoteError::NotFound)?
                    .verifier
                    .clone();
                if verifier.application_commitment() != genesis.application_commitment {
                    return Err(RemoteError::Integrity);
                }
                if state.journals.contains_key(&network) {
                    return Ok(Response::JournalReady(network));
                }
                if state.journals.len() >= 8 {
                    return Err(RemoteError::ResourceLimit);
                }
                state.store.register_journal(network)?;
                (state.store.journal_path(&network), verifier)
            };
            let exists = path.exists();
            let reservation = DiskReservation::new(
                shared,
                if exists {
                    0
                } else {
                    genesis.encode().map_err(crypto)?.len() as u64 + 44
                },
            )?;
            let journal = if exists {
                DurableJournal::open(&path, genesis, seconds(), verifier.as_ref())
            } else {
                DurableJournal::create(&path, genesis)
            }
            .map_err(crypto)?;
            shared.state.lock().map_err(io_error)?.journals.insert(
                network,
                Arc::new(Mutex::new(Network {
                    journal,
                    verifier,
                    mining: BTreeMap::new(),
                })),
            );
            drop(reservation);
            Ok(Response::JournalReady(network))
        }
        Request::JournalBlocks { network, known } => {
            let network = get_network(shared, network)?;
            let network = network.lock().map_err(io_error)?;
            let journal = network.journal.journal();
            // Header capacity excludes the pinned genesis; clients may include
            // that trust anchor in their known set without losing read access.
            if known.len() > journal.profile().max_headers as usize + 1 {
                return Err(RemoteError::ResourceLimit);
            }
            let known: std::collections::BTreeSet<_> = known.into_iter().collect();
            let next = journal
                .validated_blocks()
                .into_iter()
                .find(|(header, _)| !known.contains(&header.id()));
            Ok(Response::JournalBlocks(
                next.into_iter()
                    .map(|(header, body)| JournalBlock {
                        header: header.encode().to_vec(),
                        body: body.to_vec(),
                    })
                    .collect(),
            ))
        }
        Request::PublishBlock {
            network,
            header,
            body,
        } => {
            let _permit = ProofPermit::acquire(&shared.proof_busy)?;
            let network = get_network(shared, network)?;
            let mut network = network.lock().map_err(io_error)?;
            let header = Header::decode(&header).map_err(crypto)?;
            if body.len() > network.journal.journal().profile().max_body_bytes as usize {
                return Err(RemoteError::ResourceLimit);
            }
            let duplicate = network.journal.journal().body(header.id()).is_some();
            let _reservation = DiskReservation::new(
                shared,
                if duplicate {
                    0
                } else {
                    4 + 192 + body.len() as u64 + 32
                },
            )?;
            let verifier = network.verifier.clone();
            let accepted = network
                .journal
                .append_block(header, &body, seconds(), verifier.as_ref())
                .map_err(crypto)?;
            Ok(Response::JournalAccepted(accepted.block))
        }
        Request::MineBlock {
            network,
            parent,
            body,
            timestamp,
            attempts,
        } => {
            if attempts == 0 || attempts > 1_000_000 {
                return Err(RemoteError::ResourceLimit);
            }
            let _permit = ProofPermit::acquire(&shared.proof_busy)?;
            let network = get_network(shared, network)?;
            let mut network = network.lock().map_err(io_error)?;
            let body_value =
                Body::decode(&body, network.journal.journal().profile()).map_err(crypto)?;
            let mut header = network
                .journal
                .journal()
                .candidate(parent, &body_value, timestamp)
                .map_err(crypto)?;
            network
                .journal
                .journal()
                .validate_mining_candidate(&header, seconds())
                .map_err(crypto)?;
            network
                .journal
                .journal()
                .verify_candidate(parent, &body_value, network.verifier.as_ref())
                .map_err(crypto)?;
            let mut key = header.clone();
            key.nonce = 0;
            let key = key.id();
            header.nonce = network.mining.get(&key).copied().unwrap_or(0);
            match header.mine(attempts) {
                Ok(_) => {
                    network.mining.remove(&key);
                    Ok(Response::Mined(JournalBlock {
                        header: header.encode().to_vec(),
                        body,
                    }))
                }
                Err(version_journal::Error::MiningExhausted) => {
                    if network.mining.len() >= 64 && !network.mining.contains_key(&key) {
                        return Err(RemoteError::ResourceLimit);
                    }
                    network.mining.insert(key, header.nonce);
                    Err(RemoteError::MiningExhausted)
                }
                Err(error) => Err(crypto(error)),
            }
        }
        Request::CollectJournal { network } => {
            let _permit = ProofPermit::acquire(&shared.proof_busy)?;
            let networks: Vec<_> = {
                let state = shared.state.lock().map_err(io_error)?;
                let active: std::collections::BTreeSet<_> =
                    state.journals.keys().copied().collect();
                if state.store.has_unloaded_journal(&active) {
                    return Err(RemoteError::InvalidRequest);
                }
                state
                    .journals
                    .iter()
                    .map(|(id, value)| (*id, value.clone()))
                    .collect()
            };
            if !networks.iter().any(|(id, _)| *id == network) {
                return Err(RemoteError::NotFound);
            }
            let mut history = std::collections::BTreeSet::new();
            let mut retained = std::collections::BTreeSet::new();
            for (id, node) in networks {
                let node = node.lock().map_err(io_error)?;
                let journal = node.journal.journal();
                let mut keep = vec![journal.best_validated()];
                if let Ok(confirmed) = journal.resolve(version_journal::Freshness::LatestConfirmed)
                {
                    keep.push(confirmed);
                    if let Some(header) = journal.header(confirmed.block) {
                        let parent = if header.parent == journal.genesis_id() {
                            journal.genesis_head()
                        } else {
                            let ancestor = journal
                                .header(header.parent)
                                .ok_or(RemoteError::Integrity)?;
                            version_journal::HeadRef {
                                genesis: journal.genesis_id(),
                                database: journal.genesis().database,
                                block: header.parent,
                                height: ancestor.height,
                                state_root: ancestor.state_root,
                            }
                        };
                        keep.push(parent);
                    }
                }
                for head in keep {
                    for shard in journal.validated_shards(head).map_err(crypto)? {
                        retained.insert(crate::store::head_pair_id(
                            &shard.heads.data,
                            &shard.heads.index,
                        ));
                    }
                }
                if id == network {
                    for shard in &journal.genesis().initial_shards {
                        history.insert(crate::store::head_pair_id(
                            &shard.heads.data,
                            &shard.heads.index,
                        ));
                    }
                    for (header, _) in journal.validated_blocks() {
                        let head = version_journal::HeadRef {
                            genesis: journal.genesis_id(),
                            database: journal.genesis().database,
                            block: header.id(),
                            height: header.height,
                            state_root: header.state_root,
                        };
                        for shard in journal.validated_shards(head).map_err(crypto)? {
                            history.insert(crate::store::head_pair_id(
                                &shard.heads.data,
                                &shard.heads.index,
                            ));
                        }
                    }
                }
            }
            shared
                .state
                .lock()
                .map_err(io_error)?
                .store
                .prune_journal_objects(&history, &retained)?;
            Ok(Response::Done)
        }
        _ => Err(RemoteError::InvalidRequest),
    }
}

pub(super) fn synchronize_neighbor(shared: &Arc<Shared>, endpoint: &Endpoint) {
    let networks: Vec<_> = match shared.state.lock() {
        Ok(state) => state
            .journals
            .iter()
            .map(|(id, network)| (*id, network.clone()))
            .collect(),
        Err(_) => return,
    };
    for (id, network) in networks {
        if shared.stop.load(Ordering::Acquire) {
            return;
        }
        let known = match network.lock() {
            Ok(network) => network
                .journal
                .journal()
                .validated_blocks()
                .iter()
                .map(|(header, _)| header.id())
                .collect(),
            Err(_) => continue,
        };
        let response = RemotePeer::new(endpoint.clone(), shared.connector.clone())
            .call(Request::JournalBlocks { network: id, known });
        if let Ok(Response::JournalBlocks(mut blocks)) = response {
            if blocks.len() != 1 {
                continue;
            }
            if let Some(block) = blocks.pop() {
                let _ = dispatch(
                    shared,
                    Request::PublishBlock {
                        network: id,
                        header: block.header,
                        body: block.body,
                    },
                );
            }
        }
    }
}

pub(super) fn prove(
    shared: &Arc<Shared>,
    object: [u8; 32],
    setup: [u8; 32],
    operation: Operation,
    ciphertext: Vec<u8>,
) -> Result<Response, RemoteError> {
    if ciphertext.len() > MAX_JOB_BYTES {
        return Err(RemoteError::ResourceLimit);
    }
    let _permit = ProofPermit::acquire(&shared.proof_busy)?;
    let (evaluator, data_head, index_head) = {
        let mut state = shared.state.lock().map_err(io_error)?;
        let bundle = state.store.get(&object)?;
        let evaluator = state
            .setups
            .get(&setup)
            .ok_or(RemoteError::NotFound)?
            .verifier
            .evaluator();
        (evaluator, bundle.data_head, bundle.index_head)
    };
    let context = evaluator.request_context(&ciphertext).map_err(crypto)?;
    if context.data_head() != data_head || context.index_head() != index_head {
        return Err(RemoteError::Integrity);
    }
    let input = crate::evidence::circuit_request(&evaluator, operation, &ciphertext)?;
    let generated = bfv_query_proof::prove(&input).map_err(crypto)?;
    Ok(Response::Proved(ProofReply {
        output: generated.output().to_vec(),
        proof: generated.proof().to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_heavy_work_is_retryable_busy_and_drop_releases_admission() {
        let busy = AtomicBool::new(false);
        let first = ProofPermit::acquire(&busy).unwrap();
        assert!(matches!(
            ProofPermit::acquire(&busy),
            Err(RemoteError::Busy)
        ));
        drop(first);
        assert!(ProofPermit::acquire(&busy).is_ok());
    }
}
