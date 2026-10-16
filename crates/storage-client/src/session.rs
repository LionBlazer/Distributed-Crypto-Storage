//! Owner/client proof acceptance and independently validated network versions.
//! Storage preparation remains private; peers validate public jobs and signed roots.
use super::*;
use ed25519_dalek::SigningKey;
use peer_runtime::{
    JournalBlock,
    evidence::{JobVerifier, MutationEvidence, MutationJob, MutationManifest},
};
use version_journal::{
    AuthorizedTransition, Body, Freshness, Genesis, HeadPair, HeadRef, Header, Journal,
    ProtocolProfile, ShardState, ShardUpdate,
};
mod aggregate;
mod agreement;
mod execution;
mod insert;
mod pending;
mod select;
mod update;
mod writeback;
use pending::{MutationOutcome, PendingMutation, StoredMutation};

/// Successful results carry the independently checked confirmed version.
#[derive(Debug)]
pub enum VerifiedResult {
    Aggregated {
        projection: AggregateProjection,
        count: u64,
        sum: Option<u64>,
        version: HeadRef,
    },
    Selected {
        columns: Vec<sql_plan::Column>,
        rows: Vec<Vec<u32>>,
        version: HeadRef,
    },
    Updated {
        /// Matched rows, including values unchanged by this supported UPDATE.
        affected_rows: usize,
        version: HeadRef,
    },
    Inserted {
        count: usize,
        version: HeadRef,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateProjection {
    Count,
    Sum,
    CountSum,
}

/// Owns the write authorization key and the designated-client FHE/AEAD authority.
/// No easy-work profile is supplied by the core: callers pin an explicit contract.
pub struct Session {
    data: Database,
    participants: Vec<Participant>,
    journal: Journal,
    verifier: JobVerifier,
    signer: SigningKey,
    read_floor: HeadRef,
    pending_publication: Option<JournalBlock>,
    pending_mutation: Option<PendingMutation>,
    unavailable_this_operation: std::collections::BTreeSet<u64>,
}

pub(super) fn protocol(error: impl fmt::Display) -> Error {
    Error::Cryptography(error.to_string())
}
fn heads(info: &ShardInfo) -> HeadPair {
    HeadPair {
        data: info.data_head.encode(),
        index: info.index_head.encode(),
    }
}

// A peer's bounded heavy-operation permit can be occupied by real gossip work.
// Only that explicit resource response is retried, never invalid proofs or signatures.
pub(super) fn call_bounded(
    remote: &RemotePeer,
    make_request: impl Fn() -> Request,
) -> io::Result<Response> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        match remote.call(make_request()) {
            Err(error)
                if error
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<peer_runtime::RemoteError>())
                    .is_some_and(|source| matches!(source, peer_runtime::RemoteError::Busy))
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(50))
            }
            result => return result,
        }
    }
}

impl Session {
    pub fn create(
        name: String,
        rows: &[PlainRow],
        mut participants: Vec<Participant>,
        profile: ProtocolProfile,
    ) -> Result<Self> {
        profile.validate().map_err(protocol)?;
        if participants.len() > 16 || participants.len() > profile.max_shards as usize {
            return Err(Error::InvalidInput(
                "Network contract admits at most 16 prototype shards".into(),
            ));
        }
        participants.sort_by_key(|p| p.id);
        let data = Database::create(name, rows, participants.clone())?;
        let setup = bfv_query_core::PublicSetup::from_bytes(&data.setup).map_err(protocol)?;
        let verifier =
            JobVerifier::new(setup.update_parameters().map_err(protocol)?).map_err(protocol)?;
        let mut seed = [0; 32];
        getrandom::getrandom(&mut seed).map_err(protocol)?;
        let signer = SigningKey::from_bytes(&seed);
        seed.fill(0);
        let mut network_id = [0; 32];
        getrandom::getrandom(&mut network_id).map_err(protocol)?;
        let genesis = Genesis {
            network_id,
            database: data.shards[0].info.data_head.database(),
            owner: signer.verifying_key().to_bytes(),
            application_commitment: verifier.application_commitment(),
            timestamp: agreement::now().saturating_sub(1),
            profile,
            initial_shards: data
                .shards
                .iter()
                .map(|s| ShardState {
                    id: s.info.id,
                    heads: heads(&s.info),
                })
                .collect(),
        };
        let journal = Journal::new(genesis).map_err(protocol)?;
        let read_floor = journal.genesis_head();
        let mut session = Self {
            data,
            participants,
            journal,
            verifier,
            signer,
            read_floor,
            pending_publication: None,
            pending_mutation: None,
            unavailable_this_operation: Default::default(),
        };
        // Real copies on two processes, where available. Processes on one host
        // still share a physical failure domain; no geographic tolerance is claimed.
        if session.participants.len() > 1 {
            for slot in 0..session.data.shards.len() {
                let target = session.participants[(slot + 1) % session.participants.len()].clone();
                session
                    .data
                    .copy_shard(session.data.shards[slot].info.id, target)?;
            }
        }
        for participant in &session.participants {
            session.initialize_participant(participant)?;
        }
        for _ in 0..session.journal.profile().confirmation_depth {
            session.mine_body(Body::Empty)?;
        }
        session.read_floor = session.synchronize()?;
        Ok(session)
    }
    pub fn name(&self) -> &str {
        self.data.name()
    }
    pub fn rows(&self) -> usize {
        self.data.rows()
    }
    pub fn shards(&self) -> Vec<ShardInfo> {
        self.data.shards()
    }
    pub fn statuses(&self) -> Vec<(u64, io::Result<Status>)> {
        self.data.statuses()
    }
    pub fn version(&self) -> HeadRef {
        self.read_floor
    }
    pub fn genesis(&self) -> &Genesis {
        self.journal.genesis()
    }
    pub fn copy_shard(&mut self, shard: u64, target: Participant) -> Result<()> {
        self.initialize_participant(&target)?;
        if !self.participants.iter().any(|p| p.id == target.id) {
            self.participants.push(target.clone());
        }
        self.data.copy_shard(shard, target)
    }
    pub fn replace_participant(&mut self, participant: Participant) -> Result<()> {
        self.initialize_participant(&participant)?;
        self.data.replace_participant(participant.clone())?;
        if let Some(p) = self
            .participants
            .iter_mut()
            .find(|p| p.id == participant.id)
        {
            *p = participant;
        }
        self.unavailable_this_operation.clear();
        Ok(())
    }
    /// Explicit owner data inspection for editors; never used to answer SQL.
    pub fn inspect_rows(&self) -> Result<Vec<PlainRow>> {
        let mut rows = Vec::new();
        for shard in &self.data.shards {
            let (_, table) = self.fetch_online(shard)?;
            for row in 0..table.commitment().layout().row_count {
                rows.push(self.data.owner.decrypt_row_for_experiment(
                    &table,
                    row,
                    Limits::default(),
                )?);
            }
        }
        Ok(rows)
    }
    fn fetch_online(&self, shard: &Shard) -> Result<(RemotePeer, Table)> {
        let reachable = Shard {
            info: shard.info.clone(),
            peers: shard
                .peers
                .iter()
                .filter(|peer| !self.unavailable_this_operation.contains(&peer.id))
                .cloned()
                .collect(),
        };
        self.data.fetch(&reachable)
    }
    fn initialize_participant(&self, participant: &Participant) -> Result<()> {
        install(&participant.remote, &self.data.setup)?;
        let network = self.journal.genesis_id();
        let genesis = self.journal.genesis().encode().map_err(protocol)?;
        match call_bounded(&participant.remote, || Request::InitJournal {
            genesis: genesis.clone(),
            setup: self.data.setup_id,
        })? {
            Response::JournalReady(id) if id == network => {}
            _ => return Err(protocol("Wrong journal initialization acknowledgement")),
        }
        for (header, body) in self.journal.validated_blocks() {
            match call_bounded(&participant.remote, || Request::PublishBlock {
                network,
                header: header.encode().to_vec(),
                body: body.to_vec(),
            })? {
                Response::JournalAccepted(id) if id == header.id() => {}
                _ => return Err(protocol("Missing block acknowledgement")),
            }
        }
        Ok(())
    }
}
