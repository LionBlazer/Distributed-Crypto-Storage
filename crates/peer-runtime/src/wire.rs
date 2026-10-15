use bincode::Options;
use peer_transport::{Endpoint, Identity, MAX_FRAME_BYTES};
use serde::{Deserialize, Serialize};
use std::{io, net::SocketAddr};

#[derive(Serialize, Deserialize)]
pub struct Bootstrap {
    pub identity: Identity,
    pub authority: Vec<u8>,
    pub owner: [u8; 32],
    pub node_id: u64,
    pub quota_bytes: u64,
    pub listen: SocketAddr,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bundle {
    pub data_head: Vec<u8>,
    pub index_head: Vec<u8>,
    pub data: Vec<u8>,
    pub index: Vec<u8>,
}
impl Bundle {
    pub fn id(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for part in [&self.data_head, &self.index_head, &self.data, &self.index] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
        h.finalize().into()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Aggregate,
    Select,
    Insert,
    Update,
    /// Read-only typed byte projection. Its request binds the original encrypted
    /// table/page and schema; it is never a permitted journal mutation operation.
    ByteSelect,
}
#[derive(Serialize, Deserialize)]
pub enum Request {
    Probe,
    Status,
    Store(Bundle),
    Fetch {
        object: [u8; 32],
    },
    FetchVersion {
        data_head: Vec<u8>,
        index_head: Vec<u8>,
    },
    InstallSetup(Vec<u8>),
    Evaluate {
        object: [u8; 32],
        setup: [u8; 32],
        operation: Operation,
        ciphertext: Vec<u8>,
    },
    Prove {
        object: [u8; 32],
        setup: [u8; 32],
        operation: Operation,
        ciphertext: Vec<u8>,
    },
    InitJournal {
        genesis: Vec<u8>,
        setup: [u8; 32],
    },
    JournalBlocks {
        network: [u8; 32],
        known: Vec<[u8; 32]>,
    },
    PublishBlock {
        network: [u8; 32],
        header: Vec<u8>,
        body: Vec<u8>,
    },
    MineBlock {
        network: [u8; 32],
        parent: [u8; 32],
        body: Vec<u8>,
        timestamp: u64,
        attempts: u64,
    },
    CollectJournal {
        network: [u8; 32],
    },
    Copy {
        source: Endpoint,
        object: [u8; 32],
    },
    Neighbors(Vec<Endpoint>),
    Quota(u64),
    Shutdown,
}
impl Request {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Status => "status",
            Self::Store(_) => "store",
            Self::Fetch { .. } => "fetch",
            Self::FetchVersion { .. } => "fetch-version",
            Self::InstallSetup(_) => "public-setup",
            Self::Evaluate { .. } => "fhe",
            Self::Prove { .. } => "fhe-proof",
            Self::InitJournal { .. } => "journal-init",
            Self::JournalBlocks { .. } => "journal-sync",
            Self::PublishBlock { .. } => "journal-publish",
            Self::MineBlock { .. } => "journal-mine",
            Self::CollectJournal { .. } => "journal-collect",
            Self::Copy { .. } => "copy",
            Self::Neighbors(_) => "neighbors",
            Self::Quota(_) => "quota",
            Self::Shutdown => "shutdown",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectInfo {
    pub available: bool,
    pub id: [u8; 32],
    pub stored_bytes: u64,
    pub data_bytes: u64,
    pub index_bytes: u64,
    pub logical_bytes: u64,
    pub rows: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Neighbor {
    pub endpoint: Endpoint,
    pub reachable: bool,
    pub last_success_ms: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub sequence: u64,
    pub time_ms: u64,
    pub remote: [u8; 32],
    pub operation: String,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub succeeded: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub node_id: u64,
    pub pid: u32,
    pub quota_bytes: u64,
    pub objects: Vec<ObjectInfo>,
    pub public_setup_bytes: u64,
    pub journal_bytes: u64,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub neighbors: Vec<Neighbor>,
    pub recent: Vec<Observation>,
}
#[derive(Serialize, Deserialize)]
pub enum Response {
    Alive {
        node_id: u64,
        pid: u32,
    },
    Status(Status),
    Stored(ObjectInfo),
    Bundle(Bundle),
    Setup([u8; 32]),
    /// Genuine peer FHE output, with no fabricated proof or accepted-result wrapper.
    UnverifiedCiphertext(Vec<u8>),
    Proved(ProofReply),
    JournalReady([u8; 32]),
    JournalBlocks(Vec<JournalBlock>),
    JournalAccepted([u8; 32]),
    Mined(JournalBlock),
    Done,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReply {
    pub output: Vec<u8>,
    pub proof: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalBlock {
    pub header: Vec<u8>,
    pub body: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RemoteError {
    /// A bounded heavy-work permit is temporarily occupied; retry may succeed.
    Busy,
    Unauthorized,
    ResourceLimit,
    NotFound,
    Integrity,
    InvalidRequest,
    MiningExhausted,
    Cryptography(String),
    Io(String),
}
impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RemoteError {}
#[derive(Serialize, Deserialize)]
pub(crate) struct WireRequest {
    pub version: u16,
    pub id: u64,
    pub request: Request,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct WireResponse {
    pub version: u16,
    pub id: u64,
    pub result: Result<Response, RemoteError>,
}
pub(crate) fn encode<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME_BYTES as u64)
        .serialize(value)
        .map_err(io::Error::other)
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(io::Error::other)
}
