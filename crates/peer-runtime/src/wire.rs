pub(crate) use crate::RawBundle;
use bincode::Options;
use peer_transport::{Endpoint, MAX_FRAME_BYTES};
use serde::{Deserialize, Serialize};
use std::io;

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
    Store(RawBundle),
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
    /// Exact-address encrypted page custody, with its own fail-closed v2 payload.
    FetchPages(crate::PageBatchRequest),
    FetchReadImage(crate::ReadImageRequest),
    /// Owner-only fixed-geometry padded ciphertext upload; existing tags remain stable.
    StoreDelta(crate::StoreDeltaRequest),
    /// Owner-only exact Registry200 application pins; no BFV setup/SQL grant.
    InitRegistryJournal {
        genesis: Vec<u8>,
        application: Vec<u8>,
    },
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
            Self::InitRegistryJournal { .. } => "registry-journal-init",
            Self::JournalBlocks { .. } => "journal-sync",
            Self::PublishBlock { .. } => "journal-publish",
            Self::MineBlock { .. } => "journal-mine",
            Self::CollectJournal { .. } => "journal-collect",
            Self::Copy { .. } => "copy",
            Self::Neighbors(_) => "neighbors",
            Self::Quota(_) => "quota",
            Self::Shutdown => "shutdown",
            Self::FetchPages(_) => "fetch-pages",
            Self::FetchReadImage(_) => "read-image",
            Self::StoreDelta(_) => "store-delta",
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
impl Status {
    /// Advisory observed object/journal bytes plus the fixed initialized root
    /// profile. Excludes in-flight reservations, pending writes and RAM/setup.
    /// This status observation never grants custody or quota admission.
    pub fn disk_bytes(&self) -> u64 {
        self.objects.iter().fold(
            self.journal_bytes
                .saturating_add(crate::store::PROFILE_BYTES as u64),
            |total, object| total.saturating_add(object.stored_bytes),
        )
    }
}
#[derive(Serialize, Deserialize)]
pub enum Response {
    Alive {
        node_id: u64,
        pid: u32,
    },
    Status(Status),
    Stored(ObjectInfo),
    RawBundle(RawBundle),
    Setup([u8; 32]),
    /// Genuine peer FHE output, with no fabricated proof or accepted-result wrapper.
    UnverifiedCiphertext(Vec<u8>),
    Proved(ProofReply),
    JournalReady([u8; 32]),
    JournalBlocks(Vec<JournalBlock>),
    JournalAccepted([u8; 32]),
    Mined(JournalBlock),
    Done,
    /// Untrusted ciphertext membership response; the client verifies exact heads.
    Pages(crate::PageBatch),
    ReadImage(crate::ReadImage),
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
pub(crate) fn encoded_len<T: Serialize>(value: &T) -> io::Result<u64> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME_BYTES as u64)
        .serialized_size(value)
        .map_err(io::Error::other)
}
pub(crate) fn encode_into<T: Serialize>(
    value: &T,
    output: &mut impl std::io::Write,
) -> io::Result<()> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME_BYTES as u64)
        .serialize_into(output, value)
        .map_err(io::Error::other)
}
pub(crate) fn decode<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> io::Result<T> {
    check_frame_size(bytes)?;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(io::Error::other)
}

// Slice deserialization in pinned bincode replaces with_limit with Infinite.
// The actual complete input, including its outer envelope, needs its own cap.
pub(crate) fn check_frame_size(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Frame exceeds limit",
        ));
    }
    Ok(())
}

pub(crate) fn decode_request(bytes: &[u8]) -> io::Result<WireRequest> {
    check_frame_size(bytes)?;
    check_version(bytes)?;
    // Only Store has a full RawBundle. Every other variant keeps its ordinary
    // decoder; a malformed Store body never falls through to a second codec.
    if bytes.get(10..14) == Some(2u32.to_le_bytes().as_slice()) {
        let (version, id, _): (u16, u64, u32) = decode(&bytes[..14])?;
        let bundle = crate::objects::decode_slice(&bytes[14..])?;
        Ok(WireRequest {
            version,
            id,
            request: Request::Store(bundle),
        })
    } else {
        decode(bytes)
    }
}

pub(crate) fn decode_response(bytes: &[u8]) -> io::Result<WireResponse> {
    check_frame_size(bytes)?;
    check_version(bytes)?;
    // The fixed tags are pinned by codec tests against the actual enum encoder.
    if bytes.get(10..18) == Some([0u8, 0, 0, 0, 3, 0, 0, 0].as_slice()) {
        let (version, id, _, _): (u16, u64, u32, u32) = decode(&bytes[..18])?;
        let bundle = crate::objects::decode_slice(&bytes[18..])?;
        Ok(WireResponse {
            version,
            id,
            result: Ok(Response::RawBundle(bundle)),
        })
    } else {
        decode(bytes)
    }
}

/// Reject a substituted RPC variant before its unrelated vector decoder can
/// allocate. Page replies and errors have a separate narrow frame budget.
#[cfg(test)]
pub(crate) fn decode_page_response(bytes: &[u8]) -> io::Result<WireResponse> {
    decode_custody_response(bytes, crate::MAX_PAGE_BATCH_RESPONSE_BYTES, 12)
}
pub(crate) fn decode_custody_response(
    bytes: &[u8],
    maximum: usize,
    expected_tag: u32,
) -> io::Result<WireResponse> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid custody response envelope",
        )
    };
    if bytes.len() > maximum || bytes.len() < 18 {
        return Err(invalid());
    }
    let result_tag = u32::from_le_bytes(bytes[10..14].try_into().unwrap());
    let response_tag = u32::from_le_bytes(bytes[14..18].try_into().unwrap());
    match result_tag {
        0 if response_tag == expected_tag => {}
        1 if response_tag <= 6 && bytes.len() == 18 => {}
        1 if matches!(response_tag, 7 | 8) && bytes.len() >= 26 => {
            let length = u64::from_le_bytes(bytes[18..26].try_into().unwrap());
            if length != (bytes.len() - 26) as u64 {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(maximum as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(io::Error::other)
}

pub(crate) fn check_version(bytes: &[u8]) -> io::Result<()> {
    if bytes.get(..2) != Some(2u16.to_le_bytes().as_slice()) {
        return Err(io::Error::other("Unsupported RPC version"));
    }
    Ok(())
}

pub(crate) fn check_response_binding(version: u16, id: u64, expected: u64) -> io::Result<()> {
    if version != 2 || id != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Response version/request binding mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod version_tests {
    #[test]
    fn incompatible_rpc_prefix_rejects_before_body_decoding() {
        for bytes in [vec![], vec![2], vec![1, 0], vec![3, 0, 255, 255]] {
            assert!(super::check_version(&bytes).is_err());
        }
        assert!(super::check_version(&[2, 0]).is_ok());
    }
}
