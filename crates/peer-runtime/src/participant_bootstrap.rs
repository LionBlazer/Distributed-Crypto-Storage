//! Independently pinned local IPC bootstrap; never a network admission packet.
mod joint;
use crate::{Endpoint, Identity, finality::MAX_PEERS};
use ed25519_dalek::SigningKey;
pub use joint::JointParticipantBootstrap;
use registry200_finality::Binding;
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use std::{
    fmt,
    io::{self, Read},
    net::SocketAddr,
};
use work_finality::consensus::Rules;
use zeroize::Zeroizing;

pub const PARTICIPANT_BOOTSTRAP_BYTES: usize = 64 * 1024;
struct Seed(Zeroizing<Vec<u8>>);
impl<'de> Deserialize<'de> for Seed {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Seed;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("exactly 32 private signer bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Seed, A::Error> {
                if seq.size_hint().is_some_and(|n| n != 32) {
                    return Err(de::Error::custom("Invalid signer length"));
                }
                let mut bytes = Zeroizing::new(Vec::with_capacity(32));
                for _ in 0..32 {
                    bytes.push(
                        seq.next_element::<u8>()?
                            .ok_or_else(|| de::Error::custom("Invalid signer length"))?,
                    );
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::custom("Invalid signer length"));
                }
                Ok(Seed(bytes))
            }
        }
        d.deserialize_seq(V)
    }
}
fn neighbors<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Endpoint>, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Vec<Endpoint>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a bounded endpoint list")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|n| n > MAX_PEERS) {
                return Err(de::Error::custom("Too many neighbors"));
            }
            let mut out = Vec::with_capacity(MAX_PEERS);
            while let Some(endpoint) = seq.next_element::<Endpoint>()? {
                if out.len() == MAX_PEERS || out.contains(&endpoint) {
                    return Err(de::Error::custom("Invalid neighbors"));
                }
                out.push(endpoint);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(V)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFields {
    max_round: u64,
    timeouts_ms: [u64; 3],
    timeout_delta_ms: u64,
    wal_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u16,
    kind: String,
    identity: Identity,
    authority: Vec<u8>,
    owner: [u8; 32],
    listen: SocketAddr,
    #[serde(deserialize_with = "neighbors")]
    neighbors: Vec<Endpoint>,
    namespace: [u8; 32],
    capacity: u64,
    work_genesis: [u8; 32],
    journal_genesis: [u8; 32],
    binding: [u8; 32],
    rules: RuleFields,
    signer: Seed,
}
/// Private owned signer/configuration. No Clone, Debug, Serialize or secret getter.
///
/// ```compile_fail
/// fn copy(x: &peer_runtime::ParticipantBootstrap) { let _: peer_runtime::ParticipantBootstrap = x.clone(); }
/// ```
/// ```compile_fail
/// fn secret(x: &peer_runtime::ParticipantBootstrap) { let _ = &x.signer; }
/// ```
pub struct ParticipantBootstrap {
    pub(crate) identity: Identity,
    pub(crate) authority: Vec<u8>,
    pub(crate) owner: [u8; 32],
    pub(crate) listen: SocketAddr,
    pub(crate) neighbors: Vec<Endpoint>,
    pub(crate) namespace: [u8; 32],
    pub(crate) capacity: u64,
    pub(crate) binding: Binding,
    pub(crate) signer: SigningKey,
}

impl ParticipantBootstrap {
    /// Four exact bounded frames: secret config, original WorkGenesis, original
    /// two-shard JournalGenesis and canonical application descriptor. JSON never
    /// carries a giant byte-array roster. All trust pins originate in local IPC.
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let bytes = Zeroizing::new(peer_transport::read_frame(
            reader,
            PARTICIPANT_BOOTSTRAP_BYTES,
        )?);
        let c: Config = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        drop(bytes);
        if c.version != 1
            || c.kind != "registry200-participant-finality-v1"
            || c.capacity == 0
            || c.capacity > protocol_storage::MAX_PARTICIPANT_BYTES
        {
            return Err(io::Error::other("Invalid participant bootstrap"));
        }
        let work = peer_transport::read_frame(reader, work_finality::MAX_GENESIS_BYTES)?;
        let work =
            work_finality::Genesis::decode(&work, c.work_genesis).map_err(io::Error::other)?;
        let journal = peer_transport::read_frame(reader, 716)?;
        if journal.len() != 716 {
            return Err(io::Error::other("Original Registry200 requires two shards"));
        }
        let journal = version_journal::Genesis::decode(&journal).map_err(io::Error::other)?;
        if journal.id().map_err(io::Error::other)? != c.journal_genesis {
            return Err(io::Error::other("Wrong Journal pin"));
        }
        let descriptor = peer_transport::read_frame(reader, 312)?;
        let descriptor = registry200_journal::ApplicationDescriptor::decode(&descriptor)
            .map_err(io::Error::other)?;
        let rules = Rules::multi_slot(
            registry200_finality::profile_digest(),
            registry200_finality::DESCRIPTOR_BYTES as u32,
            c.rules.max_round,
            c.rules.timeouts_ms,
            c.rules.timeout_delta_ms,
            c.rules.wal_bytes,
        )
        .map_err(io::Error::other)?;
        let binding = Binding::new(journal.network_id, rules, work, journal, descriptor)
            .map_err(io::Error::other)?;
        if binding.id() != c.binding {
            return Err(io::Error::other("Wrong finality Binding pin"));
        }
        let signer = SigningKey::from_bytes(
            c.signer
                .0
                .as_slice()
                .try_into()
                .map_err(|_| io::Error::other("Invalid signer"))?,
        );
        if binding
            .initial_context()
            .set()
            .weight(signer.verifying_key().to_bytes())
            .is_none()
        {
            return Err(io::Error::other(
                "Signer is not in the independently pinned work roster",
            ));
        }
        Ok(Self {
            identity: c.identity,
            authority: c.authority,
            owner: c.owner,
            listen: c.listen,
            neighbors: c.neighbors,
            namespace: c.namespace,
            capacity: c.capacity,
            binding,
            signer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_local_bootstrap_is_rejected_before_any_payload_read() {
        let mut frame = Vec::new();
        peer_transport::write_frame(&mut frame, &[], PARTICIPANT_BOOTSTRAP_BYTES).unwrap();
        frame[8..16].copy_from_slice(&((PARTICIPANT_BOOTSTRAP_BYTES + 1) as u64).to_be_bytes());
        let mut input = io::Cursor::new(frame);
        let error = ParticipantBootstrap::read(&mut input).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(input.position(), 16);
    }
    #[test]
    fn private_signer_seed_has_an_exact_length_without_unbounded_sequence_growth() {
        for n in [0, 31, 33, 64] {
            let bytes = serde_json::to_vec(&vec![1u8; n]).unwrap();
            assert!(serde_json::from_slice::<Seed>(&bytes).is_err());
        }
        let bytes = serde_json::to_vec(&[1u8; 32]).unwrap();
        let seed = serde_json::from_slice::<Seed>(&bytes).unwrap();
        assert_eq!(seed.0.as_slice(), [1; 32]);
    }
    #[test]
    fn peer_list_rejects_duplicates_and_more_than_the_actor_neighbor_bound() {
        #[derive(Deserialize)]
        struct List {
            #[serde(deserialize_with = "neighbors")]
            peers: Vec<Endpoint>,
        }
        let endpoints: Vec<_> = (0..MAX_PEERS)
            .map(|n| Endpoint {
                address: format!("127.0.0.1:{}", 10000 + n).parse().unwrap(),
                identity: [n as u8; 32],
            })
            .collect();
        let decode =
            |peers: &[Endpoint]| serde_json::from_value::<List>(serde_json::json!({"peers":peers}));
        assert_eq!(decode(&endpoints).unwrap().peers, endpoints);
        let mut duplicate = endpoints[..2].to_vec();
        duplicate[1] = duplicate[0].clone();
        assert!(decode(&duplicate).is_err());
        let mut too_many = endpoints;
        too_many.push(Endpoint {
            address: "127.0.0.1:20000".parse().unwrap(),
            identity: [0xff; 32],
        });
        assert!(decode(&too_many).is_err());
    }
}
