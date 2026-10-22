//! Distinct trusted-IPC Word installation, never a remotely selected binding.
use super::*;
use registry200_finality::word::{
    Binding, CANDIDATE_BYTES, MAX_SOURCE_CERTIFICATE_BYTES, profile_digest,
};
use registry200_joint::word::{Descriptor, MAX_DESCRIPTOR_BYTES};

/// Move-only private bootstrap. Work/TLS keys stay in owner IPC; no FHE secret,
/// controller, Source opening or restored owner-vault material enters a peer.
///
/// ```compile_fail
/// fn copy(x:&peer_runtime::WordParticipantBootstrap){let _:peer_runtime::WordParticipantBootstrap=x.clone();}
/// ```
/// ```compile_fail
/// fn key(x:&peer_runtime::WordParticipantBootstrap){let _=&x.signer;}
/// ```
pub struct WordParticipantBootstrap {
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
impl WordParticipantBootstrap {
    /// Five bounded IPC frames pin configuration, work, Journal, full Source
    /// descriptor and immutable public Source proof. Every create/open performs
    /// native Source verification and Existing must replay its durable proofs.
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let bytes = Zeroizing::new(peer_transport::read_frame(
            reader,
            PARTICIPANT_BOOTSTRAP_BYTES,
        )?);
        let c: Config = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        drop(bytes);
        if c.version != 1
            || c.kind != "registry208-word-participant-finality-v1"
            || c.capacity == 0
            || c.capacity > protocol_storage::MAX_PARTICIPANT_BYTES
        {
            return Err(io::Error::other("Invalid Word bootstrap"));
        }
        let work = peer_transport::read_frame(reader, work_finality::MAX_GENESIS_BYTES)?;
        let work =
            work_finality::Genesis::decode(&work, c.work_genesis).map_err(io::Error::other)?;
        let journal = peer_transport::read_frame(reader, 716)?;
        if journal.len() != 716 {
            return Err(io::Error::other("Word requires exactly two Journal shards"));
        }
        let journal = version_journal::Genesis::decode(&journal).map_err(io::Error::other)?;
        if journal.id().map_err(io::Error::other)? != c.journal_genesis {
            return Err(io::Error::other("Wrong Word Journal pin"));
        }
        let descriptor = peer_transport::read_frame(reader, MAX_DESCRIPTOR_BYTES)?;
        let descriptor = Descriptor::decode(&descriptor).map_err(io::Error::other)?;
        let source = peer_transport::read_frame(reader, MAX_SOURCE_CERTIFICATE_BYTES)?;
        let rules = Rules::multi_slot(
            profile_digest(),
            CANDIDATE_BYTES as u32,
            c.rules.max_round,
            c.rules.timeouts_ms,
            c.rules.timeout_delta_ms,
            c.rules.wal_bytes,
        )
        .map_err(io::Error::other)?;
        let binding = Binding::new(
            journal.network_id,
            rules,
            work,
            journal,
            descriptor,
            &source,
        )
        .map_err(io::Error::other)?;
        if binding.id() != c.binding {
            return Err(io::Error::other("Wrong independently pinned Word Binding"));
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
                "Signer absent from independently pinned work roster",
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
    fn word_bootstrap_rejects_the_announced_bound_before_reading_payload() {
        let mut bytes = Vec::new();
        peer_transport::write_frame(&mut bytes, &[], PARTICIPANT_BOOTSTRAP_BYTES).unwrap();
        bytes[8..16].copy_from_slice(&((PARTICIPANT_BOOTSTRAP_BYTES + 1) as u64).to_be_bytes());
        let mut reader = io::Cursor::new(bytes);
        assert_eq!(
            WordParticipantBootstrap::read(&mut reader)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(reader.position(), 16);
    }
}
