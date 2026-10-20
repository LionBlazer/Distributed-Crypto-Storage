//! Distinct trusted-IPC Progress installation, never a remotely selected binding.
use super::*;
use registry200_finality::progress::{Binding, CANDIDATE_BYTES, durable_profile_digest};
use registry200_joint::progress::{
    DESCRIPTOR_BYTES, Descriptor, MAX_SETUP_CLAIM_BYTES, SetupClaim,
};

/// Move-only private bootstrap. Work/TLS keys stay in owner IPC; no FHE secret,
/// controller, Source opening or restored owner-vault material enters a peer.
///
/// ```compile_fail
/// fn copy(x:&peer_runtime::ProgressParticipantBootstrap){let _:peer_runtime::ProgressParticipantBootstrap=x.clone();}
/// ```
/// ```compile_fail
/// fn key(x:&peer_runtime::ProgressParticipantBootstrap){let _=&x.signer;}
/// ```
pub struct ProgressParticipantBootstrap {
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
impl ProgressParticipantBootstrap {
    /// Five exact bounded metadata frames. A New host then consumes the exact
    /// one/two public setup chunks through its SAME typed depot; Existing reads
    /// no replacement setup and must replay its retained files before Ready.
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let bytes = Zeroizing::new(peer_transport::read_frame(
            reader,
            PARTICIPANT_BOOTSTRAP_BYTES,
        )?);
        let c: Config = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        drop(bytes);
        if c.version != 2
            || c.kind != "registry208-progress-participant-finality-v2"
            || c.capacity == 0
            || c.capacity > protocol_storage::MAX_PARTICIPANT_BYTES
        {
            return Err(io::Error::other("Invalid Progress bootstrap"));
        }
        let work = peer_transport::read_frame(reader, work_finality::MAX_GENESIS_BYTES)?;
        let work =
            work_finality::Genesis::decode(&work, c.work_genesis).map_err(io::Error::other)?;
        let journal = peer_transport::read_frame(reader, 716)?;
        if journal.len() != 716 {
            return Err(io::Error::other(
                "Progress requires exactly two Journal shards",
            ));
        }
        let journal = version_journal::Genesis::decode(&journal).map_err(io::Error::other)?;
        if journal.id().map_err(io::Error::other)? != c.journal_genesis {
            return Err(io::Error::other("Wrong Progress Journal pin"));
        }
        let descriptor = peer_transport::read_frame(reader, DESCRIPTOR_BYTES)?;
        let descriptor = Descriptor::decode(&descriptor).map_err(io::Error::other)?;
        let setup = peer_transport::read_frame(reader, MAX_SETUP_CLAIM_BYTES)?;
        let setup = SetupClaim::decode(&setup).map_err(io::Error::other)?;
        if setup.application_id() != descriptor.id() {
            return Err(io::Error::other("Wrong Progress setup application pin"));
        }
        let rules = Rules::multi_slot(
            durable_profile_digest(),
            CANDIDATE_BYTES as u32,
            c.rules.max_round,
            c.rules.timeouts_ms,
            c.rules.timeout_delta_ms,
            c.rules.wal_bytes,
        )
        .map_err(io::Error::other)?;
        let binding =
            Binding::for_durable(journal.network_id, rules, work, journal, descriptor, setup)
                .map_err(io::Error::other)?;
        if binding.id() != c.binding {
            return Err(io::Error::other(
                "Wrong independently pinned Progress Binding",
            ));
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
    fn progress_bootstrap_rejects_the_announced_bound_before_reading_payload() {
        let mut bytes = Vec::new();
        peer_transport::write_frame(&mut bytes, &[], PARTICIPANT_BOOTSTRAP_BYTES).unwrap();
        bytes[8..16].copy_from_slice(&((PARTICIPANT_BOOTSTRAP_BYTES + 1) as u64).to_be_bytes());
        let mut reader = io::Cursor::new(bytes);
        assert_eq!(
            ProgressParticipantBootstrap::read(&mut reader)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(reader.position(), 16);
    }

    #[test]
    fn legacy_or_mixed_ipc_kind_stops_before_the_work_payload() {
        // Invalid metadata only: no TLS credential, fake Work proof or accepted
        // bootstrap is manufactured by this bounded parser-negative fixture.
        for (version, kind) in [
            (1, "registry200-joint-participant-finality-v1"),
            (1, "registry208-progress-participant-finality-v2"),
            (2, "registry200-joint-participant-finality-v1"),
        ] {
            let pins = [0u8; 32];
            let metadata = serde_json::to_vec(&serde_json::json!({
                "version":version, "kind":kind,
                "identity":{"certificate":[],"private_key_pkcs8":[]},
                "authority":[], "owner":pins, "listen":"127.0.0.1:0",
                "neighbors":[], "namespace":pins, "capacity":10_000_000_000u64,
                "work_genesis":pins,"journal_genesis":pins,"binding":pins,
                "rules":{"max_round":32,"timeouts_ms":[100,200,300],
                    "timeout_delta_ms":10,"wal_bytes":work_finality::consensus::MAX_RECORD_BYTES},
                "signer":pins
            }))
            .unwrap();
            let mut bytes = Vec::new();
            peer_transport::write_frame(&mut bytes, &metadata, PARTICIPANT_BOOTSTRAP_BYTES)
                .unwrap();
            let metadata_end = bytes.len();
            peer_transport::write_frame(&mut bytes, &[0xcc; 32], work_finality::MAX_GENESIS_BYTES)
                .unwrap();
            let mut input = io::Cursor::new(bytes);
            assert!(ProgressParticipantBootstrap::read(&mut input).is_err());
            assert_eq!(input.position(), metadata_end as u64);
        }
    }
}
