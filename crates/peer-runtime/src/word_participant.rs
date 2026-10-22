//! Explicit durable Word host, sharing one actual participant/proof gate.
use crate::{
    Endpoint, ProofGate, WordParticipantBootstrap,
    finality::{FinalityServer, ListenerConfig, RunningWordFinality, WordFinalityServer},
    participant::ParticipantInstall,
};
use peer_transport::{Acceptor, Connector};
use protocol_storage::ParticipantQuota;
use registry200_finality::word::DurableFinality;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self},
    path::Path,
};

pub fn word_participant_host_profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"dcs/Word-participant-finality-host/v1/no-SQL");
    h.update(protocol_storage::participant_profile_digest());
    h.update(registry200_finality::word::profile_digest());
    h.update(crate::finality::word_profile_digest());
    h.update(b"five-bounded-IPC/config-work-journal-descriptor-Source/native-Source-at-create-open/metadata-last/supervised-EOF-join/no-FHE-secret-no-SQL");
    h.finalize().into()
}
/// Startup metadata only, never proof or a fresh-head/SQL capability.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WordParticipantReady {
    pub version: u16,
    pub profile: [u8; 32],
    pub namespace: [u8; 32],
    pub binding: [u8; 32],
    pub pid: u32,
    pub endpoint: Endpoint,
}
pub struct WordParticipantHost {
    server: WordFinalityServer,
    quota: ParticipantQuota,
    namespace: [u8; 32],
    binding: [u8; 32],
}
pub struct RunningWordParticipant {
    server: RunningWordFinality,
    _quota: ParticipantQuota,
}
impl WordParticipantHost {
    pub fn bind(
        directory: &Path,
        install: ParticipantInstall,
        config: WordParticipantBootstrap,
    ) -> io::Result<Self> {
        let (acceptor, connector) = if config.authority.is_empty() {
            (
                Acceptor::permissionless(&config.identity)?,
                Connector::permissionless(&config.identity)?,
            )
        } else {
            (
                Acceptor::new(&config.identity, &config.authority)?,
                Connector::new(&config.identity, &config.authority)?,
            )
        };
        let quota = match install {
            ParticipantInstall::New => {
                ParticipantQuota::create_new(directory, config.namespace, config.capacity)
            }
            ParticipantInstall::Existing => {
                ParticipantQuota::open_existing(directory, config.namespace, config.capacity)
            }
        }
        .map_err(io::Error::other)?;
        let gate = ProofGate::new();
        let permit = gate.try_acquire().map_err(io::Error::other)?;
        let binding = config.binding.id();
        let owned = match install {
            ParticipantInstall::New => {
                DurableFinality::create_participant(&quota, config.binding, config.signer)
            }
            ParticipantInstall::Existing => {
                DurableFinality::open_participant(&quota, config.binding, config.signer)
            }
        }
        .map_err(io::Error::other)?;
        drop(permit);
        let server = FinalityServer::bind_word(
            ListenerConfig {
                listen: config.listen,
                identity: config.identity.fingerprint(),
                owner: config.owner,
                acceptor,
                connector,
                neighbors: config.neighbors,
            },
            owned,
            gate,
        )?;
        Ok(Self {
            server,
            quota,
            namespace: config.namespace,
            binding,
        })
    }
    pub fn spawn(self) -> io::Result<(WordParticipantReady, RunningWordParticipant)> {
        let server = self.server.spawn()?;
        let ready = WordParticipantReady {
            version: 1,
            profile: word_participant_host_profile_digest(),
            namespace: self.namespace,
            binding: self.binding,
            pid: std::process::id(),
            endpoint: server.endpoint().clone(),
        };
        Ok((
            ready,
            RunningWordParticipant {
                server,
                _quota: self.quota,
            },
        ))
    }
}
impl RunningWordParticipant {
    pub fn stop(&mut self) -> io::Result<()> {
        self.server.stop()
    }
}
impl Drop for RunningWordParticipant {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
