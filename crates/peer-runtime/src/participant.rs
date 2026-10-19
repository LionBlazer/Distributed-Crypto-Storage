//! Trusted, explicit original-Registry participant host. No legacy custody open.
use crate::{
    Endpoint, ProofGate,
    finality::{FinalityServer, ListenerConfig, RunningFinality},
    participant_bootstrap::ParticipantBootstrap,
};
use peer_transport::{Acceptor, Connector};
use protocol_storage::ParticipantQuota;
use registry200_finality::RegistryFinality;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io, path::Path};

#[derive(Clone, Copy)]
pub enum ParticipantInstall {
    New,
    Existing,
}
pub fn participant_host_profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"dcs/participant-finality-host/v1/original-registry-only/no-SQL");
    h.update(protocol_storage::participant_profile_digest());
    h.update(registry200_finality::participant_storage_profile_digest());
    h.update(crate::finality::profile_digest());
    h.update(b"four-bounded-IPC-frames/metadata-last/supervised-EOF-join/no-custody-v2");
    h.finalize().into()
}
/// Public startup observation, never proof or a freshness grant.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantReady {
    pub version: u16,
    pub profile: [u8; 32],
    pub namespace: [u8; 32],
    pub binding: [u8; 32],
    pub pid: u32,
    pub endpoint: Endpoint,
}
pub struct ParticipantHost {
    server: FinalityServer,
    quota: ParticipantQuota,
    namespace: [u8; 32],
    binding: [u8; 32],
}
pub struct RunningParticipant {
    server: RunningFinality,
    _quota: ParticipantQuota,
}
impl ParticipantHost {
    pub fn bind(
        directory: &Path,
        install: ParticipantInstall,
        config: ParticipantBootstrap,
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
        // This trusted host allocates ONE actual scheduling gate. All original
        // proof replay precedes listener startup; no second ByteBudget exists.
        let gate = ProofGate::new();
        let permit = gate.try_acquire().map_err(io::Error::other)?;
        let binding = config.binding.id();
        let owned = match install {
            ParticipantInstall::New => {
                RegistryFinality::create_participant(&quota, config.binding, config.signer)
            }
            ParticipantInstall::Existing => {
                RegistryFinality::open_participant(&quota, config.binding, config.signer)
            }
        }
        .map_err(io::Error::other)?;
        drop(permit);
        let server = FinalityServer::bind(
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
    pub fn spawn(self) -> io::Result<(ParticipantReady, RunningParticipant)> {
        let server = self.server.spawn()?;
        let ready = ParticipantReady {
            version: 1,
            profile: participant_host_profile_digest(),
            namespace: self.namespace,
            binding: self.binding,
            pid: std::process::id(),
            endpoint: server.endpoint().clone(),
        };
        Ok((
            ready,
            RunningParticipant {
                server,
                _quota: self.quota,
            },
        ))
    }
}
impl RunningParticipant {
    pub fn stop(&mut self) -> io::Result<()> {
        self.server.stop()
    }
}
impl Drop for RunningParticipant {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
