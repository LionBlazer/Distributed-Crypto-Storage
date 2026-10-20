//! Explicit durable Progress host, sharing one actual participant/depot/proof gate.
use crate::{
    Endpoint, ProgressParticipantBootstrap, ProofGate,
    finality::{FinalityServer, ListenerConfig, ProgressFinalityServer, RunningProgressFinality},
    participant::ParticipantInstall,
};
use peer_transport::{Acceptor, Connector};
use protocol_storage::ParticipantQuota;
use registry200_finality::progress::DurableFinality;
use registry200_joint::progress::ProgressDepot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    path::Path,
};

pub fn progress_participant_host_profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"dcs/Progress-participant-finality-host/v2/no-SQL");
    h.update(protocol_storage::participant_profile_digest());
    h.update(registry200_finality::progress::durable_profile_digest());
    h.update(crate::finality::progress_profile_digest());
    h.update(b"five-bounded-IPC-metadata/one-or-two32MiB-setup-chunks-New-only/full-hash-before-SDK/metadata-last/supervised-EOF-join/no-legacy-custody");
    h.finalize().into()
}
/// Startup metadata only, never proof or a fresh-head/SQL capability.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressParticipantReady {
    pub version: u16,
    pub profile: [u8; 32],
    pub namespace: [u8; 32],
    pub binding: [u8; 32],
    pub pid: u32,
    pub endpoint: Endpoint,
}
pub struct ProgressParticipantHost {
    server: ProgressFinalityServer,
    quota: ParticipantQuota,
    namespace: [u8; 32],
    binding: [u8; 32],
}
pub struct RunningProgressParticipant {
    server: RunningProgressFinality,
    _quota: ParticipantQuota,
}
impl ProgressParticipantHost {
    pub fn bind(
        directory: &Path,
        install: ParticipantInstall,
        config: ProgressParticipantBootstrap,
        reader: &mut impl Read,
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
        if matches!(install, ParticipantInstall::New) {
            // Cold prefetch only. Close this SAME scoped depot before the
            // durable constructor reopens it and rebuilds/verifies full setup.
            let depot = ProgressDepot::open(
                quota.depot_budget(),
                config.binding.application_descriptor(),
            )
            .map_err(io::Error::other)?;
            let ingress = depot.ingress();
            for id in config.binding.setup_claim().parts() {
                let bytes =
                    peer_transport::read_frame(reader, protocol_storage::MAX_BLOB_BYTES as usize)?;
                let digest: [u8; 32] = Sha256::digest(&bytes).into();
                if bytes.len() as u64 != id.bytes() || &digest != id.sha256() {
                    return Err(io::Error::other("Wrong pinned setup chunk"));
                }
                if ingress
                    .retain_public_blob(&bytes)
                    .map_err(io::Error::other)?
                    != *id
                {
                    return Err(io::Error::other("Setup chunk identity changed"));
                }
            }
        }
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
        let server = FinalityServer::bind_progress(
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
    pub fn spawn(self) -> io::Result<(ProgressParticipantReady, RunningProgressParticipant)> {
        let server = self.server.spawn()?;
        let ready = ProgressParticipantReady {
            version: 2,
            profile: progress_participant_host_profile_digest(),
            namespace: self.namespace,
            binding: self.binding,
            pid: std::process::id(),
            endpoint: server.endpoint().clone(),
        };
        Ok((
            ready,
            RunningProgressParticipant {
                server,
                _quota: self.quota,
            },
        ))
    }
}
impl RunningProgressParticipant {
    pub fn stop(&mut self) -> io::Result<()> {
        self.server.stop()
    }
}
impl Drop for RunningProgressParticipant {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
