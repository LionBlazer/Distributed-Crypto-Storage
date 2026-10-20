//! Concrete original Registry200 application actor over actual bounded TLS.
//! Trusted composition supplies the already-owned journal/signer and the real
//! PeerServer proof gate. Neither endpoint metadata nor this service grants SQL.
mod actor;
mod client;
mod joint_client;
mod joint_prefetch;
mod joint_server;
mod joint_wire;
mod owner;
mod server;
mod wire;

pub use client::FinalityClient;
pub use joint_client::JointFinalityClient;
pub use joint_prefetch::ProofBlobSelector;
pub use joint_server::{JointFinalityServer, RunningJointFinality};
pub use joint_wire::{
    OPERATION_BUDGET as JOINT_OPERATION_BUDGET, profile_digest as joint_profile_digest,
};
pub use server::{FinalityServer, ListenerConfig, RunningFinality};
pub use wire::profile_digest;

use registry200_finality::CandidateBlock;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

pub const MAX_PEERS: usize = 16;
pub const MAX_CONNECTIONS: usize = 8;
pub const MAX_COMMANDS: usize = 8;
pub const MAX_QUEUED_BYTES: usize = 16 * 1024 * 1024;
pub const RPC_BUDGET: Duration = Duration::from_secs(180);

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid finality packet")
}
fn busy() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "Finality resource busy")
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Finality owner stopped")
}
fn error(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

#[derive(Clone)]
struct BodyGate(Arc<AtomicBool>);
struct BodyLease(Arc<AtomicBool>);
impl BodyGate {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
    fn acquire(&self) -> io::Result<BodyLease> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| busy())?;
        Ok(BodyLease(self.0.clone()))
    }
}
impl Drop for BodyLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
struct OwnedBlock {
    block: CandidateBlock,
    _lease: BodyLease,
}

struct InboxBytes(Arc<AtomicUsize>);
struct CommandLease {
    bytes: usize,
    ledger: Arc<AtomicUsize>,
}
impl InboxBytes {
    fn acquire(&self, bytes: usize) -> io::Result<CommandLease> {
        self.0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(bytes)
                    .filter(|next| *next <= MAX_QUEUED_BYTES)
            })
            .map_err(|_| busy())?;
        Ok(CommandLease {
            bytes,
            ledger: self.0.clone(),
        })
    }
}
impl Drop for CommandLease {
    fn drop(&mut self) {
        self.ledger.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests;
