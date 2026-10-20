//! Concrete owner network driver. Transport observations never replace Host admission.
use super::*;
use ed25519_dalek::SigningKey;
use peer_runtime::finality::JointFinalityClient;
use peer_runtime::{Connector, Endpoint, ProofGate, RemotePeer, RequestControl, RequestScope};
use registry200_finality::CandidateBlock;
use registry200_finality::joint::{JointBinding, JointCheckpoint};
use std::{
    io,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

mod drive;
mod sign;
mod upload;

pub type NetworkResult<T> = core::result::Result<T, JointSqlNetworkError>;
#[derive(Debug)]
pub enum JointSqlNetworkError {
    Configuration,
    WrongSigner,
    Vault(OwnerVaultError),
    Journal(version_journal::Error),
    Application(registry200_joint::Error),
    Finality(registry200_finality::Error),
    Joint(registry200_finality::joint::Error),
    Io(io::Error),
}
impl core::fmt::Display for JointSqlNetworkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Joint owner network operation rejected: {self:?}")
    }
}
impl std::error::Error for JointSqlNetworkError {}
impl From<OwnerVaultError> for JointSqlNetworkError {
    fn from(e: OwnerVaultError) -> Self {
        Self::Vault(e)
    }
}
impl From<version_journal::Error> for JointSqlNetworkError {
    fn from(e: version_journal::Error) -> Self {
        Self::Journal(e)
    }
}
impl From<registry200_joint::Error> for JointSqlNetworkError {
    fn from(e: registry200_joint::Error) -> Self {
        Self::Application(e)
    }
}
impl From<registry200_finality::Error> for JointSqlNetworkError {
    fn from(e: registry200_finality::Error) -> Self {
        Self::Finality(e)
    }
}
impl From<registry200_finality::joint::Error> for JointSqlNetworkError {
    fn from(e: registry200_finality::joint::Error) -> Self {
        Self::Joint(e)
    }
}
impl From<io::Error> for JointSqlNetworkError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Transport configuration, not election weights, authority or a latest-head oracle.
/// Endpoints are independently configured TLS pins; quorum weights come ONLY
/// from the Host's existing independently authenticated fixed activated set.
pub struct JointSqlNetworkConfig {
    connector: Connector,
    peers: Vec<Endpoint>,
    fhe: Endpoint,
    mining_attempts: u64,
}
impl JointSqlNetworkConfig {
    pub fn new(
        connector: Connector,
        peers: Vec<Endpoint>,
        fhe: Endpoint,
        mining_attempts: u64,
    ) -> NetworkResult<Self> {
        if peers.is_empty()
            || peers.len() > peer_runtime::finality::MAX_PEERS
            || mining_attempts == 0
            || peers
                .iter()
                .enumerate()
                .any(|(i, e)| peers[..i].contains(e))
        {
            return Err(JointSqlNetworkError::Configuration);
        }
        Ok(Self {
            connector,
            peers,
            fhe,
            mining_attempts,
        })
    }
}
/// Borrowed REAL originals and independently pinned Source image. No fixture,
/// authority loader, provisioning, callback or secret export is provided here.
pub struct JointSqlNetworkInput<'a> {
    pub source: &'a SourceOwner,
    pub fetched: FetchedSource<'a>,
    pub acquire: Option<&'a OwnerVaultAcquireMaterial<'a>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JointSqlNetworkPending {
    Busy,
    Unavailable,
    Deadline,
    Cancelled,
}
/// Pending never means empty SQL success or a lock release. NeedsReopen does
/// not carry rows: only a fresh acquire-aware full open can redeliver the saved
/// latest original response. Completion is historical, never a permanent lease.
pub enum JointSqlNetworkOutcome {
    Completed {
        cursor: OwnerVaultCursor,
        reply: Box<JointSqlReply>,
    },
    Pending {
        cursor: OwnerVaultCursor,
        reason: JointSqlNetworkPending,
    },
    NeedsReopen {
        cursor: OwnerVaultCursor,
        record_sequence: u64,
    },
}

/// Sole concrete Host/signer owner. No Clone/Debug, mutable Host/bank/Journal/key
/// getter, serialized verified marker or supplied application verifier exists.
pub struct JointSqlNetworkHost {
    host: JointSqlHost,
    signer: SigningKey,
    config: JointSqlNetworkConfig,
    gate: ProofGate,
    control: RequestControl,
    next_peer: usize,
}
impl JointSqlNetworkHost {
    pub fn attach(
        host: JointSqlHost,
        signer: SigningKey,
        config: JointSqlNetworkConfig,
        gate: ProofGate,
    ) -> NetworkResult<Self> {
        host.vault.live()?;
        if signer.verifying_key().to_bytes() != host.vault.pins.binding.journal_genesis().owner {
            return Err(JointSqlNetworkError::WrongSigner);
        }
        Ok(Self {
            host,
            signer,
            config,
            gate,
            control: RequestControl::default(),
            next_peer: 0,
        })
    }
    /// Resource cancellation only. It closes operation sockets, never resets
    /// pending records, rolls back private banks or releases Registry locks.
    pub fn request_control(&self) -> RequestControl {
        self.control.clone()
    }
    pub fn cursor(&self) -> NetworkResult<OwnerVaultCursor> {
        Ok(self.host.cursor()?)
    }
    pub fn phase(&self) -> NetworkResult<OwnerVaultPhase> {
        Ok(self.host.phase()?)
    }
    /// Move back the exact owned Host, retaining its pending, completed or
    /// poisoned state. Every execution has already joined its operation owner
    /// before returning. This neither admits work nor resets cancellation,
    /// authorizes a lease or exposes a mutable borrowed Host.
    pub fn into_host(self) -> JointSqlHost {
        self.host
    }
    /// Caller MUST authenticate/authorize the logical client and retain these
    /// exact original bytes/sequence for restart. Pending56 stores a digest,
    /// not the SQL text; missing intent cannot be reconstructed from a Body.
    /// Budget is explicit and at most the existing Joint operation budget.
    pub fn execute(
        &mut self,
        client: [u8; 32],
        sequence: u64,
        sql: &str,
        input: JointSqlNetworkInput<'_>,
        budget: Duration,
    ) -> NetworkResult<JointSqlNetworkOutcome> {
        let call = self.host.call(&self.host.client(client)?, sequence, sql)?;
        if call.verb == Verb::Acquire && input.acquire.is_none() {
            return Err(OwnerVaultError::RecoveryRequired.into());
        }
        if budget.is_zero() || budget > peer_runtime::finality::JOINT_OPERATION_BUDGET {
            return Err(JointSqlNetworkError::Configuration);
        }
        let operation = Operation::new(
            &self.config,
            &self.host.vault.pins.binding,
            &self.control,
            budget,
        )?;
        let result = self.drive(&call, sql, &input, &operation);
        let finished = operation.finish();
        match (result, finished) {
            (Ok(JointSqlNetworkOutcome::Completed { cursor, reply }), Err(error)) => {
                let record_sequence = reply.completed_record_sequence();
                drop(reply);
                let _ = error;
                Ok(JointSqlNetworkOutcome::NeedsReopen {
                    cursor,
                    record_sequence,
                })
            }
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(error.into()),
            (Err(error), _) => Err(error),
        }
    }
    /// Same API, explicitly retaining the original invocation. It does NOT
    /// choose another client sequence, SQL, nonce, Source image or private bank.
    pub fn resume_original(
        &mut self,
        client: [u8; 32],
        sequence: u64,
        sql: &str,
        input: JointSqlNetworkInput<'_>,
        budget: Duration,
    ) -> NetworkResult<JointSqlNetworkOutcome> {
        let call = self.host.call(&self.host.client(client)?, sequence, sql)?;
        if self.host.existing(&call)?.is_none() {
            return Err(OwnerVaultError::RecoveryRequired.into());
        }
        self.execute(client, sequence, sql, input, budget)
    }
    pub fn acknowledge(
        &mut self,
        client: [u8; 32],
        sequence: u64,
        sql: &str,
        cursor: OwnerVaultCursor,
    ) -> NetworkResult<OwnerVaultCursor> {
        let call = self.host.call(&self.host.client(client)?, sequence, sql)?;
        Ok(self.host.acknowledge(&call, cursor)?)
    }
    fn pending(&self, reason: JointSqlNetworkPending) -> NetworkResult<JointSqlNetworkOutcome> {
        Ok(JointSqlNetworkOutcome::Pending {
            cursor: self.host.cursor()?,
            reason,
        })
    }
}

// One bounded socket-deadline owner per execution. It never starts crypto or
// detaches native work. Cancellation is generation-scoped by RequestScope and
// every finality client is fresh for this execution (old cancel cannot poison
// later calls). The watcher is joined before any result escapes.
struct Operation {
    clients: Vec<JointFinalityClient>,
    remote: RemotePeer,
    scope: RequestScope,
    expires: Instant,
    stop: Arc<(Mutex<bool>, Condvar)>,
    watcher: Option<JoinHandle<()>>,
}
impl Operation {
    fn new(
        config: &JointSqlNetworkConfig,
        binding: &JointBinding,
        control: &RequestControl,
        budget: Duration,
    ) -> io::Result<Self> {
        let scope = control.begin()?;
        let expires = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| io::Error::other("Owner deadline overflow"))?;
        let clients = config
            .peers
            .iter()
            .map(|e| JointFinalityClient::new(config.connector.clone(), e.clone(), binding))
            .collect::<Vec<_>>();
        let remote = RemotePeer::new(config.fhe.clone(), config.connector.clone())
            .with_control(control.clone());
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let watched = stop.clone();
        let cancel = scope.cancellation();
        let sockets = clients.clone();
        let watcher = thread::Builder::new()
            .name("joint-owner-deadline".into())
            .spawn(move || {
                let (flag, wakeup) = &*watched;
                loop {
                    if cancel.is_cancelled() || Instant::now() >= expires {
                        cancel.cancel();
                        for client in &sockets {
                            client.cancel();
                        }
                        break;
                    }
                    let Ok(guard) = flag.lock() else {
                        cancel.cancel();
                        for client in &sockets {
                            client.cancel();
                        }
                        break;
                    };
                    if *guard {
                        break;
                    }
                    let wait = expires
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(20));
                    match wakeup.wait_timeout(guard, wait) {
                        Ok((guard, _)) if *guard => break,
                        Ok(_) => {}
                        Err(_) => {
                            cancel.cancel();
                            for client in &sockets {
                                client.cancel();
                            }
                            break;
                        }
                    }
                }
            })?;
        Ok(Self {
            clients,
            remote,
            scope,
            expires,
            stop,
            watcher: Some(watcher),
        })
    }
    fn check(&self) -> core::result::Result<(), JointSqlNetworkPending> {
        if Instant::now() >= self.expires {
            return Err(JointSqlNetworkPending::Deadline);
        }
        if self.scope.cancellation().is_cancelled() {
            return Err(JointSqlNetworkPending::Cancelled);
        }
        Ok(())
    }
    fn stop_network(&self) {
        for client in &self.clients {
            client.cancel();
        }
    }
    fn finish(mut self) -> io::Result<()> {
        self.join()
    }
    fn join(&mut self) -> io::Result<()> {
        let (flag, wakeup) = &*self.stop;
        if let Ok(mut stopped) = flag.lock() {
            *stopped = true;
            wakeup.notify_all();
        } else {
            self.scope.cancellation().cancel();
            self.stop_network();
        }
        if let Some(watcher) = self.watcher.take() {
            watcher
                .join()
                .map_err(|_| io::Error::other("Owner deadline thread panicked"))?;
        }
        Ok(())
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        let _ = self.join();
    }
}
