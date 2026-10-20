//! Concrete Progress owner orchestration. Ordinary TLS observations supply no
//! SQL, computation, private status or finality authority.
use super::*;
use peer_runtime::{Connector, Endpoint, RequestControl};
use std::{io, time::Duration};
mod drive;
mod operation;
#[cfg(test)]
mod process_tests;
#[cfg(test)]
mod tests;
mod upload;
use operation::Operation;

/// Independently configured transport destinations, never election weights or
/// replacement Binding/setup/keys. The actual Owner supplies those fixed pins.
pub struct Config {
    connector: Connector,
    peers: Vec<Endpoint>,
    fhe: Endpoint,
    mining_attempts: u64,
}
impl Config {
    pub fn new(
        connector: Connector,
        peers: Vec<Endpoint>,
        fhe: Endpoint,
        mining_attempts: u64,
    ) -> Result<Self> {
        if peers.is_empty()
            || peers.len() > peer_runtime::finality::MAX_PEERS
            || mining_attempts == 0
            || peers
                .iter()
                .enumerate()
                .any(|(i, e)| peers[..i].contains(e))
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            connector,
            peers,
            fhe,
            mining_attempts,
        })
    }
}
/// Waiting is an OWNED durable parked result and holds no Owner/Reply borrow.
/// Pending means resource/network incompletion; it is never SQL WAIT/NOWAIT.
/// Terminal borrows only the actual QC/root/fsync-completed owner outcome.
/// Owned Waiting releases the borrow so another client's genuine End can run:
/// ```no_run
/// use storage_client::private_predicate::{FetchedSource, progress::*};
/// fn next(driver:&mut Driver,cursor:Cursor,call:&Call,other_end:&Call,material:&Material<'_>,fetched:FetchedSource<'_>)->Result<()> {
///     let first=FetchedSource{object:fetched.object,bundle:fetched.bundle,heads:fetched.heads};
///     match driver.execute(cursor,call,material,first,std::time::Duration::from_secs(1))? {
///         Run::Waiting{cursor}=>{let _=driver.execute(cursor,other_end,material,fetched,std::time::Duration::from_secs(1))?;},
///         Run::Pending{..}|Run::Terminal{..}=>{},
///     }
///     Ok(())
/// }
/// ```
pub enum Run<'a> {
    Waiting {
        cursor: Cursor,
    },
    Pending {
        cursor: Cursor,
        reason: io::ErrorKind,
    },
    Terminal {
        cursor: Cursor,
        outcome: &'a Outcome,
    },
}
/// One concrete Owner/signer. No mutable Owner/history/ingress/bank getter, raw
/// proof selector factory, supplied verifier or second native gate is exposed.
/// ```compile_fail
/// fn expose(driver:storage_client::private_predicate::progress::Driver){let _=driver.owner;}
/// ```
/// ```compile_fail
/// fn expose(value:&storage_client::private_predicate::progress::Computed){let _=value.stamp;}
/// ```
pub struct Driver {
    owner: Owner,
    signer: SigningKey,
    config: Config,
    control: RequestControl,
    next_peer: usize,
}
impl Driver {
    pub fn attach(owner: Owner, signer: SigningKey, config: Config) -> Result<Self> {
        owner.wal.live()?;
        if signer.verifying_key().to_bytes() != owner.pins.binding.journal_genesis().owner {
            return Err(Error::Pins);
        }
        Ok(Self {
            owner,
            signer,
            config,
            control: RequestControl::default(),
            next_peer: 0,
        })
    }
    pub fn cursor(&self) -> Result<Cursor> {
        self.owner.cursor()
    }
    /// Cancels local operation sockets only. Never aborts a SQL transaction,
    /// clears a pending call, releases a lock or changes the private bank.
    pub fn request_control(&self) -> RequestControl {
        self.control.clone()
    }
    /// Every operation has joined before a public method returns. Consuming this
    /// driver transfers the SAME owner, including pending/poisoned/parked state.
    pub fn into_owner(self) -> Owner {
        self.owner
    }
    pub fn execute(
        &mut self,
        cursor: Cursor,
        call: &Call,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
        budget: Duration,
    ) -> Result<Run<'_>> {
        self.run(cursor, drive::Start::Call(call), material, fetched, budget)
    }
    /// Continue a parked statement, or retry the same client's already durable
    /// acquisition. Pending controls use continue_pending or their exact Call.
    pub fn resume(
        &mut self,
        cursor: Cursor,
        client: [u8; 32],
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
        budget: Duration,
    ) -> Result<Run<'_>> {
        self.run(
            cursor,
            drive::Start::Resume(client),
            material,
            fetched,
            budget,
        )
    }
    /// The owner application resumes its ONE original durable global flight.
    /// No replacement client/sequence/SQL/q/header/catalog may enter this call.
    pub fn continue_pending(
        &mut self,
        cursor: Cursor,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
        budget: Duration,
    ) -> Result<Run<'_>> {
        self.run(cursor, drive::Start::Pending, material, fetched, budget)
    }
    pub fn acknowledge(&mut self, cursor: Cursor) -> Result<Cursor> {
        self.owner.acknowledge(cursor)
    }
    fn run(
        &mut self,
        cursor: Cursor,
        start: drive::Start<'_>,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
        budget: Duration,
    ) -> Result<Run<'_>> {
        self.owner.require(cursor)?;
        if budget.is_zero() || budget > peer_runtime::finality::PROGRESS_OPERATION_BUDGET {
            return Err(Error::Shape);
        }
        let operation = Operation::new(
            &self.config,
            &self.owner.pins.binding,
            &self.control,
            budget,
        )?;
        // Return only owned scheduling metadata until ALL operation workers and
        // the watcher have joined. A terminal borrow cannot escape prematurely.
        let result = self.drive(cursor, start, material, fetched, &operation);
        let finished = operation.finish();
        let state = match (result, finished) {
            (Ok(state), Ok(())) => state,
            (Err(e), _) => return Err(e),
            (Ok(_), Err(e)) => return Err(e.into()),
        };
        let cursor = self.owner.cursor()?;
        match state {
            drive::State::Waiting => Ok(Run::Waiting { cursor }),
            drive::State::Pending(reason) => Ok(Run::Pending { cursor, reason }),
            drive::State::Terminal => {
                if self.owner.phase != Phase::Terminal {
                    return Err(Error::Phase);
                }
                let outcome = self.owner.outcome(cursor)?.ok_or(Error::Phase)?;
                if matches!(outcome, Outcome::Waiting) {
                    return Err(Error::Phase);
                }
                Ok(Run::Terminal { cursor, outcome })
            }
        }
    }
}
