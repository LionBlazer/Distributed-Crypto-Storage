//! Fixed Owner phase machine. No private result is inferred from transport.
use super::*;
use std::{
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
pub(super) enum Start<'a> {
    Call(&'a Call),
    Resume([u8; 32]),
    Pending,
}
pub(super) enum State {
    Waiting,
    Pending(io::ErrorKind),
    Terminal,
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Io(io::Error::other("Owner clock precedes UNIX epoch")))
}
/// Compare the original independent logical call, including its bound exact SQL
/// digest, without deriving a new tx from a completed Begin/End's changed bank.
pub(super) fn matches_call(pins: &Pins, call: &Call, saved: RawCall) -> bool {
    pins.clients
        .get(saved.slot)
        .is_some_and(|route| same_call(route, &pins.id, call, saved))
}
pub(super) fn same_call(
    route: &ClientBinding,
    pins_id: &[u8; 32],
    call: &Call,
    saved: RawCall,
) -> bool {
    route.id == call.client
        && call.sequence == saved.sequence
        && call.kind == saved.kind
        && saved.digest
            == hash(&[
                b"DCS/Progress-owner/bound-private-call/v1",
                pins_id,
                &call.digest,
                &call.client,
                &call.sequence.to_le_bytes(),
            ])
}

pub(super) fn same_acquisition(route: &ClientBinding, client: [u8; 32], saved: RawCall) -> bool {
    route.id == client && saved.kind == Kind::Acquire
}

impl Driver {
    pub(super) fn drive(
        &mut self,
        cursor: Cursor,
        start: Start<'_>,
        material: &Material<'_>,
        fetched: FetchedSource<'_>,
        operation: &Operation,
    ) -> Result<State> {
        if let Err(reason) = operation.check() {
            return Ok(State::Pending(reason));
        }
        #[cfg(test)]
        let drive_started = std::time::Instant::now();
        let original = self.owner.phase == Phase::Submitted;
        if self.owner.phase == Phase::Idle {
            #[cfg(test)]
            let prepare_started = std::time::Instant::now();
            let prepared = match start {
                Start::Call(call) => self.owner.prepare(cursor, call, material, again(&fetched)),
                Start::Resume(client) => {
                    self.owner.resume(cursor, client, material, again(&fetched))
                }
                Start::Pending => return Err(Error::Phase),
            };
            #[cfg(test)]
            eprintln!(
                "progress_driver phase=prepare_done duration_ms={}",
                prepare_started.elapsed().as_millis()
            );
            match prepared {
                Ok(Preparation::Waiting(_)) => return Ok(State::Waiting),
                Ok(Preparation::Ready(_)) => {}
                Err(Error::Busy) => return Ok(State::Pending(io::ErrorKind::WouldBlock)),
                Err(e) => return Err(e),
            }
        } else {
            let saved = self.owner.book.flight.ok_or(Error::Phase)?;
            match start {
                Start::Call(call) if !matches_call(&self.owner.pins, call, saved) => {
                    return Err(Error::Busy);
                }
                Start::Resume(client)
                    if !same_acquisition(&self.owner.pins.clients[saved.slot], client, saved) =>
                {
                    return Err(Error::Busy);
                }
                _ => {}
            }
            if self.owner.attempt.as_ref().ok_or(Error::Phase)?.custody
                != material.fingerprint(&self.owner.pins)?
            {
                return Err(Error::Pins);
            }
        }
        if self.owner.phase == Phase::Terminal {
            return Ok(State::Terminal);
        }
        if let Err(reason) = operation.check() {
            return Ok(State::Pending(reason));
        }
        // Scoped native math is never a Driver field or persisted authority.
        // Returning Pending/error drops it; later Submitted retries are cold.
        let mut recording_scope = RecordingScope::default();
        let mut recorded_submission = None;
        if self.owner.phase == Phase::Prepared {
            // Checked math is operation-local only; this is never a durable
            // verified cache. Cold Prepared recovery genuinely runs Work again.
            let work = self.owner.work(self.owner.cursor()?, material)?;
            let computed = match work {
                Some(work) => {
                    #[cfg(test)]
                    let compute_started = std::time::Instant::now();
                    #[cfg(test)]
                    eprintln!("progress_driver phase=Work_compute_start");
                    let result = work.compute_recorded(&operation.remote, &mut recording_scope);
                    #[cfg(test)]
                    eprintln!(
                        "progress_driver phase=Work_compute_end duration_ms={} ok={}",
                        compute_started.elapsed().as_millis(),
                        result.is_ok()
                    );
                    match result {
                        Ok(c) => Some(c),
                        Err(Error::Busy) => return Ok(State::Pending(io::ErrorKind::WouldBlock)),
                        Err(Error::Io(e)) => {
                            return Ok(State::Pending(operation.check().err().unwrap_or(e.kind())));
                        }
                        Err(e) => return Err(e),
                    }
                }
                None => None,
            };
            if let Err(reason) = operation.check() {
                return Ok(State::Pending(reason));
            }
            #[cfg(test)]
            let proposal_started = std::time::Instant::now();
            let mut proposal = {
                let computed_ref = computed.as_ref().map(ComputedRef::Live);
                self.owner
                    .proposal(self.owner.cursor()?, computed_ref.as_ref(), &self.signer)?
            };
            // Retain exact Body and advancing nonce. Invalid time waits for a
            // genuine timestamp; neither future time nor an easier target is used.
            proposal.header = Some(loop {
                if let Err(reason) = operation.check() {
                    return Ok(State::Pending(reason));
                }
                let clock = now()?;
                match self
                    .owner
                    .history
                    .candidate_header(&proposal.body, clock, clock)
                {
                    Ok(header) => break header,
                    Err(registry200_finality::progress::Error::Journal(
                        version_journal::Error::InvalidTimestamp,
                    )) => thread::park_timeout(Duration::from_millis(50)),
                    Err(e) => return Err(crypto(e)),
                }
            });
            let mut remaining = self.config.mining_attempts;
            let mut mined = false;
            while remaining != 0 {
                if let Err(reason) = operation.check() {
                    return Ok(State::Pending(reason));
                }
                let chunk = remaining.min(4096);
                let header = proposal.header.as_mut().ok_or(Error::Phase)?;
                match header.mine(chunk) {
                    Ok(_) => {
                        mined = true;
                        break;
                    }
                    Err(version_journal::Error::MiningExhausted) => remaining -= chunk,
                    Err(e) => return Err(crypto(e)),
                }
            }
            if !mined {
                return Err(Error::Cryptography);
            }
            if let Err(reason) = operation.check() {
                return Ok(State::Pending(reason));
            }
            match computed {
                Some(computed) => {
                    recorded_submission = Some(self.owner.publish_recorded_proposal(
                        proposal,
                        computed,
                        now()?,
                    )?)
                }
                None => {
                    self.owner.publish_proposal(proposal, None, now()?)?;
                }
            }
            #[cfg(test)]
            eprintln!(
                "progress_driver phase=proposal_Submit_fsync_done duration_ms={}",
                proposal_started.elapsed().as_millis()
            );
        }
        if let Err(reason) = operation.check() {
            return Ok(State::Pending(reason));
        }
        let cursor = self.owner.cursor()?;
        let saved = self.owner.pending_submission(cursor)?.ok_or(Error::Phase)?;
        // This round holds no native permit/private bank or store lock. It only
        // schedules bounded public bytes and checks actual weighted signatures.
        let Some(checkpoint) = self.network_round(operation, saved.block(), original)? else {
            return Ok(State::Pending(
                operation.check().err().unwrap_or(io::ErrorKind::WouldBlock),
            ));
        };
        if let Err(reason) = operation.check() {
            return Ok(State::Pending(reason));
        }
        #[cfg(test)]
        let complete_started = std::time::Instant::now();
        #[cfg(test)]
        let completion_path = if recorded_submission.is_some() {
            "original_native_scoped"
        } else {
            "full_cold"
        };
        #[cfg(test)]
        if let Some(frame) = recorded_submission.as_mut() {
            super::tests::reject_substituted_live_frame(&self.owner, frame, material);
        }
        loop {
            if let Err(reason) = operation.check() {
                return Ok(State::Pending(reason));
            }
            let result = if recorded_submission.is_some() {
                self.owner.complete_recorded(
                    cursor,
                    &checkpoint,
                    &mut recorded_submission,
                    material,
                    again(&fetched),
                )
            } else {
                self.owner
                    .complete(cursor, &checkpoint, material, again(&fetched))
                    .map(|_| ())
            };
            match result {
                Ok(_) => {
                    #[cfg(test)]
                    eprintln!(
                        "progress_driver phase=actual_private_completion_done path={completion_path}"
                    );
                    break;
                }
                Err(Error::Busy) => {
                    #[cfg(test)]
                    let wait_started = std::time::Instant::now();
                    thread::park_timeout(Duration::from_millis(50));
                    #[cfg(test)]
                    eprintln!(
                        "progress_driver phase=complete_gate_Busy_wait duration_ms={}",
                        wait_started.elapsed().as_millis()
                    );
                }
                Err(e) => return Err(e),
            }
        }
        if let Err(reason) = operation.check() {
            return Ok(State::Pending(reason));
        }
        #[cfg(test)]
        eprintln!(
            "progress_driver phase=private_complete_fsync_done duration_ms={} drive_elapsed_ms={}",
            complete_started.elapsed().as_millis(),
            drive_started.elapsed().as_millis()
        );
        // The status was opened and the bank fsynced by actual Owner.complete.
        // No enum from a peer or native control builder supplies this branch.
        match self.owner.outcome(self.owner.cursor()?)? {
            Some(Outcome::Waiting) => Ok(State::Waiting),
            Some(_) => Ok(State::Terminal),
            None => Err(Error::Phase),
        }
    }
}
