//! Bounded independent shard reads, sharing query-local executor admission.
use super::*;
use crate::proof::ProofRequests;

impl Session {
    pub(super) fn read_shards<T: Send>(
        &self,
        read: impl Fn(usize, &ProofRequests) -> Result<T> + Sync,
    ) -> Result<Vec<T>> {
        const WORKERS: usize = 2;
        let requests = ProofRequests::default();
        let mut completed = Vec::new();
        for first in (0..self.data.shards.len()).step_by(WORKERS) {
            let batch = std::thread::scope(|scope| {
                let mut workers = Vec::new();
                for slot in first..(first + WORKERS).min(self.data.shards.len()) {
                    let read = &read;
                    let requests = &requests;
                    workers.push(
                        std::thread::Builder::new()
                            .name("dcs-read-shard".into())
                            .spawn_scoped(scope, move || read(slot, requests))?,
                    );
                }
                let results: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
                results
                    .into_iter()
                    .map(|result| result.map_err(|_| protocol("Read worker failed"))?)
                    .collect::<Result<Vec<_>>>()
            })?;
            completed.extend(batch);
        }
        Ok(completed)
    }
}
