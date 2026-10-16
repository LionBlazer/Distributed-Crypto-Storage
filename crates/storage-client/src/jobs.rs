//! Bounded owner-side preparation shared by shard operations and typed byte blocks.
use crate::{Error, Result};

const WORKERS: usize = 2;

pub(crate) fn run<T: Send>(
    count: usize,
    job: impl Fn(usize) -> Result<T> + Sync,
) -> Result<Vec<T>> {
    let mut completed = Vec::with_capacity(count);
    for first in (0..count).step_by(WORKERS) {
        let batch = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            let mut spawn_error = None;
            let job = &job;
            for slot in first..(first + WORKERS).min(count) {
                match std::thread::Builder::new()
                    .name("dcs-owner-job".into())
                    .spawn_scoped(scope, move || job(slot))
                {
                    Ok(worker) => workers.push(worker),
                    Err(error) => {
                        spawn_error = Some(error);
                        break;
                    }
                }
            }
            // Join every admitted worker before inspecting any failure, including
            // spawn failures. No proof work or local staging escapes an error.
            let results: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
            if let Some(error) = spawn_error {
                return Err(Error::from(error));
            }
            results
                .into_iter()
                .map(|result| {
                    result.map_err(|_| Error::Cryptography("Owner worker failed".into()))?
                })
                .collect::<Result<Vec<_>>>()
        })?;
        completed.extend(batch);
    }
    Ok(completed)
}
