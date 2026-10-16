//! Bounded owner-side preparation shared by shard operations and typed byte blocks.
//! Tasks move into their worker, so single-use preparation state needs no shared mutation.
use crate::{Error, Result};

const WORKERS: usize = 2;

pub(crate) fn run<I: Send, T: Send>(
    tasks: impl IntoIterator<Item = I>,
    job: impl Fn(I) -> Result<T> + Sync,
) -> Result<Vec<T>> {
    let mut tasks = tasks.into_iter().peekable();
    let mut completed = Vec::with_capacity(tasks.size_hint().0);
    while tasks.peek().is_some() {
        let batch = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            let mut spawn_error = None;
            let job = &job;
            for task in tasks.by_ref().take(WORKERS) {
                match std::thread::Builder::new()
                    .name("dcs-owner-job".into())
                    .spawn_scoped(scope, move || job(task))
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
