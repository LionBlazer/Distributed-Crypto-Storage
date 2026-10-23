//! Opt-in bounded observation of real challenger calls for analysis tests.
//! Captures contain public transcript data, never verification authority.
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

const MAX_TRACES: usize = 64;
const MAX_PAYLOAD: usize = 8 * 1024 * 1024;

thread_local! {
    static ACTIVE: RefCell<Option<Arc<Mutex<Store>>>> = const { RefCell::new(None) };
}

/// One actual SHA512 draw. Its preimage is prefix[..prefix_len] followed by
/// tag4, LE64(counter), LE64(retry). Retries are recorded before acceptance.
#[derive(Clone, Debug)]
pub struct Draw {
    prefix_len: usize,
    counter: u64,
    retry: u64,
    digest: [u8; 64],
}
impl Draw {
    pub fn prefix_len(&self) -> usize {
        self.prefix_len
    }
    pub fn counter(&self) -> u64 {
        self.counter
    }
    pub fn retry(&self) -> u64 {
        self.retry
    }
    pub fn digest(&self) -> &[u8; 64] {
        &self.digest
    }
}

/// Exact absorbed prefix bytes and actual draw digests for one challenger fork.
/// Draw preimages share this prefix rather than duplicating it quadratically.
#[derive(Clone, Debug)]
pub struct Trace {
    prefix: Vec<u8>,
    draws: Vec<Draw>,
}
impl Trace {
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }
    pub fn draws(&self) -> &[Draw] {
        &self.draws
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Nested,
    Limit,
}

#[derive(Default)]
struct Store {
    traces: Vec<Trace>,
    payload: usize,
    closed: bool,
    error: Option<Error>,
}
impl Store {
    fn reserve(&mut self, bytes: usize) -> bool {
        if self.closed || self.error.is_some() {
            return false;
        }
        if bytes > MAX_PAYLOAD - self.payload {
            self.error = Some(Error::Limit);
            return false;
        }
        self.payload += bytes;
        true
    }
    fn add(&mut self, trace: Trace) -> Option<usize> {
        if self.traces.len() == MAX_TRACES {
            self.error = Some(Error::Limit);
            return None;
        }
        if !self.reserve(trace.prefix.len() + trace.draws.len() * size_of::<Draw>()) {
            return None;
        }
        let index = self.traces.len();
        self.traces.push(trace);
        Some(index)
    }
}

pub(super) struct Handle {
    store: Arc<Mutex<Store>>,
    index: usize,
}
impl Clone for Handle {
    fn clone(&self) -> Self {
        let mut store = self.store.lock().expect("audit lock");
        // A challenger clone forks its complete history. Later observations
        // cannot append to the original branch's captured transcript.
        let index = if store.closed || store.error.is_some() {
            self.index
        } else {
            let trace = store.traces[self.index].clone();
            store.add(trace).unwrap_or(self.index)
        };
        Self {
            store: self.store.clone(),
            index,
        }
    }
}
impl Handle {
    pub(super) fn observe(&self, bytes: &[u8]) {
        let mut store = self.store.lock().expect("audit lock");
        if store.reserve(bytes.len()) {
            store.traces[self.index].prefix.extend_from_slice(bytes);
        }
    }
    pub(super) fn draw(&self, counter: u64, retry: u64, digest: [u8; 64]) {
        let mut store = self.store.lock().expect("audit lock");
        if store.reserve(size_of::<Draw>()) {
            let trace = &mut store.traces[self.index];
            trace.draws.push(Draw {
                prefix_len: trace.prefix.len(),
                counter,
                retry,
                digest,
            });
        }
    }
}

pub(super) fn begin(domain: &[u8]) -> Option<Handle> {
    ACTIVE.with(|active| {
        let store = active.borrow().clone()?;
        let index = store.lock().expect("audit lock").add(Trace {
            prefix: domain.to_vec(),
            draws: Vec::new(),
        })?;
        Some(Handle { store, index })
    })
}

struct Scope(Arc<Mutex<Store>>);
impl Drop for Scope {
    fn drop(&mut self) {
        self.0.lock().expect("audit lock").closed = true;
        ACTIVE.with(|active| *active.borrow_mut() = None);
    }
}

/// Observe newly constructed challengers on the calling thread and their forks.
/// Construct the actual receiving configuration inside the closure. Existing
/// challengers and newly constructed challengers on unrelated threads are not
/// enrolled. Moving an enrolled challenger between workers preserves its trace.
///
/// This cannot select coins, inject observations, configure a verifier or grant
/// acceptance. Limit errors are reported after the operation finishes; they do
/// not alter its challenges or verification decision. Scope exit, including
/// unwinding, closes recording. Nested captures reject without running their body.
pub fn capture<T>(operation: impl FnOnce() -> T) -> Result<(T, Vec<Trace>), Error> {
    let store = Arc::new(Mutex::new(Store::default()));
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        if active.is_some() {
            return Err(Error::Nested);
        }
        *active = Some(store.clone());
        Ok(())
    })?;
    let scope = Scope(store.clone());
    let value = operation();
    drop(scope);
    let mut store = store.lock().expect("audit lock");
    match store.error {
        Some(error) => Err(error),
        None => Ok((value, core::mem::take(&mut store.traces))),
    }
}

#[cfg(test)]
mod tests;
