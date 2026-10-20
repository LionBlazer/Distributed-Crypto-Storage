//! One process-owned resource gate. Acquisition conveys no proof authority.
use crate::RemoteError;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone)]
pub struct ProofGate(Arc<AtomicBool>);
pub struct ProofPermit(Arc<AtomicBool>);
#[expect(
    clippy::new_without_default,
    reason = "resource ownership must be explicit at process composition"
)]
impl ProofGate {
    /// Create one explicit resource owner. The process composition must create
    /// ONE gate and pass clones to its producer, recorder, replay and services.
    /// This allocates an independent gate; it is not process-global enforcement
    /// and conveys no proof, authorization, finalized head or lock capability.
    /// ```
    /// let owner = peer_runtime::ProofGate::new();
    /// let service = owner.clone();
    /// let work = owner.try_acquire().unwrap();
    /// assert!(service.try_acquire().is_err());
    /// drop(work);
    /// assert!(service.try_acquire().is_ok());
    /// ```
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
    pub fn try_acquire(&self) -> Result<ProofPermit, RemoteError> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RemoteError::Busy)?;
        Ok(ProofPermit(self.0.clone()))
    }
}
impl Drop for ProofPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_clones_share_busy_and_unwind_releases_the_single_owner() {
        let gate = ProofGate::new();
        let another = gate.clone();
        let permit = gate.try_acquire().unwrap();
        assert!(matches!(another.try_acquire(), Err(RemoteError::Busy)));
        drop(permit);
        let joined = std::thread::spawn(move || {
            let _permit = another.try_acquire().unwrap();
            panic!("PUBLIC fixture unwind");
        })
        .join();
        assert!(joined.is_err());
        assert!(gate.try_acquire().is_ok());
    }
}
