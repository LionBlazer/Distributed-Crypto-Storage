//! Borrowed public relinearization bytes with the complete original setup identity.
use super::{Geometry, PublicSetup, Result, keyset_id};

/// An immutable view of public material already held by one complete setup.
///
/// Its identity includes the original rotation-key bytes as well as parameters,
/// geometry and relinearization bytes. This view does not decode an evaluation
/// key, prove same-secret consistency or authenticate the setup's owner.
pub struct PublicRelinearizationMaterial<'a> {
    setup: &'a PublicSetup,
    keyset_id: [u8; 32],
}

impl PublicSetup {
    /// Borrow the original parameter and relinearization bytes after checking the
    /// existing fixed parameter contract. The full identity uses the unchanged
    /// setup encoder, including rotation keys; no subset container is assembled.
    ///
    /// Callers must independently obtain the expected setup identity from their
    /// authorized owner/application. Matching bytes is not key authorization,
    /// key-switch correctness, a computation proof or a freshness decision.
    pub fn relinearization_material(&self) -> Result<PublicRelinearizationMaterial<'_>> {
        self.checked_parameters()?;
        Ok(PublicRelinearizationMaterial {
            setup: self,
            keyset_id: keyset_id(self)?,
        })
    }
}

impl<'a> PublicRelinearizationMaterial<'a> {
    /// Exact original pinned parameter bytes, borrowed from the complete setup.
    pub fn parameters(&self) -> &'a [u8] {
        &self.setup.parameters
    }

    /// Exact original public key blob, still opaque and borrowed without decoding.
    pub fn relinearization_key(&self) -> &'a [u8] {
        &self.setup.relinearization_key
    }

    /// Existing setup geometry; this does not establish query or source coverage.
    pub fn geometry(&self) -> Geometry {
        self.setup.geometry
    }

    /// Existing SHA256 identity of the complete encoded setup, including rotations.
    /// Equality binds bytes only; an untrusted sender can supply its own setup.
    pub fn keyset_id(&self) -> [u8; 32] {
        self.keyset_id
    }
}
