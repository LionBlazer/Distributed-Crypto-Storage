//! Ready-only backup and actual private-opening + proof revalidation on restore.
use super::*;
use crate::owner_state::{
    self, EncryptedOwnerState, OwnerStateAuthority, OwnerStateIdentity, Pins, Role,
};
const MAGIC: &[u8; 8] = b"BFVES001";

impl OwnerProofEpoch<'_> {
    /// Exclusive jobs prevent an overlapping backup borrow. Awaiting/cancelled epochs reject.
    pub fn backup_ready_state(
        &self,
        setup: &PublicSetup,
        identity: &OwnerStateIdentity,
        authority: &OwnerStateAuthority,
    ) -> Result<EncryptedOwnerState> {
        key_material::check_original(self.anchor, setup)?;
        if self.stage != ProofEpochStage::Ready {
            return Err(Error::ProofEpochStage);
        }
        let frame = self.key_evidence()?.as_bytes();
        let checked = setup.verify_key_transform(&self.anchor.public, frame)?;
        if checked.statement().public_values() != self.material.statement.public_values() {
            return Err(Error::BindingMismatch);
        }
        let mut plain = Zeroizing::new(Vec::with_capacity(48 + frame.len()));
        plain.extend_from_slice(MAGIC);
        for word in self.material.output_salt.iter() {
            plain.extend_from_slice(&word.to_le_bytes());
        }
        plain.extend_from_slice(
            &u32::try_from(frame.len())
                .map_err(|_| Error::WireLimit)?
                .to_le_bytes(),
        );
        plain.extend_from_slice(&[0; 4]);
        plain.extend_from_slice(frame);
        owner_state::seal(
            Pins {
                role: Role::Epoch,
                setup,
                identity,
                anchor: Some(&self.anchor.public),
                key: Some(&self.material.statement),
            },
            authority,
            &plain,
        )
    }
}
impl<'owner> OwnerKeyAnchor<'owner> {
    /// Recompute Shat from the restored SK, reopen BOTH roots, compare all Key33,
    /// and verify the exact stored genuine proof before constructing Ready.
    pub fn restore_ready_epoch<'anchor>(
        &'anchor self,
        setup: &PublicSetup,
        expected: &bfv_key_transform::Statement,
        identity: &OwnerStateIdentity,
        authority: &OwnerStateAuthority,
        record: &EncryptedOwnerState,
    ) -> Result<OwnerProofEpoch<'anchor>> {
        key_material::check_original(self, setup)?;
        let plain = owner_state::open(
            Pins {
                role: Role::Epoch,
                setup,
                identity,
                anchor: Some(&self.public),
                key: Some(expected),
            },
            authority,
            record,
        )?;
        if plain.len() < 48 || &plain[..8] != MAGIC || plain[44..48] != [0; 4] {
            return Err(Error::InvalidShape);
        }
        let len = u32::from_le_bytes(plain[40..44].try_into().unwrap()) as usize;
        if len != plain.len() - 48
            || !(bfv_key_transform::HEADER_BYTES
                ..=bfv_key_transform::HEADER_BYTES + bfv_key_transform::MAX_PROOF_BYTES)
                .contains(&len)
        {
            return Err(Error::InvalidShape);
        }
        let salt = owner_state::salt(&plain[8..40])?;
        let mut material = KeyMaterial::with_output_salt(self, salt)?;
        if material.statement.public_values() != expected.public_values() {
            return Err(Error::BindingMismatch);
        }
        setup.require_key_transform_anchor(&self.public)?;
        let (evidence, checked) = bfv_key_transform::Evidence::verify_owned_with_transform(
            self.public.full_setup_id,
            &self.public.expected(),
            plain[48..].to_vec(),
        )
        .map_err(backend)?;
        if checked.statement().public_values() != expected.public_values() {
            return Err(Error::BindingMismatch);
        }
        material.witness = None;
        Ok(OwnerProofEpoch {
            anchor: self,
            parameters: setup.parameters.clone(),
            material,
            key_evidence: Some(evidence),
            stage: ProofEpochStage::Ready,
        })
    }
}
