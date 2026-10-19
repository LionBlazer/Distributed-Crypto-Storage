//! Private anchor opening custody, lexical under the restored Owner.
use super::*;
use crate::owner_state::{
    self, EncryptedOwnerState, OwnerStateAuthority, OwnerStateIdentity, Pins, Role,
};
const MAGIC: &[u8; 8] = b"BFVAS001";

impl OwnerKeyAnchor<'_> {
    pub fn backup_private_state(
        &self,
        setup: &PublicSetup,
        identity: &OwnerStateIdentity,
        authority: &OwnerStateAuthority,
    ) -> Result<EncryptedOwnerState> {
        owner_state::require_owner(self.owner, setup)?;
        if self.public.scope() != &identity.scope {
            return Err(Error::BindingMismatch);
        }
        // Reopen the actual commitment, even though this handle normally came from the factory.
        let coefficients = secret_coefficients(self.owner)?;
        let root = bfv_key_transform::input_commitment(
            &self.public.descriptor(),
            &coefficients,
            *self.input_salt,
        )
        .map_err(backend)?;
        if root != self.public.coefficients {
            return Err(Error::BindingMismatch);
        }
        let mut plain = Zeroizing::new(Vec::with_capacity(48));
        plain.extend_from_slice(MAGIC);
        plain.extend_from_slice(&[0; 8]);
        for word in self.input_salt.iter() {
            plain.extend_from_slice(&word.to_le_bytes());
        }
        owner_state::seal(
            Pins {
                role: Role::Anchor,
                setup,
                identity,
                anchor: Some(&self.public),
                key: None,
            },
            authority,
            &plain,
        )
    }
}
impl Owner {
    /// Restore this Owner's exact independently pinned input commitment. Decoded peer
    /// anchor claims must not replace the owner's authentic pin.
    pub fn restore_key_anchor<'owner>(
        &'owner self,
        setup: &PublicSetup,
        expected: &BfvKeyAnchor,
        identity: &OwnerStateIdentity,
        authority: &OwnerStateAuthority,
        record: &EncryptedOwnerState,
    ) -> Result<OwnerKeyAnchor<'owner>> {
        owner_state::require_owner(self, setup)?;
        let plain = owner_state::open(
            Pins {
                role: Role::Anchor,
                setup,
                identity,
                anchor: Some(expected),
                key: None,
            },
            authority,
            record,
        )?;
        if plain.len() != 48 || &plain[..8] != MAGIC || plain[8..16] != [0; 8] {
            return Err(Error::InvalidShape);
        }
        let input_salt = owner_state::salt(&plain[16..48])?;
        let coefficients = secret_coefficients(self)?;
        let root =
            bfv_key_transform::input_commitment(&expected.descriptor(), &coefficients, *input_salt)
                .map_err(backend)?;
        if root != expected.coefficients {
            return Err(Error::BindingMismatch);
        }
        Ok(OwnerKeyAnchor {
            owner: self,
            public: expected.clone(),
            input_salt,
        })
    }
}
