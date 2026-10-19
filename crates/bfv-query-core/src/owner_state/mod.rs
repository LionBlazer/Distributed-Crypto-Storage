//! Owner-authenticated encrypted backups. No peer, Source or SQL authority.
mod codec;
use crate::key_anchor::{KeyScope, secret_coefficients};
use crate::{Error, Owner, PublicSetup, Result, keyset_id};
pub(crate) use codec::{Pins, Role, open, salt, seal};
use fhe::bfv::SecretKey;
use fhe_traits::DeserializeParametrized;
use prost::Message;
use zeroize::{Zeroize, Zeroizing};

/// Caller-custodied high-entropy wrapping key. No OS store or password KDF is selected.
///
/// ```compile_fail
/// use bfv_query_core::OwnerStateAuthority;
/// fn forbidden<T: Clone>() {} fn check(){forbidden::<OwnerStateAuthority>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerStateAuthority;
/// fn forbidden<T: core::fmt::Debug>() {} fn check(){forbidden::<OwnerStateAuthority>();}
/// ```
pub struct OwnerStateAuthority(Zeroizing<[u8; 32]>);
impl OwnerStateAuthority {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }
}

/// Independently retained public record location and BFV scope, never adopted from a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerStateIdentity {
    pub scope: KeyScope,
    pub record_id: [u8; 32],
}

/// Bounded ciphertext only. Parsing checks grammar, not authentication or freshness.
pub struct EncryptedOwnerState {
    bytes: Vec<u8>,
}
impl EncryptedOwnerState {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        codec::validate(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub const OWNER_STATE_HEADER_BYTES: usize = codec::HEADER;
pub const MAX_OWNER_STATE_BYTES: usize = codec::MAX_RECORD;
const SECRET_MAGIC: &[u8; 8] = b"BFVSK001";
const SECRET_BYTES: usize = 16 + bfv_fixed_geometry::DEGREE;

pub(crate) fn require_owner(owner: &Owner, setup: &PublicSetup) -> Result<()> {
    setup.checked_parameters()?;
    if setup.geometry != owner.geometry || keyset_id(setup)? != owner.keyset_id {
        return Err(Error::BindingMismatch);
    }
    Ok(())
}
impl Owner {
    /// Encrypt the actual Owner secret only after matching the complete original setup.
    /// The caller is responsible for atomic durable custody and rollback protection.
    pub fn backup_private_state(
        &self,
        setup: &PublicSetup,
        identity: &OwnerStateIdentity,
        authority: &OwnerStateAuthority,
    ) -> Result<EncryptedOwnerState> {
        require_owner(self, setup)?;
        let coefficients = secret_coefficients(self)?;
        let mut plain = Zeroizing::new(Vec::with_capacity(SECRET_BYTES));
        plain.extend_from_slice(SECRET_MAGIC);
        plain.extend_from_slice(&(bfv_fixed_geometry::DEGREE as u32).to_le_bytes());
        plain.extend_from_slice(&[0; 4]);
        plain.extend(coefficients.iter().map(|v| (*v + 20) as u8));
        seal(
            Pins {
                role: Role::Owner,
                setup,
                identity,
                anchor: None,
                key: None,
            },
            authority,
            &plain,
        )
    }

    /// Authenticate independent pins, validate all 8192 signed CBD coefficients, then
    /// invoke the SDK deserializer on an internally generated canonical protobuf.
    pub fn restore_private_state(
        setup: &PublicSetup,
        identity: &OwnerStateIdentity,
        authority: &OwnerStateAuthority,
        record: &EncryptedOwnerState,
    ) -> Result<Self> {
        let plain = open(
            Pins {
                role: Role::Owner,
                setup,
                identity,
                anchor: None,
                key: None,
            },
            authority,
            record,
        )?;
        let key = restore_secret(&plain, &setup.checked_parameters()?)?;
        Ok(Self {
            parameters: setup.checked_parameters()?,
            key,
            geometry: setup.geometry,
            keyset_id: keyset_id(setup)?,
        })
    }
}

// The SDK's prost decoder only checks degree. This guard MUST precede its allocation.
fn secret_words(plain: &[u8]) -> Result<Zeroizing<Vec<i64>>> {
    if plain.len() != SECRET_BYTES
        || &plain[..8] != SECRET_MAGIC
        || u32::from_le_bytes(plain[8..12].try_into().unwrap()) as usize
            != bfv_fixed_geometry::DEGREE
        || plain[12..16] != [0; 4]
        || plain[16..].iter().any(|v| *v > 40)
    {
        return Err(Error::InvalidShape);
    }
    let mut words = Zeroizing::new(Vec::with_capacity(bfv_fixed_geometry::DEGREE));
    words.extend(plain[16..].iter().map(|v| i64::from(*v) - 20));
    Ok(words)
}
struct GuardedProto(fhe::proto::bfv::SecretKey);
impl Drop for GuardedProto {
    fn drop(&mut self) {
        self.0.coeffs.zeroize();
    }
}
fn restore_secret(
    plain: &[u8],
    parameters: &std::sync::Arc<fhe::bfv::BfvParameters>,
) -> Result<SecretKey> {
    let mut words = secret_words(plain)?;
    let proto = GuardedProto(fhe::proto::bfv::SecretKey {
        coeffs: core::mem::take(&mut *words),
    });
    let mut wire = Zeroizing::new(Vec::with_capacity(proto.0.encoded_len()));
    proto.0.encode(&mut *wire).map_err(crate::backend)?;
    // No untrusted protobuf is ever passed to the SDK here. Its owned SecretKey zeros on Drop.
    SecretKey::from_bytes(&wire, parameters).map_err(crate::backend)
}

#[cfg(test)]
mod tests;
