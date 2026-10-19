//! In-memory Source key/salt backups. No file, Vault, network or admission state.
mod codec;

use super::{FetchedSource, SourceOwner, cryptography, invalid};
use compact_store::Owner;
use p3_field::PrimeField64;
use registry200_proof::{Val, source};
use zeroize::Zeroizing;

/// Caller-custodied high-entropy wrapping key, distinct from the stored Source key.
/// No password KDF, OS keystore, adjacent key file or durable custody is selected.
///
/// ```compile_fail
/// use storage_client::private_predicate::SourceStateAuthority;
/// fn needs_clone<T: Clone>() {} fn forbidden() { needs_clone::<SourceStateAuthority>(); }
/// ```
/// ```compile_fail
/// use storage_client::private_predicate::SourceStateAuthority;
/// fn needs_debug<T: core::fmt::Debug>() {} fn forbidden() { needs_debug::<SourceStateAuthority>(); }
/// ```
/// ```compile_fail
/// use storage_client::private_predicate::SourceStateAuthority;
/// fn needs_serde<T: serde::Serialize>() {} fn forbidden() { needs_serde::<SourceStateAuthority>(); }
/// ```
pub struct SourceStateAuthority(Zeroizing<[u8; 32]>);
impl SourceStateAuthority {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }
}

/// Independent saved record identity and canonical public Ckey, never labels
/// adopted from a record. Full snapshot pins come from the caller's FetchedSource.
/// Ckey covers database/domain/key/salt, not a current or agreed head.
pub struct SourceStateIdentity {
    record_id: [u8; 32],
    key_commitment: [u8; 32],
}
impl SourceStateIdentity {
    pub fn new(record_id: [u8; 32], key_commitment: [u8; 32]) -> crate::Result<Self> {
        let _ = source::statement::decode_digest(key_commitment).map_err(cryptography)?;
        Ok(Self {
            record_id,
            key_commitment,
        })
    }
}

/// Ciphertext-only fixed record. Parsing checks bounded canonical grammar, not
/// authentication, Source proof, custody, freshness or a recoverable Vault phase.
///
/// ```compile_fail
/// use storage_client::private_predicate::EncryptedSourceState;
/// fn needs_clone<T: Clone>() {} fn forbidden() { needs_clone::<EncryptedSourceState>(); }
/// ```
/// ```compile_fail
/// use storage_client::private_predicate::EncryptedSourceState;
/// fn needs_debug<T: core::fmt::Debug>() {} fn forbidden() { needs_debug::<EncryptedSourceState>(); }
/// ```
/// ```compile_fail
/// use storage_client::private_predicate::EncryptedSourceState;
/// fn needs_serde<T: serde::Serialize>() {} fn forbidden() { needs_serde::<EncryptedSourceState>(); }
/// ```
pub struct EncryptedSourceState {
    bytes: Vec<u8>,
}
impl EncryptedSourceState {
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        codec::validate(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub const SOURCE_STATE_HEADER_BYTES: usize = codec::HEADER;
pub const SOURCE_STATE_BYTES: usize = codec::RECORD;

impl SourceOwner {
    /// Audit/decrypt the actual independently pinned in-memory data/index before
    /// encrypting the existing key and ORIGINAL Ckey salt. Returns ciphertext in
    /// memory only. No filesystem, OS-vault, credential or network access occurs.
    /// No plaintext DATA, query mask, per-query opening salt, Registry or
    /// completion bank is saved.
    pub fn backup_private_state(
        &self,
        identity: &SourceStateIdentity,
        fetched: FetchedSource<'_>,
        authority: &SourceStateAuthority,
    ) -> crate::Result<EncryptedSourceState> {
        let pins = codec::Pins::new(identity, fetched.object, fetched.heads)?;
        if self.key_salt.iter().any(|v| *v >= Val::ORDER_U64) {
            return Err(invalid("Noncanonical Source state salt"));
        }
        self.require_state_source(
            identity,
            FetchedSource {
                object: fetched.object,
                bundle: fetched.bundle,
                heads: fetched.heads,
            },
        )?;
        let mut plain = Zeroizing::new([0; codec::PRIVATE]);
        plain[..8].copy_from_slice(codec::PRIVATE_MAGIC);
        plain[8..40].copy_from_slice(self.key.as_ref());
        for (i, value) in self.key_salt.iter().enumerate() {
            plain[40 + 8 * i..48 + 8 * i].copy_from_slice(&value.to_le_bytes());
        }
        plain[72..104].copy_from_slice(fetched.heads.table_id().as_bytes());
        codec::seal(pins, authority, &plain)
    }

    /// Authenticate exact independent snapshot pins and restore the original
    /// caller-held key/salt without the fresh-salt factory. The private candidate
    /// returns only after actual full load/AEAD/index/Ckey validation succeeds.
    /// Repetition and old valid backups remain possible: no anti-rollback, fresh
    /// head, SQL, lock, phase promotion or lost-ACK policy is provided.
    ///
    /// ```compile_fail
    /// use storage_client::private_predicate::SourceOwner;
    /// fn forbidden(owner: SourceOwner) { let _ = owner.key; }
    /// ```
    pub fn restore_private_state(
        identity: &SourceStateIdentity,
        fetched: FetchedSource<'_>,
        authority: &SourceStateAuthority,
        record: &EncryptedSourceState,
    ) -> crate::Result<Self> {
        let pins = codec::Pins::new(identity, fetched.object, fetched.heads)?;
        let plain = codec::open(pins, authority, record)?;
        let SourceOpening { key, key_salt } =
            private_opening(&plain, fetched.heads.table_id().as_bytes())?;
        let candidate = Self {
            sealer: Owner::from_key(
                fetched.heads.data().database(),
                fetched.heads.data().key_domain(),
                Zeroizing::new(*key),
            ),
            key,
            key_salt,
        };
        candidate.require_state_source(identity, fetched)?;
        Ok(candidate)
    }

    fn require_state_source(
        &self,
        identity: &SourceStateIdentity,
        fetched: FetchedSource<'_>,
    ) -> crate::Result<()> {
        let loaded = self.load(fetched)?;
        if source::statement::encode_digest(loaded.draft.key_commitment) != identity.key_commitment
        {
            return Err(invalid(
                "Source state Ckey differs from the independent pin",
            ));
        }
        // Complete loaded plaintext/originals drop here, before backup returns.
        // Native scratch, compiler temporaries and caller copies have no erasure promise.
        Ok(())
    }
}

struct SourceOpening {
    key: Zeroizing<[u8; 32]>,
    key_salt: Zeroizing<[u64; 4]>,
}

fn private_opening(plain: &[u8; codec::PRIVATE], table: &[u8; 32]) -> crate::Result<SourceOpening> {
    if &plain[..8] != codec::PRIVATE_MAGIC || &plain[72..104] != table {
        return Err(invalid("Source state private identity mismatch"));
    }
    let key = Zeroizing::new(<[u8; 32]>::try_from(&plain[8..40]).unwrap());
    let key_salt: Zeroizing<[u64; 4]> = Zeroizing::new(core::array::from_fn(|i| {
        u64::from_le_bytes(plain[40 + 8 * i..48 + 8 * i].try_into().unwrap())
    }));
    if key_salt.iter().any(|v| *v >= Val::ORDER_U64) {
        return Err(invalid("Noncanonical Source state salt"));
    }
    Ok(SourceOpening { key, key_salt })
}

#[cfg(test)]
mod tests;
