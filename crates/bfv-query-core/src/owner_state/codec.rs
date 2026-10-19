//! A fixed public AD header and one bounded encrypted private payload per role.
use super::*;
use crate::{BfvKeyAnchor, Geometry};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, Tag},
};
use p3_field::PrimeField64;
use rand::RngCore;
use sha2::{Digest, Sha512};

pub(super) const HEADER: usize = 624;
const MAGIC: &[u8; 8] = b"BFVOPS01";
const TAG: usize = 16;
const ANCHOR_PLAIN: usize = 48;
const EPOCH_PREFIX: usize = 48;
pub(super) const MAX_RECORD: usize = HEADER
    + EPOCH_PREFIX
    + bfv_key_transform::HEADER_BYTES
    + bfv_key_transform::MAX_PROOF_BYTES
    + TAG;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Owner = 1,
    Anchor = 2,
    Epoch = 3,
}
#[derive(Clone, Copy)]
pub(crate) struct Pins<'a> {
    pub(crate) role: Role,
    pub(crate) setup: &'a PublicSetup,
    pub(crate) identity: &'a OwnerStateIdentity,
    pub(crate) anchor: Option<&'a BfvKeyAnchor>,
    pub(crate) key: Option<&'a bfv_key_transform::Statement>,
}
fn role(raw: u8) -> Result<Role> {
    match raw {
        1 => Ok(Role::Owner),
        2 => Ok(Role::Anchor),
        3 => Ok(Role::Epoch),
        _ => Err(Error::InvalidShape),
    }
}
fn limit(role: Role) -> usize {
    match role {
        Role::Owner => SECRET_BYTES,
        Role::Anchor => ANCHOR_PLAIN,
        Role::Epoch => {
            EPOCH_PREFIX + bfv_key_transform::HEADER_BYTES + bfv_key_transform::MAX_PROOF_BYTES
        }
    }
}
pub(super) fn validate(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_RECORD {
        return Err(Error::WireLimit);
    }
    if bytes.len() < HEADER + TAG
        || &bytes[..8] != MAGIC
        || bytes[8..10] != 1u16.to_le_bytes()
        || bytes[11..16] != [0; 5]
        || bytes[616..624] != [0; 8]
    {
        return Err(Error::InvalidShape);
    }
    let r = role(bytes[10])?;
    let len = u32::from_le_bytes(bytes[612..616].try_into().unwrap()) as usize;
    if len < TAG || len - TAG > limit(r) {
        return Err(Error::WireLimit);
    }
    if bytes.len() != HEADER.checked_add(len).ok_or(Error::WireLimit)? {
        return Err(Error::InvalidShape);
    }
    if matches!(r, Role::Owner | Role::Anchor) && len != limit(r) + TAG {
        return Err(Error::InvalidShape);
    }
    if r == Role::Epoch && len < EPOCH_PREFIX + bfv_key_transform::HEADER_BYTES + TAG {
        return Err(Error::InvalidShape);
    }
    if !matches!(
        u32::from_le_bytes(bytes[84..88].try_into().unwrap()),
        16 | 256
    ) {
        return Err(Error::InvalidShape);
    }
    if r == Role::Owner && bytes[184..588].iter().any(|v| *v != 0)
        || r == Role::Anchor && bytes[324..588].iter().any(|v| *v != 0)
    {
        return Err(Error::InvalidShape);
    }
    // The raw public anchor and full Key33 contain canonical Gold values, never reduced aliases.
    let canonical = |words: &[u8]| {
        words
            .as_chunks::<8>()
            .0
            .iter()
            .all(|w| u64::from_le_bytes(*w) < bfv_hiding_stark::Val::ORDER_U64)
    };
    if r != Role::Owner && (&bytes[184..192] != b"BFVKAC01" || !canonical(&bytes[292..324]))
        || r == Role::Epoch && !canonical(&bytes[324..588])
    {
        return Err(Error::InvalidShape);
    }
    Ok(())
}
fn header(pins: &Pins<'_>, nonce: &[u8], ciphertext_len: usize) -> Result<Vec<u8>> {
    let Pins {
        role,
        setup,
        identity,
        anchor,
        key,
    } = *pins;
    setup.checked_parameters()?;
    let mut h = vec![0; HEADER];
    h[..8].copy_from_slice(MAGIC);
    h[8..10].copy_from_slice(&1u16.to_le_bytes());
    h[10] = role as u8;
    h[16..32].copy_from_slice(&identity.scope.database);
    h[32..48].copy_from_slice(&identity.scope.bfv_key_domain);
    h[48..52].copy_from_slice(&identity.scope.epoch.to_le_bytes());
    h[52..84].copy_from_slice(&identity.record_id);
    let geometry = match setup.geometry {
        Geometry::Rows16 => 16u32,
        Geometry::Rows256 => 256u32,
    };
    h[84..88].copy_from_slice(&geometry.to_le_bytes());
    h[88..120].copy_from_slice(&keyset_id(setup)?);
    h[120..184].copy_from_slice(&Sha512::digest(setup.to_bytes()?));
    match role {
        Role::Owner if anchor.is_none() && key.is_none() => {}
        Role::Anchor | Role::Epoch => {
            let a = anchor.ok_or(Error::BindingMismatch)?;
            if a.scope() != &identity.scope
                || setup.decode_key_anchor_claim(&a.encode_claim()?)? != *a
            {
                return Err(Error::BindingMismatch);
            }
            h[184..324].copy_from_slice(&a.encode_claim()?);
            if role == Role::Epoch {
                let k = key.ok_or(Error::BindingMismatch)?;
                if k.expected.descriptor != a.expected().descriptor
                    || k.expected.coefficients != a.expected().coefficients
                {
                    return Err(Error::BindingMismatch);
                }
                for (i, v) in k.public_values().iter().enumerate() {
                    h[324 + 8 * i..332 + 8 * i]
                        .copy_from_slice(&v.as_canonical_u64().to_le_bytes());
                }
            } else if key.is_some() {
                return Err(Error::BindingMismatch);
            }
        }
        _ => return Err(Error::BindingMismatch),
    }
    if nonce.len() != 24 {
        return Err(Error::InvalidShape);
    }
    h[588..612].copy_from_slice(nonce);
    h[612..616].copy_from_slice(
        &u32::try_from(ciphertext_len)
            .map_err(|_| Error::WireLimit)?
            .to_le_bytes(),
    );
    Ok(h)
}
pub(crate) fn seal(
    pins: Pins<'_>,
    authority: &OwnerStateAuthority,
    plain: &[u8],
) -> Result<EncryptedOwnerState> {
    if plain.len() > limit(pins.role) {
        return Err(Error::WireLimit);
    }
    let mut nonce = [0; 24];
    rand::rng().fill_bytes(&mut nonce);
    let h = header(&pins, &nonce, plain.len() + TAG)?;
    let mut ciphertext = Zeroizing::new(plain.to_vec());
    let cipher =
        XChaCha20Poly1305::new_from_slice(authority.0.as_ref()).map_err(|_| Error::InvalidShape)?;
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &h, &mut ciphertext)
        .map_err(|_| Error::OwnerStateAuthentication)?;
    let mut out = h;
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    validate(&out)?;
    Ok(EncryptedOwnerState { bytes: out })
}
pub(crate) fn open(
    pins: Pins<'_>,
    authority: &OwnerStateAuthority,
    record: &EncryptedOwnerState,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = record.as_bytes();
    validate(bytes)?;
    let expected = header(&pins, &bytes[588..612], bytes.len() - HEADER)?;
    if bytes[..HEADER] != expected {
        return Err(Error::BindingMismatch);
    }
    let end = bytes.len() - TAG;
    let mut plain = Zeroizing::new(bytes[HEADER..end].to_vec());
    let cipher =
        XChaCha20Poly1305::new_from_slice(authority.0.as_ref()).map_err(|_| Error::InvalidShape)?;
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&bytes[588..612]),
            &expected,
            &mut plain,
            Tag::<XChaCha20Poly1305>::from_slice(&bytes[end..]),
        )
        .map_err(|_| Error::OwnerStateAuthentication)?;
    Ok(plain)
}

pub(crate) fn salt(bytes: &[u8]) -> Result<Zeroizing<[u64; 4]>> {
    if bytes.len() != 32 {
        return Err(Error::InvalidShape);
    }
    let salt = Zeroizing::new(core::array::from_fn(|i| {
        u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap())
    }));
    if salt.iter().any(|v| *v >= bfv_hiding_stark::Val::ORDER_U64) {
        return Err(Error::InvalidShape);
    }
    Ok(salt)
}
