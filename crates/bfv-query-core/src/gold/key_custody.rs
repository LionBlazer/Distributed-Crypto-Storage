//! Exact bounded AEAD key custody; independent KeyExpected and Cs reopen are mandatory.
use super::*;
use chacha20poly1305::{Tag, XNonce, aead::AeadInPlace};
use rand::{TryRngCore, rngs::OsRng};
pub(super) const PLAIN_BYTES: usize = N + 3 + 32;
const HEADER: usize = 168;
const TAG: usize = 16;
pub const KEY_RECORD_BYTES: usize = HEADER + PLAIN_BYTES + TAG;
/// Untrusted encrypted key bytes. Parsing is not key authentication or authority.
pub struct EncryptedKey {
    bytes: Vec<u8>,
}
impl EncryptedKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        validate(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
fn validate(bytes: &[u8]) -> Result<()> {
    if bytes.len() != KEY_RECORD_BYTES {
        return Err(Error::Resource);
    }
    if bytes[..8] != *b"GOKCST01"
        || bytes[8..40] != profile_digest()
        || bytes[160..164] != ((PLAIN_BYTES + TAG) as u32).to_le_bytes()
        || bytes[164..168] != [0; 4]
    {
        return Err(Error::Shape);
    }
    Ok(())
}
fn header(expected: &KeyExpected, identity: &CustodyIdentity, nonce: &[u8; 24]) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER);
    h.extend(b"GOKCST01");
    h.extend(profile_digest());
    h.extend(identity.record());
    h.extend(expected.binding());
    h.extend(nonce);
    h.extend(((PLAIN_BYTES + TAG) as u32).to_le_bytes());
    h.extend([0; 4]);
    h
}
pub(super) fn seal(
    expected: &KeyExpected,
    identity: &CustodyIdentity,
    key: &CustodyKey,
    mut plain: Zeroizing<Vec<u8>>,
) -> Result<EncryptedKey> {
    if plain.len() != PLAIN_BYTES {
        return Err(Error::Shape);
    }
    let mut nonce = [0; 24];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| Error::Backend)?;
    let h = header(expected, identity, &nonce);
    let tag = key
        .cipher()?
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &h, &mut plain)
        .map_err(|_| Error::Authentication)?;
    let mut bytes = h;
    bytes.extend_from_slice(&plain);
    bytes.extend(tag);
    validate(&bytes)?;
    Ok(EncryptedKey { bytes })
}
pub(super) fn open(
    expected: &KeyExpected,
    identity: &CustodyIdentity,
    key: &CustodyKey,
    record: &EncryptedKey,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = record.as_bytes();
    validate(bytes)?;
    let nonce: [u8; 24] = bytes[136..160].try_into().map_err(|_| Error::Shape)?;
    let h = header(expected, identity, &nonce);
    if bytes[..HEADER] != h {
        return Err(Error::Binding);
    }
    let mut plain = Zeroizing::new(bytes[HEADER..bytes.len() - TAG].to_vec());
    key.cipher()?
        .decrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &h,
            &mut plain,
            Tag::from_slice(&bytes[bytes.len() - TAG..]),
        )
        .map_err(|_| Error::Authentication)?;
    Ok(plain)
}
