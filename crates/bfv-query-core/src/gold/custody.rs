//! Bounded owner-private AEAD custody, never a serialized origin-success flag.
use super::*;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce, aead::AeadInPlace};
const HEADER: usize = 296;
const TAG: usize = 16;
pub const MAX_ORIGIN_BYTES: usize = HEADER + 32 + 4 + MAX_REQUEST_BYTES + TAG;
/// Caller-custodied high-entropy key; no key getter or persistence policy.
pub struct CustodyKey(Zeroizing<[u8; 32]>);
impl CustodyKey {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }
    pub(super) fn cipher(&self) -> Result<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(self.0.as_ref()).map_err(|_| Error::Shape)
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct CustodyIdentity {
    record: [u8; 32],
}
impl CustodyIdentity {
    pub fn checked(record: [u8; 32]) -> Result<Self> {
        if record == [0; 32] {
            return Err(Error::Binding);
        }
        Ok(Self { record })
    }
    pub(super) fn record(&self) -> &[u8; 32] {
        &self.record
    }
}
/// Independently retained original request is mandatory for exact Submitted replay.
pub struct RestoreExpected<'a> {
    binding: &'a InputBinding,
    mask: &'a Mask256,
    data: &'a lower::data::Expected,
    original: &'a PublicRequest,
}
impl<'a> RestoreExpected<'a> {
    pub fn checked(
        binding: &'a InputBinding,
        mask: &'a Mask256,
        data: &'a lower::data::Expected,
        original: &'a PublicRequest,
    ) -> Result<Self> {
        if original.binding() != binding
            || original.data_binding() != data.binding()
            || original.data_ciphertext() != data.request().ciphertext()
        {
            return Err(Error::Binding);
        }
        Ok(Self {
            binding,
            mask,
            data,
            original,
        })
    }
}
/// Untrusted bounded ciphertext. Grammar parsing authenticates no origin/math.
pub struct EncryptedOrigin {
    bytes: Vec<u8>,
}
impl EncryptedOrigin {
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
    if bytes.len() < HEADER + TAG + 36 || bytes.len() > MAX_ORIGIN_BYTES {
        return Err(Error::Resource);
    }
    if &bytes[..8] != b"GOCUST01" || bytes[8..40] != profile_digest() || bytes[292..296] != [0; 4] {
        return Err(Error::Shape);
    }
    let length = u32::from_le_bytes(bytes[288..292].try_into().map_err(|_| Error::Shape)?) as usize;
    if !(TAG + 36..=32 + 4 + MAX_REQUEST_BYTES + TAG).contains(&length)
        || HEADER.checked_add(length) != Some(bytes.len())
    {
        return Err(Error::Shape);
    }
    Ok(())
}
fn header(
    owner: &Owner,
    data: &lower::data::Expected,
    request: &PublicRequest,
    identity: &CustodyIdentity,
    nonce: [u8; 24],
    length: usize,
) -> Result<Vec<u8>> {
    owner.require_data(data)?;
    if request.data_binding() != data.binding()
        || request.data_ciphertext() != data.request().ciphertext()
    {
        return Err(Error::Binding);
    }
    let mut h = Vec::with_capacity(HEADER);
    h.extend(b"GOCUST01");
    h.extend(profile_digest());
    h.extend(identity.record);
    h.extend(owner.expected.binding());
    h.extend(data.binding());
    h.extend(digest64(
        b"DCS/Gold-owner/custody-original-request/v1",
        &[request.as_bytes()],
    ));
    h.extend(nonce);
    h.extend(
        u32::try_from(length)
            .map_err(|_| Error::Resource)?
            .to_le_bytes(),
    );
    h.extend([0; 4]);
    if h.len() != HEADER {
        return Err(Error::Shape);
    }
    Ok(h)
}
pub(super) fn payload(mask: &Mask256, request: &PublicRequest) -> Zeroizing<Vec<u8>> {
    let mut p = Zeroizing::new(Vec::with_capacity(36 + request.as_bytes().len()));
    p.extend_from_slice(mask.as_bytes());
    p.extend_from_slice(&(request.as_bytes().len() as u32).to_le_bytes());
    p.extend_from_slice(request.as_bytes());
    p
}
// A fixed owner-only helper; exposed only to sibling tests for repaired-AEAD attacks.
pub(super) fn seal_payload(
    owner: &Owner,
    data: &lower::data::Expected,
    request: &PublicRequest,
    identity: &CustodyIdentity,
    key: &CustodyKey,
    mut plain: Zeroizing<Vec<u8>>,
) -> Result<EncryptedOrigin> {
    if plain.len() > 36 + MAX_REQUEST_BYTES {
        return Err(Error::Resource);
    }
    let nonce = owner::fresh_nonce();
    let h = header(owner, data, request, identity, nonce, plain.len() + TAG)?;
    let cipher = key.cipher()?;
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &h, &mut plain)
        .map_err(|_| Error::Authentication)?;
    let mut bytes = h;
    bytes.extend_from_slice(&plain);
    bytes.extend_from_slice(&tag);
    validate(&bytes)?;
    Ok(EncryptedOrigin { bytes })
}
impl Owner {
    pub fn seal_origin(
        &self,
        query: &OriginatingQuery,
        identity: &CustodyIdentity,
        key: &CustodyKey,
    ) -> Result<EncryptedOrigin> {
        self.require_query(query)?;
        seal_payload(
            self,
            &query.data,
            &query.request,
            identity,
            key,
            payload(&query.mask, &query.request),
        )
    }
    /// Authenticate independent exact pins, then check original private equations.
    /// Neither AEAD nor its stored plaintext carries a reusable verification result.
    pub fn restore_origin(
        &self,
        expected: RestoreExpected<'_>,
        identity: &CustodyIdentity,
        key: &CustodyKey,
        record: &EncryptedOrigin,
    ) -> Result<OriginatingQuery> {
        self.require_data(expected.data)?;
        let bytes = record.as_bytes();
        validate(bytes)?;
        let nonce = bytes[264..288].try_into().map_err(|_| Error::Shape)?;
        let h = header(
            self,
            expected.data,
            expected.original,
            identity,
            nonce,
            bytes.len() - HEADER,
        )?;
        if bytes[..HEADER] != h {
            return Err(Error::Binding);
        }
        let end = bytes.len() - TAG;
        let mut plain = Zeroizing::new(bytes[HEADER..end].to_vec());
        let cipher = key.cipher()?;
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                &h,
                &mut plain,
                Tag::from_slice(&bytes[end..]),
            )
            .map_err(|_| Error::Authentication)?;
        let mut r = Reader::new(&plain);
        let mask = Mask256::new(r.array()?);
        let length = r.u32()?;
        if length > MAX_REQUEST_BYTES {
            return Err(Error::Resource);
        }
        let request = PublicRequest::decode(r.take(length)?)?;
        r.end()?;
        if mask.as_bytes() != expected.mask.as_bytes()
            || request.as_bytes() != expected.original.as_bytes()
            || request.binding() != expected.binding
        {
            return Err(Error::Binding);
        }
        self.check_original_input(&request, &mask, expected.data)?;
        Ok(OriginatingQuery {
            request,
            mask,
            data: expected.data.clone(),
            key_binding: self.expected.binding(),
        })
    }
}
