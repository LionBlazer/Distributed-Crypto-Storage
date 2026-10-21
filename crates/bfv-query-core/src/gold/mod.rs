//! Protected N4096 owner-originated input and conditional arithmetic completion.
//! DATA metadata is not admission; no Source, current head, SQL or security grant.
mod binding;
mod custody;
mod encryption;
mod origin;
mod owner;
#[cfg(test)]
mod tests;
use bfv_ciphertext_formation::gold as lower;
use bfv_hiding_stark::Val;
use bfv_unrelinearized_product as product;
pub use binding::{InputBinding, InputScope, KeyExpected, Parameters};
pub use custody::{
    CustodyIdentity, CustodyKey, EncryptedOrigin, MAX_ORIGIN_BYTES, RestoreExpected,
};
pub use origin::{
    DecryptedProduct, Evaluator, MAX_REQUEST_BYTES, Mask256, OriginatingQuery, PublicRequest,
    UnverifiedProduct,
};
pub use owner::Owner;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;
pub const N: usize = 4096;
pub const Q: [u64; 2] = [1073692673, 1073668097];
pub const T: u64 = 65537;
pub const SCALE: u64 = 16389;
pub(super) const MAX_CT: usize = 128 * 1024;
pub type Result<T> = core::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Binding,
    Resource,
    Authentication,
    Arithmetic,
    Backend,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "protected Gold input rejected {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<lower::Error> for Error {
    fn from(error: lower::Error) -> Self {
        match error {
            lower::Error::Shape | lower::Error::Encoding => Self::Shape,
            lower::Error::Arithmetic => Self::Arithmetic,
            lower::Error::Binding => Self::Binding,
            lower::Error::Resource => Self::Resource,
            _ => Self::Backend,
        }
    }
}
impl From<product::Error> for Error {
    fn from(error: product::Error) -> Self {
        match error {
            product::Error::Shape => Self::Shape,
            product::Error::Arithmetic => Self::Arithmetic,
            product::Error::Binding => Self::Binding,
            product::Error::Resource => Self::Resource,
            product::Error::Backend => Self::Backend,
        }
    }
}
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/Gold-protected-owner/v2/IMPORT-ONLY/ARITHMETIC-UNASSESSED/no-SQL");
    h.update(lower::data::profile_digest());
    h.update(product::profile_digest());
    for n in [N as u64, Q[0], Q[1], T, SCALE, 10] {
        h.update(n.to_le_bytes());
    }
    h.update(b"actualSDK-CBD20/Cs528;typedMask256;exact-original-inputs;OS-seeded-ChaCha20-stream0-error-stream1-A-remask;exact-SDK-phase-preserved;private-custody-equation-reopen-no-reencrypt;full18point-check-before-decrypt4096;no-Source-admission-head-lock-or-security");
    h.finalize().into()
}
pub(super) fn digest64(domain: &[u8], fields: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    for field in fields {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field);
    }
    h.finalize().into()
}
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub(super) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(Error::Resource)?;
        let out = self.bytes.get(self.at..end).ok_or(Error::Shape)?;
        self.at = end;
        Ok(out)
    }
    pub(super) fn array<const L: usize>(&mut self) -> Result<[u8; L]> {
        self.take(L)?.try_into().map_err(|_| Error::Shape)
    }
    pub(super) fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.array()?) as usize)
    }
    pub(super) fn end(self) -> Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Shape)
        }
    }
}
