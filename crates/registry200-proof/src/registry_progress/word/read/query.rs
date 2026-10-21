//! Exact original DATA/Stmt96/QueryCt association; construction verifies no proof.
use crate::Val;
use bfv_ciphertext_formation::gold::{self, data, query};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug)]
pub enum Error {
    Binding,
    Formation(gold::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Word query association rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<gold::Error> for Error {
    fn from(error: gold::Error) -> Self {
        Self::Formation(error)
    }
}
pub type Result<T> = core::result::Result<T, Error>;

// Original standalone mask encoding identity, shared with its test-only AIR.
pub(crate) const MASK_PROFILE_DOMAIN: &[u8] = b"DCS/research/QueryMaskEncoding/WordStmt96-Cw4112/v1/full4208/526P2/H1024/MAIN649/PP49/PUBLIC33/overwrite8-cap4/reverse256-scale16389-mod65537/high3840zero/all-padding-zero/no-owner-no-formation-no-authority";
pub(crate) fn mask_profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MASK_PROFILE_DOMAIN);
    h.update(super::super::profile_digest());
    h.finalize().into()
}
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/research/WordStmt96-QueryMask-OriginalQueryFormation/v3/fused/no-admission");
    h.update(mask_profile_digest());
    h.update(data::profile_digest());
    h.update(query::profile_digest());
    h.update(b"literal-ordered-pair/full-DATA-Expected/same-Cs-and-context/full-Stmt-root/nonzero-original-nonce/acyclic-Cw-context/one-fused-native-verifier/original-Word-header13");
    h.finalize().into()
}
fn feed(h: &mut Sha512, values: impl IntoIterator<Item = Val>) {
    for value in values {
        h.update(value.as_canonical_u64().to_le_bytes());
    }
}
/// Acyclic PUBLIC Cw context, excluding Cw and its proof. DATA must be the exact
/// first input. The complete DATA association, nonce and both ciphertexts bind it.
pub fn encoding_context(
    request: &gold::Request,
    installed: &data::Expected,
    statement: [Val; 4],
) -> Result<[Val; 8]> {
    if request.ciphertexts()[0] != installed.request().ciphertext() {
        return Err(Error::Binding);
    }
    let mut h = Sha512::new();
    h.update(b"DCS/OriginalQueryFormation/acyclic-Cw-context/v1");
    h.update(profile_digest());
    h.update((request.bytes().len() as u64).to_le_bytes());
    h.update(request.bytes());
    h.update(installed.binding());
    feed(&mut h, statement);
    let digest = h.finalize();
    Ok(core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            digest[4 * i..4 * i + 4]
                .try_into()
                .expect("fixed context word"),
        ))
    }))
}
/// Derive the sole fused query expectation from original ordered endpoints.
/// The returned metadata authenticates neither DATA nor Word. Owners use its
/// core_expected with the normal guarded DATA/Query Prepared constructors.
pub fn expected(
    request: &gold::Request,
    installed: &data::Expected,
    statement: [Val; 4],
    vector: [Val; 4],
) -> Result<query::Expected> {
    let context = encoding_context(request, installed, statement)?;
    let mut h = Sha512::new();
    h.update(b"DCS/OriginalQueryFormation/complete-association/v1");
    h.update(profile_digest());
    h.update((request.bytes().len() as u64).to_le_bytes());
    h.update(request.bytes());
    h.update(installed.binding());
    // Preserve all 33 original mask PUBLIC words in their original order.
    feed(
        &mut h,
        crate::source::statement::words(&mask_profile_digest()),
    );
    feed(&mut h, [Val::from_u32(0x514d_0001)]);
    feed(&mut h, statement);
    feed(&mut h, vector);
    feed(&mut h, context);
    feed(&mut h, crate::source::statement::words(&request.nonce()));
    let formation = data::Expected::checked(
        data::Request::checked(request.nonce(), request.ciphertexts()[1].to_vec())?,
        h.finalize().into(),
        [context, installed.contexts()[1]],
        [vector, installed.roots()[1]],
    )?;
    Ok(query::Expected::checked(
        &formation,
        statement,
        super::super::statement_header(),
    )?)
}
