//! Closed mathematical join: original Stmt96 -> Cw -> original QueryCt, same DATA Cs.
//! One fused proof; no Word history, DATA admission, key authorization or SQL.
use super::{Expected as MaskExpected, backend, writer};
use crate::Val;
use bfv_ciphertext_formation::gold::{self, data, query};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};

#[cfg(test)]
#[path = "formation_tests.rs"]
mod tests;

#[derive(Debug)]
pub(super) enum Error {
    Binding,
    Resource,
    Mask(backend::Error),
    Formation(gold::Error),
}
impl From<backend::Error> for Error {
    fn from(error: backend::Error) -> Self {
        Self::Mask(error)
    }
}
impl From<gold::Error> for Error {
    fn from(error: gold::Error) -> Self {
        Self::Formation(error)
    }
}
pub(super) type Result<T> = core::result::Result<T, Error>;

fn profile() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/research/WordStmt96-QueryMask-OriginalQueryFormation/v3/fused/no-admission");
    h.update(super::profile());
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

/// Public acyclic context: it excludes the Cw root and the proof made from it.
/// The supplied DATA Expected is mathematical metadata, never an admission token.
pub(super) fn encoding_context(
    request: &gold::Request,
    installed: &data::Expected,
    statement: [Val; 4],
) -> Result<[Val; 8]> {
    if request.ciphertexts()[0] != installed.request().ciphertext() {
        return Err(Error::Binding);
    }
    let mut h = Sha512::new();
    h.update(b"DCS/OriginalQueryFormation/acyclic-Cw-context/v1");
    h.update(profile());
    h.update((request.bytes().len() as u64).to_le_bytes());
    h.update(request.bytes());
    h.update(installed.binding());
    feed(&mut h, statement);
    let digest = h.finalize();
    // Eight u32 PUBLIC fields: no truncation of an individual Gold coordinate.
    Ok(core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            digest[4 * i..4 * i + 4]
                .try_into()
                .expect("fixed context word"),
        ))
    }))
}

/// Independently retained original endpoints. Construction performs no verification.
pub(super) struct Expected {
    mask: MaskExpected,
    formation: data::Expected,
    fused: query::Expected,
}
impl Expected {
    pub(super) fn checked(
        request: &gold::Request,
        installed: &data::Expected,
        statement: [Val; 4],
        vector: [Val; 4],
    ) -> Result<Self> {
        let context = encoding_context(request, installed, statement)?;
        let mask = MaskExpected::checked(statement, vector, context, request.nonce())
            .map_err(|_| Error::Binding)?;
        let mut h = Sha512::new();
        h.update(b"DCS/OriginalQueryFormation/complete-association/v1");
        h.update(profile());
        h.update((request.bytes().len() as u64).to_le_bytes());
        h.update(request.bytes());
        h.update(installed.binding());
        feed(&mut h, mask.values());
        let formation = data::Expected::checked(
            data::Request::checked(request.nonce(), request.ciphertexts()[1].to_vec())?,
            h.finalize().into(),
            [context, installed.contexts()[1]],
            [vector, installed.roots()[1]],
        )?;
        let fused = query::Expected::checked(
            &formation,
            statement,
            super::super::header("statement")
                .try_into()
                .map_err(|_| Error::Binding)?,
        )?;
        Ok(Self {
            mask,
            formation: fused.core_expected().clone(),
            fused,
        })
    }
}

/// One distinct UNVERIFIED fused mathematical frame. No accepted flag.
pub(super) struct Evidence {
    formation: Vec<u8>,
}
pub(super) fn produce(
    expected: &Expected,
    opening: writer::Opening,
    secret: gold::SecretOpening,
) -> Result<Evidence> {
    let prepared = opening.into_fused(&expected.mask, &expected.fused, secret)?;
    let formation = query::prove(&expected.fused, prepared)?.into_bytes();
    Ok(Evidence { formation })
}

/// The independently prepared native verifier is mandatory on EVERY receiving call.
/// This mathematical relation supplies no DATA/Word/freshness/SQL authority.
pub(super) fn verify(expected: &Expected, evidence: &Evidence) -> Result<()> {
    verify_bytes(expected, &evidence.formation)
}
pub(super) fn verify_bytes(expected: &Expected, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > query::MAX_EVIDENCE_BYTES {
        return Err(Error::Resource);
    }
    query::verify(&expected.fused, bytes)?;
    Ok(())
}
impl Evidence {
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.formation
    }
}
