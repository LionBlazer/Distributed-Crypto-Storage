//! Closed mathematical join: original Stmt96 -> Cw -> original QueryCt, same DATA Cs.
//! Neither component verifies Word history, DATA admission, key authorization or SQL.
use super::{Expected as MaskExpected, backend, wire, writer};
use crate::Val;
use bfv_ciphertext_formation::gold::{self, data};
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
type Result<T> = core::result::Result<T, Error>;

fn profile() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/research/WordStmt96-QueryMask-OriginalQueryFormation/v1/no-admission");
    h.update(super::profile());
    h.update(data::profile_digest());
    h.update(b"literal-ordered-pair/full-DATA-Expected/same-Cs-and-context/full-Stmt-root/nonzero-original-nonce/acyclic-Cw-context/two-independent-native-verifiers");
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
        Ok(Self { mask, formation })
    }
}

/// Two independently framed, UNVERIFIED mathematical proofs. No accepted flag.
pub(super) struct Evidence {
    mask: Vec<u8>,
    formation: Vec<u8>,
}
pub(super) fn produce(
    expected: &Expected,
    opening: writer::Opening,
    secret: gold::SecretOpening,
) -> Result<Evidence> {
    let prepared = data::Prepared::new(
        &expected.formation,
        opening.formation_opening(&expected.mask)?,
        secret,
    )?;
    let mask = backend::ProverSetup::new()?.produce(&expected.mask, opening)?;
    let formation = data::prove(&expected.formation, prepared)?.into_bytes();
    Ok(Evidence { mask, formation })
}

/// Both independent native verifiers are mandatory on EVERY receiving call.
/// Only these two mathematical relations are checked, not DATA/Word/freshness/SQL.
pub(super) fn verify(expected: &Expected, evidence: &Evidence) -> Result<()> {
    if evidence.mask.is_empty()
        || evidence.mask.len() > wire::MAX_FRAME
        || evidence.formation.is_empty()
        || evidence.formation.len() > data::MAX_EVIDENCE_BYTES
    {
        return Err(Error::Resource);
    }
    backend::verify(&expected.mask, &evidence.mask)?;
    data::verify(&expected.formation, &evidence.formation)?;
    Ok(())
}
