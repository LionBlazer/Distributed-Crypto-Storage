//! Result144-to-originals encoding evidence. No ciphertext formation or live SQL admission.
//! Parent model/trace and normal lifecycle proof production are now Core-owned;
//! this legacy selected-originals relation is not the private predicate FHE path.
pub(crate) mod air;
mod compiler;
mod fixture;
mod frame;
mod statement;
#[cfg(test)]
mod tests;
mod trace;
use crate::backend::{Backend, Config, Error, Val, profile_digest};
use crate::opening::selection::encoding::matrix;
use crate::primitive::Kind;
pub(in crate::opening) use compiler::{CommandOpening, CompiledQuery};
pub(in crate::opening) use frame::{Error as WireError, decode_and_verify, encode};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use sha2::{Digest, Sha256};
pub(in crate::opening) use statement::{Expected, Statement};
impl From<WireError> for Error {
    fn from(_: WireError) -> Self {
        Error::Shape
    }
}
fn verify_parent(e: &Expected, parent: Option<&super::CompositeProof>) -> Result<(), Error> {
    e.require_contract()?;
    super::verify(&e.parent, &e.producer, parent.ok_or(Error::Verification)?)
}
pub(in crate::opening) fn prove_with_trace(
    e: &Expected,
    s: &Statement,
    parent: Option<&super::CompositeProof>,
    factory: impl FnOnce() -> Result<RowMajorMatrix<Val>, Error>,
) -> Result<Proof<Config>, Error> {
    s.require_expected(e)?;
    verify_parent(e, parent)?; // Real whole Source and Lifecycle BEFORE child Backend/factory.
    Backend::new(s)?.prove_with_trace(s, factory)
}
pub(in crate::opening) fn verify(
    e: &Expected,
    s: &Statement,
    parent: Option<&super::CompositeProof>,
    proof: &Proof<Config>,
) -> Result<(), Error> {
    s.require_expected(e)?;
    verify_parent(e, parent)?;
    Backend::new(s)?.verify(s, proof)
}
pub(crate) fn profile(h: &mut Sha256) {
    h.update(b"DCS/Registry200/Result144-to-originals/full8192W/v1/no-formation-no-grant");
    h.update(profile_digest(Kind::CanonicalIndexOpening));
    h.update(profile_digest(Kind::RegistryLifecycle));
    h.update(super::statement::RESULT_DOMAIN);
    h.update(b"Source680/reset/Result144/Acquire1-outcome0/compact-return-rank/ordinal-and-all8RowIds/SQLidentity32/parentPV116/3P2/fullpadding");
    h.update(matrix::digest());
    h.update(frame::MAGIC);
    for n in [
        frame::HEADER,
        frame::MAX_SOURCE,
        frame::MAX_PARENT,
        frame::MAX_ENCODING,
        frame::MAX_FRAME,
        16384,
        24 * 1024 * 1024,
        16 * 1024 * 1024,
        16 * 1024 * 1024,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    for n in [
        512,
        air::WIDTH,
        statement::PUBLIC_VALUES,
        air::PERIODICS,
        114689,
        78307,
        103,
    ] {
        h.update((n as u64).to_le_bytes());
    }
}
pub(super) fn gate(mode: &str) -> Result<(), Error> {
    fixture::gate(mode)
}

/// Owner-side producer convenience. Verification below never receives this private witness.
pub(super) fn prove_and_encode(
    e: &Expected,
    w: &super::trace::Witness,
    parent: &super::CompositeProof,
    salt: [Val; 4],
) -> Result<Vec<u8>, Error> {
    verify_parent(e, Some(parent))?;
    let witness = trace::Witness::from_parent(e, w, salt)?;
    let s = witness.statement(e.clone());
    let proof = prove_with_trace(e, &s, Some(parent), || witness.trace(&s))?;
    encode(e, &s, parent, &proof).map_err(Error::from)
}

/// Owner-only preparation for the explicit mathematical opening. This constructor is not evidence.
pub(in crate::opening) fn prove_with_formation_opening(
    e: &Expected,
    w: &super::trace::Witness,
    parent: &super::CompositeProof,
    salt: [Val; 4],
) -> Result<(Statement, Vec<u8>, bfv_ciphertext_formation::EncodedOpening), Error> {
    verify_parent(e, Some(parent))?;
    let witness = trace::Witness::from_parent(e, w, salt)?;
    let statement = witness.statement(e.clone());
    let proof = prove_with_trace(e, &statement, Some(parent), || witness.trace(&statement))?;
    let bytes = encode(e, &statement, parent, &proof)?;
    let coefficients =
        zeroize::Zeroizing::new(witness.coefficients().into_iter().map(|(_, w)| w).collect());
    let opening = bfv_ciphertext_formation::EncodedOpening::new(
        coefficients,
        witness
            .encoding_salt
            .map(|v| p3_field::PrimeField64::as_canonical_u64(&v)),
        statement.formation_commitment()?,
    )?;
    Ok((statement, bytes, opening))
}

pub(in crate::opening) fn formation_coefficients(
    e: &Expected,
    w: &super::trace::Witness,
    salt: [Val; 4],
) -> Result<zeroize::Zeroizing<Vec<u64>>, Error> {
    let witness = trace::Witness::from_parent(e, w, salt)?;
    Ok(zeroize::Zeroizing::new(
        witness.coefficients().into_iter().map(|(_, w)| w).collect(),
    ))
}

pub(super) fn conditional_formation_shape()
-> Result<(Statement, zeroize::Zeroizing<Vec<u64>>), Error> {
    let f = fixture::Fixture::new(1)?;
    let coefficients =
        formation_coefficients(&f.expected, &f.parent_witness, f.witness.encoding_salt)?;
    Ok((f.statement, coefficients))
}

#[cfg(test)]
pub(super) fn all_skipped_formation_input()
-> Result<super::journal::FormationEncodingProduct, Error> {
    use p3_field::PrimeCharacteristicRing;
    let f = fixture::Fixture::new(1)?;
    let mut old = f.parent_witness.old.clone();
    old.transactions[1].held = [4; 4];
    let mut command = f.parent_witness.command.clone().ok_or(Error::Shape)?;
    command.offset = 0;
    let (e, w) = f.source.transition(
        old,
        command,
        f.parent.source.request,
        super::fixture::PARENT,
    )?;
    let s = w.statement(&e)?;
    let compiled = CompiledQuery::compile(
        "SELECT amount FROM records WHERE age>=128 LIMIT 1 FOR UPDATE SKIP LOCKED",
        [0xF5; 32],
        e.source.request,
    )?;
    let c = w.command.as_ref().ok_or(Error::Shape)?;
    let bound = compiled.bind(
        &e,
        &s,
        CommandOpening {
            transaction: c.transaction,
            principal: c.principal,
            controller: w.controllers[0],
            revision: w.old.revision,
            sequence: c.sequence,
            salt: w.salts[3],
        },
    )?;
    let (_, parent) = super::prove(&e, &f.source.source_witness, &w)?;
    super::verify(&e, &s, &parent)?;
    let salt = [Val::from_u8(35); 4];
    let coefficients = formation_coefficients(&bound, &w, salt)?;
    if coefficients.iter().any(|w| *w != 0) {
        return Err(Error::Shape);
    }
    let (statement, frame, opening) = prove_with_formation_opening(&bound, &w, &parent, salt)?;
    Ok(super::journal::FormationEncodingProduct {
        statement,
        frame,
        opening,
        coefficients,
        alternate: None,
    })
}
#[cfg(test)]
mod formation_tests;
