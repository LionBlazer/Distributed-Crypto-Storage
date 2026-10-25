//! Closed Role3 mathematics under the separate SHA hiding-FRI suite.
//! Callers must freshly verify the matching Source SHA proof separately. This
//! module supplies no Source authentication, old encoding token or SQL admission.
use super::{Role, air::EncodingAir, circuit::Witness, statement::Statement, wire};
use bfv_hiding_stark::{self as engine, hash as suite};
use p3_air::BaseAir;
use p3_field::PrimeField64;
use sha2::{Digest, Sha256, Sha512};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[cfg(test)]
mod public_image;

const MAGIC: &[u8; 8] = b"DCSHER01";
const HEADER: usize = 128;
/// Complete frame limit, retaining the original Role3 child byte budget.
pub const MAX_EVIDENCE_BYTES: usize = wire::MAX_CHILD;

/// Distinct fixed SHA protocol identity, wrapping the unchanged Role3 relation.
/// Neither this label nor successful native mathematics is security approval.
pub fn profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/research/hash-hiding-FRI/Role3/v1/no-live-admission\0");
    hash.update(suite::profile_digest());
    hash.update(super::profile_digest(Role::VersionSourceAllOriginal));
    hash.update(b"DCSHER01/full-Statement-PV-Cw-Source-heads-packets/SHA512-binding/relative-Source-unverified/no-old-token");
    for value in [
        HEADER,
        MAX_EVIDENCE_BYTES,
        wire::SEQUENCE,
        wire::CHILD_SLOTS,
        Role::VersionSourceAllOriginal.width(),
        Role::VersionSourceAllOriginal.public_values(),
        engine::TRACE_HEIGHT,
        engine::PROOF_DEGREE_BITS,
        super::layout::PERIODICS,
        16,
    ] {
        hash.update((value as u64).to_le_bytes());
    }
    hash.finalize().into()
}

fn binding(statement: &Statement) -> [u8; 64] {
    let mut hash = Sha512::new();
    hash.update(b"DCS/research/hash-hiding-FRI/Role3/full-Statement/v1\0");
    hash.update(profile_digest());
    let values = statement.values();
    hash.update((values.len() as u64).to_le_bytes());
    for value in values {
        hash.update(value.as_canonical_u64().to_le_bytes());
    }
    let source = statement.expected.source_claim();
    for bytes in source
        .heads
        .iter()
        .map(|head| head.as_slice())
        .chain(source.packets.iter().map(Vec::as_slice))
    {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hash.finalize().into()
}

fn require_role(statement: &Statement) -> Result<(), wire::Error> {
    if statement.expected.role() != Role::VersionSourceAllOriginal
        || statement.expected.source_claim().relation != crate::source::Relation::StateCertificate
    {
        return Err(wire::Error::Shape);
    }
    statement
        .expected
        .source_claim()
        .reaudit()
        .map_err(wire::Error::Proof)
}

fn air(statement: &Statement) -> Result<EncodingAir, wire::Error> {
    require_role(statement)?;
    let air = EncodingAir::new(statement);
    let (_, report) = engine::analyze(&air).map_err(wire::Error::Proof)?;
    report.require_target().map_err(wire::Error::Proof)?;
    if air.width() != Role::VersionSourceAllOriginal.width()
        || air.num_public_values() != Role::VersionSourceAllOriginal.public_values()
        || air.preprocessed_width() != 0
        || air.num_periodic_columns() != super::layout::PERIODICS
        || air.main_next_row_columns().is_empty()
        || report.quotient_chunks != 16
    {
        return Err(wire::Error::Shape);
    }
    Ok(air)
}

fn topology() -> Result<suite::codec::Topology, wire::Error> {
    suite::codec::Topology::checked(Role::VersionSourceAllOriginal.width(), 16).map_err(codec_error)
}

fn codec_error(error: suite::codec::Error) -> wire::Error {
    match error {
        suite::codec::Error::Encoding => wire::Error::Encoding,
        suite::codec::Error::ResourceLimit => wire::Error::ResourceLimit,
        suite::codec::Error::Shape => wire::Error::Shape,
    }
}

/// Prove the complete independently supplied Role3 statement, returning only
/// unverified bytes. The caller separately checks its matching Source SHA proof.
/// The original private witness and AIR writers remain at their owning boundary.
pub fn prove(statement: &Statement, witness: &Witness) -> Result<Vec<u8>, wire::Error> {
    catch_unwind(AssertUnwindSafe(|| {
        let air = air(statement)?;
        witness
            .require_expected(&statement.expected)
            .map_err(wire::Error::Proof)?;
        let actual = witness.statement();
        if actual.values() != statement.values() {
            return Err(wire::Error::Shape);
        }
        let trace = witness.trace(statement).map_err(wire::Error::Proof)?;
        if trace.values.len() != engine::TRACE_HEIGHT * air.width() {
            return Err(wire::Error::Shape);
        }
        let proof = p3_uni_stark::prove(
            &suite::config().map_err(wire::Error::Proof)?,
            &air,
            trace,
            &statement.values(),
        )
        .map_err(|_| wire::Error::Proof(engine::Error::Proving))?;
        let payload = suite::codec::serialize(&proof, &topology()?, MAX_EVIDENCE_BYTES - HEADER)
            .map_err(codec_error)?;
        let length = u32::try_from(payload.len()).map_err(|_| wire::Error::ResourceLimit)?;
        let mut bytes = Vec::with_capacity(HEADER + payload.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&profile_digest());
        bytes.extend_from_slice(&binding(statement));
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&[0; 20]);
        bytes.extend(payload);
        Ok(bytes)
    }))
    .map_err(|_| wire::Error::Proof(engine::Error::Proving))?
}

/// Bound and canonically decode the separate frame, then freshly assess and
/// natively verify its exact complete Role3 statement. No Source proof is checked
/// here and no old VerifiedEncoding, freshness or application token is minted.
pub fn verify(statement: &Statement, bytes: &[u8]) -> Result<(), wire::Error> {
    catch_unwind(AssertUnwindSafe(|| {
        if bytes.len() < HEADER || bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(wire::Error::ResourceLimit);
        }
        require_role(statement)?;
        if &bytes[..8] != MAGIC
            || bytes[8..40] != profile_digest()
            || bytes[40..104] != binding(statement)
            || bytes[108..HEADER] != [0; 20]
        {
            return Err(wire::Error::Shape);
        }
        let length = u32::from_le_bytes(
            bytes[104..108]
                .try_into()
                .map_err(|_| wire::Error::Encoding)?,
        ) as usize;
        if length == 0 || length.checked_add(HEADER) != Some(bytes.len()) {
            return Err(wire::Error::Encoding);
        }
        let proof = suite::codec::decode(
            &bytes[HEADER..],
            &topology()?,
            wire::SEQUENCE,
            wire::CHILD_SLOTS,
        )
        .map_err(codec_error)?;
        let air = air(statement)?;
        p3_uni_stark::verify(
            &suite::config().map_err(wire::Error::Proof)?,
            &air,
            &proof,
            &statement.values(),
        )
        .map_err(|_| wire::Error::Proof(engine::Error::Verification))
    }))
    .map_err(|_| wire::Error::Verification)?
}
