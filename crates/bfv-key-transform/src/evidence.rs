//! Canonical bounded transfer of the existing proof plus an externally pinned full-setup label.
//! The label is not an extra AIR public value and is not self-authenticating.
use crate::{Expected, ProverWitness, Statement, circuit, profile_digest};
use bfv_hiding_stark::{
    Config, Error, Val,
    codec::{self, Topology},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::Proof;

pub const HEADER_BYTES: usize = 208;
pub const MAX_PROOF_BYTES: usize = 20 * 1024 * 1024;
pub const MAX_SEQUENCE_ELEMENTS: usize = 16_384;
pub const MAX_TOTAL_ELEMENTS: usize = 24 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"DCSKTP01";

/// Public, bounded proof bytes. Construction does not grant setup authority.
pub struct Evidence {
    bytes: Vec<u8>,
}
impl Evidence {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
/// Exact public result checked against an independent prequery anchor.
pub struct VerifiedTransform {
    statement: Statement,
    full_setup_id: [u8; 32],
}
impl VerifiedTransform {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    /// Checked external label; its trust still comes from the independent caller pin.
    pub fn full_setup_id(&self) -> [u8; 32] {
        self.full_setup_id
    }
}

fn map_codec(error: codec::Error) -> Error {
    match error {
        codec::Error::Shape | codec::Error::Encoding | codec::Error::ResourceLimit => Error::Shape,
    }
}
fn write_root(bytes: &mut Vec<u8>, root: [Val; 4]) {
    for v in root {
        bytes.extend_from_slice(&v.as_canonical_u64().to_le_bytes());
    }
}
fn root(bytes: &[u8]) -> Result<[Val; 4], Error> {
    let mut out = [Val::ZERO; 4];
    for (value, bytes) in out.iter_mut().zip(bytes.as_chunks::<8>().0) {
        let raw = u64::from_le_bytes(*bytes);
        if raw >= Val::ORDER_U64 {
            return Err(Error::Shape);
        }
        *value = Val::from_u64(raw);
    }
    Ok(out)
}

/// Prove the actual fixed relation using caller-owned secret material.
/// `full_setup_id` is a caller-pinned label, not a claim inside the legacy AIR.
pub fn prove(
    full_setup_id: [u8; 32],
    expected: &Expected,
    witness: &ProverWitness,
) -> Result<Evidence, Error> {
    let statement = witness.statement(expected.descriptor.clone());
    statement.require_expected(expected)?;
    let air = statement.air();
    let (parameters, report) = bfv_hiding_stark::analyze(&air)?;
    report.require_target()?;
    let config = bfv_hiding_stark::config()?;
    let public_values = statement.public_values();
    let proof = bfv_hiding_stark::prove_with_config(
        &config,
        &air,
        witness.trace(&statement)?,
        &public_values,
    )?;
    bfv_hiding_stark::verify_with_assessment(
        &config,
        &air,
        &parameters,
        report,
        &proof,
        &public_values,
    )?;
    let shape = Topology::checked(circuit::WIDTH, report.quotient_chunks).map_err(map_codec)?;
    let payload = codec::serialize(&proof, &shape, MAX_PROOF_BYTES).map_err(map_codec)?;
    drop(proof);
    drop(config);
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&profile_digest());
    bytes.extend_from_slice(&full_setup_id);
    bytes.extend_from_slice(&expected.descriptor.bytes());
    write_root(&mut bytes, expected.coefficients);
    write_root(&mut bytes, statement.transformed);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    assert_eq!(bytes.len(), HEADER_BYTES);
    bytes.extend_from_slice(&payload);
    Ok(Evidence { bytes })
}

/// Verify complete canonical evidence under an independently owner-pinned anchor.
/// A sender's setup/anchor/proof trio is not an authorization source.
pub fn verify(
    full_setup_id: [u8; 32],
    expected: &Expected,
    bytes: &[u8],
) -> Result<VerifiedTransform, Error> {
    if bytes.len() < HEADER_BYTES
        || bytes.len() > HEADER_BYTES + MAX_PROOF_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8..40] != profile_digest()
        || bytes[40..72] != full_setup_id
        || bytes[72..140] != expected.descriptor.bytes()
    {
        return Err(Error::Shape);
    }
    let coefficients = root(&bytes[140..172])?;
    let transformed = root(&bytes[172..204])?;
    if coefficients != expected.coefficients {
        return Err(Error::Shape);
    }
    let length = u32::from_le_bytes(bytes[204..208].try_into().unwrap()) as usize;
    if length == 0
        || length > MAX_PROOF_BYTES
        || HEADER_BYTES.checked_add(length) != Some(bytes.len())
    {
        return Err(Error::Shape);
    }
    let statement = Statement {
        expected: expected.clone(),
        transformed,
    };
    let air = statement.air();
    let (parameters, report) = bfv_hiding_stark::analyze(&air)?;
    report.require_target()?;
    let shape = Topology::checked(circuit::WIDTH, report.quotient_chunks).map_err(map_codec)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof: Proof<Config> = codec::decode(
            &bytes[HEADER_BYTES..],
            &shape,
            MAX_SEQUENCE_ELEMENTS,
            MAX_TOTAL_ELEMENTS,
        )
        .map_err(map_codec)?;
        let config = bfv_hiding_stark::config()?;
        bfv_hiding_stark::verify_with_assessment(
            &config,
            &air,
            &parameters,
            report,
            &proof,
            &statement.public_values(),
        )?;
        Ok(VerifiedTransform {
            statement,
            full_setup_id,
        })
    }))
    .map_err(|_| Error::Verification)?
}
