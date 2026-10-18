//! One bounded formation component; prerequisites remain separately bounded public evidence.
use crate::{Expected, ProverWitness, Statement, circuit, profile_digest};
use bfv_hiding_stark::{
    Config, Error, Val,
    codec::{self, Topology},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
pub const HEADER_BYTES: usize = 140;
pub const MAX_PROOF_BYTES: usize = 24 * 1024 * 1024;
pub const MAX_SEQUENCE_ELEMENTS: usize = 16384;
pub const MAX_TOTAL_ELEMENTS: usize = 32 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"DCSFMP01";
/// Borrowed complete evidence. No aggregate wire format or acceptance token is defined.
pub struct Prerequisites<'a> {
    pub key: &'a [u8],
    pub bases: [&'a [u8]; 5],
}
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
/// A mathematical formation relation only; producer authority/freshness stay with the consumer.
pub struct VerifiedFormation {
    statement: Statement,
}
impl VerifiedFormation {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
}
fn header(full_setup_id: [u8; 32], expected: &Expected, noise: [Val; 4], length: usize) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_BYTES);
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&profile_digest());
    b.extend_from_slice(&full_setup_id);
    b.extend_from_slice(&expected.binding(full_setup_id));
    for v in noise {
        b.extend_from_slice(&v.as_canonical_u64().to_le_bytes());
    }
    b.extend_from_slice(&(length as u32).to_le_bytes());
    assert_eq!(b.len(), HEADER_BYTES);
    b
}
fn root(b: &[u8]) -> Result<[Val; 4], Error> {
    let mut values = [Val::ZERO; 4];
    for (v, w) in values.iter_mut().zip(b.as_chunks::<8>().0) {
        let n = u64::from_le_bytes(*w);
        if n >= Val::ORDER_U64 {
            return Err(Error::Shape);
        }
        *v = Val::from_u64(n);
    }
    Ok(values)
}
fn map_codec(_: codec::Error) -> Error {
    Error::Shape
}
fn verify_inputs(
    full_setup_id: [u8; 32],
    expected: &Expected,
    p: &Prerequisites<'_>,
) -> Result<(), Error> {
    expected.validate()?;
    bfv_basis_convolution::verify_five(full_setup_id, expected.bases(), p.key, p.bases)
}
pub(crate) fn prove_with_factory<'a>(
    full_setup_id: [u8; 32],
    expected: &Expected,
    p: &Prerequisites<'_>,
    factory: impl FnOnce() -> Result<crate::witness::Prepared<'a>, Error>,
) -> Result<Evidence, Error> {
    verify_inputs(full_setup_id, expected, p)?; // ALL genuine prerequisites BEFORE claim/oracle/AIR/trace.
    let prepared = factory()?;
    let statement = &prepared.statement;
    if statement.full_setup_id != full_setup_id
        || statement.expected.binding(full_setup_id) != expected.binding(full_setup_id)
    {
        return Err(Error::Shape);
    }
    let air = statement.air()?;
    let (parameters, report) = bfv_hiding_stark::analyze(&air)?;
    report.require_target()?;
    let config = bfv_hiding_stark::config()?;
    let values = statement.public_values();
    let trace = prepared.trace()?; // Mandatory analytical floor BEFORE allocating the full trace.
    let proof = bfv_hiding_stark::prove_with_config(&config, &air, trace, &values)?;
    bfv_hiding_stark::verify_with_assessment(&config, &air, &parameters, report, &proof, &values)?;
    let topology = Topology::checked(circuit::WIDTH, report.quotient_chunks).map_err(map_codec)?;
    let payload = codec::serialize(&proof, &topology, MAX_PROOF_BYTES).map_err(map_codec)?;
    drop(proof);
    drop(config);
    let mut bytes = header(full_setup_id, expected, statement.noise, payload.len());
    bytes.extend_from_slice(&payload);
    Ok(Evidence { bytes })
}
pub fn prove(
    full_setup_id: [u8; 32],
    expected: &Expected,
    p: &Prerequisites<'_>,
    witness: &ProverWitness<'_>,
) -> Result<Evidence, Error> {
    prove_with_factory(full_setup_id, expected, p, || {
        witness.prepare(expected, full_setup_id)
    })
}
pub fn verify(
    full_setup_id: [u8; 32],
    expected: &Expected,
    p: &Prerequisites<'_>,
    bytes: &[u8],
) -> Result<VerifiedFormation, Error> {
    if bytes.len() < HEADER_BYTES || bytes.len() > HEADER_BYTES + MAX_PROOF_BYTES {
        return Err(Error::Shape);
    }
    let noise = root(&bytes[104..136])?;
    let length = u32::from_le_bytes(bytes[136..140].try_into().unwrap()) as usize;
    if length == 0
        || length > MAX_PROOF_BYTES
        || HEADER_BYTES.checked_add(length) != Some(bytes.len())
        || header(full_setup_id, expected, noise, length) != bytes[..HEADER_BYTES]
    {
        return Err(Error::Shape);
    }
    verify_inputs(full_setup_id, expected, p)?;
    let statement = Statement {
        expected: expected.clone(),
        full_setup_id,
        noise,
    };
    let air = statement.air()?;
    let (parameters, report) = bfv_hiding_stark::analyze(&air)?;
    report.require_target()?;
    let topology = Topology::checked(circuit::WIDTH, report.quotient_chunks).map_err(map_codec)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof: p3_uni_stark::Proof<Config> = codec::decode(
            &bytes[HEADER_BYTES..],
            &topology,
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
        Ok(VerifiedFormation { statement })
    }))
    .map_err(|_| Error::Verification)?
}
