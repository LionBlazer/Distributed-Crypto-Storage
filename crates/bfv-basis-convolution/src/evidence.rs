//! One bounded Basis component. The genuine Key component is supplied separately.
use crate::{Expected, ProverWitness, PublicInput, Statement, circuit, profile_digest};
use bfv_hiding_stark::{
    Config, Error, Val,
    codec::{self, Topology},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

pub const HEADER_BYTES: usize = 308;
pub const MAX_PROOF_BYTES: usize = 20 * 1024 * 1024;
pub const MAX_SEQUENCE_ELEMENTS: usize = 16_384;
pub const MAX_TOTAL_ELEMENTS: usize = 24 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"DCSBCP01";
/// Public bytes, not an authority or all-five-completion token.
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
/// One checked relation only; independent setup/key/SQL/freshness admission stays outside.
pub struct VerifiedBasis {
    statement: Statement,
    full_setup_id: [u8; 32],
}
impl VerifiedBasis {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn full_setup_id(&self) -> [u8; 32] {
        self.full_setup_id
    }
}
fn map_codec(_: codec::Error) -> Error {
    Error::Shape
}
fn append_root(bytes: &mut Vec<u8>, root: [Val; 4]) {
    for value in root {
        bytes.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
    }
}
fn root(bytes: &[u8]) -> Result<[Val; 4], Error> {
    let mut values = [Val::ZERO; 4];
    for (value, word) in values.iter_mut().zip(bytes.as_chunks::<8>().0) {
        let word = u64::from_le_bytes(*word);
        if word >= Val::ORDER_U64 {
            return Err(Error::Shape);
        }
        *value = Val::from_u64(word);
    }
    Ok(values)
}
fn header(
    expected: &Expected,
    full_setup_id: [u8; 32],
    result: [Val; 4],
    length: usize,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&profile_digest());
    bytes.extend_from_slice(&full_setup_id);
    bytes.extend_from_slice(&expected.key().expected.descriptor.bytes());
    append_root(&mut bytes, expected.key().expected.coefficients);
    append_root(&mut bytes, expected.key().transformed);
    bytes.extend_from_slice(&expected.request());
    bytes.extend_from_slice(&expected.ciphertext_binding());
    bytes.extend_from_slice(&(expected.ciphertext().basis() as u32).to_le_bytes());
    append_root(&mut bytes, result);
    bytes.extend_from_slice(&(length as u32).to_le_bytes());
    assert_eq!(bytes.len(), HEADER_BYTES);
    bytes
}
fn verify_key(full_setup_id: [u8; 32], expected: &Expected, key: &[u8]) -> Result<(), Error> {
    let verified = bfv_key_transform::verify(full_setup_id, &expected.key().expected, key)?;
    // Descriptor+Cs alone does NOT pin the fresh CsHat. Preserve ALL original Key PV33.
    if verified.statement().public_values() != expected.key().public_values() {
        return Err(Error::Shape);
    }
    Ok(())
}
pub(crate) fn prove_with_factory(
    full_setup_id: [u8; 32],
    expected: &Expected,
    key: &[u8],
    claim: impl FnOnce() -> Statement,
    factory: impl FnOnce(&Statement) -> Result<p3_matrix::dense::RowMajorMatrix<Val>, Error>,
) -> Result<Evidence, Error> {
    verify_key(full_setup_id, expected, key)?; // BEFORE child claim oracle, AIR, trace and factory.
    let statement = claim();
    statement.require_expected(expected)?;
    let air = statement.air();
    let (parameters, report) = bfv_hiding_stark::analyze(&air)?;
    report.require_target()?;
    let config = bfv_hiding_stark::config()?;
    let values = statement.public_values();
    let proof = bfv_hiding_stark::prove_with_config(&config, &air, factory(&statement)?, &values)?;
    // One Key verification in this call; fixed same-instance Basis self-verification below.
    bfv_hiding_stark::verify_with_assessment(&config, &air, &parameters, report, &proof, &values)?;
    let topology = Topology::checked(circuit::WIDTH, report.quotient_chunks).map_err(map_codec)?;
    let payload = codec::serialize(&proof, &topology, MAX_PROOF_BYTES).map_err(map_codec)?;
    drop(proof);
    drop(config);
    let mut bytes = header(expected, full_setup_id, statement.result, payload.len());
    bytes.extend_from_slice(&payload);
    Ok(Evidence { bytes })
}
pub fn prove(
    full_setup_id: [u8; 32],
    expected: &Expected,
    key: &[u8],
    witness: &ProverWitness<'_>,
) -> Result<Evidence, Error> {
    prove_with_factory(
        full_setup_id,
        expected,
        key,
        || witness.statement(expected.clone()),
        |statement| witness.trace(statement),
    )
}
/// Strict explicit Expected path, including exact ALL33 Key public values.
pub fn verify(
    full_setup_id: [u8; 32],
    expected: &Expected,
    key: &[u8],
    bytes: &[u8],
) -> Result<VerifiedBasis, Error> {
    verify_key(full_setup_id, expected, key)?;
    verify_fixed(full_setup_id, expected, bytes)
}
/// Compound public path: one actual Key verification under independent input pins,
/// followed by exact Basis Expected construction and fixed cryptographic verification.
/// No submitted token/header can replace this actual Key proof.
pub fn verify_with_key(
    full_setup_id: [u8; 32],
    key_expected: &bfv_key_transform::Expected,
    input: &PublicInput,
    key: &[u8],
    bytes: &[u8],
) -> Result<VerifiedBasis, Error> {
    let verified = bfv_key_transform::verify(full_setup_id, key_expected, key)?;
    let expected = input.expected(verified.statement().clone())?;
    verify_fixed(full_setup_id, &expected, bytes)
}
fn verify_fixed(
    full_setup_id: [u8; 32],
    expected: &Expected,
    bytes: &[u8],
) -> Result<VerifiedBasis, Error> {
    if bytes.len() < HEADER_BYTES || bytes.len() > HEADER_BYTES + MAX_PROOF_BYTES {
        return Err(Error::Shape);
    }
    let result = root(&bytes[272..304])?;
    let length = u32::from_le_bytes(bytes[304..308].try_into().unwrap()) as usize;
    if length == 0
        || length > MAX_PROOF_BYTES
        || HEADER_BYTES.checked_add(length) != Some(bytes.len())
        || header(expected, full_setup_id, result, length) != bytes[..HEADER_BYTES]
    {
        return Err(Error::Shape);
    }
    let statement = Statement {
        expected: expected.clone(),
        result,
    };
    let air = statement.air();
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
        Ok(VerifiedBasis {
            statement,
            full_setup_id,
        })
    }))
    .map_err(|_| Error::Verification)?
}
