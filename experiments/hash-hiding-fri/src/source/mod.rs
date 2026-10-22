//! Actual existing SourceVersion relation under a separate experimental hash profile.
//! Successful verification is mathematical only; no live admission token is minted.
use crate::Error;
use crate::config::{Config, config};
use bfv_hiding_stark::{PROOF_DEGREE_BITS, TRACE_HEIGHT};
use p3_air::BaseAir;
use p3_uni_stark::Proof;
use registry200_proof::source::version::SourceVersionExpected;
use registry200_proof::source::{self, Relation, air::OpeningAir, circuit::Witness};
use sha2::{Digest, Sha256};

mod codec;
#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;

const MAGIC: &[u8; 8] = b"DCSHSF01";
const HEADER: usize = 44;
const MAX_BYTES: usize = source::version::MAX_CERTIFICATE_BYTES;

/// Candidate identity wraps the unchanged Source semantic profile. A production
/// adoption would need its own complete contract, not an alias for the old suite.
pub fn profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/research/hash-hiding-FRI/SourceVersion/v1/no-live-admission\0");
    hash.update(source::profile_digest(Relation::StateCertificate));
    hash.update(crate::merkle::LEAF_DOMAIN);
    hash.update(crate::merkle::NODE_DOMAIN);
    hash.update(crate::challenger::DOMAIN);
    hash.update(b"p3-0.8.0/Gold/EF5/raw32/cap0/scalar/SHA256/SHA512/rand0.10.3/OS-independent");
    hash.update(b"a21e3ed42905040ad49c519e402f018381c12d0c");
    hash.update(b"field1/cap2+count/sample3+counter/draw4+counter+retry/LE64/reject-ge-p");
    for value in [
        512u64,
        10,
        3,
        192,
        5,
        4,
        0,
        1,
        0,
        16,
        source::layout::PACKED_WIDTH as u64,
        691,
    ] {
        hash.update(value.to_le_bytes());
    }
    hash.finalize().into()
}

fn air(expected: &SourceVersionExpected) -> Result<OpeningAir, Error> {
    let air = OpeningAir::new(expected.statement());
    let (_, report) = bfv_hiding_stark::analyze(&air).map_err(|_| Error::Shape)?;
    report.require_target().map_err(|_| Error::Shape)?;
    if expected.statement().relation != Relation::StateCertificate
        || air.width() != source::layout::PACKED_WIDTH
        || air.num_public_values() != source::statement::PUBLIC_VALUES
        || air.preprocessed_width() != 0
        || air.main_next_row_columns().is_empty()
        || report.quotient_chunks != 16
    {
        return Err(Error::Shape);
    }
    Ok(air)
}

/// Produces an unverified, bounded candidate frame; the independent receiver
/// supplies its own SourceVersionExpected and invokes verify().
pub fn prove(expected: &SourceVersionExpected, witness: &Witness) -> Result<Vec<u8>, Error> {
    let air = measured("producer_air", || air(expected))?;
    let trace = measured("producer_trace", || witness.trace(expected.statement()))
        .map_err(|_| Error::Shape)?;
    if trace.values.len() != TRACE_HEIGHT * air.width() {
        return Err(Error::Shape);
    }
    let config = measured("producer_config", config)?;
    let proof = measured("producer_native", || {
        p3_uni_stark::prove(&config, &air, trace, &expected.statement().values())
    })
    .map_err(|_| Error::Proving)?;
    measured("producer_encode", || encode(&proof))
}

/// Bounded canonical decode and native verification of the actual complete AIR.
/// This returns no journal, version-freshness, SQL or old-suite capability.
pub fn verify(expected: &SourceVersionExpected, bytes: &[u8]) -> Result<(), Error> {
    let proof = measured("receiver_decode", || decode(bytes))?;
    let air = measured("receiver_air", || air(expected))?;
    let config = measured("receiver_config", config)?;
    measured("receiver_native", || {
        p3_uni_stark::verify(&config, &air, &proof, &expected.statement().values())
    })
    .map_err(|_| Error::Verification)
}

fn measured<T>(_phase: &'static str, operation: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    let started = std::time::Instant::now();
    let result = operation();
    #[cfg(test)]
    eprintln!(
        "hash_source phase={_phase} ms={:.3}",
        started.elapsed().as_secs_f64() * 1000.
    );
    result
}

fn encode(proof: &Proof<Config>) -> Result<Vec<u8>, Error> {
    codec::check(proof)?;
    let payload = postcard::to_allocvec(proof).map_err(|_| Error::Encoding)?;
    if payload.len() > MAX_BYTES - HEADER {
        return Err(Error::ResourceLimit);
    }
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&profile_digest());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend(payload);
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> Result<Proof<Config>, Error> {
    if bytes.len() < HEADER || bytes.len() > MAX_BYTES {
        return Err(Error::ResourceLimit);
    }
    if &bytes[..8] != MAGIC
        || bytes[8..40] != profile_digest()
        || u32::from_le_bytes(bytes[40..44].try_into().map_err(|_| Error::Encoding)?) as usize
            != bytes.len() - HEADER
    {
        return Err(Error::Encoding);
    }
    let (proof, trailing) = bounded_postcard::take_from_bytes::<Proof<Config>>(
        &bytes[HEADER..],
        bounded_postcard::Limits {
            // Same Source geometry/budgets as the existing owning decoder.
            // Gold's canonical binary representation is an eight-byte array:
            // each field charges eight nested slots, not just its outer slot.
            max_sequence_elements: 16_384,
            max_total_elements: 24 * 1024 * 1024,
        },
    )
    .map_err(|error| match error {
        bounded_postcard::Error::ResourceLimit => Error::ResourceLimit,
        bounded_postcard::Error::Encoding => Error::Encoding,
    })?;
    if !trailing.is_empty() || proof.degree_bits != PROOF_DEGREE_BITS {
        return Err(Error::Encoding);
    }
    codec::check(&proof)?;
    if encode(&proof)? != bytes {
        return Err(Error::Encoding);
    }
    Ok(proof)
}
