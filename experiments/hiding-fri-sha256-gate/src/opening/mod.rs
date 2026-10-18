//! Experimental whole-pair private AEAD byte-opening. No live accepting path.
//! Public canonical ciphertext is checked outside AIR; ALL private key/AEAD/XOR
//! and salted commitment links are constrained inside one hiding relation.
pub(crate) use registry200_proof::source::air;
pub(crate) mod basis_convolution;
pub(crate) mod coefficient_encoding;
mod source_adapter;
pub(crate) use registry200_proof::source::canonical;
use registry200_proof::source::layout;
pub(crate) mod local_formation;
pub(crate) mod private_journal;
pub(crate) use layout::PACKED_WIDTH;
#[cfg(test)]
mod canonical_tests;
use registry200_proof::source::commitment;
pub(crate) use registry200_proof::source::factorized;
#[cfg(test)]
mod factorized_tests;
mod fixture;
pub(crate) mod key_transform;
pub(crate) mod locking;
#[cfg(test)]
mod packed_tests;
pub(crate) mod peer_process;
mod poseidon;
mod proof_codec;
mod proof_wire;
pub(crate) mod registry_bootstrap;
pub(crate) mod registry_lifecycle;
pub(crate) use registry200_proof::source::schedule;
pub(crate) mod selection;
pub(crate) mod state;
pub(crate) use registry200_proof::source::statement;
#[cfg(test)]
mod tests;
mod trace;
pub(crate) use registry200_proof::source::{
    DATA_SCHEMA, INDEX_SCHEMA, Relation, index_profile, packed_index_profile, profile,
};
pub(crate) fn gate(mode: &str) -> Result<(), crate::backend::Error> {
    gate_relation(mode, Relation::Bytes)
}
pub(crate) fn canonical_gate(mode: &str) -> Result<(), crate::backend::Error> {
    gate_relation(mode, Relation::CanonicalIndex)
}
pub(crate) fn packed_canonical_gate(mode: &str) -> Result<(), crate::backend::Error> {
    gate_relation(mode, Relation::PackedCanonicalIndex)
}
pub(crate) fn factorized_canonical_gate(mode: &str) -> Result<(), crate::backend::Error> {
    gate_relation(mode, Relation::FactorizedPackedCanonicalIndex)
}
fn gate_relation(mode: &str, relation: Relation) -> Result<(), crate::backend::Error> {
    use crate::backend::Error;
    use std::time::Instant;
    let (statement, witness) = match relation {
        Relation::Bytes => fixture::fixture()?,
        Relation::CanonicalIndex => fixture::canonical_fixture()?,
        Relation::PackedCanonicalIndex => fixture::packed_canonical_fixture()?,
        Relation::FactorizedPackedCanonicalIndex => fixture::factorized_canonical_fixture()?,
        Relation::StateCertificate => return Err(Error::Shape),
    };
    let backend = crate::prepare_gate(
        &statement,
        mode,
        match relation {
            Relation::Bytes => "fixed-four-row-pair",
            Relation::CanonicalIndex => "canonical-four-row-index",
            Relation::PackedCanonicalIndex => "packed-canonical-four-row-index",
            Relation::FactorizedPackedCanonicalIndex => {
                "factorized-packed-canonical-four-row-index"
            }
            Relation::StateCertificate => return Err(Error::Shape),
        },
    )?;
    let (periodics, periodic_bytes) = if relation.factorized() {
        (factorized::COLUMNS, factorized::PAYLOAD_BYTES)
    } else {
        (512, 2_097_152)
    };
    println!(
        "{{\"stage\":\"candidate_geometry\",\"public_values\":691,\"periodic_columns\":{},\"periodic_payload_bytes\":{},\"periodic_lde_payload_estimate_bytes\":{},\"declared_degree_bound\":5,\"private_plaintext_bytes\":2348,\"cha_jobs\":42,\"mac_blocks\":163}}",
        periodics,
        periodic_bytes,
        periodics * 8192 * std::mem::size_of::<crate::backend::Val>()
    );
    if let Some(backend) = backend {
        let started = Instant::now();
        let proof = backend.prove_with_trace(&statement, || witness.trace(&statement))?;
        let proving = started.elapsed();
        let started = Instant::now();
        backend.verify(&statement, &proof)?;
        let stage = match relation {
            Relation::Bytes => "verified_experimental_pair_byte_opening",
            Relation::CanonicalIndex => "verified_experimental_canonical_index_opening",
            Relation::PackedCanonicalIndex => {
                "verified_experimental_packed_canonical_index_opening"
            }
            Relation::FactorizedPackedCanonicalIndex => {
                "verified_experimental_factorized_packed_canonical_index_opening"
            }
            Relation::StateCertificate => return Err(Error::Shape),
        };
        println!(
            "{{\"stage\":\"{}\",\"proving_ms\":{},\"verification_ms\":{}}}",
            stage,
            proving.as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    Ok(())
}
