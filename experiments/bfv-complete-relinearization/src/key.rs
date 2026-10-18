//! Verifier-owned PUBLIC setup preprocessing. No query-dependent NTT is run here.
use crate::{DEGREE, Error, MODULI, Result};
use bfv_ntt_circuit::{
    Basis, Direction, decode_request, encode_request, evaluate_with_certificate,
};
use bfv_query_core::PublicSetup;
use sha2::{Digest, Sha512};

/// Immutable local constants derived from independently pinned ORIGINAL setup bytes.
/// This is not same-secret evidence or a deserializable setup-authority receipt.
pub struct PreparedKey {
    keyset_id: [u8; 32],
    setup_digest: [u8; 64],
    pub(crate) c0: [Vec<u64>; 5],
    pub(crate) c1: [Vec<u64>; 5],
}
impl PreparedKey {
    pub fn from_original(setup: &PublicSetup, independently_expected_id: [u8; 32]) -> Result<Self> {
        let source = bfv_relinearization_key_source::decode_seeded(
            setup.relinearization_material()?,
            independently_expected_id,
        )?; // Identity and complete borrowed shape/ranges BEFORE coefficient allocation.
        let setup_bytes = setup.to_bytes()?;
        let setup_digest = Sha512::digest(&setup_bytes).into();
        drop(setup_bytes);
        let expanded = source.expand_c1_ntt()?;
        if expanded.keyset_id() != independently_expected_id {
            return Err(Error::Identity);
        }
        let mut c0: [Vec<u64>; 5] = core::array::from_fn(|_| Vec::with_capacity(5 * DEGREE));
        let mut c1: [Vec<u64>; 5] = core::array::from_fn(|_| Vec::new());
        for source_index in 0..5 {
            let original = source.c0_power_basis(source_index).ok_or(Error::Shape)?;
            for target in 0..5 {
                let basis = Basis::new(target as u8)?;
                // Fixed PUBLIC setup work, independent of every query/input c2.
                let request = decode_request(&encode_request(
                    Direction::Forward,
                    basis,
                    independently_expected_id,
                    &original[target * DEGREE..(target + 1) * DEGREE],
                )?)?;
                let evaluated = evaluate_with_certificate(&request)?;
                c0[source_index].extend_from_slice(evaluated.output.coefficients());
                drop(evaluated); // Drop this one public auxiliary before the next transform.
            }
            c1[source_index] = expanded.c1_ntt(source_index).ok_or(Error::Shape)?.to_vec();
        }
        debug_assert!(
            c0.iter()
                .chain(c1.iter())
                .all(|v| v.len() == MODULI.len() * DEGREE)
        );
        Ok(Self {
            keyset_id: independently_expected_id,
            setup_digest,
            c0,
            c1,
        })
    }
    pub fn keyset_id(&self) -> [u8; 32] {
        self.keyset_id
    }
    pub fn original_setup_digest(&self) -> [u8; 64] {
        self.setup_digest
    }
}
