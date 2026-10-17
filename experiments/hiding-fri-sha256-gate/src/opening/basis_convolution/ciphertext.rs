//! Bounded canonical upstream ciphertext decoding; never accepts an independent A/NTT table.
use super::N;
use crate::backend::{Error, Val};
use crate::opening::key_transform::trace::oracle;
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext};
use fhe_math::rq::Representation;
use fhe_traits::{DeserializeParametrized, Serialize};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

pub(in crate::opening) const MODULI: [u64; 5] = [
    8796092858369,
    8796092792833,
    17592186028033,
    17592185438209,
    17592184717313,
];
pub(in crate::opening) const PLAINTEXT: u64 = 114689;
pub(in crate::opening) const VARIANCE: usize = 10;
pub(in crate::opening) const MAX_PARAMETER_BYTES: usize = 1024;
// Pinned codec: 8192*(43+43+44+44+44)/8 = 223232 coefficient bytes/poly.
// Rq adds repr(2)+degree(3)+bytes tag/len(4)+variable-time(<=2) = <=11.
// Ct adds tag/len(4) per poly: <=2*(223232+11+4)=446494 at level0.
// Seeded form has one such poly + seed tag/len/32 = 223281. Both fit this cap.
pub(in crate::opening) const MAX_CIPHERTEXT_BYTES: usize = 512 * 1024;
pub(in crate::opening) const MAX_CANONICAL_UNSEEDED_BYTES: usize = 2 * (223232 + 11 + 4);
const _: () = assert!(MAX_CIPHERTEXT_BYTES >= MAX_CANONICAL_UNSEEDED_BYTES);

pub(in crate::opening) fn parameters() -> Arc<BfvParameters> {
    static PARAMETERS: OnceLock<Arc<BfvParameters>> = OnceLock::new();
    Arc::clone(PARAMETERS.get_or_init(|| {
        BfvParametersBuilder::new()
            .set_degree(N)
            .set_plaintext_modulus(PLAINTEXT)
            .set_moduli(&MODULI)
            .set_variance(VARIANCE)
            .build_arc()
            .expect("fixed pinned BFV parameters")
    }))
}
pub(in crate::opening) fn setup_digest() -> [u8; 32] {
    Sha256::digest(parameters().to_bytes()).into()
}

/// Fields are private: every instance originates in the complete canonical decoder.
#[derive(Clone, PartialEq, Eq)]
pub(in crate::opening) struct CanonicalCiphertext {
    parameter_bytes: Vec<u8>,
    ciphertext_bytes: Vec<u8>,
    basis: usize,
    coefficients: Vec<u64>,
    b_coefficients: Vec<u64>,
    evaluations: Vec<Val>,
}
impl CanonicalCiphertext {
    pub(in crate::opening) fn decode(
        parameters_bytes: &[u8],
        bytes: &[u8],
        basis: usize,
    ) -> Result<Self, Error> {
        if basis >= MODULI.len()
            || parameters_bytes.len() > MAX_PARAMETER_BYTES
            || bytes.len() > MAX_CIPHERTEXT_BYTES
            || bytes.is_empty()
        {
            return Err(Error::Shape);
        }
        let par = parameters();
        // No attacker-supplied parameter builder/deserializer can allocate a different N.
        if parameters_bytes != par.to_bytes() {
            return Err(Error::Shape);
        }
        // The upstream fallible codec contains internal assertions for malformed maths.
        // Those are rejection too; the byte cap precedes decoding, not a wire allocation bound.
        let ct = std::panic::catch_unwind(|| Ciphertext::from_bytes(bytes, &par))
            .map_err(|_| Error::Shape)?
            .map_err(|_| Error::Shape)?;
        if ct.len() != 2 {
            return Err(Error::Shape);
        }
        let ctx = par.context_at_level(0).map_err(|_| Error::Shape)?;
        for poly in ct.iter() {
            if poly.representation() != &Representation::Ntt
                || poly.ctx() != ctx
                || poly.coefficients().dim() != (MODULI.len(), N)
                || poly
                    .coefficients()
                    .outer_iter()
                    .zip(MODULI)
                    .any(|(row, q)| row.iter().any(|c| *c >= q))
            {
                return Err(Error::Shape);
            }
        }
        // This also binds c0/B, seed, representation, level, unknown and duplicate fields.
        if ct.to_bytes() != bytes {
            return Err(Error::Shape);
        }
        // Wire Rq stores power-basis bytes even when its enum says Ntt. Use the decoded Poly.
        let mut a = ct[1].clone();
        a.change_representation(Representation::PowerBasis);
        let coefficients = a.coefficients().row(basis).to_vec();
        if coefficients.iter().any(|c| *c >= MODULI[basis]) {
            return Err(Error::Shape);
        }
        let mut b = ct[0].clone();
        b.change_representation(Representation::PowerBasis);
        let b_coefficients = b.coefficients().row(basis).to_vec();
        if b_coefficients.iter().any(|v| *v >= MODULI[basis]) {
            return Err(Error::Shape);
        }
        let evaluations = oracle(
            &coefficients
                .iter()
                .copied()
                .map(Val::from_u64)
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            parameter_bytes: parameters_bytes.to_vec(),
            ciphertext_bytes: bytes.to_vec(),
            basis,
            coefficients,
            b_coefficients,
            evaluations,
        })
    }
    pub(in crate::opening) fn basis(&self) -> usize {
        self.basis
    }
    #[cfg(test)]
    pub(in crate::opening) fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }
    pub(in crate::opening) fn b_coefficients(&self) -> &[u64] {
        &self.b_coefficients
    }
    pub(in crate::opening) fn evaluations(&self) -> &[Val] {
        &self.evaluations
    }
    pub(in crate::opening) fn parameter_bytes(&self) -> &[u8] {
        &self.parameter_bytes
    }
    pub(in crate::opening) fn bytes(&self) -> &[u8] {
        &self.ciphertext_bytes
    }
}
