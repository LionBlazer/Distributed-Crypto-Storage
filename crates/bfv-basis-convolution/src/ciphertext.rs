//! Bounded canonical upstream ciphertext decoding; never accepts an independent A/NTT table.
use super::N;
use bfv_hiding_stark::{Error, Val};
use bfv_key_transform::circuit::oracle;
use fhe::bfv::{BfvParameters, BfvParametersBuilder, Ciphertext};
use fhe_math::rq::Representation;
use fhe_traits::{DeserializeParametrized, Serialize};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

pub const MODULI: [u64; 5] = [
    8796092858369,
    8796092792833,
    17592186028033,
    17592185438209,
    17592184717313,
];
pub const PLAINTEXT: u64 = 114689;
pub const VARIANCE: usize = 10;
pub const MAX_PARAMETER_BYTES: usize = 1024;
// Pinned codec: 8192*(43+43+44+44+44)/8 = 223232 coefficient bytes/poly.
// Rq adds repr(2)+degree(3)+bytes tag/len(4)+variable-time(<=2) = <=11.
// Ct adds tag/len(4) per poly: <=2*(223232+11+4)=446494 at level0.
// Seeded form has one such poly + seed tag/len/32 = 223281. Both fit this cap.
pub const MAX_CIPHERTEXT_BYTES: usize = 512 * 1024;
pub const MAX_CANONICAL_UNSEEDED_BYTES: usize = 2 * (223232 + 11 + 4);
const _: () = assert!(MAX_CIPHERTEXT_BYTES >= MAX_CANONICAL_UNSEEDED_BYTES);

pub fn parameters() -> Arc<BfvParameters> {
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
pub fn setup_digest() -> [u8; 32] {
    Sha256::digest(parameters().to_bytes()).into()
}

/// Fields are private: every instance originates in the complete canonical decoder.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalCiphertext {
    parameter_bytes: Vec<u8>,
    ciphertext_bytes: Vec<u8>,
    basis: usize,
    coefficients: Vec<u64>,
    b_coefficients: Vec<u64>,
    evaluations: Vec<Val>,
}
impl CanonicalCiphertext {
    pub fn decode(parameters_bytes: &[u8], bytes: &[u8], basis: usize) -> Result<Self, Error> {
        if basis >= MODULI.len()
            || parameters_bytes.len() > MAX_PARAMETER_BYTES
            || bytes.len() > MAX_CIPHERTEXT_BYTES
            || bytes.is_empty()
        {
            return Err(Error::Shape);
        }
        crate::preflight::validate(bytes)?;
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
    /// Revalidate the SAME complete canonical wire at another fixed RNS basis.
    pub fn for_basis(&self, basis: usize) -> Result<Self, Error> {
        Self::decode(&self.parameter_bytes, &self.ciphertext_bytes, basis)
    }
    pub fn basis(&self) -> usize {
        self.basis
    }
    pub fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }
    pub fn b_coefficients(&self) -> &[u64] {
        &self.b_coefficients
    }
    pub fn evaluations(&self) -> &[Val] {
        &self.evaluations
    }
    pub fn parameter_bytes(&self) -> &[u8] {
        &self.parameter_bytes
    }
    pub fn bytes(&self) -> &[u8] {
        &self.ciphertext_bytes
    }
}
