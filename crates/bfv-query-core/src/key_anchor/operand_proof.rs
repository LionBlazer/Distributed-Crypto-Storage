//! Shared private operand lifecycle. Every child still verifies its genuine prerequisites.
use super::{key_material::KeyMaterial, *};
use bfv_basis_convolution::{CanonicalCiphertext, Expected as BasisExpected};
use bfv_ciphertext_formation::{
    EncodedCommitment, EncodedOpening, Expected as FormationExpected, Prerequisites,
};

pub(super) struct BoundOperand {
    pub(super) ciphertext: CanonicalCiphertext,
    pub(super) encoding: EncodedCommitment,
}
impl BoundOperand {
    pub(super) fn new(
        parameters: &[u8],
        ciphertext: &[u8],
        encoding: EncodedCommitment,
    ) -> Result<Self> {
        Ok(Self {
            ciphertext: CanonicalCiphertext::decode(parameters, ciphertext, 0).map_err(backend)?,
            encoding,
        })
    }
}
pub(super) struct CurrentOperand {
    pub(super) salts: Zeroizing<[[u64; 4]; 5]>,
    pub(super) noise_salt: Zeroizing<[u64; 4]>,
    pub(super) opening: Option<EncodedOpening>,
}
impl CurrentOperand {
    pub(super) fn new() -> Result<Self> {
        let mut salts = Zeroizing::new([[0; 4]; 5]);
        for salt in salts.iter_mut() {
            *salt = bfv_key_transform::random_salt().map_err(backend)?;
        }
        Ok(Self {
            salts,
            noise_salt: Zeroizing::new(bfv_key_transform::random_salt().map_err(backend)?),
            opening: None,
        })
    }
    pub(super) fn bind_opening(
        &mut self,
        input: &BoundOperand,
        opening: EncodedOpening,
    ) -> Result<()> {
        if opening.commitment() != &input.encoding {
            return Err(Error::BindingMismatch);
        }
        self.opening = Some(opening);
        Ok(())
    }
}
/// Borrowed implementation inputs only. No caller callback or accepted-proof flag.
pub(super) struct OperandProver<'a> {
    pub(super) full_setup_id: [u8; 32],
    pub(super) material: &'a KeyMaterial,
    pub(super) key: &'a bfv_key_transform::Evidence,
    pub(super) request: [u8; 32],
    pub(super) input: &'a BoundOperand,
    pub(super) current: &'a CurrentOperand,
}
impl OperandProver<'_> {
    pub(super) fn prove_basis(&self, basis: usize) -> Result<bfv_basis_convolution::Evidence> {
        let expected = BasisExpected::from_ciphertext(
            self.material.statement.clone(),
            self.input.ciphertext.for_basis(basis).map_err(backend)?,
            self.request,
        )
        .map_err(backend)?;
        let witness = bfv_basis_convolution::ProverWitness::new(
            &self.material.shat,
            *self.material.output_salt,
            self.current.salts[basis],
        )
        .map_err(backend)?;
        bfv_basis_convolution::prove(self.full_setup_id, &expected, self.key.as_bytes(), &witness)
            .map_err(backend)
    }
    pub(super) fn prove_formation(
        &self,
        expected: &FormationExpected,
        bases: [&[u8]; 5],
        opening: &EncodedOpening,
    ) -> Result<bfv_ciphertext_formation::Evidence> {
        expected.validate().map_err(backend)?;
        if expected.key().public_values() != self.material.statement.public_values()
            || expected.request() != self.request
            || expected.ciphertext().bytes() != self.input.ciphertext.bytes()
            || expected.ciphertext().parameter_bytes() != self.input.ciphertext.parameter_bytes()
            || expected.encoding() != &self.input.encoding
        {
            return Err(Error::BindingMismatch);
        }
        let witness = bfv_ciphertext_formation::ProverWitness::new(
            opening,
            &self.material.shat,
            *self.current.salts,
            *self.current.noise_salt,
        )
        .map_err(backend)?;
        let prerequisites = Prerequisites {
            key: self.key.as_bytes(),
            bases,
        };
        // The library verifies ALL Key/Basis evidence before witness preparation/AIR/trace.
        bfv_ciphertext_formation::prove(self.full_setup_id, expected, &prerequisites, &witness)
            .map_err(backend)
    }
}
