//! Opaque formation continuation. The explicit W opening is not a verified SQL producer.
use super::*;
use bfv_ciphertext_formation::{EncodedOpening, Expected as FormationExpected, Prerequisites};
use fhe::bfv::{Ciphertext, Encoding, Plaintext};
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormationJobStage {
    Ready,
    Complete,
    Cancelled,
}
/// Consumes a completed actual Owner Key+five Basis job. No private openings are exported.
///
/// ```compile_fail
/// use bfv_query_core::OwnerFormationJob;
/// fn clone<T:Clone>(){} fn forbidden(){clone::<OwnerFormationJob<'static>>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerFormationJob;
/// fn debug<T:core::fmt::Debug>(){} fn forbidden(){debug::<OwnerFormationJob<'static>>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerFormationJob;
/// fn serialize<T:serde::Serialize>(){} fn forbidden(){serialize::<OwnerFormationJob<'static>>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerFormationJob;
/// fn forbidden(job:OwnerFormationJob<'_>){let _=job.opening;}
/// ```
pub struct OwnerFormationJob<'job> {
    basis: OwnerBasisJob<'job>,
    opening: Option<EncodedOpening>,
    noise_salt: Zeroizing<[u64; 4]>,
    stage: FormationJobStage,
}
impl<'job> OwnerBasisJob<'job> {
    /// Complete-only consuming transition. Invalid input consumes/drops the owned job;
    /// it cannot turn an incomplete prefix into public proof authority.
    pub fn into_formation(self, opening: EncodedOpening) -> Result<OwnerFormationJob<'job>> {
        if self.stage != BasisJobStage::Complete {
            return Err(Error::BasisJobStage);
        }
        let noise_salt = Zeroizing::new(bfv_key_transform::random_salt().map_err(backend)?);
        Ok(OwnerFormationJob {
            basis: self,
            opening: Some(opening),
            noise_salt,
            stage: FormationJobStage::Ready,
        })
    }
}
impl OwnerFormationJob<'_> {
    pub fn stage(&self) -> FormationJobStage {
        self.stage
    }
    /// ALL actual Key/Basis prerequisites are independently reverified by the reusable producer
    /// before residual derivation, AIR and trace creation. R200 admission remains consumer-owned.
    pub fn prove(
        &mut self,
        expected: &FormationExpected,
        p: &Prerequisites<'_>,
    ) -> Result<bfv_ciphertext_formation::Evidence> {
        if self.stage != FormationJobStage::Ready {
            return Err(Error::FormationJobStage);
        }
        if expected.key().public_values() != self.basis.key_statement.public_values()
            || expected.request() != self.basis.request
            || expected.ciphertext().bytes() != self.basis.ciphertext.bytes()
            || expected.ciphertext().parameter_bytes() != self.basis.ciphertext.parameter_bytes()
        {
            return Err(Error::BindingMismatch);
        }
        let witness = bfv_ciphertext_formation::ProverWitness::new(
            self.opening.as_ref().ok_or(Error::FormationJobStage)?,
            &self.basis.shat,
            core::array::from_fn(|i| self.basis.salts[i + 1]),
            *self.noise_salt,
        )
        .map_err(backend)?;
        let evidence = bfv_ciphertext_formation::prove(
            self.basis.anchor.public.full_setup_id,
            expected,
            p,
            &witness,
        )
        .map_err(backend)?;
        // No completed state is published until actual proof/selfverify/canonical encoding succeeds.
        drop(witness);
        self.opening = None;
        self.basis.cancel();
        self.noise_salt.zeroize();
        self.stage = FormationJobStage::Complete;
        Ok(evidence)
    }
    /// Synchronous between-call cancellation only. Native field/FFT/SDK memory is not promised erased.
    pub fn cancel(&mut self) {
        self.opening = None;
        self.basis.cancel();
        self.noise_salt.zeroize();
        self.stage = FormationJobStage::Cancelled;
    }
}
impl OwnerKeyAnchor<'_> {
    /// Encrypt caller-owned SCALED polynomial coefficients W; no query/Source authority is inferred.
    /// Full original setup and shape guards run before conversion or SDK encryption.
    pub fn encrypt_encoded_coefficients(
        &self,
        original: &PublicSetup,
        coefficients: &[u64],
    ) -> Result<Vec<u8>> {
        original.checked_parameters()?;
        if original.geometry != self.owner.geometry
            || keyset_id(original)? != self.owner.keyset_id
            || self.public.full_setup_id != self.owner.keyset_id
            || <[u8; 32]>::from(Sha256::digest(&original.parameters))
                != self.public.parameter_digest
        {
            return Err(Error::BindingMismatch);
        }
        if coefficients.len() != bfv_fixed_geometry::DEGREE
            || coefficients
                .iter()
                .any(|w| *w >= bfv_fixed_geometry::PLAINTEXT)
        {
            return Err(Error::InvalidShape);
        }
        // SDK to_poly multiplies m by Qmodt=78307 modulo t BEFORE delta. Recover m, not SIMD slots.
        let modulus = bfv_fixed_geometry::PLAINTEXT;
        let (mut inverse, mut base, mut exponent) = (1u64, 78307u64, modulus - 2);
        while exponent != 0 {
            if exponent & 1 != 0 {
                inverse = inverse * base % modulus;
            }
            base = base * base % modulus;
            exponent >>= 1;
        }
        let unscaled = Zeroizing::new(
            coefficients
                .iter()
                .map(|w| *w * inverse % modulus)
                .collect::<Vec<_>>(),
        );
        let plaintext = Plaintext::try_encode(
            unscaled.as_slice(),
            Encoding::poly_at_level(0),
            &self.owner.parameters,
        )
        .map_err(backend)?;
        let ciphertext: Ciphertext = self
            .owner
            .key
            .try_encrypt(&plaintext, &mut rand::rng())
            .map_err(backend)?;
        Ok(ciphertext.to_bytes())
    }
}
impl PublicSetup {
    /// Independently pinned mathematical formation only, not an encrypted SQL answer admission.
    pub fn verify_ciphertext_formation(
        &self,
        anchor: &BfvKeyAnchor,
        expected: &FormationExpected,
        p: &Prerequisites<'_>,
        bytes: &[u8],
    ) -> Result<bfv_ciphertext_formation::VerifiedFormation> {
        self.checked_parameters()?;
        if keyset_id(self)? != anchor.full_setup_id
            || <[u8; 32]>::from(Sha256::digest(&self.parameters)) != anchor.parameter_digest
            || expected.key().expected != anchor.expected()
            || expected.ciphertext().parameter_bytes() != self.parameters.as_slice()
        {
            return Err(Error::BindingMismatch);
        }
        bfv_ciphertext_formation::verify(anchor.full_setup_id, expected, p, bytes).map_err(backend)
    }
}
#[cfg(test)]
mod tests;
