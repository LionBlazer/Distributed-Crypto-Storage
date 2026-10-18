//! Actual Owner scope for one Key and five ordered Basis components; no SQL admission.
use super::*;
use bfv_basis_convolution::{CanonicalCiphertext, Expected as BasisExpected};
use p3_field::PrimeField64;
use zeroize::Zeroize;

/// Local synchronous progress, never proof authority or network freshness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BasisJobStage {
    AwaitingKey,
    Basis(usize),
    Complete,
    Cancelled,
}
/// Borrows the independently anchored Owner scope; private openings never leave this object.
/// Cancellation is BETWEEN synchronous component calls, not interruption of SDK work.
///
/// ```compile_fail
/// use bfv_query_core::OwnerBasisJob;
/// fn clone<T: Clone>() {} fn forbidden() { clone::<OwnerBasisJob<'static>>(); }
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerBasisJob;
/// fn debug<T: core::fmt::Debug>() {} fn forbidden() { debug::<OwnerBasisJob<'static>>(); }
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerBasisJob;
/// fn serialize<T: serde::Serialize>() {} fn forbidden() { serialize::<OwnerBasisJob<'static>>(); }
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerBasisJob;
/// fn forbidden(job: OwnerBasisJob<'_>) { let _ = job.shat; }
/// ```
pub struct OwnerBasisJob<'job> {
    anchor: &'job OwnerKeyAnchor<'job>,
    ciphertext: CanonicalCiphertext,
    request: [u8; 32],
    shat: Zeroizing<Vec<u64>>,
    // Shared Key output salt, then independent result salts for bases0..4.
    salts: Zeroizing<[[u64; 4]; 6]>,
    key_witness: Option<ProverWitness>,
    key_statement: bfv_key_transform::Statement,
    key_evidence: Option<bfv_key_transform::Evidence>,
    stage: BasisJobStage,
}
impl<'owner> OwnerKeyAnchor<'owner> {
    /// The full ORIGINAL setup and complete public CT are checked before the single secret copy.
    /// `request` is caller-pinned identity, not authenticated SQL or freshness.
    pub fn basis_job<'job>(
        &'job self,
        original: &PublicSetup,
        request: [u8; 32],
        ciphertext: &[u8],
    ) -> Result<OwnerBasisJob<'job>> {
        original.checked_parameters()?;
        if original.geometry != self.owner.geometry
            || keyset_id(original)? != self.owner.keyset_id
            || self.public.full_setup_id != self.owner.keyset_id
            || <[u8; 32]>::from(Sha256::digest(&original.parameters))
                != self.public.parameter_digest
        {
            return Err(Error::BindingMismatch);
        }
        let ciphertext =
            CanonicalCiphertext::decode(&original.parameters, ciphertext, 0).map_err(backend)?;
        let coefficients = secret_coefficients(self.owner)?;
        let input = bfv_key_transform::input_commitment(
            &self.public.descriptor(),
            &coefficients,
            *self.input_salt,
        )
        .map_err(backend)?;
        if input != self.public.coefficients {
            return Err(Error::BindingMismatch);
        }
        let mut salts = Zeroizing::new([[0u64; 4]; 6]);
        for salt in salts.iter_mut() {
            *salt = bfv_key_transform::random_salt().map_err(backend)?;
        }
        // One native Shat derivation outside the actual Key trace (whose NTT steps remain real).
        let signed: Vec<_> = coefficients
            .iter()
            .copied()
            .map(bfv_key_transform::signed)
            .collect();
        let evaluations = bfv_key_transform::circuit::oracle(&signed);
        drop(signed);
        let shat: Zeroizing<Vec<u64>> =
            Zeroizing::new(evaluations.iter().map(|v| v.as_canonical_u64()).collect());
        let mut key_statement = bfv_key_transform::Statement {
            expected: self.public.expected(),
            transformed: [bfv_hiding_stark::Val::ZERO; 4],
        };
        key_statement.transformed = bfv_key_transform::circuit::digest(
            key_statement.contexts()[1],
            salts[0].map(bfv_hiding_stark::Val::from_u64),
            &evaluations,
        );
        drop(evaluations);
        let key_witness =
            ProverWitness::new(coefficients, *self.input_salt, salts[0]).map_err(backend)?;
        Ok(OwnerBasisJob {
            anchor: self,
            ciphertext,
            request,
            shat,
            salts,
            key_witness: Some(key_witness),
            key_statement,
            key_evidence: None,
            stage: BasisJobStage::AwaitingKey,
        })
    }
}
impl OwnerBasisJob<'_> {
    pub fn stage(&self) -> BasisJobStage {
        self.stage
    }
    /// Produce exactly one matching Key. A repeat is an error and never replaces CsHat.
    pub fn prove_key(&mut self) -> Result<&bfv_key_transform::Evidence> {
        if self.stage != BasisJobStage::AwaitingKey {
            return Err(Error::BasisJobStage);
        }
        let witness = self.key_witness.as_ref().ok_or(Error::BasisJobStage)?;
        let evidence = bfv_key_transform::prove_statement(
            self.anchor.public.full_setup_id,
            &self.anchor.public.expected(),
            &self.key_statement,
            witness,
        )
        .map_err(backend)?;
        // No state mutation until the actual proof, self-verification and bounded encoding succeed.
        self.key_evidence = Some(evidence);
        self.key_witness = None; // drops guarded coefficients immediately after Key success.
        self.stage = BasisJobStage::Basis(0);
        self.key_evidence.as_ref().ok_or(Error::BasisJobStage)
    }
    /// Public retained Key bytes only; no witness/private opening accessor.
    pub fn key_evidence(&self) -> Result<&bfv_key_transform::Evidence> {
        self.key_evidence.as_ref().ok_or(Error::BasisJobStage)
    }
    /// Exact auto-ordinal0..4. Completed/missing/cancelled prefixes never regenerate.
    pub fn prove_next_basis(&mut self) -> Result<bfv_basis_convolution::Evidence> {
        let BasisJobStage::Basis(index) = self.stage else {
            return Err(Error::BasisJobStage);
        };
        let key = self.key_evidence.as_ref().ok_or(Error::BasisJobStage)?;
        let ciphertext = self.ciphertext.for_basis(index).map_err(backend)?;
        let expected =
            BasisExpected::from_ciphertext(self.key_statement.clone(), ciphertext, self.request)
                .map_err(backend)?;
        let witness = bfv_basis_convolution::ProverWitness::new(
            &self.shat,
            self.salts[0],
            self.salts[index + 1],
        )
        .map_err(backend)?;
        let evidence = bfv_basis_convolution::prove(
            self.anchor.public.full_setup_id,
            &expected,
            key.as_bytes(),
            &witness,
        )
        .map_err(backend)?;
        self.stage = if index == 4 {
            BasisJobStage::Complete
        } else {
            BasisJobStage::Basis(index + 1)
        };
        Ok(evidence)
    }
    /// Terminal between-call cancellation. Explicit guarded material is cleared; native SDK
    /// temporaries are not promised erased. No private-state persistence/recovery exists.
    pub fn cancel(&mut self) {
        self.key_witness = None;
        self.key_evidence = None;
        self.shat.zeroize();
        self.shat.clear();
        self.salts.zeroize();
        self.stage = BasisJobStage::Cancelled;
    }
}
impl PublicSetup {
    /// Independently pin original setup, owner anchor, q, COMPLETE CT and basis.
    /// One successful component never means complete formation or a SQL answer.
    pub fn verify_basis_convolution(
        &self,
        anchor: &BfvKeyAnchor,
        request: [u8; 32],
        ciphertext: &[u8],
        basis: usize,
        key: &[u8],
        evidence: &[u8],
    ) -> Result<bfv_basis_convolution::VerifiedBasis> {
        self.checked_parameters()?;
        if keyset_id(self)? != anchor.full_setup_id
            || <[u8; 32]>::from(Sha256::digest(&self.parameters)) != anchor.parameter_digest
        {
            return Err(Error::BindingMismatch);
        }
        let input =
            bfv_basis_convolution::PublicInput::new(&self.parameters, ciphertext, request, basis)
                .map_err(backend)?;
        bfv_basis_convolution::verify_with_key(
            anchor.full_setup_id,
            &anchor.expected(),
            &input,
            key,
            evidence,
        )
        .map_err(backend)
    }
}
#[cfg(test)]
mod tests;

#[cfg(feature = "formation-proofs")]
mod formation_job;
#[cfg(feature = "formation-proofs")]
pub use formation_job::{FormationJobStage, OwnerFormationJob};
