//! Owner-local prequery association with a complete original public setup.
//! The existing KeyTransform AIR does not prove evaluation-key same-secret consistency.
use super::{Error, Owner, PublicSetup, Result, backend, keyset_id};
use bfv_key_transform::{Expected, ProverWitness, SetupDescriptor};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Stable BFV scope selected by the trusted owner application, independent of query/parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyScope {
    pub database: [u8; 16],
    pub bfv_key_domain: [u8; 16],
    pub epoch: u32,
}
/// Public association minted by the actual local Owner and independently pinned before queries.
/// Decoded peer metadata must never replace that independent pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BfvKeyAnchor {
    scope: KeyScope,
    full_setup_id: [u8; 32],
    parameter_digest: [u8; 32],
    coefficients: [u64; 4],
}
impl BfvKeyAnchor {
    pub fn scope(&self) -> &KeyScope {
        &self.scope
    }
    pub fn full_setup_id(&self) -> [u8; 32] {
        self.full_setup_id
    }
    pub fn coefficient_commitment(&self) -> [u64; 4] {
        self.coefficients
    }
    fn descriptor(&self) -> SetupDescriptor {
        SetupDescriptor {
            database: self.scope.database,
            key_domain: self.scope.bfv_key_domain,
            public_setup_digest: self.parameter_digest,
            key_epoch: self.scope.epoch,
        }
    }
    fn expected(&self) -> Expected {
        Expected {
            descriptor: self.descriptor(),
            coefficients: self.coefficients.map(bfv_hiding_stark::Val::from_u64),
        }
    }
}
/// Borrows its original Owner. No Clone, Debug, serialization, import or private getters.
/// The private salt is not persisted; recreating this handle creates another anchor.
///
/// ```compile_fail
/// use bfv_query_core::OwnerKeyAnchor;
/// fn copy<T: Clone>() {}
/// fn forbidden() { copy::<OwnerKeyAnchor<'static>>(); }
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerKeyAnchor;
/// fn inspect<T: core::fmt::Debug>() {}
/// fn forbidden() { inspect::<OwnerKeyAnchor<'static>>(); }
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerKeyAnchor;
/// fn serialize<T: serde::Serialize>() {}
/// fn forbidden() { serialize::<OwnerKeyAnchor<'static>>(); }
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerKeyAnchor;
/// fn forbidden(handle: OwnerKeyAnchor<'_>) { let _ = handle.input_salt; }
/// ```
pub struct OwnerKeyAnchor<'owner> {
    owner: &'owner Owner,
    public: BfvKeyAnchor,
    input_salt: Zeroizing<[u64; 4]>,
}
impl Owner {
    /// Check the ORIGINAL complete setup before copying any secret coefficient.
    pub fn key_anchor<'owner>(
        &'owner self,
        original: &PublicSetup,
        scope: KeyScope,
    ) -> Result<OwnerKeyAnchor<'owner>> {
        original.checked_parameters()?;
        if original.geometry != self.geometry || keyset_id(original)? != self.keyset_id {
            return Err(Error::BindingMismatch);
        }
        let parameter_digest = Sha256::digest(&original.parameters).into();
        let input_salt = Zeroizing::new(bfv_key_transform::random_salt().map_err(backend)?);
        let mut public = BfvKeyAnchor {
            scope,
            full_setup_id: self.keyset_id,
            parameter_digest,
            coefficients: [0; 4],
        };
        let coefficients = secret_coefficients(self)?;
        public.coefficients =
            bfv_key_transform::input_commitment(&public.descriptor(), &coefficients, *input_salt)
                .map_err(backend)?;
        Ok(OwnerKeyAnchor {
            owner: self,
            public,
            input_salt,
        })
    }
}
fn secret_coefficients(owner: &Owner) -> Result<Zeroizing<Vec<i8>>> {
    // No SecretKey::to_bytes: that SDK path leaves an additional unguarded proto copy.
    let wide = Zeroizing::new(fhe::proto::bfv::SecretKey::from(&owner.key).coeffs);
    if wide.len() != bfv_fixed_geometry::DEGREE || wide.iter().any(|v| !(-20..=20).contains(v)) {
        return Err(Error::ParameterProfile);
    }
    let mut narrow = Zeroizing::new(Vec::with_capacity(wide.len()));
    for value in wide.iter() {
        narrow.push(i8::try_from(*value).map_err(|_| Error::ParameterProfile)?);
    }
    Ok(narrow)
}
impl OwnerKeyAnchor<'_> {
    pub fn public_anchor(&self) -> &BfvKeyAnchor {
        &self.public
    }
    /// Fresh output salt and independent prover randomness on every call; stable input anchor.
    pub fn prove(&self) -> Result<bfv_key_transform::Evidence> {
        self.prove_with_output_salt(Zeroizing::new(
            bfv_key_transform::random_salt().map_err(backend)?,
        ))
    }
    fn prove_with_output_salt(
        &self,
        output: Zeroizing<[u64; 4]>,
    ) -> Result<bfv_key_transform::Evidence> {
        let witness =
            ProverWitness::new(secret_coefficients(self.owner)?, *self.input_salt, *output)
                .map_err(backend)?;
        bfv_key_transform::prove(self.public.full_setup_id, &self.public.expected(), &witness)
            .map_err(backend)
    }
}
impl PublicSetup {
    /// The caller supplies the trusted independently pinned public anchor.
    /// This proves the fixed transform only, not evaluation-key correctness or SQL acceptance.
    pub fn verify_key_transform(
        &self,
        expected: &BfvKeyAnchor,
        evidence: &[u8],
    ) -> Result<bfv_key_transform::VerifiedTransform> {
        self.checked_parameters()?;
        if keyset_id(self)? != expected.full_setup_id
            || <[u8; 32]>::from(Sha256::digest(&self.parameters)) != expected.parameter_digest
        {
            return Err(Error::BindingMismatch);
        }
        bfv_key_transform::verify(expected.full_setup_id, &expected.expected(), evidence)
            .map_err(backend)
    }
}
#[cfg(test)]
mod tests;

#[cfg(feature = "basis-proofs")]
mod basis_job;
#[cfg(feature = "basis-proofs")]
mod key_material;
#[cfg(feature = "basis-proofs")]
pub use basis_job::{BasisJobStage, OwnerBasisJob};

#[cfg(feature = "formation-proofs")]
pub use basis_job::{FormationJobStage, OwnerFormationJob};

#[cfg(feature = "formation-proofs")]
mod two_operand_job;
#[cfg(feature = "formation-proofs")]
pub use two_operand_job::{Operand, OperandInput, OwnerTwoOperandScope, TwoOperandStage};

#[cfg(feature = "formation-proofs")]
mod operand_proof;
#[cfg(feature = "formation-proofs")]
mod proof_epoch;
#[cfg(feature = "formation-proofs")]
pub use proof_epoch::{EpochOperandStage, OwnerEpochOperandJob, OwnerProofEpoch, ProofEpochStage};
