//! In-memory private Key opening, reusable across exclusive sequential operand jobs.
use super::{
    key_material::{self, KeyMaterial},
    operand_proof::{BoundOperand, CurrentOperand, OperandProver},
    *,
};
use bfv_ciphertext_formation::{EncodedOpening, Expected as FormationExpected};

/// Local progress only, never proof, Source or network authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofEpochStage {
    AwaitingKey,
    Ready,
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochOperandStage {
    Basis(usize),
    AwaitingFormation,
    FormationReady,
    Complete,
    Cancelled,
}

/// Retains one actual Key33/CsHat opening until cancel/drop. It has no import or recovery API.
///
/// ```compile_fail
/// use bfv_query_core::OwnerProofEpoch;
/// fn clone<T:Clone>(){} fn forbidden(){clone::<OwnerProofEpoch<'static>>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerProofEpoch;
/// fn debug<T:core::fmt::Debug>(){} fn forbidden(){debug::<OwnerProofEpoch<'static>>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerProofEpoch;
/// fn serialize<T:serde::Serialize>(){} fn forbidden(){serialize::<OwnerProofEpoch<'static>>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerProofEpoch;
/// fn import<T:for<'de> serde::Deserialize<'de>>(){} fn forbidden(){import::<OwnerProofEpoch<'static>>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerProofEpoch;
/// fn forbidden(epoch:OwnerProofEpoch<'_>){let _=epoch.material;}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerProofEpoch;
/// fn escape<'a>(epoch:OwnerProofEpoch<'a>)->OwnerProofEpoch<'static>{epoch}
/// ```
pub struct OwnerProofEpoch<'anchor> {
    anchor: &'anchor OwnerKeyAnchor<'anchor>,
    parameters: Vec<u8>,
    material: KeyMaterial,
    key_evidence: Option<bfv_key_transform::Evidence>,
    stage: ProofEpochStage,
}
impl<'owner> OwnerKeyAnchor<'owner> {
    /// Pin the complete original setup before copying a secret. No SQL/data/Source is read.
    pub fn proof_epoch<'anchor>(
        &'anchor self,
        original: &PublicSetup,
    ) -> Result<OwnerProofEpoch<'anchor>> {
        key_material::check_original(self, original)?;
        Ok(OwnerProofEpoch {
            anchor: self,
            parameters: original.parameters.clone(),
            material: KeyMaterial::new(self)?,
            key_evidence: None,
            stage: ProofEpochStage::AwaitingKey,
        })
    }
}
impl<'anchor> OwnerProofEpoch<'anchor> {
    pub fn stage(&self) -> ProofEpochStage {
        self.stage
    }
    /// A repeat cannot rerandomize CsHat or replace the original genuine Key frame.
    pub fn prove_key(&mut self) -> Result<&bfv_key_transform::Evidence> {
        if self.stage != ProofEpochStage::AwaitingKey {
            return Err(Error::ProofEpochStage);
        }
        let evidence = self
            .material
            .prove_key(self.anchor, Error::ProofEpochStage)?;
        self.key_evidence = Some(evidence);
        self.stage = ProofEpochStage::Ready;
        self.key_evidence()
    }
    /// Public proof bytes only; no private opening is exposed.
    pub fn key_evidence(&self) -> Result<&bfv_key_transform::Evidence> {
        self.key_evidence.as_ref().ok_or(Error::ProofEpochStage)
    }
    /// A separate caller-pinned request per job. Labels do not prove uniqueness or freshness.
    /// Complete ciphertext decoding precedes private per-job salt allocation/state creation.
    pub fn begin_operand<'job>(
        &'job mut self,
        request: [u8; 32],
        input: OperandInput<'_>,
    ) -> Result<OwnerEpochOperandJob<'job, 'anchor>> {
        if self.stage != ProofEpochStage::Ready {
            return Err(Error::ProofEpochStage);
        }
        let input = BoundOperand::new(&self.parameters, input.ciphertext, input.encoding)?;
        let current = CurrentOperand::new()?;
        Ok(OwnerEpochOperandJob {
            epoch: self,
            request: Some(request),
            input: Some(input),
            current: Some(current),
            stage: EpochOperandStage::Basis(0),
        })
    }
    /// Terminal explicit cleanup. Only available when no job holds the exclusive borrow.
    pub fn cancel(&mut self) {
        self.material.clear_private();
        self.key_evidence = None;
        self.stage = ProofEpochStage::Cancelled;
    }
}

/// One exclusive operand. Completion/cancel/drop clears only its own W/salts, not epoch Key33.
/// Calls are synchronous; cancellation does not interrupt an in-flight SDK computation.
///
/// ```compile_fail
/// use bfv_query_core::OwnerEpochOperandJob;
/// fn clone<T:Clone>(){} fn forbidden(){clone::<OwnerEpochOperandJob<'static,'static>>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerEpochOperandJob;
/// fn debug<T:core::fmt::Debug>(){} fn forbidden(){debug::<OwnerEpochOperandJob<'static,'static>>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerEpochOperandJob;
/// fn serialize<T:serde::Serialize>(){} fn forbidden(){serialize::<OwnerEpochOperandJob<'static,'static>>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerEpochOperandJob;
/// fn import<T:for<'de> serde::Deserialize<'de>>(){} fn forbidden(){import::<OwnerEpochOperandJob<'static,'static>>();}
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerEpochOperandJob;
/// fn forbidden(job:OwnerEpochOperandJob<'_,'_>){let _=job.current;}
/// ```
/// ```compile_fail
/// use bfv_query_core::{OwnerProofEpoch,OperandInput};
/// fn forbidden(epoch:&mut OwnerProofEpoch<'_>,a:OperandInput<'_>,b:OperandInput<'_>){
///     let first=epoch.begin_operand([1;32],a).unwrap();
///     let second=epoch.begin_operand([2;32],b).unwrap();
///     let _=(first.stage(),second.stage());
/// }
/// ```
/// ```compile_fail
/// use bfv_query_core::{OwnerEpochOperandJob,OwnerProofEpoch,OperandInput};
/// fn escape<'a>(epoch:&'a mut OwnerProofEpoch<'a>,input:OperandInput<'_>)->OwnerEpochOperandJob<'static,'static>{
///     epoch.begin_operand([1;32],input).unwrap()
/// }
/// ```
pub struct OwnerEpochOperandJob<'job, 'anchor> {
    epoch: &'job mut OwnerProofEpoch<'anchor>,
    request: Option<[u8; 32]>,
    input: Option<BoundOperand>,
    current: Option<CurrentOperand>,
    stage: EpochOperandStage,
}
impl OwnerEpochOperandJob<'_, '_> {
    pub fn stage(&self) -> EpochOperandStage {
        self.stage
    }
    fn prover(&self) -> Result<OperandProver<'_>> {
        Ok(OperandProver {
            full_setup_id: self.epoch.anchor.public.full_setup_id,
            material: &self.epoch.material,
            key: self.epoch.key_evidence()?,
            request: self.request.ok_or(Error::EpochOperandStage)?,
            input: self.input.as_ref().ok_or(Error::EpochOperandStage)?,
            current: self.current.as_ref().ok_or(Error::EpochOperandStage)?,
        })
    }
    pub fn prove_next_basis(&mut self) -> Result<bfv_basis_convolution::Evidence> {
        let EpochOperandStage::Basis(basis) = self.stage else {
            return Err(Error::EpochOperandStage);
        };
        let evidence = self.prover()?.prove_basis(basis)?;
        self.stage = if basis == 4 {
            EpochOperandStage::AwaitingFormation
        } else {
            EpochOperandStage::Basis(basis + 1)
        };
        Ok(evidence)
    }
    pub fn begin_formation(&mut self, opening: EncodedOpening) -> Result<()> {
        if self.stage != EpochOperandStage::AwaitingFormation {
            return Err(Error::EpochOperandStage);
        }
        self.current
            .as_mut()
            .ok_or(Error::EpochOperandStage)?
            .bind_opening(
                self.input.as_ref().ok_or(Error::EpochOperandStage)?,
                opening,
            )?;
        self.stage = EpochOperandStage::FormationReady;
        Ok(())
    }
    pub fn prove_formation(
        &mut self,
        expected: &FormationExpected,
        bases: [&[u8]; 5],
    ) -> Result<bfv_ciphertext_formation::Evidence> {
        if self.stage != EpochOperandStage::FormationReady {
            return Err(Error::EpochOperandStage);
        }
        let opening = self
            .current
            .as_ref()
            .and_then(|c| c.opening.as_ref())
            .ok_or(Error::EpochOperandStage)?;
        let evidence = self.prover()?.prove_formation(expected, bases, opening)?;
        self.clear_current();
        self.stage = EpochOperandStage::Complete;
        Ok(evidence)
    }
    fn clear_current(&mut self) {
        self.current = None;
        self.input = None;
        self.request = None;
    }
    pub fn cancel(&mut self) {
        self.clear_current();
        self.stage = EpochOperandStage::Cancelled;
    }
}
impl Drop for OwnerEpochOperandJob<'_, '_> {
    fn drop(&mut self) {
        self.clear_current();
    }
}
#[cfg(test)]
mod tests;
