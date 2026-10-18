//! Two ordered public operands share one private Key opening; no SQL policy lives here.
use super::{
    key_material::{self, KeyMaterial},
    operand_proof::{BoundOperand, CurrentOperand, OperandProver},
    *,
};
#[cfg(test)]
use bfv_basis_convolution::Expected as BasisExpected;
#[cfg(test)]
use bfv_ciphertext_formation::Prerequisites;
use bfv_ciphertext_formation::{EncodedCommitment, EncodedOpening, Expected as FormationExpected};

/// Local positions only. The consumer independently binds their semantic roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    Input0,
    Input1,
}
impl Operand {
    fn index(self) -> usize {
        match self {
            Self::Input0 => 0,
            Self::Input1 => 1,
        }
    }
}
/// Caller-pinned complete ciphertext and public mathematical encoding commitment.
pub struct OperandInput<'a> {
    pub ciphertext: &'a [u8],
    pub encoding: EncodedCommitment,
}
/// Synchronous progress only; no stage is a proof, freshness or admission receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwoOperandStage {
    AwaitingKey,
    AwaitingOperands,
    Basis { operand: Operand, basis: usize },
    AwaitingFormation(Operand),
    FormationReady(Operand),
    Complete,
    Cancelled,
}
/// Owns one guarded Shat/opening and one current operand's private W/salts.
/// Calls are synchronous. Cancellation clears explicit buffers between calls;
/// native SDK/field/FFT/PCS scratch is not promised erased. Public Key bytes remain
/// available after Complete without a forced copy; cancel removes them.
///
/// ```compile_fail
/// use bfv_query_core::OwnerTwoOperandScope;
/// fn clone<T: Clone>() {} fn forbidden() { clone::<OwnerTwoOperandScope<'static>>(); }
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerTwoOperandScope;
/// fn debug<T: core::fmt::Debug>() {} fn forbidden() { debug::<OwnerTwoOperandScope<'static>>(); }
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerTwoOperandScope;
/// fn serialize<T: serde::Serialize>() {} fn forbidden() { serialize::<OwnerTwoOperandScope<'static>>(); }
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerTwoOperandScope;
/// fn forbidden(scope: OwnerTwoOperandScope<'_>) { let _ = scope.material; }
/// ```
/// ```compile_fail
/// use bfv_query_core::OwnerTwoOperandScope;
/// fn escape<'a>(scope: OwnerTwoOperandScope<'a>) -> OwnerTwoOperandScope<'static> { scope }
/// ```
pub struct OwnerTwoOperandScope<'job> {
    anchor: &'job OwnerKeyAnchor<'job>,
    parameters: Vec<u8>,
    material: KeyMaterial,
    key_evidence: Option<bfv_key_transform::Evidence>,
    operands: Option<[BoundOperand; 2]>,
    request: Option<[u8; 32]>,
    current: Option<CurrentOperand>,
    stage: TwoOperandStage,
}
impl<'owner> OwnerKeyAnchor<'owner> {
    /// Check the complete original setup before the q-independent secret copy.
    /// The scope creates no ciphertext, query, encoding or producer authority.
    pub fn two_operand_scope<'job>(
        &'job self,
        original: &PublicSetup,
    ) -> Result<OwnerTwoOperandScope<'job>> {
        key_material::check_original(self, original)?;
        Ok(OwnerTwoOperandScope {
            anchor: self,
            parameters: original.parameters.clone(),
            material: KeyMaterial::new(self)?,
            key_evidence: None,
            operands: None,
            request: None,
            current: None,
            stage: TwoOperandStage::AwaitingKey,
        })
    }
}
impl OwnerTwoOperandScope<'_> {
    pub fn stage(&self) -> TwoOperandStage {
        self.stage
    }

    /// One genuine Key proof fixes ALL33 public values, including the fresh CsHat.
    pub fn prove_key(&mut self) -> Result<&bfv_key_transform::Evidence> {
        if self.stage != TwoOperandStage::AwaitingKey {
            return Err(Error::TwoOperandStage);
        }
        let evidence = self
            .material
            .prove_key(self.anchor, Error::TwoOperandStage)?;
        self.key_evidence = Some(evidence);
        self.stage = TwoOperandStage::AwaitingOperands;
        self.key_evidence()
    }
    /// Borrow public bytes only, also after Complete. No private getters exist.
    pub fn key_evidence(&self) -> Result<&bfv_key_transform::Evidence> {
        self.key_evidence.as_ref().ok_or(Error::TwoOperandStage)
    }

    /// Bind exactly once after Key success. The caller owns q and the role mapping;
    /// neither q nor these mathematical commitments authenticate SQL or Source data.
    /// Both complete ciphertexts are checked before storing either one.
    pub fn bind_operands(
        &mut self,
        request: [u8; 32],
        inputs: [OperandInput<'_>; 2],
    ) -> Result<()> {
        if self.stage != TwoOperandStage::AwaitingOperands {
            return Err(Error::TwoOperandStage);
        }
        let [first, second] = inputs;
        let first = BoundOperand::new(&self.parameters, first.ciphertext, first.encoding)?;
        let second = BoundOperand::new(&self.parameters, second.ciphertext, second.encoding)?;
        self.operands = Some([first, second]);
        self.request = Some(request);
        self.stage = TwoOperandStage::Basis {
            operand: Operand::Input0,
            basis: 0,
        };
        Ok(())
    }
    /// One automatically ordered actual Basis proof. Callers spool public bytes;
    /// the scope retains no vector of generated proofs.
    pub fn prove_next_basis(&mut self) -> Result<bfv_basis_convolution::Evidence> {
        let TwoOperandStage::Basis { operand, basis } = self.stage else {
            return Err(Error::TwoOperandStage);
        };
        if self.current.is_none() {
            self.current = Some(CurrentOperand::new()?);
        }
        let current = self.current.as_ref().ok_or(Error::TwoOperandStage)?;
        let input = &self.operands.as_ref().ok_or(Error::TwoOperandStage)?[operand.index()];
        let evidence = OperandProver {
            full_setup_id: self.anchor.public.full_setup_id,
            material: &self.material,
            key: self.key_evidence()?,
            request: self.request.ok_or(Error::TwoOperandStage)?,
            input,
            current,
        }
        .prove_basis(basis)?;
        self.stage = if basis == 4 {
            TwoOperandStage::AwaitingFormation(operand)
        } else {
            TwoOperandStage::Basis {
                operand,
                basis: basis + 1,
            }
        };
        Ok(evidence)
    }
    /// Reject a differently committed opening before storing it or advancing.
    /// Only public metadata is inspected; W/salt remain inside EncodedOpening.
    pub fn begin_formation(&mut self, opening: EncodedOpening) -> Result<()> {
        let TwoOperandStage::AwaitingFormation(operand) = self.stage else {
            return Err(Error::TwoOperandStage);
        };
        let input = &self.operands.as_ref().ok_or(Error::TwoOperandStage)?[operand.index()];
        self.current
            .as_mut()
            .ok_or(Error::TwoOperandStage)?
            .bind_opening(input, opening)?;
        self.stage = TwoOperandStage::FormationReady(operand);
        Ok(())
    }
    /// Reverify the retained genuine Key and borrowed current five Basis proofs
    /// through the existing library BEFORE residual derivation/AIR/trace creation.
    pub fn prove_formation(
        &mut self,
        expected: &FormationExpected,
        bases: [&[u8]; 5],
    ) -> Result<bfv_ciphertext_formation::Evidence> {
        let TwoOperandStage::FormationReady(operand) = self.stage else {
            return Err(Error::TwoOperandStage);
        };
        let input = &self.operands.as_ref().ok_or(Error::TwoOperandStage)?[operand.index()];
        let current = self.current.as_ref().ok_or(Error::TwoOperandStage)?;
        let evidence = OperandProver {
            full_setup_id: self.anchor.public.full_setup_id,
            material: &self.material,
            key: self.key_evidence()?,
            request: self.request.ok_or(Error::TwoOperandStage)?,
            input,
            current,
        }
        .prove_formation(
            expected,
            bases,
            current.opening.as_ref().ok_or(Error::TwoOperandStage)?,
        )?;
        self.current = None;
        self.stage = match operand {
            Operand::Input0 => TwoOperandStage::Basis {
                operand: Operand::Input1,
                basis: 0,
            },
            Operand::Input1 => {
                self.material.clear_private();
                self.operands = None;
                self.request = None;
                TwoOperandStage::Complete
            }
        };
        Ok(evidence)
    }
    /// Terminal between-call cleanup, including retained public Key bytes.
    pub fn cancel(&mut self) {
        self.current = None;
        self.operands = None;
        self.request = None;
        self.material.clear_private();
        self.key_evidence = None;
        self.stage = TwoOperandStage::Cancelled;
    }
}
#[cfg(test)]
mod tests;
