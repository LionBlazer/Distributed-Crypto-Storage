//! Owner-only BEGIN/End products. All banks remain historical candidates.
mod completion;
mod produce;
use super::*;
pub use completion::{CompletedJointControl, JointControlOutcome};
use registry200_finality::joint::{ControlExpectation, VerifiedJointControl};
use registry200_proof::{
    control_kind,
    lifecycle::circuit::model::{Command, Operation},
};
use work_finality::consensus::Context;

/// Independently pinned historical Active parent. Registry Bootstrap is a
/// separate required producer; WorkGenesis alone never supplies an Active bank.
pub struct JointControlParent {
    binding: JointBinding,
    verified: VerifiedJointParent,
    context: Context,
}
impl JointControlParent {
    pub fn from_verified(
        parent: &VerifiedJointParent,
        binding: &JointBinding,
        current: &Context,
    ) -> crate::Result<Self> {
        if parent.binding_id() != binding.id()
            || parent.application_descriptor().encode() != binding.application_descriptor().encode()
            || parent.head().genesis != binding.journal_genesis().id().map_err(cryptography)?
            || parent.head().database != binding.journal_genesis().database
            || !matches!(parent.control(), Control::Active { .. })
            || current.rules().id() != binding.rules().id()
            || current.network_id() != binding.work_genesis().id()
            || current.journal_genesis() != parent.head().genesis
            || current.slot()
                != parent
                    .slot()
                    .checked_add(1)
                    .ok_or_else(|| invalid("Joint slot exhausted"))?
            || current.previous_decision() != parent.decision_id()
        {
            return Err(invalid(
                "Joint control parent differs from independent installation/context",
            ));
        }
        let _ = JointApplication::new(
            binding.application_descriptor().clone(),
            binding.journal_genesis(),
        )
        .map_err(cryptography)?;
        Ok(Self {
            binding: binding.clone(),
            verified: parent.clone(),
            context: current.clone(),
        })
    }
    pub fn head(&self) -> HeadRef {
        self.verified.head()
    }
    fn require_stamp(
        &self,
        binding: &JointBinding,
        parent: &VerifiedJointParent,
        context: [u8; 32],
    ) -> crate::Result<()> {
        if binding.id() != self.binding.id()
            || binding.application_descriptor().encode()
                != self.binding.application_descriptor().encode()
            || parent.head() != self.verified.head()
            || parent.slot() != self.verified.slot()
            || parent.decision_id() != self.verified.decision_id()
            || parent.control() != self.verified.control()
            || parent.binding_id() != self.verified.binding_id()
            || context != self.context.id()
        {
            return Err(invalid(
                "Owner opening belongs to a different exact Joint parent/context",
            ));
        }
        Ok(())
    }
}
/// Canonical owner-private preimage, NOT a verified/current bank. Every producer
/// reloads real Source and rehashes both roots before proof/FHE. Consumed on error.
/// ```compile_fail
/// fn clone<T:Clone>(){} fn forbidden(){clone::<storage_client::private_predicate::JointRegistryOpening>();}
/// ```
/// ```compile_fail
/// fn debug<T:core::fmt::Debug>(){} fn forbidden(){debug::<storage_client::private_predicate::JointRegistryOpening>();}
/// ```
/// ```compile_fail
/// fn leak(x:storage_client::private_predicate::JointRegistryOpening){let _=x.registry;}
/// ```
pub struct JointRegistryOpening {
    binding: JointBinding,
    parent: VerifiedJointParent,
    context: [u8; 32],
    registry: Zeroizing<Registry>,
    controllers: Zeroizing<[[u8; 32]; 2]>,
    salts: Zeroizing<[[u64; 4]; 2]>,
}
impl JointRegistryOpening {
    pub fn from_private_parts(
        parent: &JointControlParent,
        registry: Registry,
        controllers: [[u8; 32]; 2],
        salts: [[u64; 4]; 2],
    ) -> crate::Result<Self> {
        let registry = Zeroizing::new(registry);
        let controllers = Zeroizing::new(controllers);
        let salts = Zeroizing::new(salts);
        registry.require_canonical().map_err(cryptography)?;
        if controllers.contains(&[0; 32]) || salts.iter().flatten().any(|v| *v >= Val::ORDER_U64) {
            return Err(invalid("Invalid private Joint Registry opening"));
        }
        Ok(Self {
            binding: parent.binding.clone(),
            parent: parent.verified.clone(),
            context: parent.context.id(),
            registry,
            controllers,
            salts,
        })
    }
    pub(super) fn from_completed(
        binding: JointBinding,
        parent: VerifiedJointParent,
        context: [u8; 32],
        registry: Zeroizing<Registry>,
        controllers: Zeroizing<[[u8; 32]; 2]>,
        salts: Zeroizing<[[u64; 4]; 2]>,
    ) -> Self {
        Self {
            binding,
            parent,
            context,
            registry,
            controllers,
            salts,
        }
    }
    /// Select by stable transaction ID. Failed actors still fail the unchanged
    /// strict Acquire constructor. No unbound LockingControl escapes this owner.
    pub fn for_acquire(
        self,
        parent: &JointControlParent,
        transaction: u64,
        principal: u8,
    ) -> crate::Result<JointOwnedLockingControl> {
        parent.require_stamp(&self.binding, &self.parent, self.context)?;
        let sequence = self
            .registry
            .transactions
            .iter()
            .find(|tx| tx.id == transaction)
            .ok_or_else(|| invalid("Acquire transaction is absent"))?
            .sequence;
        let actor = LockingActor::new(transaction, principal, self.registry.revision, sequence)?;
        let Self {
            binding,
            parent,
            context,
            mut registry,
            controllers,
            salts,
        } = self;
        let control =
            LockingControl::new(core::mem::take(&mut *registry), *controllers, *salts, actor)?;
        Ok(JointOwnedLockingControl {
            binding,
            parent,
            context,
            control,
        })
    }
}
/// Exact historical owner stamp and private bank travel together.
/// ```compile_fail
/// fn extract(c: storage_client::private_predicate::JointOwnedLockingControl) {
///     let _ = c.control;
/// }
/// ```
pub struct JointOwnedLockingControl {
    binding: JointBinding,
    parent: VerifiedJointParent,
    context: [u8; 32],
    control: LockingControl,
}
impl JointOwnedLockingControl {
    fn checked_parent(
        &self,
        parent: &JointControlParent,
        bfv: &BfvContext<'_>,
        epoch: &OwnerProofEpoch<'_>,
    ) -> crate::Result<JointLockingParent> {
        parent.require_stamp(&self.binding, &self.parent, self.context)?;
        JointLockingParent::from_verified(
            &parent.verified,
            &parent.binding,
            BfvContext {
                owner: bfv.owner,
                setup: bfv.setup,
                anchor: bfv.anchor,
            },
            epoch,
        )
    }
}
/// Owner-selected recovery destination for the same exact historical control
/// parent. It grants no persistence, global-once completion or current lease.
pub struct JointOwnedRecovery<'a> {
    parent: &'a JointControlParent,
    identity: &'a JointRecoveryIdentity,
    key: &'a JointRecoveryKey,
}
impl<'a> JointOwnedRecovery<'a> {
    pub fn new(
        parent: &'a JointControlParent,
        identity: &'a JointRecoveryIdentity,
        key: &'a JointRecoveryKey,
    ) -> Self {
        Self {
            parent,
            identity,
            key,
        }
    }
}
impl crate::private_predicate::SourceOwner {
    pub fn prepare_joint_locking_owned(
        &self,
        bfv: BfvContext<'_>,
        epoch: &mut OwnerProofEpoch<'_>,
        fetched: FetchedSource<'_>,
        compiled: &CompiledLockingSelect,
        parent: &JointControlParent,
        control: JointOwnedLockingControl,
    ) -> crate::Result<JointLockingPreparation> {
        let checked = control.checked_parent(parent, &bfv, epoch)?;
        self.prepare_joint_locking(bfv, epoch, fetched, compiled, &checked, control.control)
    }

    /// Preserve the owned parent's full stamp before extracting its private
    /// control into the same real producer and encrypted recovery capture.
    pub fn prepare_joint_locking_owned_recoverable(
        &self,
        bfv: BfvContext<'_>,
        epoch: &mut OwnerProofEpoch<'_>,
        fetched: FetchedSource<'_>,
        compiled: &CompiledLockingSelect,
        control: JointOwnedLockingControl,
        recovery: JointOwnedRecovery<'_>,
    ) -> crate::Result<RecoverableJointLockingPreparation> {
        let checked = control.checked_parent(recovery.parent, &bfv, epoch)?;
        self.prepare_joint_locking_recoverable(
            bfv,
            epoch,
            fetched,
            compiled,
            control.control,
            JointRecovery::new(&checked, recovery.identity, recovery.key),
        )
    }
}
#[derive(Clone, Copy)]
pub enum JointEndDisposition {
    Close,
    Abort,
}
#[derive(Clone, Copy)]
enum IntentKind {
    Begin,
    End(JointEndDisposition),
}
/// Caller-local intent only. The nonce must be fresh and independent; no public
/// hash of low-entropy opcode/transaction is used as a secret commitment.
pub struct JointControlIntent {
    kind: IntentKind,
    transaction: u64,
    principal: u8,
    nonce: [u8; 32],
}
impl JointControlIntent {
    pub fn begin(transaction: u64, principal: u8, nonce: [u8; 32]) -> crate::Result<Self> {
        Self::new(IntentKind::Begin, transaction, principal, nonce)
    }
    pub fn end(
        transaction: u64,
        principal: u8,
        disposition: JointEndDisposition,
        nonce: [u8; 32],
    ) -> crate::Result<Self> {
        Self::new(IntentKind::End(disposition), transaction, principal, nonce)
    }
    fn new(
        kind: IntentKind,
        transaction: u64,
        principal: u8,
        nonce: [u8; 32],
    ) -> crate::Result<Self> {
        if transaction == 0 || !(1..=2).contains(&principal) {
            return Err(invalid("Invalid Joint control intent"));
        }
        Ok(Self {
            kind,
            transaction,
            principal,
            nonce,
        })
    }
    fn command(&self, registry: &Registry) -> crate::Result<Command> {
        let mut command = match self.kind {
            IntentKind::Begin => {
                Command::control(Operation::Begin, self.transaction, self.principal, 0)
            }
            IntentKind::End(disposition) => {
                let tx = registry
                    .transactions
                    .iter()
                    .find(|tx| tx.id == self.transaction)
                    .ok_or_else(|| invalid("End transaction is absent"))?;
                if tx.principal != self.principal {
                    return Err(invalid("End principal differs"));
                }
                let mut c = Command::control(
                    Operation::End,
                    self.transaction,
                    self.principal,
                    tx.sequence,
                );
                c.abort = matches!(disposition, JointEndDisposition::Abort);
                c
            }
        };
        command.require_shape().map_err(cryptography)?;
        // The actual state machine checks allocator, revision overflow, failed
        // End semantics and stable-ID removal. No caller-selected successor.
        command.mask.zeroize();
        Ok(command)
    }
}
impl Drop for JointControlIntent {
    fn drop(&mut self) {
        self.transaction.zeroize();
        self.principal.zeroize();
        self.kind = IntentKind::Begin;
    }
}
pub struct PreparedJointControl {
    request: JointRequest,
    lifecycle: lifecycle::Evidence,
    kind: control_kind::Evidence,
    candidate: JointControlCandidate,
}
impl PreparedJointControl {
    pub fn request(&self) -> &JointRequest {
        &self.request
    }
    pub fn lifecycle(&self) -> &lifecycle::Evidence {
        &self.lifecycle
    }
    pub fn kind(&self) -> &control_kind::Evidence {
        &self.kind
    }
    pub fn into_parts(
        self,
    ) -> (
        JointRequest,
        lifecycle::Evidence,
        control_kind::Evidence,
        JointControlCandidate,
    ) {
        (self.request, self.lifecycle, self.kind, self.candidate)
    }
}
pub struct JointControlCandidate {
    parent: JointControlParent,
    request: Vec<u8>,
    statement: lifecycle::statement::Statement,
    command: Zeroizing<Command>,
    command_salt: Zeroizing<[u64; 4]>,
    result_salt: Zeroizing<[u64; 4]>,
    revision: Zeroizing<u64>,
    table: Zeroizing<[u8; 32]>,
    row_ids: Zeroizing<[[u8; 32]; 4]>,
    next: Zeroizing<Registry>,
    controllers: Zeroizing<[[u8; 32]; 2]>,
    salts: Zeroizing<[[u64; 4]; 2]>,
    outcome: Zeroizing<u8>,
}
impl JointControlCandidate {
    pub fn expectation(
        &self,
        manifest: registry200_joint::Manifest,
    ) -> crate::Result<ControlExpectation> {
        let request = JointRequest::decode(&self.request).map_err(cryptography)?;
        ControlExpectation::new(
            &self.parent.binding,
            &self.parent.verified,
            &self.parent.context,
            &request,
            &self.statement,
            manifest,
        )
        .map_err(cryptography)
    }
}
#[cfg(test)]
mod tests;
