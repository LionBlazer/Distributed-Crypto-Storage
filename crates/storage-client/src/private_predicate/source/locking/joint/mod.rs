//! Owner-side preparation for the distinct Joint application. No SQL/lock grant.
mod bootstrap;
mod completion;
pub use bootstrap::{CompletedJointBootstrap, JointBootstrapCandidate, PreparedJointBootstrap};
mod control;
mod private_state_codec;
pub use control::{
    CompletedJointControl, JointControlCandidate, JointControlIntent, JointControlOutcome,
    JointControlParent, JointEndDisposition, JointOwnedLockingControl, JointOwnedRecovery,
    JointRegistryOpening, PreparedJointControl,
};
pub(super) mod vault;
use super::*;
use crate::private_predicate::{BfvContext, FetchedSource};
use bfv_query_core::{OwnerProofEpoch, ProofEpochStage};
pub use completion::{CompletedJointAcquire, CompletedJointRow};
use registry200_finality::joint::{JointBinding, VerifiedJointParent};
use registry200_joint::{
    Application as JointApplication, Descriptor, Lane, Request as JointRequest,
};
use registry200_journal::ApplicationDescriptor;
pub use vault::{
    EncryptedJointRecovery, JOINT_RECOVERY_BYTES, JOINT_RECOVERY_HEADER_BYTES, JointRecovery,
    JointRecoveryIdentity, JointRecoveryInputs, JointRecoveryKey, JointSqlCall, JointSqlClient,
    JointSqlClientBinding, JointSqlHost, JointSqlHostPins, JointSqlNetworkConfig,
    JointSqlNetworkError, JointSqlNetworkHost, JointSqlNetworkInput, JointSqlNetworkOutcome,
    JointSqlNetworkPending, JointSqlPreparation, JointSqlReply, RecoverableJointLockingInputs,
    RecoverableJointLockingPreparation, RecoveredJointComputePrepared,
    joint_sql_host_profile_digest,
};

/// Historical actual Joint proof+QC lineage matched to independent local pins.
/// This does not certify that no later finalized state exists.
///
/// ```compile_fail
/// use storage_client::private_predicate::JointLockingParent;
/// fn forge() { let _ = JointLockingParent { enrollment: [0;32] }; }
/// ```
/// ```compile_fail
/// fn forge(h: version_journal::HeadRef) {
///     let _: storage_client::private_predicate::JointLockingParent = h.into();
/// }
/// ```
pub struct JointLockingParent {
    binding: JointBinding,
    verified: VerifiedJointParent,
    spec: Application,
    enrollment: [u8; 32],
    registry: [u8; 32],
}
impl JointLockingParent {
    /// No generic Journal/raw root constructor exists. Setup, anchor and Ready
    /// epoch are caller-owned and cannot be selected by a responding peer.
    pub fn from_verified(
        parent: &VerifiedJointParent,
        expected: &JointBinding,
        bfv: BfvContext<'_>,
        epoch: &OwnerProofEpoch<'_>,
    ) -> crate::Result<Self> {
        let descriptor = expected.application_descriptor();
        let spec = descriptor.source_spec().map_err(cryptography)?;
        let genesis = expected.journal_genesis().id().map_err(cryptography)?;
        if parent.binding_id() != expected.id()
            || parent.application_id() != descriptor.id()
            || parent.application_descriptor().encode() != descriptor.encode()
            || parent.head().genesis != genesis
            || parent.head().database != spec.database
        {
            return Err(invalid(
                "Joint parent differs from the independently pinned installation",
            ));
        }
        JointApplication::new(descriptor.clone(), expected.journal_genesis())
            .map_err(cryptography)?;
        let Control::Active {
            enrollment,
            registry,
        } = parent.control()
        else {
            return Err(invalid("Joint locking requires an active Registry parent"));
        };
        let candidate = Self {
            binding: expected.clone(),
            verified: parent.clone(),
            spec,
            enrollment,
            registry,
        };
        candidate.require_ready(&bfv, epoch)?;
        Ok(candidate)
    }
    pub fn head(&self) -> HeadRef {
        self.verified.head()
    }
    pub fn binding_id(&self) -> [u8; 32] {
        self.binding.id()
    }
    pub(super) fn source_spec(&self) -> &Application {
        &self.spec
    }
    pub(super) fn enrollment(&self) -> [u8; 32] {
        self.enrollment
    }
    pub(super) fn registry(&self) -> [u8; 32] {
        self.registry
    }
    pub(super) fn require_object(&self, object: [u8; 32]) -> crate::Result<()> {
        if object != self.binding.application_descriptor().source_object() {
            return Err(invalid(
                "Fetched Source object differs from the independent Joint descriptor",
            ));
        }
        Ok(())
    }
    pub(super) fn require_key(
        &self,
        bfv: &BfvContext<'_>,
        key: &bfv_key_transform::Statement,
    ) -> crate::Result<()> {
        bfv.owner
            .require_public_setup(bfv.setup)
            .map_err(cryptography)?;
        let descriptor = self.binding.application_descriptor();
        let actual = Descriptor::checked(
            ApplicationDescriptor::from_application(&self.spec).map_err(cryptography)?,
            descriptor.source_object(),
            bfv.setup,
            bfv.anchor,
            key,
        )
        .map_err(cryptography)?;
        if actual.encode() != descriptor.encode() {
            return Err(invalid(
                "Joint BFV setup/anchor/full Key33 differs from the independent descriptor",
            ));
        }
        Ok(())
    }
    fn require_ready(
        &self,
        bfv: &BfvContext<'_>,
        epoch: &OwnerProofEpoch<'_>,
    ) -> crate::Result<()> {
        if epoch.stage() != ProofEpochStage::Ready {
            return Err(invalid("Joint owner epoch must already be Ready"));
        }
        bfv.owner
            .require_public_setup(bfv.setup)
            .map_err(cryptography)?;
        let checked = bfv
            .setup
            .verify_key_transform(
                bfv.anchor,
                epoch.key_evidence().map_err(cryptography)?.as_bytes(),
            )
            .map_err(cryptography)?;
        self.require_key(bfv, checked.statement())
    }
    fn application(&self) -> crate::Result<JointApplication> {
        JointApplication::new(
            self.binding.application_descriptor().clone(),
            self.binding.journal_genesis(),
        )
        .map_err(cryptography)
    }
}

/// Guarded candidates with one-shot verified completion; no installation,
/// serialization or import.
///
/// ```compile_fail
/// use storage_client::private_predicate::JointLockingCandidates;
/// fn clone<T:Clone>() {} fn forbidden() { clone::<JointLockingCandidates>(); }
/// ```
/// ```compile_fail
/// use storage_client::private_predicate::JointLockingCandidates;
/// fn debug<T:core::fmt::Debug>() {} fn forbidden() { debug::<JointLockingCandidates>(); }
/// ```
pub struct JointLockingCandidates {
    _completion: LockingCompletion,
    _staged: StagedLockingTransition,
    _binding: JointBinding,
    _parent: VerifiedJointParent,
    _outer_request: Vec<u8>,
}

/// Actual mathematical products for one exact historical Joint parent. The
/// private completion/staged banks are move-only and have no install method.
///
/// ```compile_fail
/// use storage_client::private_predicate::PreparedJointLockingInputs;
/// fn clone<T:Clone>() {} fn forbidden() { clone::<PreparedJointLockingInputs>(); }
/// ```
pub struct PreparedJointLockingInputs {
    prepared: PreparedLockingInputs,
    request: JointRequest,
    binding: JointBinding,
    parent: VerifiedJointParent,
    outer_request: Vec<u8>,
}
impl PreparedJointLockingInputs {
    pub fn inputs(&self) -> &ProducedInputs {
        &self.prepared.inputs
    }
    pub fn lifecycle(&self) -> &lifecycle::Evidence {
        &self.prepared.lifecycle
    }
    pub fn link(&self) -> &predicate_acquire::Evidence {
        &self.prepared.link
    }
    pub fn request(&self) -> &JointRequest {
        &self.request
    }
    pub fn into_parts(
        self,
    ) -> (
        ProducedInputs,
        lifecycle::Evidence,
        predicate_acquire::Evidence,
        JointRequest,
        JointLockingCandidates,
    ) {
        let PreparedLockingInputs {
            inputs,
            lifecycle,
            link,
            request: _,
            completion,
            staged,
            recovery: _,
        } = self.prepared;
        (
            inputs,
            lifecycle,
            link,
            self.request,
            JointLockingCandidates {
                _completion: completion,
                _staged: staged,
                _binding: self.binding,
                _parent: self.parent,
                _outer_request: self.outer_request,
            },
        )
    }
}
pub struct NonAdmittedJointLocking {
    outcome: LockingConflict,
    request: JointRequest,
    lifecycle: lifecycle::Evidence,
}
impl NonAdmittedJointLocking {
    pub fn outcome(&self) -> LockingConflict {
        self.outcome
    }
    pub fn request(&self) -> &JointRequest {
        &self.request
    }
    pub fn lifecycle(&self) -> &lifecycle::Evidence {
        &self.lifecycle
    }
}
pub enum JointLockingPreparation {
    Prepared(Box<PreparedJointLockingInputs>),
    NonAdmitted(Box<NonAdmittedJointLocking>),
}

impl crate::private_predicate::SourceOwner {
    /// Load ALL originals and verify the exact private control openings before
    /// FHE, reusing the existing private mathematical producer. No network I/O,
    /// consensus advancement, output completion or owner state installation.
    pub fn prepare_joint_locking(
        &self,
        bfv: BfvContext<'_>,
        epoch: &mut OwnerProofEpoch<'_>,
        fetched: FetchedSource<'_>,
        compiled: &CompiledLockingSelect,
        parent: &JointLockingParent,
        control: LockingControl,
    ) -> crate::Result<JointLockingPreparation> {
        self.prepare_joint_inner(
            bfv,
            epoch,
            fetched,
            compiled,
            control,
            PreparationRoute {
                parent: PreparationParent::Joint(parent),
                recovery: None,
            },
        )
    }
    fn prepare_joint_inner(
        &self,
        bfv: BfvContext<'_>,
        epoch: &mut OwnerProofEpoch<'_>,
        fetched: FetchedSource<'_>,
        compiled: &CompiledLockingSelect,
        control: LockingControl,
        route: PreparationRoute<'_>,
    ) -> crate::Result<JointLockingPreparation> {
        let PreparationParent::Joint(parent) = &route.parent else {
            return Err(invalid(
                "Joint preparation requires its closed parent route",
            ));
        };
        parent.require_ready(&bfv, epoch)?;
        let prepared = self.prepare_with_parent(bfv, epoch, fetched, compiled, &route, control)?;
        let app = parent.application()?;
        Ok(match prepared {
            LockingPreparation::Prepared(prepared) => {
                let request = JointRequest::new(&app, Lane::Acquire, prepared.request.clone())
                    .map_err(cryptography)?;
                let outer_request = request.encode().map_err(cryptography)?;
                JointLockingPreparation::Prepared(Box::new(PreparedJointLockingInputs {
                    prepared: *prepared,
                    request,
                    binding: parent.binding.clone(),
                    parent: parent.verified.clone(),
                    outer_request,
                }))
            }
            LockingPreparation::NonAdmitted(nonadmitted) => {
                let NonAdmittedLocking {
                    outcome,
                    request,
                    lifecycle,
                } = *nonadmitted;
                let request =
                    JointRequest::new(&app, Lane::Acquire, request).map_err(cryptography)?;
                JointLockingPreparation::NonAdmitted(Box::new(NonAdmittedJointLocking {
                    outcome,
                    request,
                    lifecycle,
                }))
            }
        })
    }
}

pub mod progress;
#[cfg(test)]
mod tests;
