//! Owner recovery capsules and the historical durable Joint owner.
mod codec;
mod durable;
mod durable_wal;
#[cfg(test)]
mod process_tests;
mod restore;
use super::*;
use bfv_mul_relin_proof::{InputEvidence, Provenance};
use bfv_query_core::PreparedPrivateCoefficientPredicate;
pub use durable::{
    JointSqlCall, JointSqlClient, JointSqlClientBinding, JointSqlHost, JointSqlHostPins,
    JointSqlPreparation, JointSqlReply, OWNER_VAULT_MAX_BODY_BYTES, OWNER_VAULT_MAX_FILE_BYTES,
    OWNER_VAULT_MAX_RECORD_BYTES, OwnerVault, OwnerVaultAcquireCompletion,
    OwnerVaultAcquireMaterial, OwnerVaultAcquirePreparation, OwnerVaultAcquireWork,
    OwnerVaultAuthority, OwnerVaultCompletion, OwnerVaultCursor, OwnerVaultDraft, OwnerVaultError,
    OwnerVaultIdentity, OwnerVaultPhase, OwnerVaultPins, OwnerVaultReplay, OwnerVaultSubmission,
    VaultResult, joint_sql_host_profile_digest, owner_vault_profile_digest,
};

/// High-entropy owner-custodied wrapping key, not database or peer authority.
/// No OS backend, password KDF, adjacent key file or durable custody is selected.
///
/// ```compile_fail
/// fn forbidden<T: Clone>() {}
/// fn check(){forbidden::<storage_client::private_predicate::JointRecoveryKey>();}
/// ```
/// ```compile_fail
/// fn forbidden<T: core::fmt::Debug>() {}
/// fn check(){forbidden::<storage_client::private_predicate::JointRecoveryKey>();}
/// ```
pub struct JointRecoveryKey(Zeroizing<[u8; 32]>);
impl JointRecoveryKey {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }
}
/// Independently retained record location. An old authentic record can repeat;
/// this identity supplies no durable generation, anti-rollback or freshness.
pub struct JointRecoveryIdentity {
    record: [u8; 32],
}
impl JointRecoveryIdentity {
    pub fn new(record: [u8; 32]) -> Self {
        Self { record }
    }
}
/// Explicit owner choice to capture a recovery record during preparation.
pub struct JointRecovery<'a> {
    parent: &'a JointLockingParent,
    identity: &'a JointRecoveryIdentity,
    key: &'a JointRecoveryKey,
}
impl<'a> JointRecovery<'a> {
    pub fn new(
        parent: &'a JointLockingParent,
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
/// Ciphertext-only bounded canonical record. Parsing is not authentication,
/// proof verification, exactly-once recovery, persistence or SQL permission.
pub struct EncryptedJointRecovery {
    bytes: Vec<u8>,
}
impl EncryptedJointRecovery {
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        codec::validate(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
pub const JOINT_RECOVERY_HEADER_BYTES: usize = codec::HEADER;
pub const JOINT_RECOVERY_BYTES: usize = codec::RECORD;

/// Borrowed public material for the exact saved operation. These values and
/// proof bytes confer no authority by construction. Setup/anchor/parent and
/// request must come from independently retained owner intent, never a peer's
/// choice of easier pins. No proof collection is copied into the AEAD record.
pub struct JointRecoveryInputs<'a> {
    pub request: &'a JointRequest,
    pub provenance: &'a Provenance,
    pub encrypted_request: &'a [u8],
    pub proofs: InputEvidence<'a>,
    pub lifecycle: &'a [u8],
    pub link: &'a [u8],
}
/// Actual restored pending/candidates; still requires the unchanged sealed
/// VerifiedJointAcquire completion path. One use is enforced per instance only.
/// Authentic encrypted bytes can be restored again without a future durable CAS.
///
/// ```compile_fail
/// fn forbidden<T: Clone>() {}
/// fn check(){forbidden::<storage_client::private_predicate::RecoveredJointComputePrepared>();}
/// ```
pub struct RecoveredJointComputePrepared {
    pending: PreparedPrivateCoefficientPredicate,
    candidates: JointLockingCandidates,
}
impl RecoveredJointComputePrepared {
    pub fn into_parts(self) -> (PreparedPrivateCoefficientPredicate, JointLockingCandidates) {
        (self.pending, self.candidates)
    }
}
pub struct RecoverableJointLockingInputs {
    prepared: PreparedJointLockingInputs,
    record: EncryptedJointRecovery,
}
impl RecoverableJointLockingInputs {
    pub fn into_parts(self) -> (PreparedJointLockingInputs, EncryptedJointRecovery) {
        (self.prepared, self.record)
    }
}
pub enum RecoverableJointLockingPreparation {
    Prepared(Box<RecoverableJointLockingInputs>),
    NonAdmitted(Box<NonAdmittedJointLocking>),
}

// Concrete optional owner request, never a producer callback or verification flag.
pub(in crate::private_predicate::source::locking) struct RecoveryTarget<'a> {
    identity: &'a JointRecoveryIdentity,
    key: &'a JointRecoveryKey,
    parent: &'a JointLockingParent,
}
pub(in crate::private_predicate::source::locking) struct Capture(codec::Payload);
impl Capture {
    pub(in crate::private_predicate::source::locking) fn new(
        opening: &NextOwnerOpening,
        completion: &LockingCompletion,
        link: &predicate_acquire::circuit::Opening,
    ) -> Self {
        Self(codec::Payload::capture(opening, completion, link))
    }
    pub(in crate::private_predicate::source::locking) fn seal(
        self,
        target: &RecoveryTarget<'_>,
        inputs: &ProducedInputs,
        life: &lifecycle::Evidence,
        link: &predicate_acquire::Evidence,
        request: &Request,
    ) -> crate::Result<EncryptedJointRecovery> {
        let outer = JointRequest::new(
            &target.parent.application()?,
            Lane::Acquire,
            request.clone(),
        )
        .map_err(cryptography)?;
        let public = JointRecoveryInputs {
            request: &outer,
            provenance: inputs.provenance(),
            encrypted_request: inputs.request(),
            proofs: inputs.proofs().as_input_evidence(),
            lifecycle: life.as_bytes(),
            link: link.as_bytes(),
        };
        let association = codec::association(target.parent, &public)?;
        codec::seal(target.identity, target.key, association, &self.0)
    }
}
impl crate::private_predicate::SourceOwner {
    /// Same actual all-original preparation with an explicit encrypted private
    /// recovery capsule. Default preparation retains no additional plaintext mask.
    /// WAIT/NOWAIT returns no capsule or staged success. No file or state advances.
    pub fn prepare_joint_locking_recoverable(
        &self,
        bfv: BfvContext<'_>,
        epoch: &mut OwnerProofEpoch<'_>,
        fetched: FetchedSource<'_>,
        compiled: &CompiledLockingSelect,
        control: LockingControl,
        recovery: JointRecovery<'_>,
    ) -> crate::Result<RecoverableJointLockingPreparation> {
        let parent = recovery.parent;
        let target = RecoveryTarget {
            identity: recovery.identity,
            key: recovery.key,
            parent,
        };
        let route = PreparationRoute {
            parent: PreparationParent::Joint(parent),
            recovery: Some(&target),
        };
        match self.prepare_joint_inner(bfv, epoch, fetched, compiled, control, route)? {
            JointLockingPreparation::Prepared(mut prepared) => {
                let record = prepared
                    .prepared
                    .recovery
                    .take()
                    .ok_or_else(|| invalid("Recoverable preparation omitted its capsule"))?;
                Ok(RecoverableJointLockingPreparation::Prepared(Box::new(
                    RecoverableJointLockingInputs {
                        prepared: *prepared,
                        record,
                    },
                )))
            }
            JointLockingPreparation::NonAdmitted(blocked) => {
                Ok(RecoverableJointLockingPreparation::NonAdmitted(blocked))
            }
        }
    }
}

#[cfg(test)]
mod tests;
