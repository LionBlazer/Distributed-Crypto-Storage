//! Owner-side joint mathematical inputs. No SQL admission, signer or finality token.
mod compiler;
mod joint;
mod produce;
pub use compiler::CompiledLockingSelect;
pub use joint::{
    CompletedJointAcquire, CompletedJointRow, EncryptedJointRecovery, JOINT_RECOVERY_BYTES,
    JOINT_RECOVERY_HEADER_BYTES, JointLockingCandidates, JointLockingParent,
    JointLockingPreparation, JointRecovery, JointRecoveryIdentity, JointRecoveryInputs,
    JointRecoveryKey, NonAdmittedJointLocking, PreparedJointLockingInputs,
    RecoverableJointLockingInputs, RecoverableJointLockingPreparation,
    RecoveredJointComputePrepared,
};
pub use joint::{
    CompletedJointControl, JointControlCandidate, JointControlIntent, JointControlOutcome,
    JointControlParent, JointEndDisposition, JointOwnedLockingControl, JointOwnedRecovery,
    JointRegistryOpening, PreparedJointControl,
};

use crate::private_predicate::{ProducedInputs, cryptography, invalid};
use p3_field::PrimeField64;
use registry200_journal::{Application, Control, Request};
use registry200_proof::{Val, lifecycle, lifecycle::circuit::model::Registry, predicate_acquire};
use version_journal::{HeadRef, Journal};
use zeroize::{Zeroize, Zeroizing};

/// Exact already-validated historical parent. Construction establishes neither
/// agreement/finality nor permission to use a stale branch for a SQL operation.
/// The owner supplies a Journal already checked by the concrete Registry verifier;
/// this constructor does not certify how a generic Journal was populated.
pub struct LockingParent {
    application: Application,
    head: HeadRef,
    enrollment: [u8; 32],
    registry: [u8; 32],
}
impl LockingParent {
    pub fn new(application: &Application, journal: &Journal, head: HeadRef) -> crate::Result<Self> {
        application
            .require_genesis(journal.genesis())
            .map_err(cryptography)?;
        let heads = application
            .control(journal.validated_shards(head).map_err(cryptography)?)
            .map_err(cryptography)?;
        let Control::Active {
            enrollment,
            registry,
        } = Control::decode(application, heads).map_err(cryptography)?
        else {
            return Err(invalid("Locking inputs require an active Registry parent"));
        };
        Ok(Self {
            application: application.clone(),
            head,
            enrollment,
            registry,
        })
    }
    pub fn head(&self) -> HeadRef {
        self.head
    }
    pub fn application(&self) -> &Application {
        &self.application
    }
}

// Closed local routes only. No consumer can nominate a raw Joint parent or
// replace its sealed provenance through a generic callback/trait implementation.
enum PreparationParent<'a> {
    Legacy(&'a LockingParent),
    Joint(&'a JointLockingParent),
}
struct PreparationRoute<'a> {
    parent: PreparationParent<'a>,
    recovery: Option<&'a joint::vault::RecoveryTarget<'a>>,
}
impl PreparationParent<'_> {
    fn application(&self) -> &Application {
        match self {
            Self::Legacy(p) => &p.application,
            Self::Joint(p) => p.source_spec(),
        }
    }
    fn head(&self) -> HeadRef {
        match self {
            Self::Legacy(p) => p.head,
            Self::Joint(p) => p.head(),
        }
    }
    fn enrollment(&self) -> [u8; 32] {
        match self {
            Self::Legacy(p) => p.enrollment,
            Self::Joint(p) => p.enrollment(),
        }
    }
    fn registry(&self) -> [u8; 32] {
        match self {
            Self::Legacy(p) => p.registry,
            Self::Joint(p) => p.registry(),
        }
    }
    fn require_object(&self, object: [u8; 32]) -> crate::Result<()> {
        match self {
            Self::Legacy(_) => Ok(()),
            Self::Joint(p) => p.require_object(object),
        }
    }
    fn require_key(
        &self,
        bfv: &crate::private_predicate::BfvContext<'_>,
        key: &bfv_key_transform::Statement,
    ) -> crate::Result<()> {
        match self {
            Self::Legacy(_) => Ok(()),
            Self::Joint(p) => p.require_key(bfv, key),
        }
    }
}

/// Exact owner-held actor intent; controller labels are not signatures or possession proofs.
pub struct LockingActor {
    transaction: u64,
    principal: u8,
    revision: u64,
    sequence: u64,
}
impl LockingActor {
    pub fn new(
        transaction: u64,
        principal: u8,
        revision: u64,
        sequence: u64,
    ) -> crate::Result<Self> {
        if transaction == 0 || !(1..=2).contains(&principal) || sequence == 0 {
            return Err(invalid("Invalid locking actor intent"));
        }
        Ok(Self {
            transaction,
            principal,
            revision,
            sequence,
        })
    }
}
impl Drop for LockingActor {
    fn drop(&mut self) {
        self.transaction.zeroize();
        self.principal.zeroize();
        self.revision.zeroize();
        self.sequence.zeroize();
    }
}

/// Consumed owner-private Registry opening. No Clone, Debug, secret getter or
/// persistence is exposed. Salts are enrollment and current Registry, in that order.
pub struct LockingControl {
    old: Zeroizing<Registry>,
    controllers: Zeroizing<[[u8; 32]; 2]>,
    salts: Zeroizing<[[u64; 4]; 2]>,
    actor: LockingActor,
}
impl LockingControl {
    pub fn new(
        registry: Registry,
        controllers: [[u8; 32]; 2],
        salts: [[u64; 4]; 2],
        actor: LockingActor,
    ) -> crate::Result<Self> {
        // Guard private copies even when a constructor rejects its inputs.
        let registry = Zeroizing::new(registry);
        let controllers = Zeroizing::new(controllers);
        let salts = Zeroizing::new(salts);
        registry.require_canonical().map_err(cryptography)?;
        if controllers.contains(&[0; 32]) || salts.iter().flatten().any(|v| *v >= Val::ORDER_U64) {
            return Err(invalid("Invalid enrollment/controller opening"));
        }
        let tx = registry
            .transactions
            .iter()
            .find(|tx| tx.id == actor.transaction)
            .ok_or_else(|| invalid("Locking transaction is absent"))?;
        if registry.revision != actor.revision
            || tx.principal != actor.principal
            || tx.sequence != actor.sequence
            || tx.failed
        {
            return Err(invalid(
                "Locking actor differs from the current Registry opening",
            ));
        }
        Ok(Self {
            old: registry,
            controllers,
            salts,
            actor,
        })
    }
}

/// Actual mathematical WAIT/NOWAIT outcomes, never an accepted lock or SQL answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockingConflict {
    Wait,
    NoWait,
}
pub struct NonAdmittedLocking {
    outcome: LockingConflict,
    request: Request,
    lifecycle: lifecycle::Evidence,
}
impl NonAdmittedLocking {
    pub fn outcome(&self) -> LockingConflict {
        self.outcome
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn lifecycle(&self) -> &lifecycle::Evidence {
        &self.lifecycle
    }
}

/// Private one-use output metadata only. No ages, amounts or predicate are kept.
/// There is intentionally no completion method until independently checked full
/// FHE output AND the exact finalized joint Acquire admission can be required.
pub struct LockingCompletion {
    table: Zeroizing<[u8; 32]>,
    row_ids: Zeroizing<[[u8; 32]; 4]>,
    ordinals: Zeroizing<[u8; 4]>,
    flags: Zeroizing<[[bool; 4]; 3]>,
    result_salt: Zeroizing<[u64; 4]>,
    projection: Zeroizing<u8>,
}
impl LockingCompletion {
    // Clear every owned completion bank without exporting a private-data getter.
    fn clear(&mut self) {
        self.table.zeroize();
        self.row_ids.zeroize();
        self.ordinals.zeroize();
        self.flags.zeroize();
        self.result_salt.zeroize();
        self.projection.zeroize();
    }
}
impl Drop for LockingCompletion {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Complete public input, Lifecycle and Link evidence; still not an SQL grant.
/// The prepared BFV pending binding stays inside `inputs`, separate from the
/// original-ordinal completion metadata. No owner state is advanced here.
pub struct PreparedLockingInputs {
    inputs: ProducedInputs,
    lifecycle: lifecycle::Evidence,
    link: predicate_acquire::Evidence,
    request: Request,
    completion: LockingCompletion,
    staged: StagedLockingTransition,
    // Only the explicitly recoverable Joint API fills this ciphertext-only field.
    recovery: Option<EncryptedJointRecovery>,
}
impl PreparedLockingInputs {
    pub fn inputs(&self) -> &ProducedInputs {
        &self.inputs
    }
    pub fn lifecycle(&self) -> &lifecycle::Evidence {
        &self.lifecycle
    }
    pub fn link(&self) -> &predicate_acquire::Evidence {
        &self.link
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn into_parts(
        self,
    ) -> (
        ProducedInputs,
        lifecycle::Evidence,
        predicate_acquire::Evidence,
        Request,
        LockingCompletion,
        StagedLockingTransition,
    ) {
        (
            self.inputs,
            self.lifecycle,
            self.link,
            self.request,
            self.completion,
            self.staged,
        )
    }
}

// Guard private copies immediately, including the short-lived complete Source
// opening used to independently recheck the retained next-control preimage.
struct NextOwnerOpening {
    control: LockingControl,
    next: Zeroizing<Registry>,
    plain: Zeroizing<[u8; 2348]>,
    source_salt: Zeroizing<[u64; 4]>,
    next_salt: Zeroizing<[u64; 4]>,
}

/// Move-only owner-private candidate, NOT a current Registry or SQL/finality token.
/// It retains the actual next opening and exact public association for a future
/// durable owner-state protocol. No getter, promotion, completion or import exists.
pub struct StagedLockingTransition {
    next: Zeroizing<Registry>,
    controllers: Zeroizing<[[u8; 32]; 2]>,
    /// Enrollment and new Registry salts, never Source/mask/encoding salts.
    salts: Zeroizing<[[u64; 4]; 2]>,
    actor: LockingActor,
    parent: HeadRef,
    application: Application,
    request: Vec<u8>,
    provenance: Vec<u8>,
    encrypted_request: Vec<u8>,
    _association: predicate_acquire::Expected,
}
impl StagedLockingTransition {
    fn new(
        parent: &PreparationParent<'_>,
        request: &Request,
        inputs: &ProducedInputs,
        lifecycle: &lifecycle::Evidence,
        link: &predicate_acquire::Evidence,
        opening: NextOwnerOpening,
    ) -> crate::Result<Self> {
        use p3_field::PrimeCharacteristicRing;
        use registry200_journal::{Operation, intent_query};
        use registry200_proof::{
            admission::CanonicalSource,
            lifecycle::{
                circuit::{Witness, commitment},
                statement::{Phase, digest},
            },
            source::{self, statement::encode_digest},
        };
        let association = link.expected();
        let source = CanonicalSource::checked_claim(association.query().expected.source_claim())
            .map_err(cryptography)?;
        parent
            .application()
            .require_source(source.claim())
            .map_err(cryptography)?;
        let encoded_request = request.encode().map_err(cryptography)?;
        let decoded = Request::decode(&encoded_request).map_err(cryptography)?;
        let reconstructed = decoded.source(parent.application()).map_err(cryptography)?;
        let expected = &association.lifecycle().expected;
        let Phase::Transition { old, command } = expected.phase else {
            return Err(invalid("Staged transition requires Acquire"));
        };
        if request.operation != Operation::Transition
            || request.genesis != parent.head().genesis
            || request.parent != parent.head().block
            || request.application != parent.application().id()
            || request.enrollment != parent.enrollment()
            || request.query
                != intent_query(
                    parent.application(),
                    parent.head().genesis,
                    parent.head().block,
                    request.nonce,
                    parent.enrollment(),
                    Operation::Transition,
                )
            || reconstructed.values() != source.claim().values()
            || reconstructed.heads != source.claim().heads
            || reconstructed.packets != source.claim().packets
            || expected.genesis != parent.head().genesis
            || expected.parent != parent.head().block
            || encode_digest(expected.enrollment) != parent.enrollment()
            || encode_digest(old) != parent.registry()
            || encode_digest(command) != request.command
            || lifecycle.statement().values() != association.lifecycle().values()
        {
            return Err(invalid(
                "Staged transition differs from its exact parent/request/Lifecycle",
            ));
        }
        let actual = predicate_acquire::Expected::new(
            &inputs.provenance.encodings()[1],
            lifecycle.statement(),
        )
        .map_err(cryptography)?;
        association.require_same(&actual).map_err(cryptography)?;
        // Exact byte comparisons bind both original ciphertexts and all public
        // labels. Encoding/Formation proofs remain actual mandatory prerequisites,
        // never replaced by these canonical metadata checks.
        let parsed = inputs
            .provenance
            .setup()
            .private_coefficient_request(&inputs.prepared.request)
            .map_err(cryptography)?;
        if parsed.query() != request.query
            || parsed.context().data_head() != source.claim().heads[0].as_slice()
            || parsed.context().index_head() != source.claim().heads[1].as_slice()
            || parsed.ciphertexts()
                != inputs
                    .prepared
                    .operand_ciphertexts()
                    .map_err(cryptography)?
            || parsed.ciphertexts()
                != inputs
                    .provenance
                    .ciphertexts()
                    .each_ref()
                    .map(Vec::as_slice)
        {
            return Err(invalid(
                "Staged transition changed its encrypted input association",
            ));
        }
        if opening
            .source_salt
            .iter()
            .chain(opening.next_salt.iter())
            .any(|v| *v >= Val::ORDER_U64)
            || source::commitment::digest(&source::commitment::opening_fields(
                source.claim(),
                (*opening.source_salt).map(Val::from_u64),
                opening.plain.as_slice(),
            )) != source.claim().open_commitment
        {
            return Err(invalid(
                "Staged Source opening differs from its actual proof",
            ));
        }
        opening.next.require_canonical().map_err(cryptography)?;
        let mut w = Witness {
            plain: *opening.plain,
            controllers: *opening.control.controllers,
            salts: [[Val::ZERO; 4]; 6],
            old: Registry::default(),
            command: None,
        };
        w.salts[1] = opening.control.salts[0].map(Val::from_u64);
        if encode_digest(source::commitment::digest(&commitment::enrollment_fields(
            expected, &w,
        ))) != parent.enrollment()
        {
            return Err(invalid(
                "Staged enrollment opening differs from its actual parent",
            ));
        }
        if digest(&commitment::registry_fields(
            expected,
            &w,
            &opening.next,
            (*opening.next_salt).map(Val::from_u64),
        )) != lifecycle.statement().next
        {
            return Err(invalid(
                "Staged next Registry differs from its actual proof",
            ));
        }
        let actor = &opening.control.actor;
        let tx = opening
            .next
            .transactions
            .iter()
            .find(|tx| tx.id == actor.transaction)
            .ok_or_else(|| invalid("Staged Acquire actor is absent"))?;
        if opening.next.revision
            != actor
                .revision
                .checked_add(1)
                .ok_or_else(|| invalid("Staged revision exhausted"))?
            || tx.principal != actor.principal
            || tx.sequence
                != actor
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid("Staged sequence exhausted"))?
            || tx.failed
        {
            return Err(invalid(
                "Staged next actor differs from the exact Acquire intent",
            ));
        }
        let provenance = inputs.provenance.encode_claim().map_err(cryptography)?;
        let LockingControl {
            old,
            controllers,
            mut salts,
            actor,
        } = opening.control;
        drop(old);
        salts[1].zeroize();
        salts[1] = *opening.next_salt;
        Ok(Self {
            next: opening.next,
            controllers,
            salts,
            actor,
            parent: parent.head(),
            application: parent.application().clone(),
            request: encoded_request,
            provenance,
            encrypted_request: inputs.prepared.request.clone(),
            _association: association.clone(),
        })
    }
}
impl Drop for StagedLockingTransition {
    fn drop(&mut self) {
        self.next.zeroize();
        self.controllers.zeroize();
        self.salts.zeroize();
        self.actor.transaction.zeroize();
        self.actor.principal.zeroize();
        self.actor.revision.zeroize();
        self.actor.sequence.zeroize();
        // Public pins are retained solely for a future exact durable association;
        // they are not exposed as an authorization or completion capability.
        self.parent.height = 0;
        self.application.database.fill(0);
        self.request.clear();
        self.provenance.clear();
        self.encrypted_request.clear();
    }
}
pub enum LockingPreparation {
    Prepared(Box<PreparedLockingInputs>),
    NonAdmitted(Box<NonAdmittedLocking>),
}

#[cfg(test)]
mod tests;
