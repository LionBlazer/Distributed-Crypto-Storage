//! One-shot owner completion of the exact operation, not general SQL admission.
use super::*;
use bfv_query_core::{
    Owner, PreparedPrivateCoefficientPredicate, UnverifiedPrivateCoefficientPredicate,
};
use p3_field::PrimeCharacteristicRing;
use registry200_finality::joint::VerifiedJointAcquire;
use registry200_proof::lifecycle::{
    circuit::{commitment, model::Operation},
    statement::{Phase, digest},
};
use registry200_proof::source::statement::encode_digest;
use version_journal::Body;

/// Owner-readable projected values. Unrequested columns are absent. No predicate,
/// window, lock policy or second query is evaluated during completion.
#[derive(Debug, PartialEq, Eq)]
pub struct CompletedJointRow {
    pub ordinal: u8,
    pub row_id: [u8; 32],
    pub age: Option<u8>,
    pub amount: Option<u16>,
}
/// Output of one already-linearized Acquire. The next owner opening remains a
/// guarded candidate; this object does not install it, persist a pending intent,
/// reconcile network freshness, or authorize a later operation after End.
pub struct CompletedJointAcquire {
    rows: Vec<CompletedJointRow>,
    head: HeadRef,
    decision: [u8; 32],
    staged: StagedLockingTransition,
}
impl CompletedJointAcquire {
    pub fn rows(&self) -> &[CompletedJointRow] {
        &self.rows
    }
    pub fn operation_head(&self) -> HeadRef {
        self.head
    }
    pub fn decision_id(&self) -> [u8; 32] {
        self.decision
    }
    pub fn into_parts(self) -> (Vec<CompletedJointRow>, StagedLockingTransition) {
        (self.rows, self.staged)
    }
}

struct Decoded(UnverifiedPrivateCoefficientPredicate);
impl Drop for Decoded {
    fn drop(&mut self) {
        for row in &mut self.0.rows {
            row.ordinal.zeroize();
            row.present.zeroize();
            row.age.zeroize();
            row.amount.zeroize();
        }
    }
}
struct Projected(Vec<CompletedJointRow>);
impl Drop for Projected {
    fn drop(&mut self) {
        for row in &mut self.0 {
            row.ordinal.zeroize();
            row.row_id.zeroize();
            if let Some(age) = &mut row.age {
                age.zeroize();
            }
            if let Some(amount) = &mut row.amount {
                amount.zeroize();
            }
        }
    }
}
impl JointLockingCandidates {
    /// Consume BOTH private banks, the original one-use pending request, and the
    /// exact sealed operation. All associations and Result144 are checked before
    /// the one actual BFV decrypt. No plaintext WHERE/window is recomputed.
    ///
    /// ```compile_fail
    /// fn twice(c: storage_client::private_predicate::JointLockingCandidates,
    ///          owner: &bfv_query_core::Owner,
    ///          p: bfv_query_core::PreparedPrivateCoefficientPredicate,
    ///          r: registry200_finality::joint::VerifiedJointAcquire) {
    ///     let _ = c.complete_acquire(owner, p, r);
    ///     let _ = c.complete_acquire(owner, p, r);
    /// }
    /// ```
    pub fn complete_acquire(
        self,
        owner: &Owner,
        prepared: PreparedPrivateCoefficientPredicate,
        operation: VerifiedJointAcquire,
    ) -> crate::Result<CompletedJointAcquire> {
        self.require_operation(&prepared, &operation)?;
        let JointLockingCandidates {
            _completion: completion,
            _staged: staged,
            ..
        } = self;
        let decoded = Decoded(
            owner
                .decrypt_private_coefficient_predicate_unverified_for_experiment(
                    prepared.pending,
                    operation.acquired().encrypted_response(),
                )
                .map_err(cryptography)?,
        );
        let mut rows = Projected(Vec::with_capacity(4));
        for (i, row) in decoded.0.rows.iter().enumerate() {
            if row.ordinal != completion.ordinals[i] {
                return Err(invalid("Joint completion changed the original ordinal"));
            }
            if !completion.flags[0][i] {
                continue;
            }
            if !row.present {
                return Err(invalid(
                    "Joint returned ordinal is absent from checked FHE output",
                ));
            }
            rows.0.push(CompletedJointRow {
                ordinal: row.ordinal,
                row_id: completion.row_ids[i],
                age: (*completion.projection != 2).then_some(row.age),
                amount: (*completion.projection != 1).then_some(row.amount),
            });
        }
        Ok(CompletedJointAcquire {
            rows: core::mem::take(&mut rows.0),
            head: operation.head(),
            decision: operation.decision_id(),
            staged,
        })
    }
    // Borrowed validation is private and unconditional in complete_acquire.
    // It grants nothing and never decrypts, installs, clones or exports a bank.
    pub(super) fn require_operation(
        &self,
        prepared: &PreparedPrivateCoefficientPredicate,
        operation: &VerifiedJointAcquire,
    ) -> crate::Result<()> {
        let JointLockingCandidates {
            _completion: completion,
            _staged: staged,
            _binding: binding,
            _parent: parent,
            _outer_request: outer_bytes,
        } = self;
        let actual = operation.acquired();
        let life = staged._association.lifecycle();
        let Phase::Transition { old, command } = life.expected.phase else {
            return Err(invalid("Joint completion requires an Acquire transition"));
        };
        let outer = JointRequest::decode(outer_bytes).map_err(cryptography)?;
        let expected_old = Control::Active {
            enrollment: encode_digest(life.expected.enrollment),
            registry: encode_digest(old),
        };
        let expected_next = Control::Active {
            enrollment: encode_digest(life.expected.enrollment),
            registry: encode_digest(life.next),
        };
        if operation.binding_id() != binding.id()
            || parent.binding_id() != binding.id()
            || parent.head() != staged.parent
            || parent.control() != expected_old
            || operation.parent() != staged.parent
            || operation.slot()
                != parent
                    .slot()
                    .checked_add(1)
                    .ok_or_else(|| invalid("Joint slot exhausted"))?
            || operation.previous_decision_id() != parent.decision_id()
            || operation.head().genesis != staged.parent.genesis
            || operation.head().database != staged.parent.database
            || operation.head().height
                != staged
                    .parent
                    .height
                    .checked_add(1)
                    .ok_or_else(|| invalid("Joint height exhausted"))?
            || operation.control() != expected_next
            || actual.request_bytes() != outer_bytes.as_slice()
            || actual.provenance_claim() != staged.provenance
            || actual.encrypted_request() != staged.encrypted_request
            || prepared.request != staged.encrypted_request
            || outer.lane() != Lane::Acquire
            || outer.inner().encode().map_err(cryptography)? != staged.request
            || outer.inner().query != life.expected.source.request
            || outer.inner().command != encode_digest(command)
            || outer.inner().enrollment != encode_digest(life.expected.enrollment)
            || life.expected.genesis != staged.parent.genesis
            || life.expected.parent != staged.parent.block
            || actual.manifest().lane() != Lane::Acquire
            || actual.manifest().next_root() != encode_digest(life.next)
            || actual.manifest().result_root() != encode_digest(life.result)
        {
            return Err(invalid(
                "Joint completion differs from its exact own operation",
            ));
        }
        prepared.operand_ciphertexts().map_err(cryptography)?;
        let Body::Transition(body) =
            Body::decode(operation.body_bytes(), &binding.journal_genesis().profile)
                .map_err(cryptography)?
        else {
            return Err(invalid("Joint completion refuses an Empty decision"));
        };
        if body.parent != staged.parent.block
            || body.request.as_slice() != outer_bytes.as_slice()
            || body.proof != actual.manifest().encode()
            || body.updates.len() != 1
            || body.updates[0].id != staged.application.control_id
            || body.updates[0].old != expected_old.heads(&staged.application)
            || body.updates[0].new != expected_next.heads(&staged.application)
            || operation.header().id() != operation.head().block
            || operation.header().body_hash != version_journal::hash(operation.body_bytes())
        {
            return Err(invalid("Joint completion changed its signed Acquire Body"));
        }
        let mut opening = commitment::ResultFieldsOpening {
            operation: Operation::Acquire,
            outcome: 0,
            transaction: staged.actor.transaction,
            flags: *completion.flags,
            salt: (*completion.result_salt).map(Val::from_u64),
        };
        let mut fields = commitment::result_fields_opening(life, &opening);
        let root = digest(&fields);
        fields.fill(Val::ZERO);
        opening.flags.zeroize();
        opening.salt.fill(Val::ZERO);
        opening.transaction.zeroize();
        if root != life.result || !(1..=3).contains(&*completion.projection) {
            return Err(invalid("Joint completion Result144 opening differs"));
        }
        Ok(())
    }
}
