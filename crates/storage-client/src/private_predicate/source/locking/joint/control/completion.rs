//! Pure opening checks after the exact concrete proof/QC receipt. No model step.
use super::*;
use p3_field::PrimeCharacteristicRing;
use registry200_proof::lifecycle::{circuit::commitment, statement::digest};
use registry200_proof::source::statement::encode_digest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JointControlOutcome {
    Begun,
    /// Registry transaction removed; NO encrypted SQL data commit is implied.
    ClosedRegistry,
    /// Requested abort or failed transaction; no encrypted overlay is applied.
    AbortedRegistry,
}
pub struct CompletedJointControl {
    opening: JointRegistryOpening,
    outcome: JointControlOutcome,
}
impl CompletedJointControl {
    pub fn outcome(&self) -> JointControlOutcome {
        self.outcome
    }
    /// Still an unverified historical candidate for every subsequent producer.
    pub fn into_opening(self) -> JointRegistryOpening {
        self.opening
    }
}
fn hash(mut fields: Vec<Val>) -> [Val; 4] {
    let value = digest(&fields);
    fields.fill(Val::ZERO);
    value
}
fn enrollment_hash(mut fields: Vec<Val>) -> [Val; 4] {
    let value = registry200_proof::source::commitment::digest(&fields);
    fields.fill(Val::ZERO);
    value
}
impl JointControlCandidate {
    pub(super) fn require_operation(&self, operation: &VerifiedJointControl) -> crate::Result<()> {
        self.command.require_shape().map_err(cryptography)?;
        let before = operation.before();
        let after = operation.checked_parent();
        let expected_next = Control::Active {
            enrollment: encode_digest(self.statement.expected.enrollment),
            registry: encode_digest(self.statement.next),
        };
        if before.binding_id() != self.parent.binding.id()
            || before.application_descriptor().encode()
                != self.parent.binding.application_descriptor().encode()
            || before.head() != self.parent.head()
            || before.slot() != self.parent.verified.slot()
            || before.decision_id() != self.parent.verified.decision_id()
            || before.control() != self.parent.verified.control()
            || operation.context_id() != self.parent.context.id()
            || operation.request_bytes() != self.request
            || operation.statement().values() != self.statement.values()
            || operation.statement().expected.source.heads != self.statement.expected.source.heads
            || operation.statement().expected.source.packets
                != self.statement.expected.source.packets
            || after.binding_id() != self.parent.binding.id()
            || after.application_descriptor().encode()
                != self.parent.binding.application_descriptor().encode()
            || after.control() != expected_next
            || after.slot()
                != before
                    .slot()
                    .checked_add(1)
                    .ok_or_else(|| invalid("Joint slot exhausted"))?
            || after.head().block != operation.header().id()
            || operation.header().parent != before.head().block
            || operation.header().body_hash != version_journal::hash(operation.body_bytes())
        {
            return Err(invalid(
                "Control completion differs from exact own operation",
            ));
        }
        let Body::Transition(body) = Body::decode(
            operation.body_bytes(),
            &self.parent.binding.journal_genesis().profile,
        )
        .map_err(cryptography)?
        else {
            return Err(invalid("Control completion refuses Empty"));
        };
        let spec = self
            .parent
            .binding
            .application_descriptor()
            .source_spec()
            .map_err(cryptography)?;
        let manifest = registry200_joint::Manifest::decode(operation.manifest_bytes())
            .map_err(cryptography)?;
        if body.parent != before.head().block
            || body.request != self.request
            || body.proof != operation.manifest_bytes()
            || body.updates.len() != 1
            || body.updates[0].id != spec.control_id
            || body.updates[0].old != before.control().heads(&spec)
            || body.updates[0].new != expected_next.heads(&spec)
            || manifest.lane() != Lane::Control
            || manifest.next_root() != encode_digest(self.statement.next)
            || manifest.result_root() != encode_digest(self.statement.result)
        {
            return Err(invalid("Control completion changed signed Body/manifest"));
        }
        let lifecycle::statement::Phase::Transition { command, .. } = self.statement.expected.phase
        else {
            return Err(invalid("Control completion requires Transition"));
        };
        if hash(commitment::command_fields_opening(
            &self.statement.expected,
            &self.command,
            &commitment::CommandFieldsOpening {
                controller: self.controllers[usize::from(self.command.principal - 1)],
                revision: *self.revision,
                salt: (*self.command_salt).map(Val::from_u64),
            },
        )) != command
            || hash(commitment::result_fields_opening(
                &self.statement,
                &commitment::ResultFieldsOpening {
                    operation: self.command.operation,
                    outcome: *self.outcome,
                    transaction: self.command.transaction,
                    flags: [[false; 4]; 3],
                    salt: (*self.result_salt).map(Val::from_u64),
                },
            )) != self.statement.result
        {
            return Err(invalid("Control Cmd160/Result144 opening differs"));
        }
        self.next.require_canonical().map_err(cryptography)?;
        if enrollment_hash(commitment::enrollment_fields_opening(
            &self.statement.expected,
            &self.table,
            &self.controllers,
            self.salts[0].map(Val::from_u64),
        )) != self.statement.expected.enrollment
            || hash(commitment::registry_fields_opening(
                &self.statement.expected,
                &self.table,
                &self.row_ids,
                &self.controllers,
                &self.next,
                self.salts[1].map(Val::from_u64),
            )) != self.statement.next
        {
            return Err(invalid(
                "Control next private opening differs from actual proof",
            ));
        }
        Ok(())
    }
    /// Consume the exact original intent and actual replay/QC result once.
    /// Failure consumes/clears this candidate; no automatic retry or installation.
    /// ```compile_fail
    /// fn twice(c:storage_client::private_predicate::JointControlCandidate,
    ///          r:registry200_finality::joint::VerifiedJointControl){let _=c.complete(r);let _=c.complete(r);}
    /// ```
    pub fn complete(self, operation: VerifiedJointControl) -> crate::Result<CompletedJointControl> {
        self.require_operation(&operation)?;
        let outcome = match (self.command.operation, *self.outcome) {
            (Operation::Begin, 0) => JointControlOutcome::Begun,
            (Operation::End, 0) => JointControlOutcome::ClosedRegistry,
            (Operation::End, 3) => JointControlOutcome::AbortedRegistry,
            _ => return Err(invalid("Unexpected private control result")),
        };
        let Self {
            parent,
            next,
            controllers,
            salts,
            ..
        } = self;
        let opening = JointRegistryOpening::from_completed(
            parent.binding,
            operation.checked_parent().clone(),
            operation.next_context_id(),
            next,
            controllers,
            salts,
        );
        Ok(CompletedJointControl { opening, outcome })
    }
}
use version_journal::Body;
