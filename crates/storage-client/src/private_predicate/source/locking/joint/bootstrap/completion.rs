//! Exact sealed operation and pure private openings; no query/model execution.
use super::*;
use p3_field::PrimeCharacteristicRing;
use registry200_proof::{lifecycle::circuit::commitment, source::statement::encode_digest};
use version_journal::Body;

/// One completed historical Bootstrap. The returned opening is still a candidate
/// that every later producer must match to its sealed parent and real Source.
pub struct CompletedJointBootstrap {
    opening: JointRegistryOpening,
}
impl CompletedJointBootstrap {
    pub fn into_opening(self) -> JointRegistryOpening {
        self.opening
    }
}
fn source_hash(mut fields: Vec<Val>) -> [Val; 4] {
    let root = registry200_proof::source::commitment::digest(&fields);
    fields.fill(Val::ZERO);
    root
}
fn registry_hash(mut fields: Vec<Val>) -> [Val; 4] {
    let root = lifecycle::statement::digest(&fields);
    fields.fill(Val::ZERO);
    root
}
impl JointBootstrapCandidate {
    pub(super) fn require_operation(
        &self,
        operation: &VerifiedJointBootstrap,
    ) -> crate::Result<()> {
        let before = operation.before();
        let after = operation.checked_parent();
        let next = Control::Active {
            enrollment: encode_digest(self.statement.expected.enrollment),
            registry: encode_digest(self.statement.next),
        };
        if before.binding_id() != self.binding.id()
            || before.application_descriptor().encode()
                != self.binding.application_descriptor().encode()
            || before.head() != self.parent.head()
            || before.slot() != self.parent.slot()
            || before.previous_decision() != self.parent.previous_decision()
            || before.context_id() != self.parent.context_id()
            || operation.context_id() != self.parent.context_id()
            || operation.request_bytes() != self.request
            || operation.statement().values() != self.statement.values()
            || operation.statement().expected.source.heads != self.statement.expected.source.heads
            || operation.statement().expected.source.packets
                != self.statement.expected.source.packets
            || after.binding_id() != self.binding.id()
            || after.application_descriptor().encode()
                != self.binding.application_descriptor().encode()
            || after.control() != next
            || after.slot() != self.parent.slot()
            || after.head().block != operation.header().id()
            || after.head().state_root != operation.header().state_root
            || operation.header().parent != self.parent.head().block
            || operation.header().body_hash != version_journal::hash(operation.body_bytes())
        {
            return Err(invalid(
                "Bootstrap completion differs from exact own operation",
            ));
        }
        let manifest = Manifest::decode(operation.manifest_bytes()).map_err(cryptography)?;
        self.require_manifest(&manifest)?;
        let Body::Transition(body) = Body::decode(
            operation.body_bytes(),
            &self.binding.journal_genesis().profile,
        )
        .map_err(cryptography)?
        else {
            return Err(invalid("Bootstrap completion refuses Empty"));
        };
        let app = require_parent(&self.binding, &self.parent)?;
        let spec = app.source_spec();
        if body.parent != self.parent.head().block
            || body.request != self.request
            || body.proof != operation.manifest_bytes()
            || body.updates.len() != 1
            || body.updates[0].id != spec.control_id
            || body.updates[0].old != Control::Pending.heads(spec)
            || body.updates[0].new != next.heads(spec)
            || manifest.next_root() != encode_digest(self.statement.next)
            || *self.registry != Registry::default()
        {
            return Err(invalid(
                "Bootstrap completion changed Body/manifest/default Registry",
            ));
        }
        if source_hash(commitment::enrollment_fields_opening(
            &self.statement.expected,
            &self.table,
            &self.controllers,
            self.salts[0].map(Val::from_u64),
        )) != self.statement.expected.enrollment
            || registry_hash(commitment::registry_fields_opening(
                &self.statement.expected,
                &self.table,
                &self.row_ids,
                &self.controllers,
                &self.registry,
                self.salts[1].map(Val::from_u64),
            )) != self.statement.next
        {
            return Err(invalid(
                "Bootstrap private enrollment/default opening differs from actual proof",
            ));
        }
        Ok(())
    }
    /// Consume this original candidate and actual proof/QC result once. Error
    /// clears owned private banks. No file, current lease or Vault is installed.
    /// ```compile_fail
    /// fn twice(c:storage_client::private_predicate::JointBootstrapCandidate,
    /// r:registry200_finality::joint::VerifiedJointBootstrap){let _=c.complete(r);let _=c.complete(r);}
    /// ```
    pub fn complete(
        self,
        operation: VerifiedJointBootstrap,
    ) -> crate::Result<CompletedJointBootstrap> {
        self.require_operation(&operation)?;
        let Self {
            binding,
            registry,
            controllers,
            salts,
            ..
        } = self;
        let opening = JointRegistryOpening::from_completed(
            binding,
            operation.checked_parent().clone(),
            operation.next_context_id(),
            registry,
            controllers,
            salts,
        );
        Ok(CompletedJointBootstrap { opening })
    }
}
