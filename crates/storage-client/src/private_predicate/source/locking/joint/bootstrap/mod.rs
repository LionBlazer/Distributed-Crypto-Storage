//! Real owner Bootstrap inputs and one exact historical completion.
mod completion;
mod produce;
use super::*;
pub use completion::CompletedJointBootstrap;
use registry200_finality::joint::{
    BootstrapExpectation, JointBootstrapParent, VerifiedJointBootstrap,
};
use registry200_joint::{Manifest, ManifestRole};

fn require_parent(
    binding: &JointBinding,
    parent: &JointBootstrapParent,
) -> crate::Result<JointApplication> {
    if parent.binding_id() != binding.id()
        || parent.application_descriptor().encode() != binding.application_descriptor().encode()
        || parent.head().genesis != binding.journal_genesis().id().map_err(cryptography)?
        || parent.head().database != binding.journal_genesis().database
    {
        return Err(invalid(
            "Bootstrap parent differs from the independent installation",
        ));
    }
    JointApplication::new(
        binding.application_descriptor().clone(),
        binding.journal_genesis(),
    )
    .map_err(cryptography)
}

/// Genuine bounded Source/Lifecycle evidence, not a network admission or bank.
pub struct PreparedJointBootstrap {
    request: JointRequest,
    lifecycle: lifecycle::Evidence,
    candidate: JointBootstrapCandidate,
}
impl PreparedJointBootstrap {
    pub fn request(&self) -> &JointRequest {
        &self.request
    }
    pub fn lifecycle(&self) -> &lifecycle::Evidence {
        &self.lifecycle
    }
    pub fn into_parts(self) -> (JointRequest, lifecycle::Evidence, JointBootstrapCandidate) {
        (self.request, self.lifecycle, self.candidate)
    }
}

/// Guarded original private candidate. It is consumed, including on completion
/// error. No raw Registry, current-state setter or serialized receipt is exposed.
/// ```compile_fail
/// fn clone<T:Clone>(){} fn forbidden(){clone::<storage_client::private_predicate::JointBootstrapCandidate>();}
/// ```
/// ```compile_fail
/// fn leak(x:storage_client::private_predicate::JointBootstrapCandidate){let _=x.controllers;}
/// ```
pub struct JointBootstrapCandidate {
    binding: JointBinding,
    parent: JointBootstrapParent,
    request: Vec<u8>,
    statement: lifecycle::statement::Statement,
    pair_hash: [u8; 32],
    pair_bytes: u64,
    table: Zeroizing<[u8; 32]>,
    row_ids: Zeroizing<[[u8; 32]; 4]>,
    controllers: Zeroizing<[[u8; 32]; 2]>,
    registry: Zeroizing<Registry>,
    salts: Zeroizing<[[u64; 4]; 2]>,
}
impl JointBootstrapCandidate {
    fn require_manifest(&self, manifest: &Manifest) -> crate::Result<()> {
        let mut refs = manifest.references();
        let reference = refs
            .next()
            .ok_or_else(|| invalid("Bootstrap pair is absent"))?;
        if manifest.lane() != Lane::Bootstrap
            || manifest.result_root() != [0; 32]
            || reference.role() != ManifestRole::LifecyclePair
            || reference.ordinal() != 0
            || reference.blob_id().sha256() != &self.pair_hash
            || reference.blob_id().bytes() != self.pair_bytes
            || refs.next().is_some()
        {
            return Err(invalid(
                "Bootstrap manifest differs from the exact produced pair",
            ));
        }
        Ok(())
    }
    pub fn expectation(&self, manifest: Manifest) -> crate::Result<BootstrapExpectation> {
        self.require_manifest(&manifest)?;
        let request = JointRequest::decode(&self.request).map_err(cryptography)?;
        BootstrapExpectation::new(
            &self.binding,
            &self.parent,
            &request,
            &self.statement,
            manifest,
        )
        .map_err(cryptography)
    }
}

#[cfg(test)]
mod tests;
