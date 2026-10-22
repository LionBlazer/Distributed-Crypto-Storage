//! Owner-private proposal construction; no state installation or lock authority.
use super::{
    CommandInput, CurrentRegistry, Error, Expected, PrivateInputs, Result, SourceOpening, WalkInput,
};
use crate::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use zeroize::Zeroizing;

/// Original fixed Registry208 commitment. This opens no source/proof/QC or
/// currentness authority; callers must compare it to an independently checked root.
pub fn registry_root(words: &[u64; 208]) -> Result<[Val; 4]> {
    if words.iter().any(|&word| word >= Val::ORDER_U64) {
        return Err(Error::Shape);
    }
    let mut state = [Val::ZERO; 12];
    let mut scratch = [Val::ZERO; crate::poseidon::WIDTH];
    for block in words.as_chunks::<8>().0 {
        state[..8].copy_from_slice(&block.map(Val::from_u64));
        state = crate::poseidon::write(&mut scratch, state);
    }
    let root = state[..4].try_into().expect("fixed Registry208 root");
    state.fill(Val::ZERO);
    scratch.fill(Val::ZERO);
    Ok(root)
}

pub struct TransitionMaterial {
    pub source: SourceOpening,
    pub registry: CurrentRegistry,
    pub command: CommandInput,
    pub walk: WalkInput,
    pub mask: Zeroizing<[u8; 32]>,
    pub salts: [[Val; 4]; 3],
}
/// Private candidate openings, not a checked bank, SQL answer or lock grant.
/// Their consumer must require the original computation proof and fresh agreed
/// head before installing the candidate. No install/commit method is provided.
/// ```compile_fail
/// fn copy(x:&registry200_proof::registry_progress::word::TransitionOpening) { let _=x.clone().into_words(); }
/// ```
pub struct TransitionOpening {
    next: Zeroizing<[u64; 208]>,
    result: Zeroizing<[u64; 160]>,
}
impl TransitionOpening {
    pub fn into_words(self) -> (Zeroizing<[u64; 208]>, Zeroizing<[u64; 160]>) {
        (self.next, self.result)
    }
}
/// Move-only prepared mathematical proposal. Its expectation is owner-derived;
/// a receiver must authenticate the source, old root, command and current quorum.
pub struct PreparedTransition {
    expected: Expected,
    inputs: PrivateInputs,
    opening: TransitionOpening,
}
impl PreparedTransition {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
    pub fn into_parts(self) -> (Expected, PrivateInputs, TransitionOpening) {
        (self.expected, self.inputs, self.opening)
    }
}
/// Execute only the owner's private witness recipes for the original Word
/// relation. Source/enrollment/parent and old root are pinned by `draft`; new
/// Cmd/Stmt/Next/Result roots are proposed. All original assertions still run.
pub fn prepare_transition(
    draft: &Expected,
    material: TransitionMaterial,
) -> Result<PreparedTransition> {
    let mut inputs = PrivateInputs::new(
        material.source,
        material.registry.into_registry(),
        material.command,
        material.walk,
        material.mask,
        material.salts,
    );
    let (metadata, result) =
        super::super::word_inventory::preparation::transition(&draft.inner, &mut inputs.inner)
            .ok_or(Error::Binding)?;
    let next = Zeroizing::new(inputs.inner.banks[1].map(|v| v.as_canonical_u64()));
    let mut expected = draft.clone();
    expected.inner = metadata;
    Ok(PreparedTransition {
        expected,
        inputs,
        opening: TransitionOpening { next, result },
    })
}

#[cfg(test)]
mod tests;
