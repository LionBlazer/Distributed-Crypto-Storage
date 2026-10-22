//! Private owner witness production from the unchanged fixed relation.
//! Derived roots are proposals, never independently retained public expectations.
use super::{Metadata, Val, evaluate::Evaluator, owner::PrimaryInputs, public_values};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use zeroize::Zeroizing;

pub(in crate::registry_progress) fn transition(
    draft: &Metadata,
    input: &mut PrimaryInputs,
) -> Option<(Metadata, Zeroizing<[u64; 160]>)> {
    let built = super::complete_role(draft.predicate).ok()?;
    let public = public_values::Expected::checked(draft).ok()?;
    // The original relation requires zero new-progress salt on Done/Error. The
    // owner supplies candidate entropy before learning which branch is taken.
    if draft.predicate {
        let status = Evaluator::new(&built.pool, &built.origins, input, &public)
            .ok()?
            .synthesize()
            .named("stream/result/118")
            .ok()?;
        if status != Val::ZERO {
            input.walk.new_salt.fill(Val::ZERO);
        }
    }
    let values = Evaluator::new(&built.pool, &built.origins, input, &public)
        .ok()?
        .synthesize()
        .finish()
        .ok()?;
    let field = |label: &str| {
        built
            .pool
            .fields
            .get(label)
            .and_then(|&id| values.values.get(id))
            .copied()
    };
    // Reject a noncanonical old opening rather than silently repairing its
    // header, table, row identities or padding while committing a different bank.
    for i in 0..208 {
        if field(&format!("old/serialized/{i}"))? != input.banks[0][i] {
            return None;
        }
    }
    let root = |group| {
        core::array::from_fn(|i| values.values[public_values::Address::new(group, i).ordinal() + 1])
    };
    let mut proposed = draft.clone();
    proposed.old = root(public_values::Group::Old);
    if proposed.old != draft.old {
        return None;
    }
    proposed.command = root(public_values::Group::Command);
    proposed.statement = root(public_values::Group::Statement);
    proposed.next = root(public_values::Group::Next);
    proposed.result = root(public_values::Group::Result);
    let mut result = Zeroizing::new([0u64; 160]);
    for (i, out) in result.iter_mut().enumerate() {
        *out = field(&format!("stream/result/{i}"))?.as_canonical_u64();
    }
    for i in 0..208 {
        input.banks[1][i] = field(&format!("new/serialized/{i}"))?;
    }
    Some((proposed, result))
}
