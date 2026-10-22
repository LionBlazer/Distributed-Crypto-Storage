//! Explicitly public source/state examples; no live state is committed here.
use super::*;
use crate::registry_progress::{
    word,
    word_inventory::{
        self,
        owner::PrimaryInputs,
        owner_cases::{self, Kind},
    },
};
use p3_field::PrimeCharacteristicRing;

fn draft(m: &word_inventory::Metadata) -> Expected {
    let expected = Expected::checked(
        &m.source,
        if m.predicate {
            word::Role::Predicate
        } else {
            word::Role::Control
        },
        [0xa7; 32],
        m.parent
            .iter()
            .flat_map(|v| (v.as_canonical_u64() as u32).to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        m.enrollment,
        word::Claims {
            old: m.old,
            command: [Val::ONE; 4],
            statement: [Val::ZERO; 4],
            next: [Val::TWO; 4],
            result: [Val::ONE; 4],
            blind_sql: m.blind_sql,
        },
    )
    .unwrap();
    assert_eq!(expected.context(), &m.context);
    expected
}
fn material(p: &mut PrimaryInputs) -> TransitionMaterial {
    TransitionMaterial {
        source: SourceOpening::checked(
            Zeroizing::new(
                p.source
                    .iter()
                    .flat_map(|v| (v.as_canonical_u64() as u32).to_le_bytes())
                    .collect(),
            ),
            Zeroizing::new(p.source_salt.map(|v| v.as_canonical_u64())),
        )
        .unwrap(),
        registry: CurrentRegistry::new(
            p.controllers,
            Zeroizing::new(p.banks[0].map(|v| v.as_canonical_u64())),
            Zeroizing::new(core::array::from_fn(|i| {
                p.banks[1][190 + i].as_canonical_u64()
            })),
        )
        .unwrap(),
        command: core::mem::take(&mut p.command),
        walk: core::mem::take(&mut p.walk),
        mask: Zeroizing::new(p.mask),
        salts: p.salts,
    }
}
#[test]
fn current_bank_produces_every_original_wait_skip_resume_nowait_and_end_opening() {
    for kind in Kind::ALL {
        let mut case = owner_cases::case(kind);
        let independent_result = owner_cases::result(&case)
            .iter()
            .map(|v| v.as_canonical_u64())
            .collect::<Vec<_>>();
        let expected_next = case.input.banks[1].map(|v| v.as_canonical_u64());
        let expected_binding = word_inventory::probe::binding(&case.metadata);
        let expected = draft(&case.metadata);
        let mut input = material(&mut case.input);
        // Supplying entropy does not require guessing Done/Error in advance.
        if kind.predicate() && kind != Kind::ConflictBeforeOffset {
            input.walk.new_salt.fill(Val::from_u32(99));
        }
        let transition = prepare_transition(&expected, input).unwrap();
        assert_eq!(
            transition.expected().binding(),
            expected_binding,
            "{}",
            kind.label()
        );
        let (proposed, _, opening) = transition.into_parts();
        let (next, result) = opening.into_words();
        assert_eq!(word::registry_root(&next).unwrap(), proposed.claims().next);
        assert!(word::registry_root(&[u64::MAX; 208]).is_err());
        assert_eq!(*next, expected_next, "{}", kind.label());
        assert_eq!(result.as_slice(), independent_result, "{}", kind.label());
    }
}
#[test]
fn proposed_control_lifecycle_still_requires_actual_independent_native_proofs() {
    let (mut metadata, mut p) = word_inventory::owner::public_case(false);
    let producer = word::Prover::new(word::Role::Control).unwrap();
    let receiver = word::Verifier::new(word::Role::Control).unwrap();
    for op in [0, 3, 3, 5, 4, 6] {
        metadata.old = word_inventory::owner::hash(&p.banks[0]);
        p.command = word::CommandInput {
            op,
            actor: (op != 0).then_some(0),
            principal: 1,
            id: 1,
            name: if matches!(op, 3..=5) { [7; 8] } else { [0; 8] },
            ..Default::default()
        };
        let transition = prepare_transition(&draft(&metadata), material(&mut p)).unwrap();
        let (expected, inputs, opening) = transition.into_parts();
        let evidence = producer.produce(&expected, inputs).unwrap();
        receiver.verify(&expected, evidence.as_bytes()).unwrap();
        let mut wrong = expected.clone();
        wrong.inner.next[0] += Val::ONE;
        assert!(receiver.verify(&wrong, evidence.as_bytes()).is_err());
        let (next, result) = opening.into_words();
        assert_eq!(word::registry_root(&next).unwrap(), expected.claims().next);
        let slot = &next[84..137];
        assert_eq!(result[117], op as u64 + 2);
        assert_eq!(result[118], 1);
        if op == 6 {
            assert_eq!(slot, [0; 53]);
        } else {
            assert_eq!(slot[0], 1);
            assert_eq!(slot[1], 1);
            assert_eq!(slot[27], u64::from(op != 0));
            assert_eq!(slot[40], u64::from(op == 3 && slot[12] == 3));
        }
        // Public fixture chaining exercises producer recipes, not live admission.
        // There is no candidate installation capability in the production API.
        p.banks[0] = next.map(Val::from_u64);
        p.banks[1] = p.banks[0];
    }
}
#[test]
fn stale_old_root_wrong_controller_and_forged_resume_are_rejected_before_proving() {
    let mut case = owner_cases::case(Kind::SkipBeforeOffset);
    let mut wrong = draft(&case.metadata);
    wrong.inner.old[0] += Val::ONE;
    assert!(matches!(
        prepare_transition(&wrong, material(&mut case.input)),
        Err(Error::Binding)
    ));
    let mut case = owner_cases::case(Kind::SkipBeforeOffset);
    let expected = draft(&case.metadata);
    case.input.controllers[0][0] += Val::ONE;
    assert!(matches!(
        prepare_transition(&expected, material(&mut case.input)),
        Err(Error::Binding)
    ));
    let mut case = owner_cases::case(Kind::ResumePrefix);
    let expected = draft(&case.metadata);
    case.input.walk.selected[0] = !case.input.walk.selected[0];
    assert!(matches!(
        prepare_transition(&expected, material(&mut case.input)),
        Err(Error::Binding)
    ));
    let mut case = owner_cases::case(Kind::SkipBeforeOffset);
    let expected = draft(&case.metadata);
    case.input.banks[0][207] = Val::ONE;
    assert!(matches!(
        prepare_transition(&expected, material(&mut case.input)),
        Err(Error::Binding)
    ));
    assert!(
        CurrentRegistry::new(
            [[Val::ONE; 8]; 2],
            Zeroizing::new([u64::MAX; 208]),
            Zeroizing::new([1; 4])
        )
        .is_err()
    );
    for field in [80, 84 + 12] {
        let mut case = owner_cases::case(Kind::SkipBeforeOffset);
        case.input.banks[0][field..field + 2].fill(Val::from_u32(u32::MAX));
        case.metadata.old = word_inventory::owner::hash(&case.input.banks[0]);
        assert!(
            matches!(
                prepare_transition(&draft(&case.metadata), material(&mut case.input)),
                Err(Error::Binding)
            ),
            "64-bit counter overflow at field {field}"
        );
    }
}
