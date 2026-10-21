//! Public mathematical API examples over the existing bounded NONSECRET cases.
use super::{
    owner_cases::{self, Case, Kind},
    probe,
};
use crate::{Val, registry_progress::word as api};
use bfv_hiding_stark::{Challenge, Config};
use p3_batch_stark::BatchProof;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use zeroize::Zeroizing;
fn expected(case: &Case) -> api::Expected {
    let m = &case.metadata;
    api::Expected::checked(
        &m.source,
        if m.predicate {
            api::Role::Predicate
        } else {
            api::Role::Control
        },
        [0xa7; 32],
        m.parent
            .into_iter()
            .flat_map(|v| u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        m.enrollment,
        api::Claims {
            old: m.old,
            command: m.command,
            statement: m.statement,
            next: m.next,
            result: m.result,
            blind_sql: m.blind_sql,
        },
    )
    .unwrap()
}
fn inputs(case: &mut Case) -> api::PrivateInputs {
    let p = &mut case.input;
    let plain = Zeroizing::new(
        p.source
            .iter()
            .flat_map(|v| u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes())
            .collect(),
    );
    let source = api::SourceOpening::checked(
        plain,
        Zeroizing::new(p.source_salt.map(|v| v.as_canonical_u64())),
    )
    .unwrap();
    api::PrivateInputs::new(
        source,
        api::RegistryOpening::new(p.controllers, p.banks),
        core::mem::take(&mut p.command),
        core::mem::take(&mut p.walk),
        Zeroizing::new(p.mask),
        p.salts,
    )
}
#[test]
fn public_metadata_derivation_preserves_every_complete_original_binding() {
    for kind in Kind::ALL {
        let case = owner_cases::case(kind);
        let actual = expected(&case);
        assert_eq!(
            actual.binding(),
            probe::binding(&case.metadata),
            "{}",
            kind.label()
        );
        assert_eq!(
            api::statement_header().as_slice(),
            super::header("statement")
        );
        assert_eq!(
            actual.source().statement().values(),
            case.metadata.source.statement().values()
        );
    }
    assert_eq!(api::profile_digest(), super::profile());
    assert_eq!(api::wire_profile_digest(), super::probe_wire::profile());
}
#[test]
fn public_openings_reject_wrong_source_length_and_noncanonical_salt() {
    assert!(matches!(
        api::SourceOpening::checked(Zeroizing::new(vec![0; 2347]), Zeroizing::new([0; 4])),
        Err(api::Error::Shape)
    ));
    assert!(matches!(
        api::SourceOpening::checked(
            Zeroizing::new(vec![0; 2348]),
            Zeroizing::new([Val::ORDER_U64; 4])
        ),
        Err(api::Error::Shape)
    ));
}
#[test]
fn public_proofs_verify_all_original_owner_cases_and_reject_damaged_native_arguments() {
    // Each receiving role independently constructs PUBLIC preprocessing. Both
    // immutable setups are reusable; no private inputs, RNG or verdict is reused.
    let predicate_prover = api::Prover::new(api::Role::Predicate).unwrap();
    let predicate_verifier = api::Verifier::new(api::Role::Predicate).unwrap();
    let control_prover = api::Prover::new(api::Role::Control).unwrap();
    let control_verifier = api::Verifier::new(api::Role::Control).unwrap();
    for kind in Kind::ALL {
        let mut case = owner_cases::case(kind);
        let e = expected(&case);
        let (p, v, wrong) = if kind.predicate() {
            (&predicate_prover, &predicate_verifier, &control_verifier)
        } else {
            (&control_prover, &control_verifier, &predicate_verifier)
        };
        let evidence = p
            .produce(&e, inputs(&mut case))
            .expect("actual public producer");
        let result = v
            .verify(&e, evidence.as_bytes())
            .expect("actual independent public verifier");
        assert_eq!(result.expected().binding(), e.binding());
        assert!(matches!(
            wrong.verify(&e, evidence.as_bytes()),
            Err(api::Error::Binding)
        ));
        let mut proof: BatchProof<Config> =
            postcard::from_bytes(&evidence.as_bytes()[128..]).unwrap();
        proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] += Challenge::ONE;
        let payload = postcard::to_allocvec(&proof).unwrap();
        let mut bad = evidence.as_bytes()[..128].to_vec();
        bad[104..108].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bad.extend(payload);
        assert!(
            matches!(v.verify(&e, &bad), Err(api::Error::Verification)),
            "{}",
            kind.label()
        );
        let mut foreign_case = owner_cases::case(kind);
        foreign_case.metadata.result[0] += Val::ONE;
        let foreign = expected(&foreign_case);
        let mut repaired = evidence.into_bytes();
        repaired[40..104].copy_from_slice(&foreign.binding());
        assert!(matches!(
            v.verify(&foreign, &repaired),
            Err(api::Error::Verification)
        ));
    }
    // Cold receiving bounds the frame before allocating any role setup.
    let case = owner_cases::case(Kind::SkipBeforeOffset);
    assert!(matches!(
        api::verify(&expected(&case), &[]),
        Err(api::Error::Resource)
    ));
    assert!(matches!(
        api::verify(&expected(&case), &vec![0; api::MAX_EVIDENCE_BYTES + 1]),
        Err(api::Error::Resource)
    ));
    let mut case = owner_cases::case(Kind::SkipBeforeOffset);
    assert!(matches!(
        control_prover.produce(&expected(&case), inputs(&mut case)),
        Err(api::Error::Binding)
    ));
}
