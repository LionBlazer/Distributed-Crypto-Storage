//! Public synthetic rows exercising real encrypted rotation/append, not owner-assembled answers.
use bfv_query_core::{
    Error, Geometry, Owner, PeerEvaluator, ProofStatus, QueryContext, SelectedField,
};
fn context() -> QueryContext {
    QueryContext::new([31; 16], [2; 112], [3; 112])
}
#[test]
fn encrypted_append_places_new_rows_after_actual_old_relation_including_empty_and_full256() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    for count in [0, 1, 16, 127, 128, 255] {
        let fields: Vec<_> = (0..count)
            .map(|slot| SelectedField {
                age: (slot % 256) as u8,
                amount: if slot % 2 == 0 { 65535 } else { 256 },
                active: true,
            })
            .collect();
        let incoming = SelectedField {
            age: 255,
            amount: 65535,
            active: true,
        };
        let prepared = owner
            .prepare_indexed_insert_for_experiment(context(), &fields, incoming)
            .unwrap();
        let output = peer
            .evaluate_indexed_insert_for_experiment(&prepared.request)
            .unwrap();
        assert_eq!(
            (
                output.stats.ciphertext_additions,
                output.stats.ct_ct_multiplications,
                output.stats.multiplicative_depth
            ),
            (1, 0, 0)
        );
        assert!(output.stats.rotations >= 1);
        let result = owner
            .decrypt_indexed_insert_unverified_for_experiment(prepared.pending, &output.output)
            .unwrap();
        assert_eq!(result.proof, ProofStatus::Unavailable);
        assert_eq!(result.rows.len(), count + 1);
        for (slot, row) in result.rows.iter().enumerate() {
            let expected = if slot < count { fields[slot] } else { incoming };
            assert_eq!(
                (row.slot, row.age, row.amount),
                (slot, expected.age, expected.amount)
            );
        }
    }
}
#[test]
fn full_tables_inactive_holes_and_unsupported_geometry_reject_before_encryption() {
    let (owner, _) = Owner::generate(Geometry::Rows256).unwrap();
    let row = SelectedField {
        age: 0,
        amount: 0,
        active: true,
    };
    assert!(matches!(
        owner.prepare_indexed_insert_for_experiment(context(), &[row; 256], row),
        Err(Error::GeometryLimit)
    ));
    let inactive = SelectedField {
        active: false,
        ..row
    };
    assert!(matches!(
        owner.prepare_indexed_insert_for_experiment(context(), &[inactive], row),
        Err(Error::InvalidShape)
    ));
    assert!(matches!(
        owner.prepare_indexed_insert_for_experiment(context(), &[], inactive),
        Err(Error::InvalidShape)
    ));
    let (small, _) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(matches!(
        small.prepare_indexed_insert_for_experiment(context(), &[], row),
        Err(Error::GeometryLimit)
    ));
}
#[test]
fn zero_insert_is_a_real_row_and_fresh_ciphertexts_do_not_depend_on_context_changes() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let bytes = setup.to_bytes().unwrap();
    let row = SelectedField {
        age: 0,
        amount: 0,
        active: true,
    };
    let first = owner
        .prepare_indexed_insert_for_experiment(context(), &[], row)
        .unwrap();
    let second = owner
        .prepare_indexed_insert_for_experiment(context(), &[], row)
        .unwrap();
    assert_ne!(
        first.ciphertext_payload_bytes().unwrap(),
        second.ciphertext_payload_bytes().unwrap()
    );
    let result = peer
        .evaluate_indexed_insert_for_experiment(&first.request)
        .unwrap();
    let result = owner
        .decrypt_indexed_insert_unverified_for_experiment(first.pending, &result.output)
        .unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!((result.rows[0].age, result.rows[0].amount), (0, 0));
    assert_eq!(setup.to_bytes().unwrap(), bytes);
}
