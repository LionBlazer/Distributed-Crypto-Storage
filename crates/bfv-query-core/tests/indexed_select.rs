//! Explicit public fixtures; real ciphertext masking/relinearization and final BFV decoding.
use bfv_query_core::{
    Geometry, Owner, PeerEvaluator, ProofStatus, QueryContext, RowProjection, SelectedField,
};

fn context(id: u8) -> QueryContext {
    QueryContext::new([id; 16], [2; 112], [3; 112])
}

#[test]
fn encrypted_projection_covers_full256_unsigned_maximum_for_every_column_mask() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let fields = [SelectedField {
        age: 255,
        amount: 65535,
        active: true,
    }; 256];
    for projection in [
        RowProjection::Age,
        RowProjection::Amount,
        RowProjection::AgeAmount,
    ] {
        let prepared = owner
            .prepare_indexed_select_for_experiment(context(1), &fields, projection)
            .unwrap();
        let evaluated = peer
            .evaluate_indexed_select_for_experiment(&prepared.request)
            .unwrap();
        assert_eq!(
            (
                evaluated.stats.ct_ct_multiplications,
                evaluated.stats.relinearizations,
                evaluated.stats.rotations,
                evaluated.stats.multiplicative_depth
            ),
            (1, 1, 0, 1)
        );
        let actual = owner
            .decrypt_indexed_select_unverified_for_experiment(prepared.pending, &evaluated.output)
            .unwrap();
        assert_eq!(actual.proof, ProofStatus::Unavailable);
        assert_eq!(actual.rows.len(), 256);
        for (slot, row) in actual.rows.iter().enumerate() {
            assert_eq!(row.slot, slot);
            assert_eq!(
                row.age,
                (projection != RowProjection::Amount).then_some(255)
            );
            assert_eq!(
                row.amount,
                (projection != RowProjection::Age).then_some(65535)
            );
        }
    }
}

#[test]
fn zero_rows_and_inactive_nonzero_inputs_are_distinct_from_absent_rows() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let fields = [
        SelectedField {
            age: 0,
            amount: 0,
            active: true,
        },
        SelectedField {
            age: 255,
            amount: 65535,
            active: false,
        },
        SelectedField {
            age: 18,
            amount: 256,
            active: true,
        },
    ];
    let prepared = owner
        .prepare_indexed_select_for_experiment(context(2), &fields, RowProjection::AgeAmount)
        .unwrap();
    let actual = peer
        .evaluate_indexed_select_for_experiment(&prepared.request)
        .unwrap();
    let actual = owner
        .decrypt_indexed_select_unverified_for_experiment(prepared.pending, &actual.output)
        .unwrap();
    assert_eq!(
        actual
            .rows
            .iter()
            .map(|row| (row.slot, row.age, row.amount))
            .collect::<Vec<_>>(),
        vec![(0, Some(0), Some(0)), (2, Some(18), Some(256))]
    );
    for fields in [
        vec![],
        vec![
            SelectedField {
                age: 255,
                amount: 65535,
                active: false
            };
            16
        ],
    ] {
        let prepared = owner
            .prepare_indexed_select_for_experiment(context(3), &fields, RowProjection::Amount)
            .unwrap();
        let evaluated = peer
            .evaluate_indexed_select_for_experiment(&prepared.request)
            .unwrap();
        assert!(
            owner
                .decrypt_indexed_select_unverified_for_experiment(
                    prepared.pending,
                    &evaluated.output
                )
                .unwrap()
                .rows
                .is_empty()
        );
    }
}

#[test]
fn identical_context_freshly_encrypts_original_rows_and_masks_without_changing_setup() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let before = setup.to_bytes().unwrap();
    for fields in [
        vec![],
        vec![SelectedField {
            age: 42,
            amount: 65535,
            active: true,
        }],
    ] {
        let first = owner
            .prepare_indexed_select_for_experiment(context(4), &fields, RowProjection::Age)
            .unwrap();
        let second = owner
            .prepare_indexed_select_for_experiment(context(4), &fields, RowProjection::Age)
            .unwrap();
        assert_ne!(
            first.ciphertext_payload_bytes().unwrap(),
            second.ciphertext_payload_bytes().unwrap()
        );
    }
    assert_eq!(setup.to_bytes().unwrap(), before);
    assert!(matches!(
        owner.prepare_indexed_select_for_experiment(
            context(4),
            &[SelectedField {
                age: 0,
                amount: 0,
                active: true
            }; 257],
            RowProjection::Age
        ),
        Err(bfv_query_core::Error::GeometryLimit)
    ));
}
