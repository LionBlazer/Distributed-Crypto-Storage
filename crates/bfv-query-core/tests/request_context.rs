//! Public fixtures only; role keys are generated in memory and never exported.
use bfv_query_core::{
    Geometry, Owner, PublicUpdateEvaluator, QueryContext, RowProjection, SelectedField,
};

#[test]
fn supported_original_requests_expose_exact_query_and_both_heads_after_full_shape_validation() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let context = QueryContext::new([31; 16], [4; 112], [5; 112]);
    let fields = [SelectedField {
        age: 18,
        amount: 256,
        active: true,
    }];
    let update = owner
        .prepare_indexed_update_for_experiment(context.clone(), &fields, 5)
        .unwrap();
    let select = owner
        .prepare_exact_select_for_experiment(context.clone(), &fields, RowProjection::AgeAmount)
        .unwrap();
    let insert = owner
        .prepare_indexed_insert_for_experiment(context.clone(), &fields, &[fields[0]])
        .unwrap();

    for request in [&update.request, &select.request, &insert.request] {
        let actual = peer.request_context(request).unwrap();

        assert_eq!(actual, context);
        assert_eq!(actual.data_head(), &[4; 112]);
        assert_eq!(actual.index_head(), &[5; 112]);
        let mut trailing = request.clone();
        trailing.push(0);
        assert!(peer.request_context(&trailing).is_err());
        assert!(peer.request_context(&request[..request.len() - 1]).is_err());
        let mut wrong_domain = request.clone();
        wrong_domain[0] ^= 1;
        assert!(peer.request_context(&wrong_domain).is_err());
    }
    assert!(peer.request_context(&[]).is_err());
    assert!(peer.request_context(b"BFVADDQ").is_err());
}

#[test]
fn context_inspection_does_not_admit_another_keyset_or_the_private_active_select_domain() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let (_, other_setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let other =
        PublicUpdateEvaluator::from_parameters(&other_setup.update_parameters().unwrap()).unwrap();
    let context = QueryContext::new([32; 16], [4; 112], [5; 112]);
    let fields = [SelectedField {
        age: 18,
        amount: 256,
        active: true,
    }];
    let select = owner
        .prepare_exact_select_for_experiment(context.clone(), &fields, RowProjection::AgeAmount)
        .unwrap();
    let update = owner
        .prepare_indexed_update_for_experiment(context.clone(), &fields, 5)
        .unwrap();
    for request in [&select.request, &update.request] {
        assert!(other.request_context(request).is_err());
    }
    let private = owner
        .prepare_indexed_select_for_experiment(context, &fields, RowProjection::AgeAmount)
        .unwrap();
    assert!(peer.request_context(&private.request).is_err());
}
