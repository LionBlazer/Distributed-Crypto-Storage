//! Protocol adversarial controls use public fixtures and never expose secret key bytes.
use super::*;
fn context() -> QueryContext {
    QueryContext::new([5; 16], [2; 112], [3; 112])
}
fn fields() -> [SelectedField; 2] {
    [
        SelectedField {
            age: 42,
            amount: 65535,
            active: true,
        },
        SelectedField {
            age: 255,
            amount: 65535,
            active: false,
        },
    ]
}
fn prepare(owner: &Owner) -> PreparedIndexedSelect {
    owner
        .prepare_indexed_select_for_experiment(context(), &fields(), RowProjection::Age)
        .unwrap()
}
fn reply(request: &Request, projected: Vec<u8>) -> Response {
    Response {
        magic: RESPONSE_MAGIC,
        version: SELECT_VERSION,
        operation: request.operation,
        keyset_id: request.keyset_id,
        context: request.context.clone(),
        geometry: request.geometry,
        projection: request.projection,
        projected,
    }
}
fn slots(owner: &Owner, wire: &[u8]) -> Zeroizing<Vec<u64>> {
    let ct = checked_ciphertext(wire, &owner.parameters).unwrap();
    let pt = Zeroizing::new(owner.key.try_decrypt(&ct).unwrap());
    Zeroizing::new(Vec::<u64>::try_decode(&pt, Encoding::simd()).unwrap())
}

#[test]
fn request_contains_unprojected_originals_and_peer_actually_masks_ciphertext() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let prepared = prepare(&owner);
    let request: Request = decode(&prepared.request).unwrap();
    let original = slots(&owner, &request.rows);
    assert_eq!(
        (
            original[0],
            original[1],
            original[DEGREE / 2],
            original[DEGREE / 2 + 1],
            original[VALIDITY_START + 1]
        ),
        (42, 255, 65535, 65535, 1)
    );
    let mask = slots(&owner, &request.mask);
    assert_eq!(
        (
            mask[0],
            mask[1],
            mask[DEGREE / 2],
            mask[VALIDITY_START],
            mask[VALIDITY_START + 1]
        ),
        (1, 0, 0, 1, 0)
    );
    let evaluated = peer
        .evaluate_indexed_select_for_experiment(&prepared.request)
        .unwrap();
    let output: Response = decode(&evaluated.output).unwrap();
    assert_ne!(output.projected, request.rows);
    assert_ne!(output.projected, request.mask);
    let projected = slots(&owner, &output.projected);
    assert_eq!(
        (
            projected[0],
            projected[1],
            projected[DEGREE / 2],
            projected[VALIDITY_START],
            projected[VALIDITY_START + 1]
        ),
        (42, 0, 0, 1, 0)
    );
    // Echoing original encrypted values is not valid projection: it retains forbidden columns/rows.
    assert!(matches!(
        owner.decrypt_indexed_select_unverified_for_experiment(
            prepared.pending,
            &encode(&reply(&request, request.rows.clone())).unwrap()
        ),
        Err(Error::SelectBounds)
    ));
}

#[test]
fn metadata_domains_query_heads_geometry_and_projection_bind_both_roles() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let prepared = prepare(&owner);
    let honest = peer
        .evaluate_indexed_select_for_experiment(&prepared.request)
        .unwrap();
    for fault in 0..9 {
        let pending = prepare(&owner).pending;
        let mut response: Response = decode(&honest.output).unwrap();
        match fault {
            0 => response.magic[0] ^= 1,
            1 => response.version += 1,
            2 => response.keyset_id[0] ^= 1,
            3 => response.geometry = Geometry::Rows256,
            4 => response.context.query_id[0] ^= 1,
            5 => response.context.data_head[0] ^= 1,
            6 => response.context.index_head[0] ^= 1,
            7 => response.projection = RowProjection::Amount,
            8 => {
                response.context.index_head.pop();
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            owner.decrypt_indexed_select_unverified_for_experiment(
                pending,
                &encode(&response).unwrap()
            ),
            Err(Error::BindingMismatch)
        ));
    }
    for fault in 0..6 {
        let mut request: Request = decode(&prepared.request).unwrap();
        match fault {
            0 => request.magic[0] ^= 1,
            1 => request.version += 1,
            2 => request.keyset_id[0] ^= 1,
            3 => request.geometry = Geometry::Rows256,
            4 => {
                request.context.data_head.pop();
            }
            5 => request.mask.clear(),
            _ => unreachable!(),
        }
        assert!(
            peer.evaluate_indexed_select_for_experiment(&encode(&request).unwrap())
                .is_err()
        );
    }
    let mut unknown_operation = prepared.request.clone();
    unknown_operation[10..14].copy_from_slice(&1u32.to_le_bytes());
    assert!(
        peer.evaluate_indexed_select_for_experiment(&unknown_operation)
            .is_err()
    );
    let mut trailing = prepared.request.clone();
    trailing.push(0);
    assert!(
        peer.evaluate_indexed_select_for_experiment(&trailing)
            .is_err()
    );
    assert!(
        peer.evaluate_indexed_select_for_experiment(
            &prepared.request[..prepared.request.len() - 1]
        )
        .is_err()
    );
    assert!(peer.evaluate_indexed_update(&prepared.request).is_err());
    assert!(
        peer.evaluate_exact_index_aggregate_for_experiment(&prepared.request)
            .is_err()
    );
    let update = owner
        .prepare_indexed_update_for_experiment(context(), &fields(), 1)
        .unwrap();
    assert!(
        peer.evaluate_indexed_select_for_experiment(&update.request)
            .is_err()
    );
}

#[test]
fn every_active_inactive_and_reserved_output_slot_is_checked() {
    let (owner, _) = Owner::generate(Geometry::Rows16).unwrap();
    for (index, value) in [
        (0, 256),
        (1, 1),
        (DEGREE / 2, 1),
        (VALIDITY_START, 0),
        (VALIDITY_START + 1, 1),
        (DEGREE - 1, 1),
    ] {
        let prepared = prepare(&owner);
        let request: Request = decode(&prepared.request).unwrap();
        let mut values = Zeroizing::new(vec![0u64; DEGREE]);
        values[0] = 42;
        values[VALIDITY_START] = 1;
        values[index] = value;
        let response = reply(&request, owner.encrypted(&values).unwrap());
        assert!(
            matches!(
                owner.decrypt_indexed_select_unverified_for_experiment(
                    prepared.pending,
                    &encode(&response).unwrap()
                ),
                Err(Error::SelectBounds)
            ),
            "slot{index}"
        );
    }
    let prepared = owner
        .prepare_indexed_select_for_experiment(context(), &fields(), RowProjection::Amount)
        .unwrap();
    let request: Request = decode(&prepared.request).unwrap();
    let mut values = Zeroizing::new(vec![0u64; DEGREE]);
    values[DEGREE / 2] = 65536; // Still below t; must reject the unsigned u16 overflow.
    values[VALIDITY_START] = 1;
    let response = reply(&request, owner.encrypted(&values).unwrap());
    assert!(matches!(
        owner.decrypt_indexed_select_unverified_for_experiment(
            prepared.pending,
            &encode(&response).unwrap()
        ),
        Err(Error::SelectBounds)
    ));
}

#[test]
fn changed_level_extra_component_and_wrong_keyset_fail_before_computation_or_decode() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let (other, other_setup) = Owner::generate(Geometry::Rows16).unwrap();
    let other_peer = PeerEvaluator::from_public_setup(&other_setup).unwrap();
    let prepared = prepare(&owner);
    assert!(
        other_peer
            .evaluate_indexed_select_for_experiment(&prepared.request)
            .is_err()
    );
    let request: Request = decode(&prepared.request).unwrap();
    let ct = checked_ciphertext(&request.rows, &owner.parameters).unwrap();
    let mut lower = ct.clone();
    lower.switch_to_level(1).unwrap();
    let extra = Ciphertext::new(
        vec![ct[0].clone(), ct[1].clone(), ct[1].clone()],
        &owner.parameters,
    )
    .unwrap();
    for malformed in [lower.to_bytes(), extra.to_bytes()] {
        for input in 0..2 {
            let mut changed: Request = decode(&prepared.request).unwrap();
            if input == 0 {
                changed.rows = malformed.clone();
            } else {
                changed.mask = malformed.clone();
            }
            assert!(matches!(
                peer.evaluate_indexed_select_for_experiment(&encode(&changed).unwrap()),
                Err(Error::InvalidShape)
            ));
        }
        assert!(matches!(
            owner.decrypt_indexed_select_unverified_for_experiment(
                prepare(&owner).pending,
                &encode(&reply(&request, malformed)).unwrap()
            ),
            Err(Error::InvalidShape)
        ));
    }
    let output = peer
        .evaluate_indexed_select_for_experiment(&prepared.request)
        .unwrap();
    assert!(
        other
            .decrypt_indexed_select_unverified_for_experiment(prepared.pending, &output.output)
            .is_err()
    );
}

#[test]
fn in_bounds_public_homomorphic_forgery_remains_explicitly_unverified() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let prepared = prepare(&owner);
    let honest = peer
        .evaluate_indexed_select_for_experiment(&prepared.request)
        .unwrap();
    let mut response: Response = decode(&honest.output).unwrap();
    let mut ct = checked_ciphertext(&response.projected, peer.kernel.parameters()).unwrap();
    let mut values = vec![0u64; DEGREE];
    values[0] = 1;
    let delta = Plaintext::try_encode(&values, Encoding::simd(), peer.kernel.parameters()).unwrap();
    ct += &delta;
    response.projected = ct.to_bytes();
    let result = owner
        .decrypt_indexed_select_unverified_for_experiment(
            prepared.pending,
            &encode(&response).unwrap(),
        )
        .unwrap();
    assert_eq!(result.rows[0].age, Some(43));
    assert_eq!(result.proof, ProofStatus::Unavailable);
}
