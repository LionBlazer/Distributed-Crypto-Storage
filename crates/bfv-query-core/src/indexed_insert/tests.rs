//! Protocol failures use public non-secret fixtures. No keys are exported.
use super::*;
fn context() -> QueryContext {
    QueryContext::new([32; 16], [2; 112], [3; 112])
}
fn field(age: u8, amount: u16) -> SelectedField {
    SelectedField {
        age,
        amount,
        active: true,
    }
}
fn prepare(owner: &Owner) -> PreparedIndexedInsert {
    owner
        .prepare_indexed_insert_for_experiment(context(), &[field(18, 255)], field(42, 256))
        .unwrap()
}
fn response(request: &Request, rows: Vec<u8>) -> Response {
    Response {
        magic: RESPONSE_MAGIC,
        version: INSERT_VERSION,
        operation: request.operation,
        keyset_id: request.keyset_id,
        context: request.context.clone(),
        geometry: request.geometry,
        existing_rows: request.existing_rows,
        rows,
    }
}
#[test]
fn original_incoming_is_staged_elsewhere_and_only_peer_rotation_places_it_at_append_slot() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let prepared = prepare(&owner);
    let request: Request = decode(&prepared.request).unwrap();
    let ct = checked_ciphertext(&request.incoming, &owner.parameters).unwrap();
    let pt = Zeroizing::new(owner.key.try_decrypt(&ct).unwrap());
    let slots = Zeroizing::new(Vec::<u64>::try_decode(&pt, Encoding::simd()).unwrap());
    assert_eq!(
        (
            slots[1],
            slots[MAX_ROWS],
            slots[DEGREE / 2 + MAX_ROWS],
            slots[VALIDITY + MAX_ROWS]
        ),
        (0, 42, 256, 1)
    );
    let evaluated = peer
        .evaluate_indexed_insert_for_experiment(&prepared.request)
        .unwrap();
    let result: Response = decode(&evaluated.output).unwrap();
    assert_ne!(result.rows, request.existing);
    assert_ne!(result.rows, request.incoming);
    assert!(matches!(
        owner.decrypt_indexed_insert_unverified_for_experiment(
            prepared.pending,
            &encode(&response(&request, request.incoming.clone())).unwrap()
        ),
        Err(Error::InsertBounds)
    ));
}
#[test]
fn insert_metadata_wire_and_other_operation_domains_are_bound_at_both_roles() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let prepared = prepare(&owner);
    let honest = peer
        .evaluate_indexed_insert_for_experiment(&prepared.request)
        .unwrap();
    for fault in 0..8 {
        let mut reply: Response = decode(&honest.output).unwrap();
        match fault {
            0 => reply.magic[0] ^= 1,
            1 => reply.version += 1,
            2 => reply.keyset_id[0] ^= 1,
            3 => reply.geometry = Geometry::Rows16,
            4 => reply.context.query_id[0] ^= 1,
            5 => reply.context.data_head[0] ^= 1,
            6 => reply.context.index_head[0] ^= 1,
            7 => reply.existing_rows += 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            owner.decrypt_indexed_insert_unverified_for_experiment(
                prepare(&owner).pending,
                &encode(&reply).unwrap()
            ),
            Err(Error::BindingMismatch)
        ));
    }
    for fault in 0..7 {
        let mut request: Request = decode(&prepared.request).unwrap();
        match fault {
            0 => request.magic[0] ^= 1,
            1 => request.version += 1,
            2 => request.keyset_id[0] ^= 1,
            3 => request.geometry = Geometry::Rows16,
            4 => {
                request.context.data_head.pop();
            }
            5 => request.existing_rows = 256,
            6 => request.incoming.clear(),
            _ => unreachable!(),
        }
        assert!(
            peer.evaluate_indexed_insert_for_experiment(&encode(&request).unwrap())
                .is_err()
        );
    }
    let mut operation = prepared.request.clone();
    operation[10..14].copy_from_slice(&1u32.to_le_bytes());
    assert!(
        peer.evaluate_indexed_insert_for_experiment(&operation)
            .is_err()
    );
    let mut trailing = prepared.request.clone();
    trailing.push(0);
    assert!(
        peer.evaluate_indexed_insert_for_experiment(&trailing)
            .is_err()
    );
    assert!(
        peer.evaluate_indexed_insert_for_experiment(
            &prepared.request[..prepared.request.len() - 1]
        )
        .is_err()
    );
    assert!(
        peer.evaluate_indexed_select_for_experiment(&prepared.request)
            .is_err()
    );
    assert!(peer.evaluate_indexed_update(&prepared.request).is_err());
    assert!(
        peer.evaluate_exact_index_aggregate_for_experiment(&prepared.request)
            .is_err()
    );
    let select = owner
        .prepare_indexed_select_for_experiment(context(), &[], crate::RowProjection::Age)
        .unwrap();
    assert!(
        peer.evaluate_indexed_insert_for_experiment(&select.request)
            .is_err()
    );
}
#[test]
fn all_decoded_rows_validity_and_unused_slots_are_checked_before_returning_any_relation() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let request: Request = decode(&prepare(&owner).request).unwrap();
    for (index, value) in [
        (0, 256),
        (DEGREE / 2 + 1, 65536),
        (VALIDITY + 1, 0),
        (2, 1),
        (VALIDITY + 2, 1),
        (DEGREE - 1, 1),
    ] {
        let mut slots = Zeroizing::new(vec![0u64; DEGREE]);
        slots[VALIDITY] = 1;
        slots[VALIDITY + 1] = 1;
        slots[index] = value;
        let reply = response(&request, owner.encrypted(&slots).unwrap());
        assert!(matches!(
            owner.decrypt_indexed_insert_unverified_for_experiment(
                prepare(&owner).pending,
                &encode(&reply).unwrap()
            ),
            Err(Error::InsertBounds)
        ));
    }
    let ct = checked_ciphertext(&request.existing, &owner.parameters).unwrap();
    let mut lower = ct.clone();
    lower.switch_to_level(1).unwrap();
    let extra = Ciphertext::new(
        vec![ct[0].clone(), ct[1].clone(), ct[1].clone()],
        &owner.parameters,
    )
    .unwrap();
    for malformed in [lower.to_bytes(), extra.to_bytes()] {
        for input in 0..2 {
            let mut changed: Request = decode(&prepare(&owner).request).unwrap();
            if input == 0 {
                changed.existing = malformed.clone()
            } else {
                changed.incoming = malformed.clone()
            }
            assert!(matches!(
                peer.evaluate_indexed_insert_for_experiment(&encode(&changed).unwrap()),
                Err(Error::InvalidShape)
            ));
        }
        assert!(matches!(
            owner.decrypt_indexed_insert_unverified_for_experiment(
                prepare(&owner).pending,
                &encode(&response(&request, malformed)).unwrap()
            ),
            Err(Error::InvalidShape)
        ));
    }
}
#[test]
fn wrong_owner_and_in_bounds_public_output_forgery_never_gain_a_proof() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let (other, other_setup) = Owner::generate(Geometry::Rows256).unwrap();
    let other_peer = PeerEvaluator::from_public_setup(&other_setup).unwrap();
    let prepared = prepare(&owner);
    assert!(
        other_peer
            .evaluate_indexed_insert_for_experiment(&prepared.request)
            .is_err()
    );
    let output = peer
        .evaluate_indexed_insert_for_experiment(&prepared.request)
        .unwrap();
    assert!(
        other
            .decrypt_indexed_insert_unverified_for_experiment(prepared.pending, &output.output)
            .is_err()
    );
    let prepared = prepare(&owner);
    let output = peer
        .evaluate_indexed_insert_for_experiment(&prepared.request)
        .unwrap();
    let mut reply: Response = decode(&output.output).unwrap();
    let mut ct = checked_ciphertext(&reply.rows, peer.kernel.parameters()).unwrap();
    let mut delta = vec![0u64; DEGREE];
    delta[1] = 1;
    let delta = Plaintext::try_encode(&delta, Encoding::simd(), peer.kernel.parameters()).unwrap();
    ct += &delta;
    reply.rows = ct.to_bytes();
    let result = owner
        .decrypt_indexed_insert_unverified_for_experiment(
            prepared.pending,
            &encode(&reply).unwrap(),
        )
        .unwrap();
    assert_eq!(result.rows[1].age, 43);
    assert_eq!(result.proof, ProofStatus::Unavailable);
}
