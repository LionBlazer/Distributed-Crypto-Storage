//! Owning protocol tests use only public non-secret fixtures and never export a secret key.
use super::*;
use fhe::bfv::Ciphertext;
use fhe_traits::DeserializeParametrized;

fn context(id: u8) -> QueryContext {
    QueryContext::new([id; 16], [2; 112], [3; 112])
}
fn field(amount: u16, active: bool) -> SelectedField {
    SelectedField {
        age: 250,
        amount,
        active,
    }
}
fn response(request: &IndexedUpdateRequest, updated_limbs: Vec<u8>) -> IndexedUpdateResponse {
    IndexedUpdateResponse {
        magic: RESPONSE_MAGIC,
        version: UPDATE_VERSION,
        operation: OperationTag::IndexedAddAmount,
        keyset_id: request.keyset_id,
        context: request.context.clone(),
        geometry: request.geometry,
        updated_limbs,
    }
}
fn slots(owner: &Owner, ciphertext: &[u8]) -> Vec<u64> {
    let ciphertext = checked_ciphertext(ciphertext, &owner.parameters).unwrap();
    let plaintext = owner.key.try_decrypt(&ciphertext).unwrap();
    Vec::<u64>::try_decode(&plaintext, Encoding::simd()).unwrap()
}

#[test]
fn prepared_ciphertexts_contain_original_amounts_and_masked_delta_not_updated_answers() {
    let (owner, _) = Owner::generate(Geometry::Rows16).unwrap();
    let prepared = owner
        .prepare_indexed_update_for_experiment(
            context(20),
            &[field(10, true), field(65535, false), field(255, true)],
            1,
        )
        .unwrap();
    let request: IndexedUpdateRequest = decode(&prepared.request).unwrap();
    let original = slots(&owner, &request.amounts);
    let delta = slots(&owner, &request.deltas);
    let mut expected_original = vec![0; DEGREE];
    expected_original[0] = 10;
    expected_original[2] = 255;
    let mut expected_delta = vec![0; DEGREE];
    expected_delta[0] = 1;
    expected_delta[2] = 1;
    assert_eq!(original, expected_original);
    assert_eq!(delta, expected_delta);
}

#[test]
fn public_echo_forgery_is_in_bounds_but_remains_explicitly_unverified() {
    let (owner, _) = Owner::generate(Geometry::Rows16).unwrap();
    let prepared = owner
        .prepare_indexed_update_for_experiment(context(21), &[field(10, true)], 1)
        .unwrap();
    let request: IndexedUpdateRequest = decode(&prepared.request).unwrap();
    // A public peer can echo the original ciphertext and valid public binding without addition.
    let forged = encode(&response(&request, request.amounts.clone())).unwrap();
    let actual = owner
        .decrypt_indexed_update_unverified_for_experiment(prepared.pending, &forged)
        .unwrap();
    let UnverifiedUpdateOutcome::Values(values) = actual else {
        panic!("Unexpected overflow")
    };
    assert_eq!(values.rows[0].amount, 10);
    assert_ne!(values.rows[0].amount, 11);
    assert_eq!(values.proof, ProofStatus::Unavailable);
}

#[test]
fn every_slot_is_validated_before_overflow_can_hide_a_later_malformed_value() {
    let (owner, _) = Owner::generate(Geometry::Rows16).unwrap();
    let fields = [field(65535, true), field(0, true)];
    // First row overflows; all subsequent faults must still reject, rather than return Overflow.
    for (index, value) in [
        (1, 511),
        (2, 1),
        (DEGREE / 2 + 1, 511),
        (128, 1),
        (DEGREE - 1, 1),
    ] {
        let prepared = owner
            .prepare_indexed_update_for_experiment(context(22), &fields, 1)
            .unwrap();
        let request: IndexedUpdateRequest = decode(&prepared.request).unwrap();
        let mut forged_slots = vec![0; DEGREE];
        forged_slots[0] = 256;
        forged_slots[DEGREE / 2] = 255;
        forged_slots[index] = value;
        let forged = encode(&response(&request, owner.encrypted(&forged_slots).unwrap())).unwrap();
        assert!(matches!(
            owner.decrypt_indexed_update_unverified_for_experiment(prepared.pending, &forged),
            Err(Error::UpdateBounds)
        ));
    }
}

#[test]
fn request_operation_version_keyset_geometry_and_head_shapes_gate_addition() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let prepared = owner
        .prepare_indexed_update_for_experiment(context(23), &[field(10, true)], 1)
        .unwrap();
    for fault in 0..6 {
        let mut request: IndexedUpdateRequest = decode(&prepared.request).unwrap();
        match fault {
            0 => request.magic[0] ^= 1,
            1 => request.version += 1,
            2 => request.operation = OperationTag::CountSum,
            3 => request.geometry = Geometry::Rows256,
            4 => request.keyset_id[0] ^= 1,
            5 => {
                request.context.data_head.pop();
            }
            _ => unreachable!(),
        }
        assert!(
            peer.evaluate_indexed_update(&encode(&request).unwrap())
                .is_err()
        );
    }
}

#[test]
fn response_operation_version_keyset_geometry_query_and_heads_gate_decryption() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let prepared = owner
        .prepare_indexed_update_for_experiment(context(24), &[field(10, true)], 1)
        .unwrap();
    let evaluated = peer.evaluate_indexed_update(&prepared.request).unwrap();
    for fault in 0..8 {
        let pending = owner
            .prepare_indexed_update_for_experiment(context(24), &[field(10, true)], 1)
            .unwrap()
            .pending;
        let mut reply: IndexedUpdateResponse = decode(&evaluated.output).unwrap();
        match fault {
            0 => reply.magic[0] ^= 1,
            1 => reply.version += 1,
            2 => reply.operation = OperationTag::CountSum,
            3 => reply.geometry = Geometry::Rows256,
            4 => reply.keyset_id[0] ^= 1,
            5 => reply.context.query_id[0] ^= 1,
            6 => reply.context.data_head[0] ^= 1,
            7 => reply.context.index_head[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            owner.decrypt_indexed_update_unverified_for_experiment(
                pending,
                &encode(&reply).unwrap()
            ),
            Err(Error::BindingMismatch)
        ));
    }
}

#[test]
fn lower_level_and_extra_component_ciphertexts_are_rejected_at_both_roles() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let prepared = owner
        .prepare_indexed_update_for_experiment(context(25), &[field(10, true)], 1)
        .unwrap();
    let original: IndexedUpdateRequest = decode(&prepared.request).unwrap();
    let ciphertext = Ciphertext::from_bytes(&original.amounts, &owner.parameters).unwrap();
    let mut lower = ciphertext.clone();
    lower.switch_to_level(1).unwrap();
    let extra = Ciphertext::new(
        vec![
            ciphertext[0].clone(),
            ciphertext[1].clone(),
            ciphertext[1].clone(),
        ],
        &owner.parameters,
    )
    .unwrap();
    for malformed in [lower.to_bytes(), extra.to_bytes()] {
        // Each input position is checked, and every decode uses the evaluator's same Arc.
        for replace_amounts in [true, false] {
            let mut request: IndexedUpdateRequest = decode(&prepared.request).unwrap();
            if replace_amounts {
                request.amounts = malformed.clone();
            } else {
                request.deltas = malformed.clone();
            }
            assert!(matches!(
                peer.evaluate_indexed_update(&encode(&request).unwrap()),
                Err(Error::InvalidShape)
            ));
        }
        let pending = owner
            .prepare_indexed_update_for_experiment(context(25), &[field(10, true)], 1)
            .unwrap()
            .pending;
        let forged = encode(&response(&original, malformed)).unwrap();
        assert!(matches!(
            owner.decrypt_indexed_update_unverified_for_experiment(pending, &forged),
            Err(Error::InvalidShape)
        ));
    }
}

#[test]
fn legacy_read_and_update_frames_do_not_cross_evaluation_entrypoints() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let read = owner
        .prepare(
            context(26),
            &[field(10, true)],
            crate::Predicate::Equal(250),
        )
        .unwrap();
    let update = owner
        .prepare_indexed_update_for_experiment(context(26), &[field(10, true)], 1)
        .unwrap();
    assert!(peer.evaluate_indexed_update(&read.request).is_err());
    assert!(peer.evaluate(&update.request).is_err());
    let update_output = peer.evaluate_indexed_update(&update.request).unwrap();
    assert!(
        owner
            .decrypt_unverified(read.pending, &update_output.output)
            .is_err()
    );
}
