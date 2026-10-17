//! Explicit public test fixtures; fresh secret keys remain in memory only.
use super::*;

fn context() -> QueryContext {
    QueryContext::new([19; 16], [2; HEAD_BYTES], [3; HEAD_BYTES])
}
fn fields(count: usize) -> Vec<SelectedField> {
    (0..count)
        .map(|slot| SelectedField {
            age: if slot == 0 { 255 } else { slot as u8 },
            amount: if slot % 2 == 0 { 65535 } else { 256 },
            active: true,
        })
        .collect()
}
fn evaluator(setup: &PublicSetup) -> PublicUpdateEvaluator {
    PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap()
}

#[test]
fn canonical_products_match_actual_upstream_projection_for_both_geometries_and_every_column() {
    for geometry in [Geometry::Rows16, Geometry::Rows256] {
        let (owner, setup) = Owner::generate(geometry).unwrap();
        let peer = evaluator(&setup);
        for projection in [
            RowProjection::Age,
            RowProjection::Amount,
            RowProjection::AgeAmount,
        ] {
            for count in [0, 1, geometry.slots()] {
                let original = fields(count);
                let prepared = owner
                    .prepare_exact_select_for_experiment(context(), &original, projection)
                    .unwrap();

                let canonical = peer.select_circuit_request(&prepared.request).unwrap();
                let computed = bfv_product_circuit::evaluate(&canonical).unwrap();
                let restored = peer
                    .restore_select_circuit_output(&prepared.request, &computed)
                    .unwrap();
                let upstream = peer.evaluate_exact_select(&prepared.request).unwrap();

                assert!(
                    restored == upstream,
                    "Canonical product and upstream ciphertext bytes differ"
                );
                let result = owner
                    .decrypt_indexed_select_unverified_for_experiment(prepared.pending, &restored)
                    .unwrap();
                assert_eq!(result.proof, ProofStatus::Unavailable);
                assert_eq!(result.rows.len(), count);
                for (row, field) in result.rows.iter().zip(original) {
                    assert_eq!(row.age, projection.age().then_some(field.age));
                    assert_eq!(row.amount, projection.amount().then_some(field.amount));
                }
            }
        }
    }
}

#[test]
fn original_fields_are_encrypted_before_projection_and_count_never_changes_public_mask_or_wire_size()
 {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = evaluator(&setup);
    let mut sizes = Vec::new();
    let mut masks = Vec::new();
    for count in [0, 1, 256] {
        let prepared = owner
            .prepare_exact_select_for_experiment(context(), &fields(count), RowProjection::Age)
            .unwrap();
        sizes.push(prepared.request.len());
        let request: Request = decode(&prepared.request).unwrap();
        assert!(request.mask.is_empty());
        let rows = checked_ciphertext(&request.rows, &owner.parameters).unwrap();
        let plaintext = Zeroizing::new(owner.key.try_decrypt(&rows).unwrap());
        let decoded = Zeroizing::new(Vec::<u64>::try_decode(&plaintext, Encoding::simd()).unwrap());
        if count > 0 {
            // Amount is not requested, but the original encrypted input must retain it.
            assert_eq!(
                (decoded[0], decoded[DEGREE / 2], decoded[VALIDITY_START]),
                (255, 65535, 1)
            );
        }
        let circuit = peer.select_circuit_request(&prepared.request).unwrap();
        masks.push(circuit[40 + bfv_product_circuit::COEFFICIENTS * 8..].to_vec());
    }
    assert!(sizes.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(masks.windows(2).all(|pair| pair[0] == pair[1]));
    // The public mask is fixed over all 256 possible rows, including encrypted padding.
    let mask = public_projection(&owner.parameters, RowProjection::Age).unwrap();
    let slots = Vec::<u64>::try_decode(&mask, Encoding::simd()).unwrap();
    assert!(slots[..MAX_ROWS].iter().all(|value| *value == 1));
    assert!(
        slots[VALIDITY_START..VALIDITY_START + MAX_ROWS]
            .iter()
            .all(|value| *value == 1)
    );
    assert!(
        slots[DEGREE / 2..DEGREE / 2 + MAX_ROWS]
            .iter()
            .all(|value| *value == 0)
    );
}

#[test]
fn private_active_holes_cannot_use_public_projection_and_operation_domains_do_not_mix() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = evaluator(&setup);
    let full = PeerEvaluator::from_public_setup(&setup).unwrap();
    let hole = SelectedField {
        age: 255,
        amount: 65535,
        active: false,
    };
    assert!(matches!(
        owner.prepare_exact_select_for_experiment(context(), &[hole], RowProjection::Age),
        Err(Error::InvalidShape)
    ));
    assert!(matches!(
        owner.prepare_exact_select_for_experiment(context(), &fields(17), RowProjection::Age),
        Err(Error::GeometryLimit)
    ));
    let private = owner
        .prepare_indexed_select_for_experiment(context(), &[hole], RowProjection::AgeAmount)
        .unwrap();
    assert!(peer.select_circuit_request(&private.request).is_err());
    assert!(peer.request_context(&private.request).is_err());
    assert!(peer.evaluate_exact_select(&private.request).is_err());
    let exact = owner
        .prepare_exact_select_for_experiment(context(), &fields(1), RowProjection::AgeAmount)
        .unwrap();
    assert!(
        full.evaluate_indexed_select_for_experiment(&exact.request)
            .is_err()
    );
    let exact_output = peer.evaluate_exact_select(&exact.request).unwrap();
    assert!(matches!(
        owner.decrypt_indexed_select_unverified_for_experiment(private.pending, &exact_output),
        Err(Error::BindingMismatch)
    ));
    let again = owner
        .prepare_exact_select_for_experiment(context(), &fields(1), RowProjection::AgeAmount)
        .unwrap();
    assert_ne!(
        again.ciphertext_payload_bytes().unwrap(),
        exact.ciphertext_payload_bytes().unwrap()
    );
}

#[test]
fn exact_query_and_both_heads_are_bound_even_when_ciphertexts_are_identical() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = evaluator(&setup);
    let prepared = owner
        .prepare_exact_select_for_experiment(context(), &fields(2), RowProjection::AgeAmount)
        .unwrap();
    let output =
        bfv_product_circuit::evaluate(&peer.select_circuit_request(&prepared.request).unwrap())
            .unwrap();
    for fault in 0..7 {
        let mut request: Request = decode(&prepared.request).unwrap();
        match fault {
            0 => request.context.query_id[0] ^= 1,
            1 => request.context.data_head[HEAD_BYTES - 1] ^= 1,
            2 => request.context.index_head[HEAD_BYTES - 1] ^= 1,
            3 => request.projection = RowProjection::Age,
            4 => request.geometry = Geometry::Rows256,
            5 => request.keyset_id[0] ^= 1,
            6 => request.mask.push(1),
            _ => unreachable!(),
        }
        assert!(
            peer.restore_select_circuit_output(&encode(&request).unwrap(), &output)
                .is_err()
        );
    }
}

#[test]
fn malformed_originals_and_metadata_are_rejected_before_conversion_or_restoration() {
    use fhe_math::rq::Representation;
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = evaluator(&setup);
    let prepared = owner
        .prepare_exact_select_for_experiment(context(), &fields(2), RowProjection::AgeAmount)
        .unwrap();
    let honest: Request = decode(&prepared.request).unwrap();
    let fresh = checked_ciphertext(&honest.rows, &owner.parameters).unwrap();
    let explicit = Ciphertext::new(fresh.to_vec(), &owner.parameters).unwrap();
    let mut bad_wires = vec![Vec::new()];
    for component in 0..2 {
        let mut bad = explicit.clone();
        bad[component].change_representation(Representation::PowerBasis);
        bad_wires.push(bad.to_bytes());
    }
    let mut lower = explicit.clone();
    lower.switch_to_level(1).unwrap();
    bad_wires.push(lower.to_bytes());
    bad_wires.push(
        Ciphertext::new(
            vec![fresh[0].clone(), fresh[1].clone(), fresh[1].clone()],
            &owner.parameters,
        )
        .unwrap()
        .to_bytes(),
    );
    for rows in bad_wires {
        let mut request: Request = decode(&prepared.request).unwrap();
        request.rows = rows;
        let wire = encode(&request).unwrap();
        let zeros = vec![0; bfv_product_circuit::COEFFICIENTS];
        let output = bfv_product_circuit::evaluate(
            &bfv_product_circuit::encode_request(Sha256::digest(&wire).into(), &zeros, &zeros)
                .unwrap(),
        )
        .unwrap();
        assert!(peer.evaluate_exact_select(&wire).is_err());
        assert!(peer.request_context(&wire).is_err());
        assert!(peer.select_circuit_request(&wire).is_err());
        assert!(peer.restore_select_circuit_output(&wire, &output).is_err());
    }
    for fault in 0..5 {
        let mut request: Request = decode(&prepared.request).unwrap();
        match fault {
            0 => request.magic[0] ^= 1,
            1 => request.version += 1,
            2 => {
                request.context.data_head.pop();
            }
            3 => {
                request.context.index_head.pop();
            }
            4 => request.operation = Operation::IndexedMaskedSelect,
            _ => unreachable!(),
        }
        assert!(
            peer.select_circuit_request(&encode(&request).unwrap())
                .is_err()
        );
        assert!(peer.request_context(&encode(&request).unwrap()).is_err());
    }
    let mut trailing = prepared.request.clone();
    trailing.push(0);
    assert!(peer.select_circuit_request(&trailing).is_err());
    assert!(
        peer.select_circuit_request(&prepared.request[..prepared.request.len() - 1])
            .is_err()
    );
}

#[test]
fn public_select_encoder_reuses_the_exact_owner_codec_without_reencryption_or_pending_state() {
    for geometry in [Geometry::Rows16, Geometry::Rows256] {
        let (owner, setup) = Owner::generate(geometry).unwrap();
        let peer = evaluator(&setup);
        for projection in [
            RowProjection::Age,
            RowProjection::Amount,
            RowProjection::AgeAmount,
        ] {
            let original = owner
                .prepare_exact_select_for_experiment(context(), &fields(2), projection)
                .unwrap();
            let decoded: Request = decode(&original.request).unwrap();

            let actual = peer
                .encode_public_select(context(), projection, &decoded.rows)
                .unwrap();

            assert_eq!(actual, original.request);
            let restored: Request = decode(&actual).unwrap();
            assert_eq!(restored.rows, decoded.rows);
            assert!(restored.mask.is_empty());
            assert_eq!(peer.request_context(&actual).unwrap(), context());
        }
    }
}

#[test]
fn actual_upstream_public_material_and_ciphertext_need_no_owner_at_the_projection_boundary() {
    // Explicitly PUBLIC NONSECRET fixture, generated here through upstream public APIs.
    let parameters = official_parameters().unwrap();
    let key = SecretKey::random(&parameters, &mut rand::rng());
    let relin = RelinearizationKey::new(&key, &mut rand::rng())
        .unwrap()
        .to_bytes();
    let mut builder = EvaluationKeyBuilder::new(&key).unwrap();
    for shift in rotation_steps(Geometry::Rows16) {
        builder.enable_column_rotation(shift).unwrap();
    }
    let rotations = builder.build(&mut rand::rng()).unwrap().to_bytes();
    drop(builder);
    let setup = PublicSetup::from_public_material(
        Geometry::Rows16,
        &parameters.to_bytes(),
        &relin,
        &rotations,
    )
    .unwrap();
    let peer = evaluator(&setup);
    let mut original = vec![0u64; DEGREE];
    original[0] = 255;
    original[DEGREE / 2] = 65535;
    original[VALIDITY_START] = 1;
    let plaintext =
        Plaintext::try_encode(original.as_slice(), Encoding::simd(), &parameters).unwrap();
    let ciphertext: Ciphertext = key.try_encrypt(&plaintext, &mut rand::rng()).unwrap();
    let ciphertext_bytes = ciphertext.to_bytes();

    let request = peer
        .encode_public_select(context(), RowProjection::Amount, &ciphertext_bytes)
        .unwrap();
    let canonical = peer.select_circuit_request(&request).unwrap();
    let products = bfv_product_circuit::evaluate(&canonical).unwrap();
    let output = peer
        .restore_select_circuit_output(&request, &products)
        .unwrap();

    assert_eq!(output, peer.evaluate_exact_select(&request).unwrap());
    let response: Response = decode(&output).unwrap();
    assert_ne!(
        response.projected, ciphertext_bytes,
        "An echo must not replace actual projection"
    );
    // Client-side fixture completion only; no key reaches the evaluator and no proof is asserted.
    let projected = checked_ciphertext(&response.projected, &parameters).unwrap();
    let decrypted = key.try_decrypt(&projected).unwrap();
    let decoded = Vec::<u64>::try_decode(&decrypted, Encoding::simd()).unwrap();
    let mut expected = vec![0; DEGREE];
    expected[DEGREE / 2] = 65535;
    expected[VALIDITY_START] = 1;
    assert_eq!(decoded, expected);
}

#[test]
fn encoded_public_select_binds_both_heads_query_projection_and_exact_ciphertext_bytes() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = evaluator(&setup);
    let prepared = owner
        .prepare_exact_select_for_experiment(context(), &fields(2), RowProjection::Amount)
        .unwrap();
    let original: Request = decode(&prepared.request).unwrap();
    let canonical = peer.select_circuit_request(&prepared.request).unwrap();
    let output = bfv_product_circuit::evaluate(&canonical).unwrap();
    for (other_context, projection) in [
        (
            QueryContext::new([20; 16], [2; HEAD_BYTES], [3; HEAD_BYTES]),
            RowProjection::Amount,
        ),
        (
            QueryContext::new([19; 16], [4; HEAD_BYTES], [3; HEAD_BYTES]),
            RowProjection::Amount,
        ),
        (
            QueryContext::new([19; 16], [2; HEAD_BYTES], [5; HEAD_BYTES]),
            RowProjection::Amount,
        ),
        (context(), RowProjection::Age),
    ] {
        let other = peer
            .encode_public_select(other_context, projection, &original.rows)
            .unwrap();
        assert!(matches!(
            peer.restore_select_circuit_output(&other, &output),
            Err(Error::BindingMismatch)
        ));
    }
    let rows = checked_ciphertext(&original.rows, &owner.parameters).unwrap();
    let another = owner.encrypted(&vec![0; DEGREE]).unwrap();
    let other_rows = checked_ciphertext(&another, &owner.parameters).unwrap();
    // Exact wire identity includes compressed seed/A and c0, even when a different
    // representation encodes the same polynomial pair. Syntax does not certify formation.
    let explicit = Ciphertext::new(rows.to_vec(), &owner.parameters)
        .unwrap()
        .to_bytes();
    let changed_b = Ciphertext::new(
        vec![other_rows[0].clone(), rows[1].clone()],
        &owner.parameters,
    )
    .unwrap()
    .to_bytes();
    for bytes in [explicit, changed_b, another] {
        assert_ne!(bytes, original.rows);
        let other = peer
            .encode_public_select(context(), RowProjection::Amount, &bytes)
            .unwrap();
        let decoded: Request = decode(&other).unwrap();
        assert_eq!(decoded.rows, bytes);
        assert!(matches!(
            peer.restore_select_circuit_output(&other, &output),
            Err(Error::BindingMismatch)
        ));
    }
}

#[test]
fn public_select_encoder_rejects_noncanonical_oversized_and_malformed_ciphertext_or_context() {
    use fhe_math::rq::Representation;
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = evaluator(&setup);
    let bytes = owner.encrypted(&vec![0; DEGREE]).unwrap();
    let rows = checked_ciphertext(&bytes, &owner.parameters).unwrap();
    let explicit = Ciphertext::new(rows.to_vec(), &owner.parameters).unwrap();
    let mut bad = vec![Vec::new(), bytes[..bytes.len() - 1].to_vec()];
    let mut unknown_field = bytes.clone();
    unknown_field.extend_from_slice(&[0x78, 0]);
    assert!(Ciphertext::from_bytes(&unknown_field, &owner.parameters).is_ok());
    bad.push(unknown_field);
    for component in 0..2 {
        let mut wrong_representation = explicit.clone();
        wrong_representation[component].change_representation(Representation::PowerBasis);
        bad.push(wrong_representation.to_bytes());
    }
    let mut lower = explicit.clone();
    lower.switch_to_level(1).unwrap();
    bad.push(lower.to_bytes());
    bad.push(
        Ciphertext::new(
            vec![rows[0].clone(), rows[1].clone(), rows[1].clone()],
            &owner.parameters,
        )
        .unwrap()
        .to_bytes(),
    );
    for bytes in bad {
        assert!(
            peer.encode_public_select(context(), RowProjection::Age, &bytes)
                .is_err()
        );
    }
    assert!(matches!(
        peer.encode_public_select(
            context(),
            RowProjection::Age,
            &vec![0; MAX_PUBLIC_SELECT_CIPHERTEXT_BYTES + 1]
        ),
        Err(Error::WireLimit)
    ));
    for index_head in [false, true] {
        let mut malformed = context();
        if index_head {
            malformed.index_head.pop();
        } else {
            malformed.data_head.pop();
        }
        assert!(matches!(
            peer.encode_public_select(malformed, RowProjection::Age, &bytes),
            Err(Error::BindingMismatch)
        ));
    }
}

#[test]
fn public_select_syntax_does_not_self_certify_ciphertext_key_authority_or_source_membership() {
    let (_, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let (other_owner, other_setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = evaluator(&setup);
    let other_peer = evaluator(&other_setup);
    let foreign = other_owner.encrypted(&vec![0; DEGREE]).unwrap();

    let syntax_only = peer
        .encode_public_select(context(), RowProjection::Amount, &foreign)
        .unwrap();

    // A canonical foreign-key ciphertext has the same public parameter shape.
    // The assembler supplies no key-consistency/source/permission/proof authority.
    assert_eq!(decode::<Request>(&syntax_only).unwrap().rows, foreign);
    assert!(peer.select_circuit_request(&syntax_only).is_ok());
    assert!(matches!(
        other_peer.select_circuit_request(&syntax_only),
        Err(Error::BindingMismatch)
    ));
}
