use compact_bfv_byte_limb_core::{
    Error, Geometry, Owner, PeerEvaluator, Predicate, ProofStatus, PublicSetup, QueryContext,
    SelectedField,
};

fn context(id: u8) -> QueryContext {
    QueryContext::new([id; 16], [2; 112], [3; 112])
}
fn field(age: u8, amount: u16, active: bool) -> SelectedField {
    SelectedField {
        age,
        amount,
        active,
    }
}

#[test]
fn inactive_and_missing_fixed16_fields_contribute_no_count_or_sum() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let cases = vec![
        (vec![], Predicate::AtLeast(0), (0, 0)),
        (
            vec![field(0, 0, true), field(255, 65535, false)],
            Predicate::AtLeast(0),
            (1, 0),
        ),
        (
            vec![
                field(0, 255, true),
                field(255, 256, true),
                field(128, 65535, true),
                field(42, 65535, false),
            ],
            Predicate::Equal(255),
            (1, 256),
        ),
        (
            vec![
                field(0, 255, true),
                field(255, 256, true),
                field(128, 65535, true),
                field(42, 65535, false),
            ],
            Predicate::AtLeast(128),
            (2, 65791),
        ),
        (
            vec![
                field(0, 255, true),
                field(255, 256, true),
                field(128, 65535, true),
                field(42, 65535, false),
            ],
            Predicate::ClosedRange {
                lower: 0,
                upper: 128,
            },
            (2, 65790),
        ),
    ];
    for (i, (fields, predicate, expected)) in cases.into_iter().enumerate() {
        let prepared = owner.prepare(context(i as u8), &fields, predicate).unwrap();
        let evaluated = peer.evaluate(&prepared.request).unwrap();
        let actual = owner
            .decrypt_unverified(prepared.pending, &evaluated.output)
            .unwrap();
        assert_eq!((actual.count, actual.sum), expected);
        assert_eq!(actual.proof, ProofStatus::Unavailable);
        assert_eq!(evaluated.stats.multiplicative_depth, 5);
    }
}

#[test]
fn all256_maximum_amounts_decode_unsigned_limbs_and_exact_u32_sum() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let fields = (0..256)
        .map(|age| field(age as u8, 65535, true))
        .collect::<Vec<_>>();
    let prepared = owner
        .prepare(
            context(10),
            &fields,
            Predicate::ClosedRange {
                lower: 0,
                upper: 255,
            },
        )
        .unwrap();
    let evaluated = peer.evaluate(&prepared.request).unwrap();
    let actual = owner
        .decrypt_unverified(prepared.pending, &evaluated.output)
        .unwrap();
    assert_eq!((actual.count, actual.sum), (256, 16_776_960));
    assert_eq!(
        (actual.low_limb_sum, actual.high_limb_sum),
        (65_280, 65_280)
    );
    assert_eq!(evaluated.stats.ct_ct_multiplications, 15);
    assert_eq!(evaluated.stats.rotations, 20);
}

#[test]
fn byte_boundaries_and_age_edges_match_expected_eq_ge_and_closed_ranges() {
    let (owner, setup) = Owner::generate(Geometry::Rows256).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let fields = (0..256)
        .map(|i| {
            field(
                [0, 255, 17, 18, 42, 127, 128, 254][i % 8],
                [0, 1, 255, 256, 257, 65280, 65534, 65535][i % 8],
                true,
            )
        })
        .collect::<Vec<_>>();
    let cases = [
        (Predicate::Equal(0), (32, 0)),
        (Predicate::Equal(255), (32, 32)),
        (Predicate::Equal(19), (0, 0)),
        (Predicate::AtLeast(0), (256, 6_307_776)),
        (Predicate::AtLeast(255), (32, 32)),
        (
            Predicate::ClosedRange {
                lower: 18,
                upper: 128,
            },
            (128, 4_202_464),
        ),
        (
            Predicate::ClosedRange {
                lower: 19,
                upper: 19,
            },
            (0, 0),
        ),
    ];
    for (i, (predicate, expected)) in cases.into_iter().enumerate() {
        let prepared = owner
            .prepare(context(20 + i as u8), &fields, predicate)
            .unwrap();
        let evaluated = peer.evaluate(&prepared.request).unwrap();
        let actual = owner
            .decrypt_unverified(prepared.pending, &evaluated.output)
            .unwrap();
        assert_eq!((actual.count, actual.sum), expected, "case {i}");
    }
}

#[test]
fn preparation_rejects_reversed_range_and_fields_beyond_the_fixed_geometry() {
    let (owner, _) = Owner::generate(Geometry::Rows16).unwrap();
    assert!(matches!(
        owner.prepare(
            context(40),
            &[],
            Predicate::ClosedRange {
                lower: 255,
                upper: 0
            }
        ),
        Err(Error::ReversedRange)
    ));
    let fields = vec![field(0, 0, true); 17];
    assert!(matches!(
        owner.prepare(context(41), &fields, Predicate::AtLeast(0)),
        Err(Error::GeometryLimit)
    ));
}

#[test]
fn output_binding_rejects_changed_query_id_data_head_and_index_head() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let peer = PeerEvaluator::from_public_setup(&setup).unwrap();
    let fields = [field(18, 256, true)];
    let prepared = owner
        .prepare(context(50), &fields, Predicate::AtLeast(18))
        .unwrap();
    let evaluated = peer.evaluate(&prepared.request).unwrap();
    let contexts = [
        QueryContext::new([51; 16], [2; 112], [3; 112]),
        QueryContext::new([50; 16], [4; 112], [3; 112]),
        QueryContext::new([50; 16], [2; 112], [4; 112]),
    ];
    for changed in contexts {
        let pending = owner
            .prepare(changed, &fields, Predicate::AtLeast(18))
            .unwrap()
            .pending;
        assert!(matches!(
            owner.decrypt_unverified(pending, &evaluated.output),
            Err(Error::BindingMismatch)
        ));
    }
    let actual = owner
        .decrypt_unverified(prepared.pending, &evaluated.output)
        .unwrap();
    assert_eq!((actual.count, actual.sum), (1, 256));
}

#[test]
fn fresh_ciphertexts_change_without_relying_on_query_id_or_context_changes() {
    let (owner, _) = Owner::generate(Geometry::Rows16).unwrap();
    let fields = [field(255, 65535, true)];
    let a = owner
        .prepare(context(60), &fields, Predicate::Equal(255))
        .unwrap();
    let b = owner
        .prepare(context(60), &fields, Predicate::Equal(255))
        .unwrap();
    assert_ne!(
        a.ciphertext_payload_bytes().unwrap(),
        b.ciphertext_payload_bytes().unwrap()
    );
}

#[test]
fn public_setup_roundtrip_preserves_profile_and_trailing_wire_is_rejected() {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let setup_wire = setup.to_bytes().unwrap();
    let restored = PublicSetup::from_bytes(&setup_wire).unwrap();
    assert_eq!(
        restored.byte_counts().unwrap().serialized_wire,
        setup_wire.len()
    );
    let profile = restored.profile().unwrap();
    assert_eq!(profile.degree, 8192);
    assert_eq!(profile.plaintext_modulus, 114689);
    assert_eq!(profile.coefficient_moduli_bits, vec![43, 43, 44, 44, 44]);
    assert_eq!(owner.secret_key_serialized_bytes(), 8195);
    let peer = PeerEvaluator::from_public_setup(&restored).unwrap();
    let prepared = owner
        .prepare(context(70), &[field(0, 0, true)], Predicate::AtLeast(0))
        .unwrap();
    let mut request = prepared.request.clone();
    request.push(1);
    assert!(peer.evaluate(&request).is_err());
    assert!(peer.evaluate(&[0, 1, 2]).is_err());
    let mut response = peer.evaluate(&prepared.request).unwrap().output;
    response.push(1);
    assert!(
        owner
            .decrypt_unverified(prepared.pending, &response)
            .is_err()
    );
    let mut bad_setup = setup_wire;
    bad_setup.push(1);
    assert!(PublicSetup::from_bytes(&bad_setup).is_err());
}
