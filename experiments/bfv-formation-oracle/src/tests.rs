use super::*;
use packing::{Layout, PRESENCE, PUBLIC_ROWS, Packed, Row, pack};
use zeroize::Zeroizing;

#[test]
fn genuine_upstream_encryption_matches_every_residue_for_the_three_core_layouts() {
    for layout in Layout::ALL {
        let original = pack(layout, &PUBLIC_ROWS).unwrap();
        let fixture = oracle::Fixture::encrypt(&original).unwrap();
        assert!(fixture.check(&original).is_ok());
    }
}

#[test]
fn empty_sources_still_encrypt_real_complete_zero_polynomials() {
    for layout in Layout::ALL {
        let original = pack(layout, &[]).unwrap();
        assert!(original.values.iter().all(|v| *v == 0));
        let fixture = oracle::Fixture::encrypt(&original).unwrap();
        assert!(fixture.check(&original).is_ok());
    }
}

#[test]
fn changed_original_age_amount_presence_or_unused_slot_rejects_the_same_ciphertext() {
    let original = pack(Layout::ExactSelect, &PUBLIC_ROWS).unwrap();
    let fixture = oracle::Fixture::encrypt(&original).unwrap();
    for slot in [0, DEGREE / 2, PRESENCE, DEGREE - 1] {
        let mut changed = pack(Layout::ExactSelect, &PUBLIC_ROWS).unwrap();
        changed.values[slot] ^= 1;
        assert!(fixture.check(&changed).is_err());
    }
}

#[test]
fn exact_core_lanes_preserve_original_values_and_zero_every_other_position() {
    // Independent sparse golden vectors for PUBLIC_ROWS, not a second packer.
    let cases: [(Layout, &[(usize, u64)]); 3] = [
        (
            Layout::ExactSelect,
            &[
                (0, 255),
                (2, 255),
                (3, 128),
                (4097, 65535),
                (4098, 256),
                (4099, 255),
                (512, 1),
                (513, 1),
                (514, 1),
                (515, 1),
            ],
        ),
        (
            Layout::UpdateAmounts,
            &[(1, 255), (3, 255), (4097, 255), (4098, 1)],
        ),
        (
            Layout::PolynomialAggregate,
            &[
                (1, 255),
                (3, 255),
                (2561, 255),
                (2562, 1),
                (5120, 1),
                (5121, 1),
                (5122, 1),
                (5123, 1),
            ],
        ),
    ];
    for (layout, golden) in cases {
        let packed = pack(layout, &PUBLIC_ROWS).unwrap();
        for (index, value) in packed.values.iter().enumerate() {
            let expected = golden
                .iter()
                .find(|(slot, _)| *slot == index)
                .map_or(0, |(_, v)| *v);
            assert_eq!(*value, expected, "public fixture slot {index}");
        }
    }
    let rows = vec![Row { age: 0, amount: 0 }; 257];
    assert!(pack(Layout::ExactSelect, &rows).is_err());
    assert!(pack(Layout::UpdateAmounts, &rows).is_err());
    let rows = vec![Row { age: 0, amount: 0 }; 2561];
    assert!(pack(Layout::PolynomialAggregate, &rows).is_err());
}

#[test]
fn simd_inverse_map_is_not_the_same_as_coefficient_embedding() {
    let simd = pack(Layout::ExactSelect, &PUBLIC_ROWS).unwrap();
    let direct = Packed {
        layout: Layout::PolynomialAggregate,
        values: Zeroizing::new(simd.values.to_vec()),
    };
    let coefficients = oracle::plaintext_coefficients(&simd).unwrap();
    assert!(*coefficients != *direct.values);
    let ciphertext = oracle::Fixture::encrypt(&simd).unwrap();
    assert!(ciphertext.check(&direct).is_err());
}

#[test]
fn signed_noise_support_includes_both_twenty_boundaries_without_clamping() {
    let mut sample = vec![0; DEGREE];
    sample[0] = -20;
    sample[1] = 20;
    assert!(oracle::check_support(&sample).is_ok());
    sample[0] = -21;
    assert!(oracle::check_support(&sample).is_err());
    sample[0] = 21;
    assert!(oracle::check_support(&sample).is_err());
    assert!(oracle::check_support(&sample[..DEGREE - 1]).is_err());
}

#[test]
fn reference_ntt_matches_upstream_forward_and_backward_at_all_pinned_moduli() {
    use fhe_math::{ntt::NttOperator, zq::Modulus};
    for q in MODULI.into_iter().chain([PLAINTEXT]) {
        let reference = ntt::ReferenceNtt::new(q).unwrap();
        let native = NttOperator::new(&Modulus::new(q).unwrap(), DEGREE).unwrap();
        let original: Vec<_> = (0..DEGREE).map(|i| [0, q - 1, 1, q / 2][i % 4]).collect();
        let mut expected = original.clone();
        let mut actual = original.clone();
        native.forward(&mut expected);
        reference.forward(&mut actual).unwrap();
        assert!(actual == expected);
        native.backward(&mut expected);
        reference.backward(&mut actual).unwrap();
        assert!(actual == original && actual == expected);
    }
}
