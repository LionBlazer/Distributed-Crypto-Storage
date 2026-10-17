//! Owning public representation/routing/limb tests; actual SDK/proofs live in consumer.
use super::*;
fn request(direction: Direction, index: u8, input: &[u64]) -> Request {
    decode_request(
        &encode_request(direction, Basis::new(index).unwrap(), [0x51; 32], input).unwrap(),
    )
    .unwrap()
}
fn zero(direction: Direction, index: u8) -> Request {
    request(direction, index, &vec![0; DEGREE])
}
#[test]
fn fixed_frames_bind_all_ten_bases_direction_representation_and_every_residue() {
    assert!(Basis::new(10).is_err());
    let mut profiles = std::collections::HashSet::new();
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        let p = basis.modulus();
        for direction in [Direction::Forward, Direction::Inverse] {
            assert!(profiles.insert(profile_digest(direction, basis)));
            let mut input = vec![0; DEGREE];
            input[0] = 1;
            input[DEGREE - 1] = p - 1;
            let wire = encode_request(direction, basis, [7; 32], &input).unwrap();
            let r = decode_request(&wire).unwrap();
            assert_eq!(r.input(), input);
            assert_eq!(r.encode(), wire);
            assert_eq!(r.binding(), [7; 32]);
            for offset in [0, 8, 72, 73, 74, 75] {
                let mut bad = wire.clone();
                bad[offset] ^= 128;
                assert!(decode_request(&bad).is_err());
            }
            assert!(decode_request(&wire[..wire.len() - 1]).is_err());
            let mut tail = wire.clone();
            tail.push(0);
            assert!(decode_request(&tail).is_err());
            let mut bad = wire;
            bad[80 + (DEGREE - 1) * 8..].copy_from_slice(&p.to_le_bytes());
            assert!(matches!(
                decode_request(&bad),
                Err(Error::NonCanonicalResidue)
            ));
        }
    }
}
#[test]
fn exact_root_tables_have_the_native_inverse_exponent_offset_and_fixed_route_boundaries() {
    for index in 0..10 {
        let basis = Basis::new(index).unwrap();
        let p = basis.modulus();
        let v = parameters(basis);
        let root = v.primitive_root();
        assert_eq!(parameters::pow(root, (2 * DEGREE) as u64, p), 1);
        assert_eq!(parameters::pow(root, DEGREE as u64, p), p - 1);
        assert_eq!(parameters::mul(v.inverse_size(), DEGREE as u64, p), 1);
        assert_eq!(v.forward_twiddles().len(), DEGREE);
        assert_eq!(v.inverse_twiddles().len(), DEGREE);
        for i in 0..DEGREE {
            let reversed = i.reverse_bits() >> (usize::BITS - 13);
            assert_eq!(
                v.forward_twiddles()[i],
                parameters::pow(root, reversed as u64, p)
            );
            assert_eq!(
                v.inverse_twiddles()[i],
                parameters::pow(root, (2 * DEGREE - reversed - 1) as u64, p)
            );
        }
        let left = parameters::lane(Direction::Forward, basis, 0, 0);
        let right = parameters::lane(Direction::Forward, basis, 0, DEGREE / 2);
        assert_eq!(
            (left.x, left.y, left.a, left.b),
            (0, DEGREE / 2, 1, v.forward_twiddles()[1])
        );
        assert_eq!(
            (right.x, right.y, right.a, right.b),
            (0, DEGREE / 2, 1, p - v.forward_twiddles()[1])
        );
        let last = parameters::lane(Direction::Inverse, basis, 12, DEGREE - 1);
        assert_eq!(
            (last.x, last.y, last.a, last.b),
            (
                DEGREE / 2 - 1,
                DEGREE - 1,
                v.inverse_twiddles()[DEGREE - 2],
                p - v.inverse_twiddles()[DEGREE - 2]
            )
        );
        let scale = parameters::lane(Direction::Inverse, basis, 13, DEGREE - 1);
        assert_eq!(
            (scale.x, scale.a, scale.b),
            (DEGREE - 1, v.inverse_size(), 0)
        );
    }
}
#[test]
fn full_zero_transforms_roundtrip_every_canonical_public_stage_and_fixed_frame_length() {
    for direction in [Direction::Forward, Direction::Inverse] {
        let r = zero(direction, 9);
        let e = evaluate_with_certificate(&r).unwrap();
        assert_eq!(e.aux.stages().len(), direction.stages());
        assert!(e.output.coefficients().iter().all(|&v| v == 0));
        for stage in e.aux.stages() {
            assert_eq!(stage.coefficients().len(), DEGREE);
            assert_eq!(stage.rows().len(), DEGREE);
            assert!(stage.coefficients().iter().all(|&v| v == 0));
        }
        let output = e.output.encode();
        let aux = e.aux.encode();
        assert_eq!(output.len(), direction.output_bytes());
        assert_eq!(aux.len(), direction.aux_bytes());
        assert_eq!(decode_output(&output).unwrap().encode(), output);
        assert_eq!(decode_aux(&aux).unwrap().encode(), aux);
        assert!(decode_output(&output[..output.len() - 1]).is_err());
        assert!(decode_aux(&aux[..aux.len() - 1]).is_err());
        let mut tail = aux;
        tail.push(0);
        assert!(decode_aux(&tail).is_err());
    }
}
#[test]
fn forward_then_inverse_preserves_all_original_words_including_both_modulus_extremes() {
    for index in [0, 9] {
        let p = Basis::new(index).unwrap().modulus();
        let mut original: Vec<_> = (0..DEGREE)
            .map(|j| ((j as u128 * 7919 + 17) % p as u128) as u64)
            .collect();
        original[0] = 0;
        original[DEGREE - 1] = p - 1;
        let forward =
            evaluate_with_certificate(&request(Direction::Forward, index, &original)).unwrap();
        let inverse = evaluate_with_certificate(&request(
            Direction::Inverse,
            index,
            forward.output.coefficients(),
        ))
        .unwrap();
        assert_eq!(inverse.output.coefficients(), original);
    }
}
#[test]
fn inverse_requires_a_fourteenth_normalization_stage_instead_of_only_thirteen_butterfly_layers() {
    let r = request(Direction::Inverse, 0, &vec![1; DEGREE]);
    let e = evaluate_with_certificate(&r).unwrap();
    assert_eq!(e.aux.stages().len(), 14);
    assert_eq!(e.aux.stages()[12].coefficients()[0], DEGREE as u64);
    assert_eq!(e.output.coefficients()[0], 1);
    assert!(e.output.coefficients()[1..].iter().all(|&v| v == 0));
}
#[test]
fn auxiliary_high_bits_aliases_and_noncanonical_intermediate_residues_reject() {
    let r = zero(Direction::Inverse, 9);
    let e = evaluate_with_certificate(&r).unwrap();
    let wire = e.aux.encode();
    for (offset, mask) in [(16, 4), (20, 2)] {
        let mut bad = wire.clone();
        bad[144 + offset] |= mask;
        assert!(matches!(decode_aux(&bad), Err(Error::AuxiliaryRange)));
    }
    let mut bad = wire.clone();
    let last = 144 + (r.direction().stages() * DEGREE - 1) * AUXILIARY_ROW_BYTES;
    bad[last..last + 8].copy_from_slice(&r.basis().modulus().to_le_bytes());
    assert!(matches!(decode_aux(&bad), Err(Error::NonCanonicalResidue)));
    let mut wrong = wire;
    wrong[74] = 1;
    assert!(decode_aux(&wrong).is_err());
}
#[test]
fn exact_request_binding_and_last_stage_identity_cannot_be_relabelled_by_public_hashes() {
    let r = zero(Direction::Forward, 0);
    let mut e = evaluate_with_certificate(&r).unwrap();
    let other =
        decode_request(&encode_request(r.direction(), r.basis(), [8; 32], r.input()).unwrap())
            .unwrap();
    assert_eq!(
        codec::check_binding(&other, &e.output, &e.aux),
        Err(Error::Binding)
    );
    e.output.coefficients[DEGREE - 1] = 1;
    e.aux.output_digest = codec::digest(&e.output.encode());
    assert_eq!(
        codec::check_binding(&r, &e.output, &e.aux),
        Err(Error::Binding)
    );
}
#[cfg(feature = "plonky3")]
#[test]
fn public_preparation_gathers_exact_fixed_route_and_inverse_normalization_without_host_ntt_math() {
    use p3_air::BaseAir;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    let r = zero(Direction::Inverse, 9);
    let e = evaluate_with_certificate(&r).unwrap();
    let shape = plonky3::NttAir::shape(r.direction(), r.basis());
    assert!(!shape.is_prepared());
    assert!(shape.preprocessed_trace().is_none());
    assert_eq!(shape.preprocessed_width(), 448);
    let prepared = plonky3::prepare(&r, &e.output, &e.aux).unwrap();
    let row = prepared.coefficient_row(DEGREE - 1).unwrap();
    assert_eq!(row.len(), 448);
    let integer = |at: usize, n: usize| {
        row[at..at + n]
            .iter()
            .enumerate()
            .map(|(i, v)| (v.as_canonical_u64() as u128) << (16 * i))
            .sum::<u128>()
    };
    let p = r.basis().modulus();
    let v = parameters(r.basis());
    assert_eq!(integer(12, 4), v.inverse_twiddles()[4095] as u128);
    assert_eq!(integer(16, 4), (p - v.inverse_twiddles()[4095]) as u128);
    let last = 13 * 32;
    assert_eq!(integer(last + 4, 4), 0);
    assert_eq!(integer(last + 12, 4), v.inverse_size() as u128);
    assert_eq!(integer(last + 16, 4), 0);
    let (air, pv) = prepared.into_parts();
    let trace =
        p3_matrix::dense::RowMajorMatrix::new(vec![p3_goldilocks::Goldilocks::ZERO; DEGREE], 1);
    assert!(p3_air::check_all_constraints(&air, &trace, &pv, Some(1)).is_ok());
}
#[cfg(feature = "plonky3")]
#[test]
fn canonical_rebuilt_stage_output_quotient_and_carry_forgeries_reach_air_and_reject() {
    use p3_field::PrimeCharacteristicRing;
    let r = zero(Direction::Inverse, 9);
    let original = evaluate_with_certificate(&r).unwrap();
    let trace =
        p3_matrix::dense::RowMajorMatrix::new(vec![p3_goldilocks::Goldilocks::ZERO; DEGREE], 1);
    for attack in 0..4 {
        let mut output = original.output.clone();
        let mut aux = original.aux.clone();
        match attack {
            0 => aux.stages[6].coefficients[DEGREE - 1] = 1,
            1 => {
                output.coefficients[DEGREE - 1] = 1;
                aux.stages[13].coefficients[DEGREE - 1] = 1;
                aux.output_digest = codec::digest(&output.encode());
            }
            2 => aux.stages[13].rows[DEGREE - 1].biased_quotient ^= 1,
            _ => aux.stages[0].rows[0].carries[0] ^= 1,
        }
        let wire = aux.encode();
        let decoded = decode_aux(&wire).unwrap();
        let (air, pv) = plonky3::prepare(&r, &output, &decoded)
            .unwrap()
            .into_parts();
        assert!(
            !p3_air::check_all_constraints(&air, &trace, &pv, Some(1)).is_ok(),
            "attack{attack}"
        );
    }
}
