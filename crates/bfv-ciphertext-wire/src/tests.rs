//! Public, non-secret byte fixtures; no SDK or encrypted computation is used here.
use super::*;
use bfv_fixed_geometry::{DEGREE, MODULI};

fn varint(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            break;
        }
    }
}
fn polynomial(degree: usize, representation: u8, variable_time: bool) -> Vec<u8> {
    let mut bytes = vec![8, representation, 16];
    varint(degree, &mut bytes);
    bytes.push(26);
    let packed = degree * (43 + 43 + 44 + 44 + 44) / 8;
    varint(packed, &mut bytes);
    bytes.resize(bytes.len() + packed, 0);
    if variable_time {
        bytes.extend([32, 1]);
    }
    bytes
}
fn envelope(polynomials: &[Vec<u8>], seed: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for polynomial in polynomials {
        bytes.push(10);
        varint(polynomial.len(), &mut bytes);
        bytes.extend(polynomial);
    }
    if let Some(seed) = seed {
        bytes.push(18);
        varint(seed.len(), &mut bytes);
        bytes.extend(seed);
    }
    bytes
}
fn set_residue(polynomial: &mut [u8], modulus_index: usize, index: usize, value: u64) {
    let packed_start = polynomial.len() - PACKED_POLYNOMIAL_BYTES;
    let preceding_bits: usize = MODULI[..modulus_index]
        .iter()
        .map(|q| (u64::BITS - (q - 1).leading_zeros()) as usize * DEGREE)
        .sum();
    let width = (u64::BITS - (MODULI[modulus_index] - 1).leading_zeros()) as usize;
    for bit in 0..width {
        let at = preceding_bits + index * width + bit;
        let mask = 1 << (at % 8);
        let byte = &mut polynomial[packed_start + at / 8];
        *byte &= !mask;
        if value & (1 << bit) != 0 {
            *byte |= mask;
        }
    }
}

#[test]
fn fixed_seeded_and_unseeded_forms_preserve_both_variable_time_policies() {
    for first in [false, true] {
        let p = polynomial(DEGREE, 2, first);
        assert_eq!(
            validate(&envelope(std::slice::from_ref(&p), Some(&[0; 32]))),
            Ok(())
        );
        for second in [false, true] {
            let wire = envelope(&[p.clone(), polynomial(DEGREE, 2, second)], None);
            assert_eq!(validate(&wire), Ok(()));
            assert!(wire.len() <= MAX_CANONICAL_UNSEEDED_BYTES);
        }
    }
    assert_eq!(PACKED_POLYNOMIAL_BYTES, 223232);
    assert_eq!(MAX_CANONICAL_UNSEEDED_BYTES, 446494);
}

#[test]
fn first_and_final_residues_of_every_modulus_have_exact_canonical_bounds() {
    let zero = polynomial(DEGREE, 2, false);
    let mut boundary = zero.clone();
    for (lane, q) in MODULI.into_iter().enumerate() {
        for index in [0, DEGREE - 1] {
            set_residue(&mut boundary, lane, index, q - 1);
        }
    }
    assert_eq!(
        validate(&envelope(std::slice::from_ref(&boundary), Some(&[7; 32]))),
        Ok(())
    );
    assert_eq!(validate(&envelope(&[zero.clone(), boundary], None)), Ok(()));
    for (lane, q) in MODULI.into_iter().enumerate() {
        for index in [0, DEGREE - 1] {
            let mut bad = zero.clone();
            set_residue(&mut bad, lane, index, q);
            for seeded in [true, false] {
                let wire = if seeded {
                    envelope(std::slice::from_ref(&bad), Some(&[7; 32]))
                } else {
                    envelope(&[zero.clone(), bad.clone()], None)
                };
                assert_eq!(
                    validate(&wire),
                    Err(WireError::InvalidEncoding),
                    "lane {lane}, index {index}, seeded {seeded}"
                );
            }
        }
    }
}

#[test]
fn many_tiny_polynomials_are_rejected_without_any_sdk_dependency() {
    // The actual historical amplification input fits the byte cap. An SDK decoder
    // would expand these degree8/NttShoup records against its N8192 context.
    let tiny = polynomial(8, 3, false);
    let wire = envelope(&vec![tiny; 2299], None);
    assert_eq!(wire.len(), 524172);
    assert!(wire.len() < MAX_CIPHERTEXT_BYTES);
    assert_eq!(validate(&wire), Err(WireError::InvalidEncoding));
}

#[test]
fn count_seed_degree_representation_and_noncanonical_fields_reject() {
    let p = polynomial(DEGREE, 2, false);
    assert!(validate(&envelope(&[], None)).is_err());
    assert!(validate(&envelope(std::slice::from_ref(&p), None)).is_err());
    assert!(validate(&envelope(&[p.clone(), p.clone()], Some(&[0; 32]))).is_err());
    for length in [0, 1, 31, 33] {
        assert!(validate(&envelope(std::slice::from_ref(&p), Some(&vec![0; length]))).is_err());
    }
    for degree in [0, 8, 8191, 16384] {
        let wire = envelope(&[polynomial(degree, 2, false)], Some(&[0; 32]));
        assert!(validate(&wire).is_err());
    }
    for representation in [0, 1, 3, 255] {
        let wire = envelope(&[polynomial(DEGREE, representation, false)], Some(&[0; 32]));
        assert!(validate(&wire).is_err());
    }
    for suffix in [[32, 0], [32, 2], [40, 1], [8, 2]] {
        let mut bad = p.clone();
        bad.extend(suffix);
        assert!(validate(&envelope(&[bad], Some(&[0; 32]))).is_err());
    }
    let valid = envelope(std::slice::from_ref(&p), Some(&[0; 32]));
    for suffix in [
        vec![24, 0],
        vec![24, 1],
        vec![18, 0],
        vec![32, 1],
        vec![128],
    ] {
        let mut bad = valid.clone();
        bad.extend(suffix);
        assert!(validate(&bad).is_err());
    }
}

#[test]
fn nonminimal_overflowing_truncated_and_oversized_lengths_reject() {
    let p = polynomial(DEGREE, 2, false);
    let mut overlong = p.clone();
    overlong.splice(3..5, [128, 192, 0]);
    assert!(validate(&envelope(&[overlong], Some(&[0; 32]))).is_err());
    let mut overflow = vec![10];
    overflow.extend([255; 9]);
    overflow.push(1);
    assert_eq!(validate(&overflow), Err(WireError::InvalidEncoding));
    let mut invalid_u64 = vec![10];
    invalid_u64.extend([255; 9]);
    invalid_u64.push(2);
    assert_eq!(validate(&invalid_u64), Err(WireError::InvalidEncoding));
    let valid = envelope(std::slice::from_ref(&p), Some(&[0; 32]));
    for length in [0, 1, 2, 3, 4, 10, p.len(), valid.len() - 1] {
        assert!(validate(&valid[..length]).is_err());
    }
    assert_eq!(
        validate(&vec![0; MAX_CIPHERTEXT_BYTES + 1]),
        Err(WireError::ResourceLimit)
    );
}

// Public, non-secret coefficient fixtures. This bit writer is independent of the
// library's packed-row reader; expected values are chosen before serialization.
fn public_coefficient(component: usize, basis: usize, index: usize) -> u64 {
    match index {
        0 => 0,
        1 => 1,
        2 => MODULI[basis] - 1,
        last if last == DEGREE - 1 => MODULI[basis] - 1 - component as u64,
        _ => (index as u64 * 257) + basis as u64 * 17 + component as u64 * 3,
    }
}
fn patterned_polynomial(component: usize, variable_time: bool) -> Vec<u8> {
    // set_residue's existing fixture convention has no optional suffix.
    let mut bytes = polynomial(DEGREE, 2, false);
    for basis in 0..MODULI.len() {
        for index in 0..DEGREE {
            set_residue(
                &mut bytes,
                basis,
                index,
                public_coefficient(component, basis, index),
            );
        }
    }
    if variable_time {
        bytes.extend([32, 1]);
    }
    bytes
}

#[test]
fn complete_view_reads_all_power_basis_rows_with_both_and_mixed_stored_policies() {
    for first_policy in [false, true] {
        for second_policy in [false, true] {
            // Arrange: both complete packed polynomials carry distinct known values.
            let wire = envelope(
                &[
                    patterned_polynomial(0, first_policy),
                    patterned_polynomial(1, second_policy),
                ],
                None,
            );

            // Act: the same strict parser returns only borrowed read-only views.
            let view = parse(&wire).unwrap();
            let SecondComponent::Stored(second) = view.second() else {
                panic!("an unseeded wire must expose the stored second polynomial");
            };

            // Assert: the Ntt tag does not reinterpret the stored PB coefficients.
            assert!(std::ptr::eq(view.original_bytes(), wire.as_slice()));
            for (component, (stored, policy)) in
                [(view.c0(), first_policy), (second, second_policy)]
                    .into_iter()
                    .enumerate()
            {
                assert_eq!(stored.allow_variable_time(), policy);
                assert_eq!(stored.packed_bytes().len(), PACKED_POLYNOMIAL_BYTES);
                for basis in 0..MODULI.len() {
                    let mut row = stored.row(basis).unwrap();
                    assert_eq!(row.len(), DEGREE);
                    for (index, actual) in row.by_ref().enumerate() {
                        assert_eq!(
                            actual,
                            public_coefficient(component, basis, index),
                            "component {component}, basis {basis}, coefficient {index}"
                        );
                    }
                    assert_eq!(row.len(), 0);
                    assert_eq!(row.next(), None);
                }
            }
        }
    }
}

#[test]
fn seeded_view_borrows_the_exact_original_seed_without_inventing_c1_rows() {
    let seed = core::array::from_fn::<_, 32, _>(|i| i as u8);
    for policy in [false, true] {
        let wire = envelope(&[patterned_polynomial(0, policy)], Some(&seed));

        let view = parse(&wire).unwrap();

        let SecondComponent::Seed(borrowed) = view.second() else {
            panic!("the original seeded form must stay seeded");
        };
        assert_eq!(borrowed, &seed);
        assert!(std::ptr::eq(
            borrowed.as_slice(),
            &wire[wire.len() - seed.len()..],
        ));
        assert!(std::ptr::eq(view.original_bytes(), wire.as_slice()));
        assert_eq!(view.c0().allow_variable_time(), policy);
        for basis in 0..MODULI.len() {
            let row = view.c0().row(basis).unwrap();
            assert_eq!(row.len(), DEGREE);
            for (index, value) in row.enumerate() {
                assert_eq!(value, public_coefficient(0, basis, index));
            }
        }
    }
}

#[test]
fn row_outlives_a_short_lived_view_and_is_exact_sized_fused_and_index_bounded() {
    fn borrowed_row(bytes: &[u8]) -> Coefficients<'_> {
        let view = parse(bytes).unwrap();
        view.c0().row(4).unwrap()
    }
    fn exact_and_fused<I: ExactSizeIterator<Item = u64> + core::iter::FusedIterator>(row: I) -> I {
        row
    }
    let wire = envelope(&[patterned_polynomial(0, false)], Some(&[9; 32]));

    // The view and polynomial handles have ended their scope; only wire is retained.
    let mut row = exact_and_fused(borrowed_row(&wire));

    assert_eq!(row.size_hint(), (DEGREE, Some(DEGREE)));
    assert_eq!(row.next(), Some(0));
    assert_eq!(row.len(), DEGREE - 1);
    assert_eq!(row.last(), Some(public_coefficient(0, 4, DEGREE - 1)));

    let mut exhausted = borrowed_row(&wire);
    assert_eq!(exhausted.by_ref().count(), DEGREE);
    assert_eq!(exhausted.size_hint(), (0, Some(0)));
    for _ in 0..3 {
        assert_eq!(exhausted.next(), None);
    }
    let stored = parse(&wire).unwrap().c0();
    for invalid in [MODULI.len(), MODULI.len() + 1, DEGREE, usize::MAX] {
        assert!(
            stored.row(invalid).is_none(),
            "invalid modulus index {invalid}"
        );
    }
}

#[test]
fn complete_view_rejects_a_noncanonical_last_coefficient_at_every_q_and_component() {
    let zero = polynomial(DEGREE, 2, false);
    for (basis, modulus) in MODULI.into_iter().enumerate() {
        for component in 0..2 {
            let mut polynomials = [zero.clone(), zero.clone()];
            set_residue(&mut polynomials[component], basis, DEGREE - 1, modulus - 1);
            let valid = envelope(&polynomials, None);
            let view = parse(&valid).unwrap();
            let stored = match (component, view.second()) {
                (0, _) => view.c0(),
                (1, SecondComponent::Stored(stored)) => stored,
                _ => unreachable!("the fixture has two stored polynomials"),
            };
            assert_eq!(stored.row(basis).unwrap().last(), Some(modulus - 1));

            set_residue(&mut polynomials[component], basis, DEGREE - 1, modulus);
            let invalid = envelope(&polynomials, None);
            assert!(matches!(parse(&invalid), Err(WireError::InvalidEncoding)));
            if component == 0 {
                let seeded = envelope(&polynomials[..1], Some(&[7; 32]));
                assert!(matches!(parse(&seeded), Err(WireError::InvalidEncoding)));
            }
        }
    }
}

#[test]
fn complete_view_requires_canonical_second_component_and_final_eof() {
    let first = patterned_polynomial(0, true);
    let mut malformed_second = polynomial(DEGREE, 2, false);
    malformed_second.extend([32, 0]); // explicit false is not canonical proto3.
    let invalid_second = envelope(&[first.clone(), malformed_second], None);
    assert!(matches!(
        parse(&invalid_second),
        Err(WireError::InvalidEncoding)
    ));

    let valid = envelope(std::slice::from_ref(&first), Some(&[5; 32]));
    for suffix in [[24, 0], [24, 1], [32, 1], [18, 0]] {
        let mut trailing = valid.clone();
        trailing.extend(suffix);
        assert!(matches!(parse(&trailing), Err(WireError::InvalidEncoding)));
    }
    assert!(matches!(
        parse(&vec![0; MAX_CIPHERTEXT_BYTES + 1]),
        Err(WireError::ResourceLimit)
    ));
}
