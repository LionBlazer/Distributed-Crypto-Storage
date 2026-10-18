//! PUBLIC NONSECRET vector claims. These tests perform routing, not proof verification.
use super::*;

const BINDING: [u8; 32] = [0x61; 32];
const KEYSET: [u8; 32] = [0x62; 32];

fn component(tag: u64) -> Vec<u64> {
    let mut values = Vec::with_capacity(BASES * DEGREE);
    for (target, &modulus) in MODULI.iter().enumerate() {
        values.extend((0..DEGREE).map(|index| tag * 1_000_000 + (target * DEGREE + index) as u64));
        *values.last_mut().unwrap() = modulus - 1;
    }
    values
}

fn digits() -> Vec<u64> {
    let mut values = Vec::with_capacity(BASES * BASES * DEGREE);
    for source in 0..BASES {
        for (target, &modulus) in MODULI.iter().enumerate() {
            values.extend(
                (0..DEGREE).map(|index| ((BASES * source + target + 1) * DEGREE + index) as u64),
            );
            *values.last_mut().unwrap() = modulus - 1;
        }
    }
    values
}

fn key_rows() -> [[Vec<u64>; 5]; 2] {
    core::array::from_fn(|component_index| {
        core::array::from_fn(|decomposition| {
            component(10 + (5 * component_index + decomposition) as u64)
        })
    })
}

fn borrowed_keys(keys: &[[Vec<u64>; 5]; 2]) -> [[&[u64]; 5]; 2] {
    keys.each_ref()
        .map(|component| component.each_ref().map(Vec::as_slice))
}

#[test]
fn embed_request_preserves_every_power_basis_coefficient_and_both_context_labels() {
    let original = component(1);

    let request = embed_request(BINDING, KEYSET, &original).unwrap();

    assert_eq!(request.role(), Role::Embed);
    assert_eq!(request.binding(), BINDING);
    assert_eq!(request.keyset_context(), KEYSET);
    assert_eq!(request.input(), original);
    for length in [original.len() - 1, original.len() + 1] {
        assert!(matches!(
            embed_request(BINDING, KEYSET, &vec![0; length]),
            Err(Error::Shape)
        ));
    }
    let mut alias = original;
    *alias.last_mut().unwrap() = MODULI[4];
    assert!(matches!(
        embed_request(BINDING, KEYSET, &alias),
        Err(Error::NonCanonicalResidue)
    ));
}

#[test]
fn digit_row_borrows_each_complete_source_target_row_and_rejects_invalid_indices_or_residues() {
    let original = digits();
    for source in 0..BASES {
        for (target, &modulus) in MODULI.iter().enumerate() {
            let index = BASES * source + target;
            let row = digit_row(&original, source, target).unwrap();
            assert_eq!(row.len(), DEGREE);
            assert_eq!(row.as_ptr(), original[index * DEGREE..].as_ptr());
            assert_eq!(row, &original[index * DEGREE..(index + 1) * DEGREE]);
            assert_eq!(row[0], ((index + 1) * DEGREE) as u64);
            assert_eq!(row[DEGREE - 1], modulus - 1);
        }
    }
    for (source, target) in [(5, 0), (0, 5), (usize::MAX, 0), (0, usize::MAX)] {
        assert!(matches!(
            digit_row(&original, source, target),
            Err(Error::Shape)
        ));
    }
    assert!(matches!(
        digit_row(&original[..original.len() - 1], 0, 0),
        Err(Error::Shape)
    ));
    let mut longer = original.clone();
    longer.push(0);
    assert!(matches!(digit_row(&longer, 0, 0), Err(Error::Shape)));
    for (target, &modulus) in MODULI.iter().enumerate() {
        let mut alias = original.clone();
        alias[(5 * 4 + target + 1) * DEGREE - 1] = modulus;
        assert!(matches!(
            digit_row(&alias, 4, target),
            Err(Error::NonCanonicalResidue)
        ));
    }
}

#[test]
fn mac_request_routes_both_originals_all25_digits_and_all50_key_rows_without_arithmetic() {
    let originals = [component(1), component(2)];
    let digits = digits();
    let keys = key_rows();

    let request = mac_request(
        BINDING,
        KEYSET,
        originals.each_ref().map(Vec::as_slice),
        &digits,
        borrowed_keys(&keys),
    )
    .unwrap();

    assert_eq!(request.role(), Role::AccumulateAndAdd);
    assert_eq!(request.binding(), BINDING);
    assert_eq!(request.keyset_context(), KEYSET);
    assert_eq!(request.input().len(), 85 * DEGREE);
    let rows = request.input().as_chunks::<DEGREE>().0;
    for target in 0..BASES {
        let qrow = target * DEGREE..(target + 1) * DEGREE;
        assert_eq!(&rows[17 * target][..], &originals[0][qrow.clone()]);
        assert_eq!(&rows[17 * target + 1][..], &originals[1][qrow.clone()]);
        for source in 0..BASES {
            let digit = 5 * source + target;
            assert_eq!(
                &rows[17 * target + 2 + source][..],
                &digits[digit * DEGREE..(digit + 1) * DEGREE]
            );
            assert_eq!(
                &rows[17 * target + 7 + source][..],
                &keys[0][source][qrow.clone()]
            );
            assert_eq!(
                &rows[17 * target + 12 + source][..],
                &keys[1][source][qrow.clone()]
            );
        }
    }
}

#[test]
fn mac_request_rejects_incomplete_inputs_and_last_coefficient_aliases_in_every_operand_family() {
    let originals = [component(1), component(2)];
    let digits = digits();
    let keys = key_rows();
    for (component, original) in originals.iter().enumerate() {
        let mut refs = originals.each_ref().map(Vec::as_slice);
        refs[component] = &original[..original.len() - 1];
        assert!(matches!(
            mac_request(BINDING, KEYSET, refs, &digits, borrowed_keys(&keys)),
            Err(Error::Shape)
        ));
        let mut alias = originals.clone();
        *alias[component].last_mut().unwrap() = MODULI[4];
        assert!(matches!(
            mac_request(
                BINDING,
                KEYSET,
                alias.each_ref().map(Vec::as_slice),
                &digits,
                borrowed_keys(&keys)
            ),
            Err(Error::NonCanonicalResidue)
        ));
    }
    assert!(matches!(
        mac_request(
            BINDING,
            KEYSET,
            originals.each_ref().map(Vec::as_slice),
            &digits[..digits.len() - 1],
            borrowed_keys(&keys)
        ),
        Err(Error::Shape)
    ));
    let mut alias = digits.clone();
    *alias.last_mut().unwrap() = MODULI[4];
    assert!(matches!(
        mac_request(
            BINDING,
            KEYSET,
            originals.each_ref().map(Vec::as_slice),
            &alias,
            borrowed_keys(&keys)
        ),
        Err(Error::NonCanonicalResidue)
    ));
    for (component, component_rows) in keys.iter().enumerate() {
        for (decomposition, row) in component_rows.iter().enumerate() {
            let mut refs = borrowed_keys(&keys);
            refs[component][decomposition] = &row[..5 * DEGREE - 1];
            assert!(matches!(
                mac_request(
                    BINDING,
                    KEYSET,
                    originals.each_ref().map(Vec::as_slice),
                    &digits,
                    refs
                ),
                Err(Error::Shape)
            ));
            let mut alias = keys.clone();
            *alias[component][decomposition].last_mut().unwrap() = MODULI[4];
            assert!(matches!(
                mac_request(
                    BINDING,
                    KEYSET,
                    originals.each_ref().map(Vec::as_slice),
                    &digits,
                    borrowed_keys(&alias)
                ),
                Err(Error::NonCanonicalResidue)
            ));
        }
    }
}

#[test]
fn component_outputs_validate_every_target_row_and_transpose_all8192_native_ntt_values() {
    let mut accumulated = Vec::with_capacity(10 * DEGREE);
    for (target, &modulus) in MODULI.iter().enumerate() {
        for component in 0..2 {
            accumulated.extend(
                (0..DEGREE).map(|index| (1_000_000 * (2 * target + component + 1) + index) as u64),
            );
            *accumulated.last_mut().unwrap() = modulus - 1;
        }
    }

    let output = component_outputs(&accumulated).unwrap();

    for (component, values) in output.iter().enumerate() {
        assert_eq!(values.len(), 5 * DEGREE);
        for target in 0..BASES {
            let row = 2 * target + component;
            assert_eq!(
                &values[target * DEGREE..(target + 1) * DEGREE],
                &accumulated[row * DEGREE..(row + 1) * DEGREE]
            );
        }
    }
    assert!(matches!(
        component_outputs(&accumulated[..accumulated.len() - 1]),
        Err(Error::Shape)
    ));
    let mut longer = accumulated.clone();
    longer.push(0);
    assert!(matches!(component_outputs(&longer), Err(Error::Shape)));
    for (row, &modulus) in Role::AccumulateAndAdd.output_moduli().iter().enumerate() {
        let mut alias = accumulated.clone();
        alias[(row + 1) * DEGREE - 1] = modulus;
        assert!(matches!(
            component_outputs(&alias),
            Err(Error::NonCanonicalResidue)
        ));
    }
}
