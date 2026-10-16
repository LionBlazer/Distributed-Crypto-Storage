use p3_air::{BaseAir, check_constraints};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;

use super::air::{
    CANONICAL, CANONICAL_CARRY, KEY, MESSAGE, PRODUCT_CARRY, Poly1305Air, STATE, TAG_CARRY, WIDTH,
    clamped_r, cyclic_carries, folded_product, message_limbs, reduce, schedule_columns, tag_words,
    write_bits, write_state, write_tag_carries,
};
use super::statement::{Mode, Statement, public_key, reference_tag};
use super::{LIMB_BITS, LIMBS, MASK, MAX_BLOCKS, MAX_BYTES, RADIX};
use crate::backend::{self, Backend, Challenge, Error, TRACE_HEIGHT, Val};
use crate::primitive::{PrimitiveStatement, PublicStatement};

#[test]
fn rfc_tag_and_raw_boundary_lengths_match_independent_oracle_and_actual_trace() {
    let rfc = Statement::raw_fixture();
    assert_eq!(
        rfc.tag,
        [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9
        ]
    );
    for length in [0, 1, 15, 16, 17, 31, 32, 34, 47, 48] {
        for key in [public_key(), [0; 32], [255; 32]] {
            let payload: Vec<_> = (0..length).map(|index| (index * 113 + 255) as u8).collect();
            let statement = Statement::raw(key, &payload).unwrap();
            assert_genuine_trace(&statement);
            if length == 0 || clamped_r(key) == [0; LIMBS] {
                assert_eq!(statement.tag, key[16..]);
            }
        }
    }
    assert_genuine_trace(&rfc);
}

#[test]
fn padded_segments_preserve_original_boundaries_empty_inputs_and_full_hibits() {
    let key = public_key();
    for segments in [
        vec![],
        vec![&b""[..]],
        vec![&b""[..], &b""[..], &b""[..]],
        vec![&b"a"[..]],
        vec![&b"a"[..], &b"b"[..]],
        vec![&b"0123456789abcdef"[..], &b"tail"[..]],
        vec![&b"1"[..], &b"2"[..], &b"3"[..]],
    ] {
        assert_genuine_trace(&Statement::padded(key, &segments).unwrap());
    }
    let raw = Statement::raw(key, b"a").unwrap();
    let padded = Statement::padded(key, &[b"a"]).unwrap();
    assert_ne!(raw.tag, padded.tag); // Raw 1-byte tail vs padded full block.
    assert_ne!(
        Statement::padded(key, &[b"a", b"b"]).unwrap().tag,
        Statement::padded(key, &[b"ab"]).unwrap().tag
    );
    assert_eq!(
        Statement::raw(key, b"0123456789abcdef").unwrap().tag,
        Statement::padded(key, &[b"0123456789abcdef"]).unwrap().tag
    );
}

#[test]
fn raw_byte_block_and_descriptor_caps_reject_before_trace_construction() {
    let key = public_key();
    assert!(matches!(
        Statement::raw(key, &[0; MAX_BYTES + 1]),
        Err(Error::Shape)
    ));
    assert!(matches!(
        Statement::padded(key, &[b"", b"", b"", b""]),
        Err(Error::Shape)
    ));
    assert!(matches!(
        Statement::padded(key, &[&[0; 17], &[0; 17]]),
        Err(Error::Shape)
    ));
    assert!(matches!(
        Statement::padded(key, &[&[0; 49]]),
        Err(Error::Shape)
    ));
    assert_genuine_trace(&Statement::padded(key, &[&[0; 16], &[0; 16], &[0; 16]]).unwrap());
}

#[test]
fn canonical_boundary_states_are_zero_p_minus_one_and_one_not_modular_aliases() {
    for (last_byte, expected) in [
        (0xfb, [RADIX - 6, MASK, MASK, MASK, MASK]),
        (0xfc, [0; LIMBS]),
        (0xfd, [1, 0, 0, 0, 0]),
    ] {
        let statement = canonical_boundary(last_byte);
        let trace = statement.trace();
        assert_eq!(state_at(&trace, 2), expected);
        assert_genuine_trace(&statement);
    }
}

#[test]
fn complete_public_schedule_openings_and_security_gate_use_actual_air() {
    let schedule = schedule_columns();
    assert_eq!(schedule.len(), MAX_BLOCKS);
    for row in 0..TRACE_HEIGHT {
        for (block, column) in schedule.iter().enumerate() {
            assert_eq!(column[row], Val::from_bool(row == block));
        }
    }
    let mut shape = None;
    for statement in [
        Statement::raw_fixture(),
        Statement::padded_fixture(),
        Statement::raw(public_key(), &[]).unwrap(),
        Statement::raw(public_key(), &[255; 48]).unwrap(),
        Statement::padded(public_key(), &[b"", b"", b""]).unwrap(),
    ] {
        let air = statement.air();
        assert_eq!(air.width(), 813);
        assert_eq!(air.main_next_row_columns(), (0..STATE).collect::<Vec<_>>());
        assert_eq!(air.num_periodic_columns(), 3);
        assert_eq!(air.preprocessed_width(), 0);
        let (parameters, report) = backend::analyze(&air).unwrap();
        report.require_target().unwrap(); // Numerical review must precede executing this test.
        assert_eq!(parameters.max_combo, 2);
        assert_eq!(parameters.fri_num_queries, 192);
        assert_eq!(
            report.degree,
            if statement.layout().active == 0 { 2 } else { 3 }
        );
        // Some(3) fixes committed quotient sizing; it does not replace the
        // SDK's separately reported actual symbolic degree for empty inputs.
        let current = (
            report.constraints,
            report.quotient_chunks,
            report.batched_functions,
        );
        if let Some(expected) = shape {
            assert_eq!(current, expected);
        } else {
            shape = Some(current);
        }
        assert_eq!(
            report.batched_functions,
            2 * (WIDTH + 5) + report.quotient_chunks * 10 + 10
        );
    }
}

#[test]
fn genuine_proofs_bind_modes_original_lengths_segments_request_key_and_shape() {
    // The genuine raw fixture must exercise a final carry: SDK boundary
    // selectors are unnormalized, so a Boolean-complement shortcut rejects it.
    {
        let trace = Statement::raw_fixture().trace();
        assert!(
            trace.values[(TRACE_HEIGHT - 1) * WIDTH + TAG_CARRY..].contains(&Val::ONE),
            "The genuine fixture must retain a nonzero final tag carry"
        );
    }
    for statement in [Statement::raw_fixture(), Statement::padded_fixture()] {
        let backend = Backend::new(&statement).unwrap();
        let mut proof = backend.prove(&statement).unwrap();
        Backend::new(&statement)
            .unwrap()
            .verify(&statement, &proof)
            .unwrap();
        let empty = match statement.layout().mode {
            Mode::Raw => Statement::raw(statement.key, &[]).unwrap(),
            Mode::PaddedSegments => Statement::padded(statement.key, &[]).unwrap(),
        };
        let empty_backend = Backend::new(&empty).unwrap();
        assert_eq!(empty_backend.prove(&statement).err(), Some(Error::Shape));
        assert_eq!(empty_backend.verify(&statement, &proof), Err(Error::Shape));
        let mut changed = statement.clone();
        changed.request[0] ^= 1;
        assert!(backend.verify(&changed, &proof).is_err());
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );
        changed = statement.clone();
        changed.key[3] ^= 0x80; // Clamped-away bit remains identity-bound.
        assert!(backend.verify(&changed, &proof).is_err());
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );
        changed = statement.clone();
        changed.tag[15] ^= 1;
        assert!(backend.verify(&changed, &proof).is_err());
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );
        let other_mode =
            Statement::padded(statement.key, &[b"Cryptographic Forum Research Group"]).unwrap();
        assert!(backend.verify(&other_mode, &proof).is_err());
        assert!(
            Backend::new(&other_mode)
                .unwrap()
                .verify(&other_mode, &proof)
                .is_err()
        );
        let different_boundaries =
            Statement::padded(statement.key, &[b"public a", b"adpublic ciphertext"]).unwrap();
        assert!(backend.verify(&different_boundaries, &proof).is_err());
        assert!(
            Backend::new(&different_boundaries)
                .unwrap()
                .verify(&different_boundaries, &proof)
                .is_err()
        );
        let next = proof.opened_values.trace_next.take().unwrap();
        assert_eq!(next.len(), WIDTH);
        assert_eq!(backend.verify(&statement, &proof), Err(Error::Shape));
        proof.opened_values.trace_next = Some(next);
        proof.opened_values.random.as_mut().unwrap()[0] += Challenge::ONE;
        assert!(backend.verify(&statement, &proof).is_err());
    }
}

#[test]
fn clamped_away_raw_key_bits_are_valid_but_cannot_change_the_mac_or_replay_proofs() {
    let original = Statement::raw_fixture();
    let mut key = original.key;
    key[3] ^= 0x80;
    let changed = Statement::raw(key, b"Cryptographic Forum Research Group").unwrap();
    assert_eq!(original.tag, changed.tag);
    assert_ne!(original.identity(), changed.identity());
    assert_genuine_trace(&changed);
    let backend = Backend::new(&original).unwrap();
    let proof = backend.prove(&original).unwrap();
    assert!(backend.verify(&changed, &proof).is_err());
    assert!(
        Backend::new(&changed)
            .unwrap()
            .verify(&changed, &proof)
            .is_err()
    );
    let fresh = Backend::new(&changed).unwrap();
    fresh
        .verify(&changed, &fresh.prove(&changed).unwrap())
        .unwrap();
}

#[test]
fn rebuilt_canonical_p_alias_with_matching_tag_and_carries_is_rejected() {
    let mut statement = canonical_boundary(0xfc);
    let mut trace = statement.trace();
    let false_h = [RADIX - 5, MASK, MASK, MASK, MASK];
    let mut second = [255; 16];
    second[0] = 0xfc;
    let product = folded_product(
        state_at(&trace, 1),
        message_limbs(second, 128),
        clamped_r(statement.key),
    );
    // U=p admits cyclic q=0,H=p. Only H<p makes the field residue unique.
    let carries = cyclic_carries(product, false_h, 0);
    for (limb, carry) in carries.into_iter().enumerate() {
        write_bits(
            &mut trace.values
                [WIDTH + PRODUCT_CARRY + limb * 32..WIDTH + PRODUCT_CARRY + (limb + 1) * 32],
            carry,
        );
    }
    for row in 2..TRACE_HEIGHT {
        write_state(&mut trace.values[row * WIDTH..(row + 1) * WIDTH], false_h);
        assert_eq!(
            trace.values[row * WIDTH + CANONICAL_CARRY + LIMBS - 1],
            Val::ONE
        );
    }
    rebind_false_tag(&mut statement, &mut trace);
    assert_ne!(statement.tag, [0; 16]);
    assert_rebuilt_rejected(&statement, trace);
}

#[test]
fn rebuilt_tail_modes_omission_reordering_and_extra_empty_block_are_rejected() {
    let key = public_key();
    let raw = Statement::raw(key, b"a").unwrap();
    let padded = Statement::padded(key, &[b"a"]).unwrap();
    assert_alternate_rejected(raw.clone(), padded.clone());
    assert_alternate_rejected(padded, raw);
    assert_alternate_rejected(
        Statement::raw(key, &[]).unwrap(),
        Statement::raw(key, &[0; 16]).unwrap(),
    );
    assert_alternate_rejected(
        Statement::raw(key, &[7; 16]).unwrap(),
        Statement::raw(key, &[7; 32]).unwrap(),
    );
    assert_alternate_rejected(
        Statement::padded(key, &[b"alpha", b"beta", b"gamma"]).unwrap(),
        Statement::padded(key, &[b"alpha", b"beta"]).unwrap(),
    );
    assert_alternate_rejected(
        Statement::padded(key, &[b"alpha", b"beta"]).unwrap(),
        Statement::padded(key, &[b"beta", b"alpha"]).unwrap(),
    );
}

#[test]
fn rebuilt_nonboolean_negative_carry_and_inactive_witnesses_are_rejected() {
    let statement = Statement::raw_fixture();
    let genuine = statement.trace();
    for (offset, value) in [
        (PRODUCT_CARRY, -Val::ONE),
        (3 * WIDTH + PRODUCT_CARRY, Val::ONE),
        (3 * WIDTH + MESSAGE, Val::ONE),
        (WIDTH + KEY + 31, Val::ONE), // Forbidden raw-r bit must still bind on block2.
        (
            4 * WIDTH + CANONICAL,
            Val::ONE - genuine.values[4 * WIDTH + CANONICAL],
        ), // Comparator is required even during padding.
        (4 * WIDTH + STATE - 1, Val::TWO),
        (0, Val::ONE),
    ] {
        let mut trace = genuine.clone();
        trace.values[offset] = value;
        assert_rebuilt_rejected(&statement, trace);
    }
    let mut carry = genuine.clone();
    let position = (0..statement.layout().active)
        .flat_map(|row| (0..LIMBS * 32).map(move |bit| row * WIDTH + PRODUCT_CARRY + bit))
        .find(|index| carry.values[*index] == Val::ONE)
        .expect("RFC fixture has nonzero multiplication carries");
    carry.values[position] = Val::ZERO;
    assert_rebuilt_rejected(&statement, carry);
}

#[test]
fn rebuilt_effective_r_cannot_use_a_forbidden_raw_key_bit() {
    let mut key = [0; 32];
    key[3] = 0x80; // This bit is removed by the real clamp, so true R=0.
    let mut statement = Statement::raw(key, &[1]).unwrap();
    assert_eq!(statement.tag, [0; 16]);
    let mut trace = statement.trace();
    let false_integer = 257_u64 * (1 << 31);
    // false_integer is <2^40: the high limbs are independently zero.
    let false_h = [
        false_integer & MASK,
        (false_integer >> LIMB_BITS) & MASK,
        0,
        0,
        0,
    ];
    let unclamped = message_limbs(key[..16].try_into().unwrap(), 130);
    let product = folded_product(
        [0; LIMBS],
        message_limbs([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8),
        unclamped,
    );
    for (limb, carry) in cyclic_carries(product, false_h, 0).into_iter().enumerate() {
        write_bits(
            &mut trace.values[PRODUCT_CARRY + limb * 32..PRODUCT_CARRY + (limb + 1) * 32],
            carry,
        );
    }
    for row in 1..TRACE_HEIGHT {
        write_state(&mut trace.values[row * WIDTH..(row + 1) * WIDTH], false_h);
    }
    rebind_false_tag(&mut statement, &mut trace);
    assert_rebuilt_rejected(&statement, trace);
}

#[test]
fn tag_is_little_endian_low128_plus_s_with_real_internal_and_discarded_final_carries() {
    let mut key = [255; 32];
    key[..16].fill(0);
    key[0] = 1;
    let statement = Statement::raw(key, &[1]).unwrap();
    let genuine = statement.trace();
    assert_eq!(
        &genuine.values[(TRACE_HEIGHT - 1) * WIDTH + TAG_CARRY..],
        &[Val::ONE; 4]
    );
    assert_eq!(
        statement.tag,
        [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_genuine_trace(&statement);
    for word in 0..4 {
        let mut trace = genuine.clone();
        trace.values[(TRACE_HEIGHT - 1) * WIDTH + TAG_CARRY + word] = Val::ZERO;
        assert_rebuilt_rejected(&statement, trace);
    }
    let mut missing_s = statement.clone();
    missing_s.tag = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_rebuilt_rejected(&missing_s, genuine.clone());
    let mut wrong_endian = statement.clone();
    wrong_endian.tag.reverse();
    assert_rebuilt_rejected(&wrong_endian, genuine.clone());
    let mut retained_high = statement;
    retained_high.tag[0] ^= 1;
    assert_rebuilt_rejected(&retained_high, genuine);
}

#[test]
fn final_s_addition_uses_mod_two_to_128_not_mod_p() {
    // H=p-1, S=2. Correct low128(H)+S is 2^128-4; reduction mod p would give 1.
    let mut key = [0; 32];
    key[0] = 1;
    key[16] = 2;
    let mut payload = [255; 32];
    payload[16] = 0xfb;
    let mut statement = Statement::raw(key, &payload).unwrap();
    assert_genuine_trace(&statement);
    let mut expected = [255; 16];
    expected[0] = 0xfc;
    assert_eq!(statement.tag, expected);
    let trace = statement.trace();
    statement.tag = [0; 16];
    statement.tag[0] = 1;
    assert_rebuilt_rejected(&statement, trace);
}

#[test]
fn rebuilt_product_cannot_omit_hibit_or_replace_the_fold_factor_five() {
    for mutation in [
        WrongProduct::NoFullHibit,
        WrongProduct::WrongTailBit,
        WrongProduct::FoldOne,
    ] {
        let mut statement = Statement::raw_fixture();
        let mut trace = statement.trace();
        let mut h = [0; LIMBS];
        for row in 0..TRACE_HEIGHT {
            let cells = &mut trace.values[row * WIDTH..(row + 1) * WIDTH];
            write_state(cells, h);
            if row < statement.layout().active {
                let block = statement.layout().blocks[row];
                let bytes = core::array::from_fn(|byte| {
                    block.payload[byte].map_or(0, |source| statement.payload()[source])
                });
                let appended = if matches!(mutation, WrongProduct::NoFullHibit)
                    && block.appended_bit == 128
                {
                    130
                } else if matches!(mutation, WrongProduct::WrongTailBit) && block.appended_bit < 128
                {
                    block.appended_bit + 1
                } else {
                    block.appended_bit
                };
                let n = message_limbs(bytes, appended);
                let r = clamped_r(statement.key);
                let mut product = folded_product(h, n, r);
                if matches!(mutation, WrongProduct::FoldOne) {
                    for (i, (h, n)) in h.into_iter().zip(n).enumerate() {
                        for (j, r) in r.into_iter().enumerate() {
                            if i + j >= LIMBS {
                                product[(i + j) % LIMBS] -= 4 * (h + n) * r;
                            }
                        }
                    }
                }
                let (updated, carry) = reduce(product);
                for (limb, value) in carry.into_iter().enumerate() {
                    write_bits(
                        &mut cells[PRODUCT_CARRY + limb * 32..PRODUCT_CARRY + (limb + 1) * 32],
                        value,
                    );
                }
                h = updated;
            }
        }
        let correct = statement.tag;
        rebind_false_tag(&mut statement, &mut trace);
        assert_ne!(statement.tag, correct);
        assert_rebuilt_rejected(&statement, trace);
    }
}
#[derive(Clone, Copy)]
enum WrongProduct {
    NoFullHibit,
    WrongTailBit,
    FoldOne,
}

fn canonical_boundary(second_low_byte: u8) -> Statement {
    let mut key = [0; 32];
    key[0] = 1;
    let mut payload = [255; 32];
    payload[16] = second_low_byte;
    Statement::raw(key, &payload).unwrap()
}
fn state_at(trace: &RowMajorMatrix<Val>, row: usize) -> [u64; LIMBS] {
    core::array::from_fn(|limb| {
        trace.values[row * WIDTH + limb * LIMB_BITS..row * WIDTH + (limb + 1) * LIMB_BITS]
            .iter()
            .enumerate()
            .fold(0, |sum, (bit, value)| {
                sum | (value.as_canonical_u64() << bit)
            })
    })
}
fn tag_from_trace(statement: &Statement, trace: &RowMajorMatrix<Val>) -> [u8; 16] {
    let words = tag_words(state_at(trace, TRACE_HEIGHT - 1), statement.key).0;
    let mut bytes = [0; 16];
    for (word, bytes) in words.into_iter().zip(bytes.as_chunks_mut::<4>().0) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn assert_genuine_trace(statement: &Statement) {
    let trace = statement.trace();
    assert_eq!(reference_tag(statement), statement.tag);
    assert_eq!(tag_from_trace(statement, &trace), statement.tag);
    check_constraints(&statement.air(), &trace, &statement.public_values());
}
fn rebind_false_tag(statement: &mut Statement, trace: &mut RowMajorMatrix<Val>) {
    statement.tag = tag_from_trace(statement, trace);
    let h = state_at(trace, TRACE_HEIGHT - 1);
    write_tag_carries(
        &mut trace.values[(TRACE_HEIGHT - 1) * WIDTH..],
        h,
        statement.key,
    );
}
fn assert_alternate_rejected(mut original: Statement, alternate: Statement) {
    assert_genuine_trace(&alternate);
    let mut trace = alternate.trace();
    rebind_false_tag(&mut original, &mut trace);
    assert_rebuilt_rejected(&original, trace);
}
fn assert_rebuilt_rejected(statement: &Statement, trace: RowMajorMatrix<Val>) {
    let backend = Backend::new(statement).unwrap();
    // Actual rebuilt malicious proof, bypassing the honest trace generator.
    // Future execution is gated by separate numerical/source review.
    let result = p3_uni_stark::prove(
        &backend.config,
        &Poly1305Air::new(statement),
        trace,
        &statement.public_values(),
    );
    if let Ok(proof) = result {
        assert!(backend.verify(statement, &proof).is_err());
    }
}
