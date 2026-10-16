//! PUBLIC NONSECRET cases for the separate packed relation. Every rebuilt
//! negative invokes the real SDK prover/verifier, never an accepting stub.
use super::{
    Relation, air::OpeningAir, commitment, fixture, layout, schedule, statement::Statement,
    trace::Witness,
};
use crate::backend::{self, Backend, TRACE_HEIGHT, Val};
use crate::primitive::{Kind, PublicStatement};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;

fn pair_with(suffix: &[u8], packed: bool) -> (Statement, Witness) {
    fixture::from_suffix(
        if packed {
            Relation::PackedCanonicalIndex
        } else {
            Relation::CanonicalIndex
        },
        core::array::from_fn(|i| i as u8),
        ([Val::from_u8(17); 4], [Val::from_u8(29); 4]),
        [0x83; 32],
        [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0],
        suffix,
    )
    .unwrap()
}
fn pair() -> (Statement, Witness) {
    pair_with(&fixture::canonical_suffix(), true)
}
fn valid(statement: &Statement, witness: &Witness) -> RowMajorMatrix<Val> {
    // Numerical floor/shape gate before this test helper allocates any trace.
    Backend::new(statement).unwrap();
    let trace = witness.trace(statement).unwrap();
    check_constraints(&statement.air(), &trace, &statement.public_values());
    trace
}
fn reject_native(statement: &Statement, trace: &RowMajorMatrix<Val>) {
    assert!(
        !check_all_constraints(&statement.air(), trace, &statement.public_values(), Some(1))
            .is_ok()
    );
}
fn reject_rebuilt(statement: &Statement, trace: RowMajorMatrix<Val>) {
    reject_native(statement, &trace);
    let backend = Backend::new(statement).unwrap();
    let result = p3_uni_stark::prove(
        &backend.config,
        &statement.air(),
        trace,
        &statement.public_values(),
    );
    if let Ok(proof) = result {
        assert!(backend.verify(statement, &proof).is_err());
    }
}
fn decrypt(statement: &Statement) -> Vec<u8> {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let cipher = XChaCha20Poly1305::new(&key.into());
    let mut bytes = Vec::new();
    for page in 0..2 {
        bytes.extend(
            cipher
                .decrypt(
                    &statement.nonce(page).into(),
                    Payload {
                        msg: &statement.packets[page][32..],
                        aad: &statement.aad(page),
                    },
                )
                .unwrap(),
        );
    }
    bytes
}
fn change_interval(trace: &mut RowMajorMatrix<Val>, column: usize, rows: std::ops::Range<usize>) {
    for row in rows {
        trace.values[row * trace.width + column] += Val::ONE;
    }
}
fn identities(values: [[u32; 8]; 4], table: [u8; 32]) -> Vec<u8> {
    let mut suffix = fixture::canonical_suffix();
    suffix[..32].copy_from_slice(&table);
    for (i, words) in values.into_iter().enumerate() {
        for (word, value) in words.into_iter().enumerate() {
            let at = 2208 - 112 + i * 32 + word * 4;
            suffix[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    suffix
}
fn nonzero_ids() -> [[u32; 8]; 4] {
    core::array::from_fn(|i| {
        let mut words = [0; 8];
        words[7] = i as u32 + 1;
        words
    })
}

#[test]
fn packed_schedule_captures_before_every_read_and_preserves_exact_stale_word_coverage() {
    let schedule = schedule::Schedule::new(true);
    assert_eq!(schedule.captures(), [87, 178, 260, 342, 424]);
    assert_eq!(schedule.boundary(5), 491);
    assert_eq!(schedule.final_absorb(), 505);
    let mut words = Vec::new();
    let mut stale = Vec::new();
    let mut blocks = Vec::new();
    for row in 0..TRACE_HEIGHT {
        if let Some((false, block)) = schedule.absorb(row) {
            blocks.push(block);
            for field in block * 8..block * 8 + 8 {
                if (87..674).contains(&field) {
                    let word = field - 87;
                    let (group, _, _) = schedule::plain_location(word);
                    assert!(row >= schedule.boundary(group));
                    if row >= schedule.boundary(group + 1) {
                        stale.push(word);
                    }
                    words.push(word);
                }
            }
        }
    }
    assert_eq!(words, (0..587).collect::<Vec<_>>());
    assert_eq!(blocks, (0..85).collect::<Vec<_>>());
    assert_eq!(stale, [33, 34, 145, 146, 257, 258, 369, 370, 481, 482]);
}

#[test]
fn packed_core_fixture_decrypts_every_u32_and_matches_the_shared_native_commitment() {
    let (statement, witness) = pair();
    let trace = valid(&statement, &witness);
    let air = OpeningAir::new(&statement);
    let plain = decrypt(&statement);
    assert_eq!(&plain[12 + 112..], fixture::canonical_suffix());
    for (word, bytes) in plain.as_chunks::<4>().0.iter().enumerate() {
        let (group, lane, slot) = schedule::plain_location(word);
        let row = air.schedule().boundary(group);
        let actual = trace.values[row * trace.width + air.columns().buffers + lane * 16 + slot];
        assert_eq!(
            actual.as_canonical_u64(),
            u64::from(u32::from_le_bytes(*bytes))
        );
    }
    assert_eq!(
        statement.open_commitment,
        commitment::digest(&commitment::opening_fields(
            &statement,
            [Val::from_u8(29); 4],
            &plain
        ))
    );
    let (old, old_witness) = pair_with(&fixture::canonical_suffix(), false);
    assert_eq!(old.heads, statement.heads);
    assert_eq!(old.packets, statement.packets);
    assert_eq!(old.key_commitment, statement.key_commitment);
    assert_ne!(old.open_commitment, statement.open_commitment);
    assert_eq!(valid(&old, &old_witness).width, 11521);
}

#[test]
fn genuine_packed_source_proof_verifies_and_cannot_be_reused_as_the_old_profile() {
    let (statement, witness) = pair();
    let backend = Backend::new(&statement).unwrap();
    let proof = backend
        .prove_with_trace(&statement, || witness.trace(&statement))
        .unwrap();
    backend.verify(&statement, &proof).unwrap();
    let (old, _) = pair_with(&fixture::canonical_suffix(), false);
    assert!(Backend::new(&old).unwrap().verify(&old, &proof).is_err());
    assert!(backend.verify(&old, &proof).is_err());
}

#[test]
fn rebuilt_u32_range_feedforward_carry_and_reset_substitutions_are_rejected() {
    let (statement, witness) = pair();
    let genuine = valid(&statement, &witness);
    let c = layout::Columns::new(true);
    let mut outside_u32 = genuine.clone();
    for row in 0..TRACE_HEIGHT {
        outside_u32.values[row * outside_u32.width + c.master] += Val::from_u64(1 << 32);
    }
    reject_rebuilt(&statement, outside_u32);
    let mut carry = genuine.clone();
    let at =
        80 * carry.width + 4 * crate::chacha::air::WIDTH + crate::chacha::air::FEEDFORWARD_CARRY;
    carry.values[at] = Val::ONE - carry.values[at];
    reject_rebuilt(&statement, carry);
    let mut reset = genuine;
    let at = 82 * reset.width + 4 * 32;
    reset.values[at] = Val::ONE - reset.values[at];
    reject_rebuilt(&statement, reset);
}

#[test]
fn rebuilt_current_capture_and_all_ten_stale_word_paths_reject_substitution() {
    let (statement, witness) = pair();
    let genuine = valid(&statement, &witness);
    let c = layout::Columns::new(true);
    let mut capture = genuine.clone();
    change_interval(&mut capture, c.buffers + 4 * 16, 81..163);
    reject_rebuilt(&statement, capture);
    for (group, first) in [87, 178, 260, 342, 424].into_iter().enumerate() {
        let end = [178, 260, 342, 424, 512][group];
        for word in 0..2 {
            let mut changed = genuine.clone();
            change_interval(&mut changed, c.carry + word, first..end);
            reject_native(&statement, &changed);
            if (group, word) == (4, 1) {
                reject_rebuilt(&statement, changed);
            }
        }
    }
    let mut predecessor = genuine;
    predecessor.values[80 * predecessor.width + c.buffers + 4 * 16] += Val::ONE;
    reject_rebuilt(&statement, predecessor);
}

#[test]
fn rebuilt_immutable_key_banks_and_selected_polykey_bit_view_cannot_diverge() {
    let (statement, witness) = pair();
    let genuine = valid(&statement, &witness);
    let c = layout::Columns::new(true);
    for bank in [c.master, c.subkey, c.subkey + 8, c.polykey, c.polykey + 8] {
        let mut changed = genuine.clone();
        change_interval(&mut changed, bank, 0..TRACE_HEIGHT);
        reject_native(&statement, &changed);
        if bank == c.polykey + 8 {
            reject_rebuilt(&statement, changed);
        }
    }
    for row in [0, 10, 164, 165, 511] {
        let mut changed = genuine.clone();
        let at = row * changed.width + c.polykey_bits + 255;
        changed.values[at] = Val::ONE - changed.values[at];
        reject_native(&statement, &changed);
        if row == 10 {
            reject_rebuilt(&statement, changed);
        }
    }
}

#[test]
fn packed_id_checks_accept_high_words_and_canceling_word_differences_without_aliases() {
    let mut ids = nonzero_ids();
    ids[0] = [1, 0, 0, 0, 0, 0, 0, 0];
    ids[1] = [0, 1, 0, 0, 0, 0, 0, 0];
    ids[2] = [u32::MAX; 8];
    for half in [0..16, 16..32] {
        let mut table = [0; 32];
        table[half].fill(0xff);
        let (statement, witness) = pair_with(&identities(ids, table), true);
        drop(valid(&statement, &witness));
    }
}

#[test]
fn genuine_encrypted_zero_duplicate_ids_and_zero_table_cannot_produce_valid_packed_proofs() {
    let mut zero = nonzero_ids();
    zero[3] = [0; 8];
    let mut duplicate = nonzero_ids();
    duplicate[3] = duplicate[0];
    for suffix in [
        identities(zero, [0x31; 32]),
        identities(duplicate, [0x31; 32]),
        identities(nonzero_ids(), [0; 32]),
    ] {
        let (statement, witness) = pair_with(&suffix, true);
        let backend = Backend::new(&statement).unwrap();
        let trace = witness.trace(&statement).unwrap();
        // Actual AEAD and the independent native C_open remain correct.
        assert_eq!(
            statement.open_commitment,
            commitment::digest(&commitment::opening_fields(
                &statement,
                [Val::from_u8(29); 4],
                &decrypt(&statement)
            ))
        );
        reject_native(&statement, &trace);
        let result = p3_uni_stark::prove(
            &backend.config,
            &statement.air(),
            trace,
            &statement.public_values(),
        );
        if let Ok(proof) = result {
            assert!(backend.verify(&statement, &proof).is_err());
        }
    }
}

#[test]
fn rebuilt_word_zero_flags_and_index_header_cannot_substitute_for_authentic_ids_and_counts() {
    let (statement, witness) = pair();
    let mut changed = valid(&statement, &witness);
    let ci = layout::CanonicalColumns::new(true);
    let at = 491 * changed.width + ci.identity + 11;
    changed.values[at] = Val::ONE - changed.values[at];
    reject_rebuilt(&statement, changed);
    for offset in [144 - 112, 2192 - 112, 2196 - 112, 2207 - 112] {
        let mut suffix = fixture::canonical_suffix();
        suffix[offset] ^= 1;
        let (bad, witness) = pair_with(&suffix, true);
        Backend::new(&bad).unwrap();
        let trace = witness.trace(&bad).unwrap();
        reject_native(&bad, &trace);
        if offset == 144 - 112 {
            reject_rebuilt(&bad, trace);
        }
    }
}

#[test]
fn packed_shape_and_security_keep_the_original_height_hiding_and_primitive_profiles() {
    let (statement, _) = pair();
    let air = statement.air();
    assert_eq!(
        (
            air.width(),
            air.num_public_values(),
            air.num_periodic_columns()
        ),
        (7161, 691, 512)
    );
    assert_eq!(air.main_next_row_columns().len(), 7161);
    let (_, report) = backend::analyze(&air).unwrap();
    report.require_target().unwrap();
    assert!(report.degree <= 5);
    assert_eq!(
        (
            backend::QUERIES,
            backend::RANDOM_CODEWORDS,
            backend::PROOF_DEGREE_BITS
        ),
        (192, 5, 10)
    );
    assert_eq!(
        backend::AllocationEstimate::for_width(7161).main_lde_bytes,
        469_630_976
    );
    let (old, _) = pair_with(&fixture::canonical_suffix(), false);
    let (bytes, _) = fixture::fixture().unwrap();
    assert_eq!((old.air().width(), bytes.air().width()), (11521, 11079));
    assert_ne!(
        backend::profile_digest(Kind::PackedCanonicalIndexOpening),
        backend::profile_digest(Kind::CanonicalIndexOpening)
    );
    assert_ne!(
        backend::profile_digest(Kind::PackedCanonicalIndexOpening),
        backend::profile_digest(Kind::PairOpening)
    );
}
