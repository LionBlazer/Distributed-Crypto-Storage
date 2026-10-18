//! PUBLIC NONSECRET owning tests for the canonical N4 relation. Invalid source
//! cases retain real AEAD, complete public roots and correctly recomputed C_open.
use super::{Relation, air, canonical as ci, commitment, fixture, statement::Statement};
use crate::backend::{self, Backend, TRACE_HEIGHT, Val};
use crate::primitive::PublicStatement;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use p3_air::{BaseAir, check_all_constraints, check_constraints};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use registry200_proof::source::circuit::Witness;

const AGES: [u8; 4] = [255, 0, 255, 128];
fn key() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}
fn salts() -> ([Val; 4], [Val; 4]) {
    ([Val::from_u8(17); 4], [Val::from_u8(29); 4])
}
fn data(ages: [u8; 4]) -> [u8; 12] {
    let amounts = [0_u16, 65535, 256, 255];
    let mut bytes = [0; 12];
    for (i, age) in ages.into_iter().enumerate() {
        bytes[i * 3] = age;
        bytes[i * 3 + 1..i * 3 + 3].copy_from_slice(&amounts[i].to_le_bytes());
    }
    bytes
}
fn ids() -> [[u8; 32]; 4] {
    core::array::from_fn(|i| {
        let mut id = [0; 32];
        id[31] = i as u8 + 1;
        id
    })
}
/// Test-only independent literal N4 format construction; the default result is
/// compared with the CORE encoder-owned vector, not accepted as its own oracle.
fn suffix(ages: [u8; 4], table: [u8; 32], ids: [[u8; 32]; 4]) -> Vec<u8> {
    let mut bytes = vec![0; 2336];
    bytes[112..144].copy_from_slice(&table);
    let mut used = 0;
    for age in 0..256 {
        let rows: Vec<_> = (0..4).filter(|i| ages[*i] as usize == age).collect();
        bytes[144 + age * 4..148 + age * 4].copy_from_slice(&(rows.len() as u32).to_le_bytes());
        bytes[1168 + age * 4..1172 + age * 4].copy_from_slice(&(used as u32).to_le_bytes());
        for (position, ordinal) in rows.iter().enumerate() {
            bytes[2196 + used] = if position == 0 {
                *ordinal
            } else {
                *ordinal - rows[position - 1]
            } as u8;
            used += 1;
        }
    }
    bytes[2192..2196].copy_from_slice(&(used as u32).to_le_bytes());
    for (i, id) in ids.into_iter().enumerate() {
        bytes[2208 + i * 32..2240 + i * 32].copy_from_slice(&id);
    }
    bytes[112..].to_vec()
}
fn pair_with(ages: [u8; 4], suffix: &[u8]) -> (Statement, Witness) {
    fixture::from_suffix(
        Relation::CanonicalIndex,
        key(),
        salts(),
        [0x83; 32],
        data(ages),
        suffix,
    )
    .unwrap()
}
fn pair() -> (Statement, Witness) {
    pair_with(AGES, &fixture::canonical_suffix())
}
fn plaintext(statement: &Statement) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&key().into());
    let mut plain = Vec::new();
    for page in 0..2 {
        plain.extend(
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
    plain
}
fn valid(statement: &Statement, witness: &Witness) -> RowMajorMatrix<Val> {
    let trace = witness.trace(statement).unwrap();
    check_constraints(&statement.air(), &trace, &statement.public_values());
    trace
}
fn rejects_native(statement: &Statement, trace: &RowMajorMatrix<Val>) {
    let report =
        check_all_constraints(&statement.air(), trace, &statement.public_values(), Some(1));
    assert!(!report.is_ok());
}
fn rejected_rebuilt(statement: &Statement, trace: RowMajorMatrix<Val>) {
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
fn reject_source(ages: [u8; 4], bad: &[u8], rebuild: bool) {
    let (statement, witness) = pair_with(ages, bad);
    let plain = plaintext(&statement);
    assert_eq!(&plain[..12], &data(ages));
    assert_eq!(&plain[12 + 112..], bad);
    // The same source genuinely satisfies the older byte-opening relation.
    // Only the newly requested canonical predicate is false.
    let mut bytes = statement.clone();
    bytes.relation = Relation::Bytes;
    bytes.open_commitment =
        commitment::digest(&commitment::opening_fields(&bytes, salts().1, &plain));
    drop(valid(&bytes, &witness));
    let trace = witness.trace(&statement).unwrap();
    rejects_native(&statement, &trace);
    if rebuild {
        rejected_rebuilt(&statement, trace);
    }
}

#[test]
fn canonical_index_fixture_matches_the_core_codec_vector_and_authentic_row_bytes() {
    let (statement, witness) = pair();
    let plain = plaintext(&statement);
    assert_eq!(fixture::canonical_suffix(), suffix(AGES, [0x31; 32], ids()));
    assert_eq!(
        &plain[..12],
        &[255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0]
    );
    assert_eq!(&plain[12..124], &statement.heads[0]);
    assert_eq!(&plain[12 + 112..], &fixture::canonical_suffix());
    assert_eq!(&plain[12 + 2196..12 + 2200], &[1, 3, 0, 2]);
    assert_eq!(&plain[12 + 2200..12 + 2208], &[0; 8]);
    let trace = valid(&statement, &witness);
    assert_eq!(trace.width, 11521);
    assert_eq!(statement.public_values().len(), 691);
    // Private age/permutation banks exist from row0 and bind actual source at80.
    assert_eq!(
        &trace.values[ci::AGES..ci::SORT],
        &trace.values[511 * ci::WIDTH + ci::AGES..511 * ci::WIDTH + ci::SORT]
    );
}
#[test]
fn canonical_index_supports_equal_boundary_and_reordered_ages_without_identity_ordering_rules() {
    for ages in [
        [0; 4],
        [255; 4],
        [0, 255, 128, 1],
        [255, 128, 0, 255],
        [128, 127, 128, 127],
    ] {
        let mut identity = ids();
        identity.reverse();
        let source = suffix(ages, [0x31; 32], identity);
        let (statement, witness) = pair_with(ages, &source);
        drop(valid(&statement, &witness));
    }
    // Neither half of TableId has to be nonzero individually.
    for half in [0, 16] {
        let mut table = [0; 32];
        table[half] = 1;
        let (statement, witness) = pair_with(AGES, &suffix(AGES, table, ids()));
        drop(valid(&statement, &witness));
    }
}
#[test]
fn genuine_canonical_index_proof_binds_the_new_relation_and_rejects_old_byte_evidence() {
    let (statement, witness) = pair();
    let backend = Backend::new(&statement).unwrap();
    let proof = backend
        .prove_with_trace(&statement, || witness.trace(&statement))
        .unwrap();
    backend.verify(&statement, &proof).unwrap();
    let mut changed = statement.clone();
    changed.request[0] ^= 1;
    assert!(
        Backend::new(&changed)
            .unwrap()
            .verify(&changed, &proof)
            .is_err()
    );
    let plain = plaintext(&statement);
    let mut bytes = statement.clone();
    bytes.relation = Relation::Bytes;
    bytes.open_commitment =
        commitment::digest(&commitment::opening_fields(&bytes, salts().1, &plain));
    assert_ne!(&bytes.public_values()[..8], &statement.public_values()[..8]);
    assert_ne!(bytes.open_commitment, statement.open_commitment);
    let byte_backend = Backend::new(&bytes).unwrap();
    let old = byte_backend
        .prove_with_trace(&bytes, || witness.trace(&bytes))
        .unwrap();
    byte_backend.verify(&bytes, &old).unwrap();
    assert!(backend.verify(&statement, &old).is_err());
    assert!(byte_backend.verify(&bytes, &proof).is_err());
}
#[test]
fn valid_aead_cannot_hide_wrong_counts_offsets_or_stale_buffer_header_words() {
    for (word, rebuild) in [
        (36, true),
        (291, true),
        (292, true),
        (548, true),
        (142, true),
        (143, false),
        (254, false),
        (255, false),
        (366, false),
        (367, false),
        (478, false),
        (479, true),
    ] {
        let mut bad = fixture::canonical_suffix();
        bad[word * 4 - 112] ^= 1;
        reject_source(AGES, &bad, rebuild);
    }
    // A high count byte cannot alias a small field count or fit a valid u32 cell.
    let mut bad = fixture::canonical_suffix();
    bad[144 - 112 + 3] = 1;
    reject_source(AGES, &bad, true);
}
#[test]
fn rebuilt_posting_omissions_duplicates_bucket_order_varints_and_padding_are_rejected() {
    for postings in [
        [1, 3, 0, 0],
        [1, 3, 0, 1],
        [3, 1, 0, 2],
        [1, 3, 2, 0],
        [0x81, 3, 0, 2],
        [1, 3, 0, 0x82],
    ] {
        let mut bad = fixture::canonical_suffix();
        bad[2196 - 112..2200 - 112].copy_from_slice(&postings);
        reject_source(AGES, &bad, true);
    }
    for offset in [2200, 2203, 2204, 2207] {
        let mut bad = fixture::canonical_suffix();
        bad[offset - 112] = 1;
        reject_source(AGES, &bad, offset == 2200 || offset == 2207);
    }
}
#[test]
fn table_identity_must_be_nonzero_across_both_authenticated_halves() {
    let mut bad = fixture::canonical_suffix();
    bad[..32].fill(0);
    reject_source(AGES, &bad, true);
}
#[test]
fn all_four_row_identities_are_nonzero_and_all_six_pairs_are_distinct() {
    for row in 0..4 {
        let mut bad = fixture::canonical_suffix();
        bad[2208 - 112 + row * 32..2240 - 112 + row * 32].fill(0);
        reject_source(AGES, &bad, row == 3);
    }
    for first in 0..4 {
        for second in first + 1..4 {
            let mut identity = ids();
            identity[second] = identity[first];
            reject_source(AGES, &suffix(AGES, [0x31; 32], identity), true);
        }
    }
    // Full 256-bit equality, not only the low word or last byte.
    let mut identity = [[0; 32]; 4];
    for (i, id) in identity.iter_mut().enumerate() {
        id[i * 8] = 1;
    }
    let (statement, witness) = pair_with(AGES, &suffix(AGES, [0x31; 32], identity));
    drop(valid(&statement, &witness));
}
#[test]
fn immutable_age_permutation_sort_and_header_witnesses_cannot_replace_the_real_rows() {
    let (statement, witness) = pair();
    let genuine = valid(&statement, &witness);
    for (row, column) in [
        (0, ci::AGES),
        (80, ci::AGES + 31),
        (511, ci::PERMUTATION),
        (0, ci::SORT),
        (162, ci::HEADER + (6 * 4) * 11 + 8),
        (162, ci::HEADER + (6 * 4) * 11 + 10),
        (80, ci::TABLE_HALF),
        (161, ci::IDENTITY),
        (485, ci::IDENTITY + 10),
        (511, ci::HEADER),
    ] {
        let mut trace = genuine.clone();
        let cell = &mut trace.values[row * ci::WIDTH + column];
        *cell += Val::ONE;
        rejects_native(&statement, &trace);
        rejected_rebuilt(&statement, trace);
    }
    let mut trace = genuine.clone();
    // A field value p-1 is not an eight-bit nonnegative sorted difference.
    trace.values[ci::SORT] = Val::from_u64(Val::ORDER_U64 - 1);
    rejects_native(&statement, &trace);
    rejected_rebuilt(&statement, trace);
}
#[test]
fn a_fresh_commitment_covers_the_current_mapping_without_claiming_identity_history() {
    let (original, _) = pair();
    let mut identity = ids();
    identity.rotate_left(1);
    let (mut changed, witness) = pair_with(AGES, &suffix(AGES, [0x42; 32], identity));
    // No independent logical identity/history anchor is part of this relation.
    assert_eq!(original.key_commitment, changed.key_commitment);
    assert_ne!(original.open_commitment, changed.open_commitment);
    drop(valid(&changed, &witness));
    changed.open_commitment = original.open_commitment;
    rejected_rebuilt(&changed, witness.trace(&changed).unwrap());
}
#[test]
fn fresh_private_salt_changes_the_index_opening_without_exposing_id_or_key_fields() {
    let (first, _) = pair();
    let (second, witness) = fixture::from_suffix(
        Relation::CanonicalIndex,
        key(),
        (salts().0, [Val::from_u8(30); 4]),
        first.request,
        data(AGES),
        &fixture::canonical_suffix(),
    )
    .unwrap();
    assert_eq!(first.key_commitment, second.key_commitment);
    assert_ne!(first.open_commitment, second.open_commitment);
    let a = first.public_values();
    let b = second.public_values();
    assert_eq!(
        &a[..super::statement::OPEN_COMMITMENT],
        &b[..super::statement::OPEN_COMMITMENT]
    );
    drop(valid(&second, &witness));
}
#[test]
fn canonical_geometry_and_security_are_analyzed_without_inventing_a_degree_or_rss_result() {
    let (statement, _) = pair();
    let air = statement.air();
    assert_eq!(air.width(), 11521);
    assert_eq!(air.num_public_values(), 691);
    assert_eq!(air.num_periodic_columns(), 512);
    assert_eq!(air.main_next_row_columns().len(), 11521);
    let (_, report) = backend::analyze(&air).unwrap();
    report.require_target().unwrap();
    assert!(report.degree <= 5);
    let arrays = backend::AllocationEstimate::for_width(air.width());
    assert_eq!(arrays.trace_bytes, 47_190_016);
    assert_eq!(arrays.masked_trace_bytes, 94_420_992);
    assert_eq!(arrays.main_lde_bytes, 755_367_936);
    assert_eq!(ci::WIDTH - air::WIDTH, 442);
}

#[test]
fn a_coherent_fake_age_bank_and_index_cannot_replace_the_authenticated_data_ages() {
    let fake = [255, 1, 255, 128];
    let (statement, _) = pair_with(AGES, &suffix(fake, [0x31; 32], ids()));
    let witness = Witness::new(key(), salts().0, salts().1, fake);
    let plain = plaintext(&statement);
    let mut bytes = statement.clone();
    bytes.relation = Relation::Bytes;
    bytes.open_commitment =
        commitment::digest(&commitment::opening_fields(&bytes, salts().1, &plain));
    drop(valid(&bytes, &witness));

    // Every private age, permutation, sort and header auxiliary coherently uses B.
    // The actual AEAD data is A: its single differing age bit binds at row80.
    let trace = witness.trace(&statement).unwrap();
    let report = check_all_constraints(
        &statement.air(),
        &trace,
        &statement.public_values(),
        Some(33),
    );
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].row, 80);
    rejected_rebuilt(&statement, trace);
}
#[test]
fn a_coherently_retained_nonzero_table_half_cannot_replace_the_zero_source_identity() {
    let (statement, witness) = pair_with(AGES, &suffix(AGES, [0; 32], ids()));
    let mut trace = witness.trace(&statement).unwrap();
    for row in 80..TRACE_HEIGHT {
        trace.values[row * ci::WIDTH + ci::TABLE_HALF] = Val::ONE;
    }
    trace.values[161 * ci::WIDTH + ci::IDENTITY] = Val::ONE;
    // Copy rules and final nonzero equation are valid; only authentic capture is false.
    let report = check_all_constraints(
        &statement.air(),
        &trace,
        &statement.public_values(),
        Some(2),
    );
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].row, 80);
    rejected_rebuilt(&statement, trace);
}
