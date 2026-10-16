//! Owning examples for the complete opening. Future execution is gated separately
//! by source, actual numerical/security and externally observed resource reviews.
use super::{
    air::*,
    commitment, fixture, poseidon,
    schedule::{self, Job},
    statement::{self, Statement},
    trace::Witness,
};
use crate::backend::{self, Backend, Error, TRACE_HEIGHT, Val};
use crate::chacha::{self, air as ca};
use crate::poly1305::arithmetic as pa;
use crate::primitive::{Kind, PrimitiveStatement, PublicStatement};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use compact_store::Commitment;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, check_constraints};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;
use std::borrow::Cow;
fn key() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}
fn salts() -> ([Val; 4], [Val; 4]) {
    ([Val::from_u8(17); 4], [Val::from_u8(29); 4])
}
fn pair() -> (Statement, Witness) {
    let (a, b) = salts();
    fixture::make(
        key(),
        a,
        b,
        [0x83; 32],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 255],
    )
    .unwrap()
}
fn plaintext(statement: &Statement) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&key().into());
    let mut result = Vec::new();
    for page in 0..2 {
        let packet = &statement.packets[page];
        let plain = cipher
            .decrypt(
                &statement.nonce(page).into(),
                Payload {
                    msg: &packet[32..],
                    aad: &statement.aad(page),
                },
            )
            .unwrap();
        result.extend(plain);
    }
    result
}
fn images(statement: &Statement) -> [Vec<u8>; 2] {
    core::array::from_fn(|page| {
        let mut out = statement.heads[page].to_vec();
        out.extend_from_slice(&statement.packets[page]);
        out
    })
}
fn checked_like(original: &Statement, images: [Vec<u8>; 2]) -> Statement {
    let heads = images
        .each_ref()
        .map(|bytes| Commitment::decode(&bytes[..112], statement::limits()).unwrap());
    Statement::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        original.request,
        statement::encode_digest(original.key_commitment),
        statement::encode_digest(original.open_commitment),
    )
    .unwrap()
}
fn rebind_opening(statement: &mut Statement, plain: &[u8]) {
    statement.open_commitment =
        commitment::digest(&commitment::opening_fields(statement, salts().1, plain));
}
fn valid_trace(statement: &Statement, witness: &Witness) -> RowMajorMatrix<Val> {
    let trace = witness.trace(statement).unwrap();
    check_constraints(&statement.air(), &trace, &statement.public_values());
    trace
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
fn bit(trace: &mut RowMajorMatrix<Val>, row: usize, column: usize) {
    let cell = &mut trace.values[row * WIDTH + column];
    *cell = Val::ONE - *cell;
}

#[test]
fn canonical_pair_statement_contains_only_exact_public_source_and_two_commitments() {
    let (statement, _) = pair();
    let values = statement.public_values();
    assert_eq!(values.len(), 691);
    assert_eq!(
        values[statement::HEADS..statement::PACKETS],
        statement
            .heads
            .iter()
            .flat_map(|h| statement::words(h))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        values[statement::PACKETS..statement::KEY_COMMITMENT],
        statement
            .packets
            .iter()
            .flat_map(|p| statement::words(p))
            .collect::<Vec<_>>()
    );
    let bytes = images(&statement);
    let heads = bytes
        .each_ref()
        .map(|b| Commitment::decode(&b[..112], statement::limits()).unwrap());
    for page in 0..2 {
        assert!(
            u64::from_le_bytes(statement.packets[page][..8].try_into().unwrap())
                < heads[page].revision()
        );
        let mut changed = bytes.clone();
        changed[page][112] ^= 1;
        assert!(
            Statement::checked(
                [&changed[0], &changed[1]],
                [&heads[0], &heads[1]],
                statement.request,
                [0; 32],
                [0; 32]
            )
            .is_err()
        );
        let mut changed = bytes.clone();
        changed[page].push(0);
        assert!(
            Statement::checked(
                [&changed[0], &changed[1]],
                [&heads[0], &heads[1]],
                statement.request,
                [0; 32],
                [0; 32]
            )
            .is_err()
        );
    }
    let mut noncanonical = [0; 32];
    noncanonical[..8].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    assert!(matches!(
        statement::decode_digest(noncanonical),
        Err(Error::Shape)
    ));
}
#[test]
fn fixed_absorbs_consume_every_plain_word_once_and_use_only_the_ten_required_carries() {
    let mut words = Vec::new();
    let mut stale = Vec::new();
    let mut seen_blocks = Vec::new();
    for row in 0..512 {
        if let Some((key, block)) = schedule::absorb(row) {
            if key {
                continue;
            }
            seen_blocks.push(block);
            for field in block * 8..block * 8 + 8 {
                if (87..674).contains(&field) {
                    let word = field - 87;
                    words.push(word);
                    let (group, _, _) = schedule::plain_location(word);
                    let last_overwrite = group * 81 + 161;
                    if row >= last_overwrite {
                        stale.push(word);
                    }
                }
            }
        }
    }
    assert_eq!(seen_blocks, (0..85).collect::<Vec<_>>());
    assert_eq!(words, (0..587).collect::<Vec<_>>());
    assert_eq!(stale, [33, 34, 145, 146, 257, 258, 369, 370, 481, 482]);
    assert_eq!(
        schedule::columns().iter().map(Vec::len).sum::<usize>(),
        512 * 512
    );
}
#[test]
fn genuine_whole_pair_matches_independent_aead_and_preserves_all_partial_tail_words() {
    for data in [
        [0; 12],
        [255; 12],
        [0, 1, 127, 128, 254, 255, 17, 38, 59, 80, 101, 122],
    ] {
        let (a, b) = salts();
        let (statement, witness) = fixture::make(key(), a, b, [0x83; 32], data).unwrap();
        let plain = plaintext(&statement);
        assert_eq!(&plain[..12], &data);
        assert_eq!(&plain[12..124], &statement.heads[0]);
        let trace = valid_trace(&statement, &witness);
        let expected = commitment::digest(&commitment::opening_fields(&statement, b, &plain));
        assert_eq!(expected, statement.open_commitment);
        let air = OpeningAir::new(&statement);
        for word in 0..587 {
            let (group, _, _) = schedule::plain_location(word);
            let row = schedule::boundary(group);
            let actual =
                air.plain_word::<Val, _>(&trace.values[row * WIDTH..(row + 1) * WIDTH], word);
            let wanted = Val::from_u32(u32::from_le_bytes(
                plain[word * 4..word * 4 + 4].try_into().unwrap(),
            ));
            assert_eq!(actual, wanted, "word{word}");
        }
    }
}
#[test]
fn exact_statement_binding_rejects_before_witness_factory_and_fresh_backend_replays_reach_sdk() {
    let (statement, witness) = pair();
    let backend = Backend::new(&statement).unwrap();
    let proof = backend
        .prove_with_trace(&statement, || witness.trace(&statement))
        .unwrap();
    backend.verify(&statement, &proof).unwrap();
    let mut changed = statement.clone();
    changed.request[0] ^= 1;
    assert!(matches!(
        backend.prove_with_trace(&changed, || panic!(
            "Must reject before private witness work"
        )),
        Err(Error::Shape)
    ));
    assert!(backend.verify(&changed, &proof).is_err());
    assert!(
        Backend::new(&changed)
            .unwrap()
            .verify(&changed, &proof)
            .is_err()
    );
    for change in 0..2 {
        let mut changed = statement.clone();
        if change == 0 {
            changed.key_commitment[0] += Val::ONE;
        } else {
            changed.open_commitment[0] += Val::ONE;
        }
        assert!(
            Backend::new(&changed)
                .unwrap()
                .verify(&changed, &proof)
                .is_err()
        );
    }
}
#[test]
fn fresh_salt_hides_equal_byte_openings_without_changing_the_independently_fixed_key_anchor() {
    let (a, b) = salts();
    let (first, _) = pair();
    let (second, witness) = fixture::make(
        key(),
        a,
        [Val::from_u8(30); 4],
        [0x83; 32],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 255],
    )
    .unwrap();
    assert_eq!(first.key_commitment, second.key_commitment);
    assert_ne!(first.open_commitment, second.open_commitment);
    assert_ne!(b, [Val::from_u8(30); 4]);
    valid_trace(&second, &witness);
}
#[test]
fn a_correct_mac_cannot_authenticate_a_false_opening_of_any_plaintext_region() {
    let (statement, witness) = pair();
    let plain = plaintext(&statement);
    let genuine = witness.trace(&statement).unwrap();
    for offset in [0, 11, 12, 123, 124, 2195, 2347] {
        let mut false_plain = plain.clone();
        false_plain[offset] ^= 1;
        let mut changed = statement.clone();
        rebind_opening(&mut changed, &false_plain);
        rejected_rebuilt(&changed, genuine.clone());
    }
}
#[test]
fn independently_valid_but_inconsistent_cipher_jobs_cannot_cross_secret_banks_or_counters() {
    let (statement, witness) = pair();
    let genuine = witness.trace(&statement).unwrap();
    for (job_index, change) in [(0, 0), (1, 0), (2, 1), (3, 1), (4, 2), (21, 2), (41, 2)] {
        let mut trace = genuine.clone();
        install_alternate_job(&statement, &mut trace, job_index, change);
        rejected_rebuilt(&statement, trace);
    }
}
fn install_alternate_job(
    statement: &Statement,
    trace: &mut RowMajorMatrix<Val>,
    index: usize,
    change: usize,
) {
    let group = index / 7;
    let lane = index % 7;
    let start = group * 81;
    let air = OpeningAir::new(statement);
    let row = &trace.values[start * WIDTH..(start + 1) * WIDTH];
    let mut input = air
        .input::<Val, _>(row, schedule::job(index))
        .map(|x| x.as_canonical_u64() as u32);
    match change {
        0 | 1 => input[4] ^= 1,
        _ => input[12] = input[12].wrapping_add(1),
    }
    let kind = if matches!(schedule::job(index), Job::H(_)) {
        Kind::HChaCha20
    } else {
        Kind::ChaCha20
    };
    let mut alternate = chacha::statement::Statement {
        kind,
        request: [0x43; 32],
        input,
        output: [0; 16],
    };
    alternate.output = chacha::statement::reference_output(&alternate);
    let source = alternate.trace();
    check_constraints(&alternate.air(), &source, &alternate.public_values());
    for step in 0..=80 {
        let cells = &mut trace.values[(start + step) * WIDTH + lane * ca::WIDTH
            ..(start + step) * WIDTH + (lane + 1) * ca::WIDTH];
        cells.copy_from_slice(&source.values[step * ca::WIDTH..(step + 1) * ca::WIDTH]);
        if step == 80 {
            cells[ca::FEEDFORWARD_CARRY..].copy_from_slice(
                &source.values[511 * ca::WIDTH + ca::FEEDFORWARD_CARRY..512 * ca::WIDTH],
            );
        }
    }
    let until = if group == 5 {
        512
    } else {
        schedule::boundary(group + 1)
    };
    for row in schedule::boundary(group)..until {
        for bit in 0..512 {
            trace.values[row * WIDTH + BUFFERS + lane * 512 + bit] =
                Val::from_u32((alternate.output[bit / 32] >> (bit % 32)) & 1);
        }
    }
}
#[test]
fn full_public_roots_do_not_replace_aead_tag_nonce_revision_or_header_authentication() {
    let (original, witness) = pair();
    let plain = plaintext(&original);
    for offset in [0, 8, 23, 24, 31, 32, 2383] {
        let mut packet = original.packets[1].clone();
        packet[offset] ^= 1;
        if offset < 8 {
            packet[..8].copy_from_slice(&2_u64.to_le_bytes());
        }
        let mut source = images(&original);
        source[1] = fixture::assemble(original.heads[1], packet);
        let mut changed = checked_like(&original, source);
        rebind_opening(&mut changed, &plain);
        rejected_rebuilt(&changed, witness.trace(&changed).unwrap());
    }
    // Genuine second packet under another master key: its valid standalone MAC
    // must not be confused with the independently anchored first packet's key.
    let mut source = images(&original);
    source[1] = fixture::image(1, &plain[12..], [0x71; 32], original.nonce(1), 1, 3);
    let mut changed = checked_like(&original, source);
    rebind_opening(&mut changed, &plain);
    rejected_rebuilt(&changed, witness.trace(&changed).unwrap());
    let mut wrong_header = plain[12..].to_vec();
    wrong_header[80] ^= 1;
    let mut source = images(&original);
    source[1] = fixture::image(1, &wrong_header, key(), original.nonce(1), 1, 3);
    let mut changed = checked_like(&original, source);
    let mut changed_plain = plain;
    changed_plain[12..].copy_from_slice(&wrong_header);
    rebind_opening(&mut changed, &changed_plain);
    rejected_rebuilt(&changed, witness.trace(&changed).unwrap());
}
#[test]
fn every_secret_bank_buffer_carry_and_gap_is_bound_through_final_padding() {
    let (statement, witness) = pair();
    let genuine = witness.trace(&statement).unwrap();
    for (row, column) in [
        (0, MASTER),
        (84, SUBKEY),
        (160, POLYKEY),
        (511, MASTER),
        (80, BUFFERS + 4 * 512),
        (161, BUFFERS + 6 * 512 + 511),
        (485, BUFFERS + 6 * 512 + 255),
        (86, CARRY),
        (162, CARRY + 1),
        (176, CARRY),
        (257, CARRY + 1),
        (338, CARRY),
        (419, CARRY + 1),
        (511, BUFFERS),
        (10, POLY),
        (165, POLY),
        (511, POLY),
        (9, POLY + pa::TAG),
        (164, POLY + pa::TAG + 3),
    ] {
        let mut trace = genuine.clone();
        bit(&mut trace, row, column);
        rejected_rebuilt(&statement, trace);
    }
    for (row, column) in [
        (20, SALTS),
        (511, SALTS + 7),
        (200, CHECKPOINT + 11),
        (500, CHECKPOINT),
        (511, CHECKPOINT + 8),
    ] {
        let mut trace = genuine.clone();
        trace.values[row * WIDTH + column] += Val::ONE;
        rejected_rebuilt(&statement, trace);
    }
}
#[test]
fn rebuilt_native_permutations_cannot_change_rate_overwrite_capacity_reset_padding_or_salt() {
    let (statement, witness) = pair();
    let genuine = witness.trace(&statement).unwrap();
    for rule in [
        WrongSponge::AddRate,
        WrongSponge::NoReset,
        WrongSponge::FinalZero,
        WrongSponge::SkipBlock,
        WrongSponge::WrongPrefix,
    ] {
        let mut changed = statement.clone();
        let mut trace = genuine.clone();
        rebuild_sponge(&mut changed, &mut trace, rule);
        rejected_rebuilt(&changed, trace);
    }
    for (row, offset) in [(0, 12), (3, 247), (81, 12), (175, 70), (499, 246)] {
        let mut trace = genuine.clone();
        trace.values[row * WIDTH + POSEIDON + offset] += Val::ONE;
        rejected_rebuilt(&statement, trace);
    }
}
#[derive(Clone, Copy)]
enum WrongSponge {
    AddRate,
    NoReset,
    FinalZero,
    SkipBlock,
    WrongPrefix,
}
fn rebuild_sponge(statement: &mut Statement, trace: &mut RowMajorMatrix<Val>, rule: WrongSponge) {
    let air = OpeningAir::new(statement);
    let mut checkpoint = [Val::ZERO; 12];
    for index in 0..512 {
        let row = &mut trace.values[index * WIDTH..(index + 1) * WIDTH];
        row[CHECKPOINT..CARRY].copy_from_slice(&checkpoint);
        let mut input = [Val::ZERO; 12];
        if let Some((key, block)) = schedule::absorb(index) {
            for (word, cell) in input[..8].iter_mut().enumerate() {
                *cell = air.stream_field(row, key, block * 8 + word, index);
                if matches!(rule, WrongSponge::AddRate) {
                    *cell += checkpoint[word];
                }
            }
            if index != 0 && (index != 4 || matches!(rule, WrongSponge::NoReset)) {
                input[8..].copy_from_slice(&checkpoint[8..]);
            }
            if index == 499 && matches!(rule, WrongSponge::FinalZero) {
                input[7] = Val::ONE;
            }
            if index == 81 && matches!(rule, WrongSponge::WrongPrefix) {
                input[6] += Val::ONE;
            }
        }
        let output = poseidon::write(&mut row[POSEIDON..CHECKPOINT], input);
        if schedule::absorb(index).is_some()
            && !(index == 256 && matches!(rule, WrongSponge::SkipBlock))
        {
            checkpoint = output;
        }
        if index == 499 {
            statement.open_commitment = output[..4].try_into().unwrap();
        }
    }
}
#[test]
fn whole_geometry_reports_actual_periodics_degree_and_both_complete_width_openings_before_trace() {
    let (statement, _) = pair();
    let air = statement.air();
    let (parameters, report) = backend::analyze(&air).unwrap();
    report.require_target().unwrap();
    assert_eq!(air.width(), 11079);
    assert_eq!(air.num_public_values(), 691);
    assert_eq!(air.num_periodic_columns(), 512);
    assert_eq!(parameters.max_combo, 2);
    assert_eq!(air.main_next_row_columns().len(), 11079);
    assert!(report.degree <= 5);
    assert!(report.unique_decoding_bits >= 128 && report.list_decoding_bits >= 128);
    let arrays = backend::AllocationEstimate::for_width(air.width());
    assert_eq!(arrays.trace_bytes, 45_379_584);
    assert_eq!(arrays.masked_trace_bytes, 90_800_128);
    assert_eq!(arrays.main_lde_bytes, 726_401_024);
}

struct PermutationAir;
impl BaseAir<Val> for PermutationAir {
    fn width(&self) -> usize {
        poseidon::WIDTH
    }
    fn num_public_values(&self) -> usize {
        24
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(&[])
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for PermutationAir {
    fn eval(&self, b: &mut AB) {
        let public: [AB::PublicVar; 24] = b.public_values().try_into().unwrap();
        let main = b.main();
        let row = main.current_slice();
        let output = poseidon::evaluate(b, row);
        for i in 0..12 {
            b.assert_eq(row[i], public[i]);
            b.assert_eq(output[i].clone(), public[12 + i]);
        }
    }
}
#[test]
fn internal_poseidon_gadget_matches_pinned_native_permutation_at_field_boundaries() {
    for input in [
        [Val::ZERO; 12],
        [Val::ONE; 12],
        [Val::from_u64(Val::ORDER_U64 - 1); 12],
        core::array::from_fn(|i| Val::from_u64((i as u64 + 1) * 0x1f31_9d13)),
    ] {
        let mut expected = input;
        default_goldilocks_poseidon2_12().permute_mut(&mut expected);
        let mut row = Val::zero_vec(poseidon::WIDTH);
        assert_eq!(poseidon::write(&mut row, input), expected);
        let trace = RowMajorMatrix::new(row.repeat(TRACE_HEIGHT), poseidon::WIDTH);
        check_constraints(
            &PermutationAir,
            &trace,
            &input.into_iter().chain(expected).collect::<Vec<_>>(),
        );
    }
}

#[test]
fn rebuilt_mac_with_a_matching_false_packet_tag_cannot_change_full_hibits_padding_lengths_or_reset()
{
    let (original, witness) = pair();
    let plain = plaintext(&original);
    for rule in [
        WrongMac::NoHibit,
        WrongMac::WrongPadding,
        WrongMac::PacketLength,
        WrongMac::FoldOne,
        WrongMac::NoPageReset,
        WrongMac::SwapBlocks,
    ] {
        let mut first = witness.trace(&original).unwrap();
        let wrong_tag = rebuild_mac(&original, &mut first, rule);
        let mut packet = original.packets[1].clone();
        let length = packet.len();
        packet[length - 16..].copy_from_slice(&wrong_tag);
        let mut bytes = images(&original);
        bytes[1] = fixture::assemble(original.heads[1], packet);
        let mut changed = checked_like(&original, bytes);
        rebind_opening(&mut changed, &plain);
        let mut trace = witness.trace(&changed).unwrap();
        assert_eq!(rebuild_mac(&changed, &mut trace, rule), wrong_tag);
        rejected_rebuilt(&changed, trace);
    }
}
#[derive(Clone, Copy)]
enum WrongMac {
    NoHibit,
    WrongPadding,
    PacketLength,
    FoldOne,
    NoPageReset,
    SwapBlocks,
}
fn rebuild_mac(statement: &Statement, trace: &mut RowMajorMatrix<Val>, rule: WrongMac) -> [u8; 16] {
    use crate::poly1305::{LIMBS, air as poly};
    let mut h = [0_u64; LIMBS];
    let mut claimed = [0; 16];
    for index in 0..512 {
        let row = &mut trace.values[index * WIDTH..(index + 1) * WIDTH];
        let local = &mut row[POLY..POSEIDON];
        local.fill(Val::ZERO);
        let (state, rest) = local.split_at_mut(pa::STATE);
        let (_, rest) = rest.split_at_mut(160);
        let (canonical, rest) = rest.split_at_mut(pa::STATE);
        let (canonical_carry, _) = rest.split_at_mut(5);
        pa::write_canonical(state, canonical, canonical_carry, h);
        let page = match schedule::mac(index) {
            schedule::Mac::Block { page, .. } | schedule::Mac::Final(page) => page,
            schedule::Mac::Idle => 0,
        };
        let key: [u8; 32] = core::array::from_fn(|byte| {
            (0..8).fold(0, |sum, bit| {
                sum | ((row[POLYKEY + page * 256 + byte * 8 + bit].as_canonical_u64() as u8) << bit)
            })
        });
        match schedule::mac(index) {
            schedule::Mac::Block { page, block } => {
                let source = if page == 1 && matches!(rule, WrongMac::SwapBlocks) {
                    match block {
                        50 => 51,
                        51 => 50,
                        _ => block,
                    }
                } else {
                    block
                };
                let mut message = statement.mac_block(page, source);
                if page == 1 && block == 6 && matches!(rule, WrongMac::WrongPadding) {
                    message[10] = 1;
                }
                if page == 1 && block == 153 && matches!(rule, WrongMac::PacketLength) {
                    message[8..].copy_from_slice(&2384_u64.to_le_bytes());
                }
                let n = poly::message_limbs(
                    message,
                    if page == 1 && matches!(rule, WrongMac::NoHibit) {
                        130
                    } else {
                        128
                    },
                );
                let r = poly::clamped_r(key);
                let mut product = poly::folded_product(h, n, r);
                if page == 1 && matches!(rule, WrongMac::FoldOne) {
                    for (i, (h, n)) in h.into_iter().zip(n).enumerate() {
                        for (j, r) in r.into_iter().enumerate() {
                            if i + j >= LIMBS {
                                product[(i + j) % LIMBS] -= 4 * (h + n) * r;
                            }
                        }
                    }
                }
                let (updated, carries) = poly::reduce(product);
                for (limb, carry) in carries.into_iter().enumerate() {
                    poly::write_bits(
                        &mut row[POLY + pa::CARRY + limb * 32..POLY + pa::CARRY + (limb + 1) * 32],
                        carry,
                    );
                }
                h = updated;
            }
            schedule::Mac::Final(page) => {
                let (words, carries) = poly::tag_words(h, key);
                for (word, carry) in carries.into_iter().enumerate() {
                    row[POLY + pa::TAG + word] = Val::from_bool(carry);
                }
                if page == 1 {
                    for (bytes, word) in claimed.as_chunks_mut::<4>().0.iter_mut().zip(words) {
                        *bytes = word.to_le_bytes();
                    }
                }
                if page != 0 || !matches!(rule, WrongMac::NoPageReset) {
                    h = [0; LIMBS];
                }
            }
            schedule::Mac::Idle => {}
        }
    }
    claimed
}

#[test]
fn independently_valid_both_packet_openings_under_another_key_cannot_replace_the_fixed_anchor() {
    let (original, _) = pair();
    let fixed_anchor = original.key_commitment;
    let other_key = [0x71; 32]; // Explicitly PUBLIC NONSECRET alternate fixture key.
    let (key_salt, open_salt) = salts();
    let (alternate, witness) = fixture::make(
        other_key,
        key_salt,
        open_salt,
        original.request,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 255],
    )
    .unwrap();
    let honest = valid_trace(&alternate, &witness);
    assert_ne!(alternate.key_commitment, fixed_anchor);

    // Independently decrypt BOTH authentic packets with the alternate fixture
    // key. Preserve the complete source/AEAD witness, but keep the original
    // independently expected anchor and recompute C_open in that exact context.
    let cipher = XChaCha20Poly1305::new(&other_key.into());
    let mut plain = Vec::new();
    for page in 0..2 {
        plain.extend(
            cipher
                .decrypt(
                    &alternate.nonce(page).into(),
                    Payload {
                        msg: &alternate.packets[page][32..],
                        aad: &alternate.aad(page),
                    },
                )
                .unwrap(),
        );
    }
    let mut changed = alternate.clone();
    changed.key_commitment = fixed_anchor;
    rebind_opening(&mut changed, &plain);
    let trace = witness.trace(&changed).unwrap();

    // Every H/Cha/MAC state, key bank and output buffer remains the SAME valid
    // alternate-key computation. C_open includes the retained old anchor and
    // still matches native Poseidon; only the C_key opening equality is false.
    for row in 0..TRACE_HEIGHT {
        assert_eq!(
            &trace.values[row * WIDTH..row * WIDTH + POSEIDON],
            &honest.values[row * WIDTH..row * WIDTH + POSEIDON]
        );
    }
    let perm = default_goldilocks_poseidon2_12();
    let mut key_output: [Val; 12] = trace.values[3 * WIDTH + POSEIDON..3 * WIDTH + POSEIDON + 12]
        .try_into()
        .unwrap();
    perm.permute_mut(&mut key_output);
    assert_eq!(&key_output[..4], &alternate.key_commitment);
    assert_ne!(&key_output[..4], &changed.key_commitment);
    let mut open_output: [Val; 12] = trace.values
        [499 * WIDTH + POSEIDON..499 * WIDTH + POSEIDON + 12]
        .try_into()
        .unwrap();
    perm.permute_mut(&mut open_output);
    assert_eq!(&open_output[..4], &changed.open_commitment);

    rejected_rebuilt(&changed, trace); // Fresh raw SDK proof, not replay/constructor rejection.
}
