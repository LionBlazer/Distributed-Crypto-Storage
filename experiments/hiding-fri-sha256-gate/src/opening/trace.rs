//! Private fixture witness. It is never serialized, cloned, Debug-printed or
//! placed in public values. This experiment does not certify buffer erasure.
use super::{
    air::*,
    poseidon,
    schedule::{self, Job, Mac},
    statement::Statement,
};
use crate::backend::{Error, TRACE_HEIGHT, Val};
use crate::chacha::{self, air as ca};
use crate::poly1305::{LIMBS, air as poly, arithmetic as pa};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
pub(crate) struct Witness {
    key: [u8; 32],
    key_salt: [Val; 4],
    open_salt: [Val; 4],
    ages: [u8; 4],
}
impl Witness {
    pub(super) fn new(
        key: [u8; 32],
        key_salt: [Val; 4],
        open_salt: [Val; 4],
        ages: [u8; 4],
    ) -> Self {
        Self {
            key,
            key_salt,
            open_salt,
            ages,
        }
    }
    pub(crate) fn trace(&self, statement: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        let air = OpeningAir::new(statement);
        let width = statement.relation.width();
        let mut template = Val::zero_vec(width);
        write_bytes(&mut template[MASTER..SUBKEY], &self.key);
        for page in 0..2 {
            let input = words(air.input::<Val, _>(&template, Job::H(page)));
            let output = complete(input, true);
            write_words(
                &mut template[SUBKEY + page * 256..SUBKEY + (page + 1) * 256],
                &output[..8],
            );
            let input = words(air.input::<Val, _>(&template, Job::Cha { page, counter: 0 }));
            let output = complete(input, false);
            write_words(
                &mut template[POLYKEY + page * 256..POLYKEY + (page + 1) * 256],
                &output[..8],
            );
        }
        template[SALTS..SALTS + 4].copy_from_slice(&self.key_salt);
        template[SALTS + 4..WIDTH].copy_from_slice(&self.open_salt);
        if statement.relation == super::Relation::CanonicalIndex {
            super::canonical::write_template(&mut template, self.ages);
        }
        let mut states: [[u32; 16]; 7] =
            core::array::from_fn(|lane| words(air.input::<Val, _>(&template, schedule::job(lane))));
        let mut buffers = [[0_u32; 16]; 7];
        let mut h = [0_u64; LIMBS];
        let mut checkpoint = [Val::ZERO; 12];
        let mut carries = [Val::ZERO; 2];
        let mut table_half = Val::ZERO;
        let mut values = Val::zero_vec(TRACE_HEIGHT * width);
        for (index, row) in values.chunks_exact_mut(width).enumerate() {
            row[BANKS..POLY].copy_from_slice(&template[BANKS..POLY]);
            row[SALTS..].copy_from_slice(&template[SALTS..]);
            let group = index / 81;
            let step = index % 81;
            for lane in 0..7 {
                let local = &mut row[lane * ca::WIDTH..(lane + 1) * ca::WIDTH];
                write_words(&mut local[..512], &states[lane]);
                if group < 6 && step < 80 {
                    chacha::arithmetic::write_round(
                        local,
                        &mut states[lane],
                        chacha::SCHEDULE[step % 8],
                    );
                }
                if group < 6 && step == 80 {
                    let job = schedule::job(group * 7 + lane);
                    match job {
                        Job::H(_) => {
                            buffers[lane] = [0; 16];
                            for (out, word) in chacha::HCHACHA_OUTPUT.into_iter().enumerate() {
                                buffers[lane][out] = states[lane][word];
                            }
                        }
                        Job::Cha { .. } => {
                            let input = words(air.input::<Val, _>(&template, job));
                            for word in 0..16 {
                                let (sum, carry) = states[lane][word].overflowing_add(input[word]);
                                buffers[lane][word] = sum;
                                local[ca::FEEDFORWARD_CARRY + word] = Val::from_bool(carry);
                            }
                        }
                    }
                    if group < 5 {
                        states[lane] = words(
                            air.input::<Val, _>(&template, schedule::job((group + 1) * 7 + lane)),
                        );
                    }
                }
                write_words(
                    &mut row[BUFFERS + lane * 512..BUFFERS + (lane + 1) * 512],
                    &buffers[lane],
                );
            }
            let local = &mut row[POLY..POSEIDON];
            let (state, rest) = local.split_at_mut(pa::STATE);
            let (_, rest) = rest.split_at_mut(160);
            let (canonical, rest) = rest.split_at_mut(pa::STATE);
            let (canonical_carry, _) = rest.split_at_mut(5);
            pa::write_canonical(state, canonical, canonical_carry, h);
            match schedule::mac(index) {
                Mac::Block { page, block } => {
                    let key = read_key(&template[POLYKEY + page * 256..POLYKEY + (page + 1) * 256]);
                    let n = poly::message_limbs(statement.mac_block(page, block), 128);
                    let product = poly::folded_product(h, n, poly::clamped_r(key));
                    let (next, carry) = poly::reduce(product);
                    for (limb, value) in carry.into_iter().enumerate() {
                        poly::write_bits(
                            &mut row
                                [POLY + pa::CARRY + limb * 32..POLY + pa::CARRY + (limb + 1) * 32],
                            value,
                        );
                    }
                    h = next;
                }
                Mac::Final(page) => {
                    let key = read_key(&template[POLYKEY + page * 256..POLYKEY + (page + 1) * 256]);
                    for (word, carry) in poly::tag_words(h, key).1.into_iter().enumerate() {
                        row[POLY + pa::TAG + word] = Val::from_bool(carry);
                    }
                    h = [0; LIMBS];
                }
                Mac::Idle => {}
            }
            if let Some(group) = schedule::capture(index) {
                for (position, carry) in carries.iter_mut().enumerate() {
                    *carry = air.plain_word(row, [33, 145, 257, 369, 481][group] + position);
                }
            }
            row[CARRY..SALTS].copy_from_slice(&carries);
            row[CHECKPOINT..CARRY].copy_from_slice(&checkpoint);
            let mut input = [Val::ZERO; 12];
            if let Some((key, block)) = schedule::absorb(index) {
                for (word, cell) in input[..8].iter_mut().enumerate() {
                    *cell = air.stream_field(row, key, block * 8 + word, index);
                }
                if index != 0 && index != 4 {
                    input[8..].copy_from_slice(&checkpoint[8..]);
                }
            }
            let output = poseidon::write(&mut row[POSEIDON..CHECKPOINT], input);
            if schedule::absorb(index).is_some() {
                checkpoint = output;
            }
            if statement.relation == super::Relation::CanonicalIndex {
                super::canonical::write_row(&air, row, index, &mut table_half);
            }
        }
        Ok(RowMajorMatrix::new(values, width))
    }
}
fn complete(input: [u32; 16], h: bool) -> [u32; 16] {
    let mut state = input;
    let mut local = [Val::ZERO; ca::WIDTH];
    for step in 0..80 {
        chacha::arithmetic::write_round(&mut local, &mut state, chacha::SCHEDULE[step % 8]);
    }
    if h {
        let mut out = [0; 16];
        for (i, j) in chacha::HCHACHA_OUTPUT.into_iter().enumerate() {
            out[i] = state[j];
        }
        out
    } else {
        core::array::from_fn(|i| state[i].wrapping_add(input[i]))
    }
}
fn words(values: [Val; 16]) -> [u32; 16] {
    values.map(|x| x.as_canonical_u64() as u32)
}
fn write_bytes(out: &mut [Val], bytes: &[u8]) {
    assert_eq!(out.len(), bytes.len() * 8);
    for (i, cell) in out.iter_mut().enumerate() {
        *cell = Val::from_u8((bytes[i / 8] >> (i % 8)) & 1);
    }
}
fn write_words(out: &mut [Val], words: &[u32]) {
    assert_eq!(out.len(), words.len() * 32);
    for (i, cell) in out.iter_mut().enumerate() {
        *cell = Val::from_u32((words[i / 32] >> (i % 32)) & 1);
    }
}
fn read_key(bits: &[Val]) -> [u8; 32] {
    core::array::from_fn(|i| {
        (0..8).fold(0, |byte, j| {
            byte | ((bits[i * 8 + j].as_canonical_u64() as u8) << j)
        })
    })
}
