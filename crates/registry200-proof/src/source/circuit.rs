//! Explicit owner-side private circuit witness for all five Source relations.
//! A trace contains private data; it is mathematical input, never proof authority.
use super::chacha as ca;
use super::poly1305 as poly;
use super::poly1305 as pa;
use super::poly1305::LIMBS;
use super::{
    air::*,
    poseidon,
    schedule::{self, Job, Mac},
    statement::Statement,
};
use bfv_hiding_stark::{Error, TRACE_HEIGHT, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use zeroize::Zeroizing;
pub struct Witness {
    key: Zeroizing<[u8; 32]>,
    salts: Zeroizing<[[u64; 4]; 2]>,
    ages: Zeroizing<[u8; 4]>,
}
impl Witness {
    pub fn new(key: [u8; 32], key_salt: [Val; 4], open_salt: [Val; 4], ages: [u8; 4]) -> Self {
        Self {
            key: Zeroizing::new(key),
            salts: Zeroizing::new([
                key_salt.map(|v| v.as_canonical_u64()),
                open_salt.map(|v| v.as_canonical_u64()),
            ]),
            ages: Zeroizing::new(ages),
        }
    }
    pub fn trace(&self, statement: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        // Mathematical hostile claims may deliberately have invalid AEAD/roots.
        // Bound all indexed packet slices before AIR construction; the typed
        // producer separately reaudits complete canonical images.
        if statement.packets[0].len() != 60 || statement.packets[1].len() != 2384 {
            return Err(Error::Shape);
        }
        let air = OpeningAir::new(statement);
        let width = statement.relation.width();
        let cols = air.columns();
        let schedule = air.schedule();
        let mut template = Val::zero_vec(width);
        write_bank(
            &mut template[cols.master..cols.subkey],
            self.key.as_slice(),
            cols.packed,
        );
        for page in 0..2 {
            let input = words(air.input::<Val, _>(&template, Job::H(page)));
            let output = complete(input, true);
            write_bank_words(
                &mut template[cols.subkey + page * cols.key_stride()
                    ..cols.subkey + (page + 1) * cols.key_stride()],
                &output[..8],
                cols.packed,
            );
            let input = words(air.input::<Val, _>(&template, Job::Cha { page, counter: 0 }));
            let output = complete(input, false);
            write_bank_words(
                &mut template[cols.polykey + page * cols.key_stride()
                    ..cols.polykey + (page + 1) * cols.key_stride()],
                &output[..8],
                cols.packed,
            );
        }
        template[cols.salts..cols.salts + 4].copy_from_slice(&self.salts[0].map(Val::from_u64));
        template[cols.salts + 4..cols.width].copy_from_slice(&self.salts[1].map(Val::from_u64));
        if statement.relation.is_canonical() {
            super::canonical::write_template(&mut template, *self.ages, cols.packed);
        }
        let mut states: [[u32; 16]; 7] =
            core::array::from_fn(|lane| words(air.input::<Val, _>(&template, schedule::job(lane))));
        let mut buffers = [[0_u32; 16]; 7];
        let mut plaintext = [[0_u32; 16]; 7];
        let mut h = [0_u64; LIMBS];
        let mut checkpoint = [Val::ZERO; 12];
        let mut carries = [Val::ZERO; 2];
        let mut table_half = Val::ZERO;
        let mut values = Val::zero_vec(TRACE_HEIGHT * width);
        for (index, row) in values.chunks_exact_mut(width).enumerate() {
            row[cols.banks..cols.poly].copy_from_slice(&template[cols.banks..cols.poly]);
            row[cols.salts..].copy_from_slice(&template[cols.salts..]);
            let group = index / schedule.job_rows();
            let step = index % schedule.job_rows();
            for lane in 0..7 {
                let local = &mut row[lane * ca::WIDTH..(lane + 1) * ca::WIDTH];
                write_words(&mut local[..512], &states[lane]);
                if group < 6 && step < 80 {
                    ca::write_round(local, &mut states[lane], ca::SCHEDULE[step % 8]);
                }
                if group < 6 && step == 80 {
                    let job = schedule::job(group * 7 + lane);
                    match job {
                        Job::H(_) => {
                            buffers[lane] = [0; 16];
                            for (out, word) in ca::HCHACHA_OUTPUT.into_iter().enumerate() {
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
                    if cols.packed {
                        // NEXT row holds range-constrained feedforward/extracted bits.
                        states[lane] = buffers[lane];
                    } else if group < 5 {
                        states[lane] = words(
                            air.input::<Val, _>(&template, schedule::job((group + 1) * 7 + lane)),
                        );
                    }
                }
                if cols.packed && group < 6 && step == 81 {
                    plaintext[lane] =
                        plain_words(statement, schedule::job(group * 7 + lane), buffers[lane]);
                    if group < 5 {
                        states[lane] = words(
                            air.input::<Val, _>(&template, schedule::job((group + 1) * 7 + lane)),
                        );
                    }
                }
                let start = cols.buffers + lane * cols.buffer_stride();
                write_bank_words(
                    &mut row[start..start + cols.buffer_stride()],
                    if cols.packed {
                        &plaintext[lane]
                    } else {
                        &buffers[lane]
                    },
                    cols.packed,
                );
            }
            if cols.packed {
                let page = usize::from((10..165).contains(&index));
                let key = read_key(
                    &template[cols.polykey + page * 8..cols.polykey + (page + 1) * 8],
                    true,
                );
                write_bytes(&mut row[cols.polykey_bits..cols.poly], &key);
            }
            let local = &mut row[cols.poly..cols.poseidon];
            let (state, rest) = local.split_at_mut(pa::STATE);
            let (_, rest) = rest.split_at_mut(160);
            let (canonical, rest) = rest.split_at_mut(pa::STATE);
            let (canonical_carry, _) = rest.split_at_mut(5);
            pa::write_canonical(state, canonical, canonical_carry, h);
            match schedule::mac(index) {
                Mac::Block { page, block } => {
                    let key = read_key(
                        &template[cols.polykey + page * cols.key_stride()
                            ..cols.polykey + (page + 1) * cols.key_stride()],
                        cols.packed,
                    );
                    let n = poly::message_limbs(statement.mac_block(page, block), 128);
                    let product = poly::folded_product(h, n, poly::clamped_r(key));
                    let (next, carry) = poly::reduce(product);
                    for (limb, value) in carry.into_iter().enumerate() {
                        poly::write_bits(
                            &mut row[cols.poly + pa::CARRY + limb * 32
                                ..cols.poly + pa::CARRY + (limb + 1) * 32],
                            value,
                        );
                    }
                    h = next;
                }
                Mac::Final(page) => {
                    let key = read_key(
                        &template[cols.polykey + page * cols.key_stride()
                            ..cols.polykey + (page + 1) * cols.key_stride()],
                        cols.packed,
                    );
                    for (word, carry) in poly::tag_words(h, key).1.into_iter().enumerate() {
                        row[cols.poly + pa::TAG + word] = Val::from_bool(carry);
                    }
                    h = [0; LIMBS];
                }
                Mac::Idle => {}
            }
            if let Some(group) = schedule.capture(index) {
                for (position, carry) in carries.iter_mut().enumerate() {
                    *carry = air.plain_word(row, [33, 145, 257, 369, 481][group] + position);
                }
            }
            row[cols.carry..cols.salts].copy_from_slice(&carries);
            row[cols.checkpoint..cols.carry].copy_from_slice(&checkpoint);
            let mut input = [Val::ZERO; 12];
            if let Some((key, block)) = schedule.absorb(index) {
                for (word, cell) in input[..8].iter_mut().enumerate() {
                    *cell = air.stream_field(row, key, block * 8 + word, index);
                }
                if index != 0 && index != 4 {
                    input[8..].copy_from_slice(&checkpoint[8..]);
                }
            }
            let output = poseidon::write(&mut row[cols.poseidon..cols.checkpoint], input);
            if schedule.absorb(index).is_some() {
                checkpoint = output;
            }
            if statement.relation.is_canonical() {
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
        ca::write_round(&mut local, &mut state, ca::SCHEDULE[step % 8]);
    }
    if h {
        let mut out = [0; 16];
        for (i, j) in ca::HCHACHA_OUTPUT.into_iter().enumerate() {
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
fn read_key(bits: &[Val], packed: bool) -> [u8; 32] {
    if packed {
        let mut key = [0; 32];
        for (word, bytes) in bits.iter().zip(key.as_chunks_mut::<4>().0) {
            bytes.copy_from_slice(&(word.as_canonical_u64() as u32).to_le_bytes());
        }
        return key;
    }
    core::array::from_fn(|i| {
        (0..8).fold(0, |byte, j| {
            byte | ((bits[i * 8 + j].as_canonical_u64() as u8) << j)
        })
    })
}

fn write_bank(out: &mut [Val], bytes: &[u8], packed: bool) {
    if packed {
        for (cell, word) in out.iter_mut().zip(bytes.as_chunks::<4>().0) {
            *cell = Val::from_u32(u32::from_le_bytes(*word));
        }
    } else {
        write_bytes(out, bytes);
    }
}
fn write_bank_words(out: &mut [Val], words: &[u32], packed: bool) {
    if packed {
        assert_eq!(out.len(), words.len());
        for (cell, word) in out.iter_mut().zip(words) {
            *cell = Val::from_u32(*word);
        }
    } else {
        write_words(out, words);
    }
}
fn plain_words(statement: &Statement, job: Job, stream: [u32; 16]) -> [u32; 16] {
    let Job::Cha { page, counter } = job else {
        return [0; 16];
    };
    if counter == 0 {
        return [0; 16];
    }
    let cipher = statement.ciphertext(page);
    core::array::from_fn(|word| {
        let start = (counter as usize - 1) * 64 + word * 4;
        if start >= cipher.len() {
            0
        } else {
            stream[word] ^ u32::from_le_bytes(cipher[start..start + 4].try_into().unwrap())
        }
    })
}
