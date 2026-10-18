use super::chacha as ca;
use super::chacha;
use super::poly1305::{self as pa, LIMBS};
use super::{
    DATA_BYTES, commitment,
    layout::Columns,
    poseidon,
    schedule::{self, Job, Mac},
    statement::{self, PUBLIC_VALUES, Statement},
};
use bfv_hiding_stark::{TRACE_HEIGHT, Val};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};
pub const LANES: usize = 7;
pub const BUFFERS: usize = LANES * ca::WIDTH;
pub const BANKS: usize = BUFFERS + LANES * 512;
pub const MASTER: usize = BANKS;
pub const SUBKEY: usize = MASTER + 256;
pub const POLYKEY: usize = SUBKEY + 512;
pub const POLY: usize = POLYKEY + 512;
pub const POSEIDON: usize = POLY + pa::WIDTH;
pub const CHECKPOINT: usize = POSEIDON + poseidon::WIDTH;
pub const CARRY: usize = CHECKPOINT + 12;
pub const SALTS: usize = CARRY + 2;
pub const WIDTH: usize = SALTS + 8;
const _: () = assert!(WIDTH == 11079);

pub struct OpeningAir {
    pub source: Statement,
    values: [Val; PUBLIC_VALUES],
    key_prefix: [Val; 14],
    open_prefix: [Val; 83],
    mac_fields: [[Val; 5]; 165],
    public_schedule: OnceLock<Vec<Vec<Val>>>,
}
impl OpeningAir {
    pub fn new(source: &Statement) -> Self {
        Self {
            public_schedule: OnceLock::new(),
            source: source.clone(),
            values: source.values().try_into().unwrap(),
            key_prefix: commitment::key_fields(&source.heads[0], [0; 32], [Val::ZERO; 4])[..14]
                .try_into()
                .unwrap(),
            open_prefix: commitment::prefix(source, [Val::ZERO; 4])[..83]
                .try_into()
                .unwrap(),
            mac_fields: core::array::from_fn(|row| match schedule::mac(row) {
                Mac::Block { page, block } => {
                    super::poly1305::message_limbs(source.mac_block(page, block), 128)
                        .map(Val::from_u64)
                }
                _ => [Val::ZERO; 5],
            }),
        }
    }
    fn row_sum<E: PrimeCharacteristicRing>(
        selectors: &[E; TRACE_HEIGHT],
        rows: impl Iterator<Item = usize>,
    ) -> E {
        rows.map(|r| selectors[r].clone()).sum()
    }
    pub fn columns(&self) -> Columns {
        if self.source.relation.packed() {
            Columns::new(true)
        } else {
            Columns {
                packed: false,
                buffers: BUFFERS,
                banks: BANKS,
                master: MASTER,
                subkey: SUBKEY,
                polykey: POLYKEY,
                polykey_bits: POLY,
                poly: POLY,
                poseidon: POSEIDON,
                checkpoint: CHECKPOINT,
                carry: CARRY,
                salts: SALTS,
                width: WIDTH,
            }
        }
    }
    pub fn schedule(&self) -> schedule::Schedule {
        schedule::Schedule::new(self.source.relation.packed())
    }
    fn key_word<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        base: usize,
        word: usize,
    ) -> E {
        if self.columns().packed {
            row[base + word].into()
        } else {
            pack_bits_le(
                row[base + word * 32..base + (word + 1) * 32]
                    .iter()
                    .copied(),
            )
        }
    }
    /// Packed source bits are read only at CURRENT81, while lane4 contains
    /// the genuinely constrained counter1 output. Retained-bit profiles use
    /// their ordinary buffer path at CURRENT80.
    pub fn age_source_bit<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        byte: usize,
        bit: usize,
    ) -> E {
        if self.columns().packed {
            self.output_plain_bit(
                row,
                4,
                byte / 4,
                byte % 4 * 8 + bit,
                self.source.ciphertext(0)[byte],
            )
        } else {
            self.plain_bit(row, byte, bit)
        }
    }
    fn output_plain_bit<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        lane: usize,
        word: usize,
        bit: usize,
        cipher_byte: u8,
    ) -> E {
        let cipher = E::from_u8((cipher_byte >> (bit % 8)) & 1);
        let stream: E = row[lane * ca::WIDTH + word * 32 + bit].into();
        cipher.clone() + stream.clone() - cipher * stream * E::TWO
    }
    fn output_plain_word<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        lane: usize,
        job: Job,
        word: usize,
    ) -> E {
        let Job::Cha { page, counter } = job else {
            return E::ZERO;
        };
        if counter == 0 {
            return E::ZERO;
        }
        let byte = (counter as usize - 1) * 64 + word * 4;
        let cipher = self.source.ciphertext(page);
        if byte >= cipher.len() {
            return E::ZERO;
        }
        (0..32)
            .map(|bit| {
                self.output_plain_bit::<E, _>(row, lane, word, bit, cipher[byte + bit / 8])
                    * E::from_u64(1 << bit)
            })
            .sum()
    }
    fn packed_lane<AB: AirBuilder<F = Val>>(
        &self,
        b: &mut AB,
        (row, next): (&[AB::Var], &[AB::Var]),
        (local, updated): (&[AB::Var], &[AB::Expr]),
        lane: usize,
        selectors: &[AB::Expr; TRACE_HEIGHT],
    ) {
        let c = self.columns();
        let s = self.schedule();
        let feed: AB::Expr = (0..6).map(|g| selectors[g * 82 + 80].clone()).sum();
        let reset: AB::Expr = (0..5).map(|g| selectors[s.boundary(g)].clone()).sum();
        let next_capture = feed.clone();
        for bit in 0..512 {
            b.when_transition().assert_zero(
                (AB::Expr::ONE - feed.clone() - reset.clone())
                    * (next[lane * ca::WIDTH + bit] - updated[bit].clone()),
            );
        }
        for word in 0..16 {
            let buf = c.buffers + lane * 16 + word;
            b.when_first_row().assert_zero(row[buf]);
            b.when_transition()
                .assert_zero((AB::Expr::ONE - next_capture.clone()) * (next[buf] - row[buf]));
        }
        let mut normal_feed = AB::Expr::ZERO;
        for group in 0..6 {
            let job = schedule::job(7 * group + lane);
            let selected = selectors[group * 82 + 80].clone();
            let capture = selectors[s.boundary(group)].clone();
            let input = self.input::<AB::Expr, _>(row, job);
            for word in 0..16 {
                let output: AB::Expr = pack_bits_le(
                    next[lane * ca::WIDTH + word * 32..lane * ca::WIDTH + (word + 1) * 32]
                        .iter()
                        .copied(),
                );
                match job {
                    Job::H(_) => {
                        let expected: AB::Expr = if word < 8 {
                            let original = chacha::HCHACHA_OUTPUT[word];
                            pack_bits_le(local[original * 32..(original + 1) * 32].iter().copied())
                        } else {
                            AB::Expr::ZERO
                        };
                        b.assert_zero(selected.clone() * (output - expected));
                    }
                    Job::Cha { .. } => {
                        let state: AB::Expr =
                            pack_bits_le(local[word * 32..(word + 1) * 32].iter().copied());
                        b.assert_zero(
                            selected.clone()
                                * (state + input[word].clone()
                                    - output
                                    - local[ca::FEEDFORWARD_CARRY + word] * Val::from_u64(1 << 32)),
                        );
                    }
                }
                b.assert_zero(
                    capture.clone()
                        * (row[c.buffers + lane * 16 + word]
                            - self.output_plain_word::<AB::Expr, _>(row, lane, job, word)),
                );
            }
            let key_base = match job {
                Job::H(page) => Some(c.subkey + page * 8),
                Job::Cha { page, counter: 0 } => Some(c.polykey + page * 8),
                Job::Cha { .. } => None,
            };
            if let Some(base) = key_base {
                for word in 0..8 {
                    let output: AB::Expr =
                        pack_bits_le(local[word * 32..(word + 1) * 32].iter().copied());
                    b.assert_zero(capture.clone() * (row[base + word] - output));
                }
            }
            if matches!(job, Job::Cha { .. }) {
                normal_feed += selected;
            }
            if group < 5 {
                let next_input =
                    self.input::<AB::Expr, _>(row, schedule::job(7 * (group + 1) + lane));
                for word in 0..16 {
                    let actual: AB::Expr = pack_bits_le(
                        next[lane * ca::WIDTH + word * 32..lane * ca::WIDTH + (word + 1) * 32]
                            .iter()
                            .copied(),
                    );
                    b.assert_zero(capture.clone() * (actual - next_input[word].clone()));
                }
            }
        }
        for carry in &local[ca::FEEDFORWARD_CARRY..] {
            b.assert_zero((AB::Expr::ONE - normal_feed.clone()) * *carry);
        }
    }
    pub fn input<E: Algebra<Val>, T: Copy + Into<E>>(&self, row: &[T], job: Job) -> [E; 16] {
        let cols = self.columns();
        let (page, h, counter) = match job {
            Job::H(page) => (page, true, 0),
            Job::Cha { page, counter } => (page, false, counter),
        };
        let nonce = self.source.nonce(page);
        core::array::from_fn(|word| match word {
            0..=3 => E::from_u32(chacha::CONSTANTS[word]),
            4..=11 => {
                let start = if h {
                    cols.master
                } else {
                    cols.subkey + page * cols.key_stride()
                };
                self.key_word(row, start, word - 4)
            }
            _ if h => E::from_u32(u32::from_le_bytes(
                nonce[(word - 12) * 4..(word - 11) * 4].try_into().unwrap(),
            )),
            12 => E::from_u32(counter),
            13 => E::ZERO,
            _ => E::from_u32(u32::from_le_bytes(
                nonce[16 + (word - 14) * 4..20 + (word - 14) * 4]
                    .try_into()
                    .unwrap(),
            )),
        })
    }
    pub fn plain_word<E: Algebra<Val>, T: Copy + Into<E>>(&self, row: &[T], word: usize) -> E {
        let cols = self.columns();
        if cols.packed {
            let (_, lane, slot) = schedule::plain_location(word);
            return row[cols.buffers + lane * 16 + slot].into();
        }
        (0..32).fold(E::ZERO, |sum, bit| {
            sum + self.plain_bit::<E, _>(row, word * 4 + bit / 8, bit % 8) * E::from_u64(1 << bit)
        })
    }
    pub fn plain_bit<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        byte: usize,
        bit: usize,
    ) -> E {
        let cols = self.columns();
        let word = byte / 4;
        let (_, lane, slot) = schedule::plain_location(word);
        let (page, index) = if byte < DATA_BYTES {
            (0, byte)
        } else {
            (1, byte - DATA_BYTES)
        };
        let c = E::from_u8((self.source.ciphertext(page)[index] >> bit) & 1);
        let s: E = row[cols.buffers + lane * 512 + slot * 32 + (byte % 4) * 8 + bit].into();
        c.clone() + s.clone() - c * s * E::TWO
    }
    pub fn stream_field<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        key: bool,
        index: usize,
        physical_row: usize,
    ) -> E {
        let cols = self.columns();
        if key {
            match index {
                0..=13 => self.key_prefix[index].into(),
                14..=21 => self.key_word(row, cols.master, index - 14),
                22..=25 => row[cols.salts + index - 22].into(),
                _ => E::ZERO,
            }
        } else if index < 87 {
            if index >= 83 {
                row[cols.salts + 4 + index - 83].into()
            } else {
                self.open_prefix[index].into()
            }
        } else if index < 674 {
            let word = index - 87;
            let (group, _, _) = schedule::plain_location(word);
            let overwritten_at = self.schedule().boundary(group + 1);
            if physical_row >= overwritten_at {
                let stale = [33, 34, 145, 146, 257, 258, 369, 370, 481, 482];
                let position = stale
                    .iter()
                    .position(|w| *w == word)
                    .expect("Fixed source schedule retains every stale word");
                return row[cols.carry + position % 2].into();
            }
            self.plain_word(row, word)
        } else {
            E::ZERO
        }
    }
}
impl BaseAir<Val> for OpeningAir {
    fn width(&self) -> usize {
        self.source.relation.width()
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..self.source.relation.width()).collect()
    }
    fn num_periodic_columns(&self) -> usize {
        if self.source.relation.factorized() {
            super::factorized::COLUMNS
        } else {
            TRACE_HEIGHT
        }
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(self.public_schedule.get_or_init(|| {
            if self.source.relation.factorized() {
                super::factorized::columns()
            } else {
                schedule::columns()
            }
        }))
    }
    // Upper bound only; actual selector-aware inference is a separate gate.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(5)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for OpeningAir {
    fn eval(&self, builder: &mut AB) {
        let cols = self.columns();
        let schedule = self.schedule();
        let public: [AB::PublicVar; PUBLIC_VALUES] = builder.public_values().try_into().unwrap();
        for (actual, expected) in public.into_iter().zip(self.values) {
            builder.assert_eq(actual, expected);
        }
        let selectors: [AB::Expr; TRACE_HEIGHT] = if self.source.relation.factorized() {
            super::factorized::selectors(builder.periodic_values())
        } else {
            core::array::from_fn(|r| builder.periodic_values()[r].into())
        };
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        if cols.packed {
            for cell in row[..cols.buffers]
                .iter()
                .chain(&row[cols.polykey_bits..cols.poly])
                .chain(&row[cols.poly..cols.poseidon])
            {
                builder.assert_bool(*cell);
            }
        } else {
            // Preserve the original profile's exact Boolean constraint order.
            for cell in &row[..cols.poseidon] {
                builder.assert_bool(*cell);
            }
        }
        for index in cols.banks..cols.polykey_bits {
            builder.when_transition().assert_eq(next[index], row[index]);
        }
        for index in cols.salts..cols.width {
            builder.when_transition().assert_eq(next[index], row[index]);
        }
        let qr: [AB::Expr; 8] = core::array::from_fn(|step| {
            Self::row_sum(
                &selectors,
                (0..6 * schedule.job_rows()).filter(|r| {
                    r % schedule.job_rows() < 80 && r % schedule.job_rows() % 8 == step
                }),
            )
        });
        let next_boundary = Self::row_sum(&selectors, (0..6).map(|g| schedule.boundary(g) - 1));
        for lane in 0..LANES {
            let offset = lane * ca::WIDTH;
            let local = &row[offset..offset + ca::WIDTH];
            let updated = chacha::updated_bits(builder, local, &qr);
            for group in 0..if cols.packed { 1 } else { 6 } {
                let job = schedule::job(7 * group + lane);
                let input = self.input::<AB::Expr, _>(row, job);
                for word in 0..16 {
                    let actual: AB::Expr =
                        pack_bits_le(local[word * 32..word * 32 + 32].iter().copied());
                    builder.assert_zero(
                        selectors[group * schedule.job_rows()].clone()
                            * (actual - input[word].clone()),
                    );
                }
            }
            if cols.packed {
                self.packed_lane(builder, (row, next), (local, &updated), lane, &selectors);
                continue;
            }
            for bit in 0..512 {
                let mut expected = updated[bit].clone();
                // Reset AFTER a completed job; do not gate the QR expression by
                // another selector. After the sixth job retain its final state.
                for group in 0..5 {
                    let word = bit / 32;
                    let position = bit % 32;
                    let job = schedule::job(7 * (group + 1) + lane);
                    let input_bit: AB::Expr = if (4..12).contains(&word) {
                        let start = match job {
                            Job::H(_) => cols.master,
                            Job::Cha { page, .. } => cols.subkey + page * cols.key_stride(),
                        };
                        row[start + (word - 4) * 32 + position].into()
                    } else {
                        let (page, h, counter) = match job {
                            Job::H(page) => (page, true, 0),
                            Job::Cha { page, counter } => (page, false, counter),
                        };
                        let nonce = self.source.nonce(page);
                        let value = match word {
                            0..=3 => chacha::CONSTANTS[word],
                            _ if h => u32::from_le_bytes(
                                nonce[(word - 12) * 4..(word - 11) * 4].try_into().unwrap(),
                            ),
                            12 => counter,
                            13 => 0,
                            _ => u32::from_le_bytes(
                                nonce[16 + (word - 14) * 4..20 + (word - 14) * 4]
                                    .try_into()
                                    .unwrap(),
                            ),
                        };
                        Val::from_u32((value >> position) & 1).into()
                    };
                    expected +=
                        selectors[schedule.boundary(group)].clone() * (input_bit - local[bit]);
                }
                builder
                    .when_transition()
                    .assert_eq(next[offset + bit], expected);
                let buf = cols.buffers + lane * 512 + bit;
                builder.when_first_row().assert_zero(row[buf]);
                builder
                    .when_transition()
                    .assert_zero((AB::Expr::ONE - next_boundary.clone()) * (next[buf] - row[buf]));
            }
            let mut normal_boundary = AB::Expr::ZERO;
            for group in 0..6 {
                let selected = selectors[schedule.boundary(group)].clone();
                let job = schedule::job(7 * group + lane);
                match job {
                    Job::H(page) => {
                        for word in 0..16 {
                            let output: AB::Expr = pack_bits_le(
                                row[cols.buffers + lane * 512 + word * 32
                                    ..cols.buffers + lane * 512 + (word + 1) * 32]
                                    .iter()
                                    .copied(),
                            );
                            let expected = if word < 8 {
                                pack_bits_le(
                                    local[chacha::HCHACHA_OUTPUT[word] * 32
                                        ..(chacha::HCHACHA_OUTPUT[word] + 1) * 32]
                                        .iter()
                                        .copied(),
                                )
                            } else {
                                AB::Expr::ZERO
                            };
                            builder.assert_zero(selected.clone() * (output - expected));
                        }
                        for bit in 0..256 {
                            builder.assert_zero(
                                selected.clone()
                                    * (row[cols.subkey + page * cols.key_stride() + bit]
                                        - row[cols.buffers + lane * 512 + bit]),
                            );
                        }
                    }
                    Job::Cha { page, counter } => {
                        normal_boundary += selected.clone();
                        let input = self.input::<AB::Expr, _>(row, job);
                        for word in 0..16 {
                            let state: AB::Expr =
                                pack_bits_le(local[word * 32..(word + 1) * 32].iter().copied());
                            let output: AB::Expr = pack_bits_le(
                                row[cols.buffers + lane * 512 + word * 32
                                    ..cols.buffers + lane * 512 + (word + 1) * 32]
                                    .iter()
                                    .copied(),
                            );
                            builder.assert_zero(
                                selected.clone()
                                    * (state + input[word].clone()
                                        - output
                                        - local[ca::FEEDFORWARD_CARRY + word]
                                            * Val::from_u64(1 << 32)),
                            );
                        }
                        if counter == 0 {
                            for bit in 0..256 {
                                builder.assert_zero(
                                    selected.clone()
                                        * (row[cols.polykey + page * cols.key_stride() + bit]
                                            - row[cols.buffers + lane * 512 + bit]),
                                );
                            }
                        }
                    }
                }
            }
            for carry in &local[ca::FEEDFORWARD_CARRY..] {
                builder.assert_zero((AB::Expr::ONE - normal_boundary.clone()) * *carry);
            }
        }
        // Complete embedded data-head equality, from actual counter1/2 XOR words.
        for word in 0..28 {
            builder.assert_zero(
                selectors[schedule.boundary(0)].clone()
                    * (self.plain_word::<AB::Expr, _>(row, 3 + word)
                        - self.values[statement::HEADS + word]),
            );
        }
        let cells = pa::Cells::packed(&row[cols.poly..cols.poseidon]);
        let active = Self::row_sum(
            &selectors,
            (0..165).filter(|r| matches!(schedule::mac(*r), Mac::Block { .. })),
        );
        let finalizing = selectors[9].clone() + selectors[164].clone();
        let page1 = Self::row_sum(&selectors, 10..165);
        let key = core::array::from_fn(|bit| {
            if cols.packed {
                row[cols.polykey_bits + bit].into()
            } else {
                row[cols.polykey + bit]
                    + page1.clone() * (row[cols.polykey + 256 + bit] - row[cols.polykey + bit])
            }
        });
        if cols.packed {
            for word in 0..8 {
                let actual: AB::Expr = pack_bits_le(
                    row[cols.polykey_bits + word * 32..cols.polykey_bits + (word + 1) * 32]
                        .iter()
                        .copied(),
                );
                let first: AB::Expr = row[cols.polykey + word].into();
                let second: AB::Expr = row[cols.polykey + 8 + word].into();
                builder.assert_eq(actual, first.clone() + page1.clone() * (second - first));
            }
        }
        let message: [AB::Expr; LIMBS] = core::array::from_fn(|limb| {
            (0..165)
                .filter(|r| matches!(schedule::mac(*r), Mac::Block { .. }))
                .map(|r| selectors[r].clone() * self.mac_fields[r][limb])
                .sum()
        });
        let tags: [AB::Expr; 4] = core::array::from_fn(|word| {
            selectors[9].clone() * Val::from_u32(self.source.tag(0)[word])
                + selectors[164].clone() * Val::from_u32(self.source.tag(1)[word])
        });
        pa::evaluate(
            builder,
            cells,
            pa::Step {
                updated: pa::limbs(&next[cols.poly..cols.poly + pa::STATE]),
                key,
                message,
                active: active.clone(),
                finalize: finalizing.clone(),
                inactive_tag: AB::Expr::ONE - finalizing.clone(),
                tag: tags,
            },
        );
        for bit in 0..pa::STATE {
            builder.when_first_row().assert_zero(row[cols.poly + bit]);
            builder.assert_zero(
                (selectors[10].clone() + Self::row_sum(&selectors, 165..512))
                    * row[cols.poly + bit],
            );
            builder.when_transition().assert_zero(
                (AB::Expr::ONE - active.clone() - finalizing.clone())
                    * (next[cols.poly + bit] - row[cols.poly + bit]),
            );
        }
        let p2row = &row[cols.poseidon..cols.checkpoint];
        let out = poseidon::evaluate(builder, p2row);
        let absorbs: Vec<_> = (0..512)
            .filter_map(|r| schedule.absorb(r).map(|(key, block)| (r, key, block)))
            .collect();
        let p2active: AB::Expr = absorbs.iter().map(|(r, _, _)| selectors[*r].clone()).sum();
        for (word, actual) in p2row.iter().take(8).enumerate() {
            let expected: AB::Expr = absorbs
                .iter()
                .map(|(r, key, block)| {
                    selectors[*r].clone()
                        * self.stream_field::<AB::Expr, _>(row, *key, *block * 8 + word, *r)
                })
                .sum();
            builder.assert_eq(*actual, expected);
        }
        for word in 8..12 {
            builder.assert_eq(
                p2row[word],
                (p2active.clone() - selectors[0].clone() - selectors[4].clone())
                    * row[cols.checkpoint + word],
            );
        }
        for word in 0..12 {
            builder
                .when_first_row()
                .assert_zero(row[cols.checkpoint + word]);
            builder.when_transition().assert_eq(
                next[cols.checkpoint + word],
                p2active.clone() * out[word].clone()
                    + (AB::Expr::ONE - p2active.clone()) * row[cols.checkpoint + word],
            );
        }
        for (word, actual) in out.iter().take(4).enumerate() {
            builder.assert_zero(
                selectors[3].clone()
                    * (actual.clone() - self.values[statement::KEY_COMMITMENT + word]),
            );
            builder.assert_zero(
                selectors[schedule.final_absorb()].clone()
                    * (actual.clone() - self.values[statement::OPEN_COMMITMENT + word]),
            );
        }
        let next_capture: AB::Expr = schedule
            .captures()
            .into_iter()
            .map(|r| selectors[r - 1].clone())
            .sum();
        for word in 0..2 {
            builder.when_first_row().assert_zero(row[cols.carry + word]);
            for (group, r) in schedule.captures().into_iter().enumerate() {
                let payload = [33, 145, 257, 369, 481][group] + word;
                builder.assert_zero(
                    selectors[r].clone()
                        * (row[cols.carry + word] - self.plain_word::<AB::Expr, _>(row, payload)),
                );
            }
            // CURRENT capture is defined above; skip predecessor copy by NEXT capture.
            builder.when_transition().assert_zero(
                (AB::Expr::ONE - next_capture.clone())
                    * (next[cols.carry + word] - row[cols.carry + word]),
            );
        }
        if self.source.relation.is_canonical() {
            super::canonical::evaluate(self, builder, row, next, &selectors);
        }
    }
}
