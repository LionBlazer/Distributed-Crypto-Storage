use super::{
    DATA_BYTES, commitment, poseidon,
    schedule::{self, Job, Mac},
    statement::{self, PUBLIC_VALUES, Statement},
};
use crate::backend::{TRACE_HEIGHT, Val};
use crate::chacha::{self, air as ca};
use crate::poly1305::{LIMBS, arithmetic as pa};
use crate::primitive::PublicStatement;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::borrow::Cow;
pub(crate) const LANES: usize = 7;
pub(crate) const BUFFERS: usize = LANES * ca::WIDTH;
pub(crate) const BANKS: usize = BUFFERS + LANES * 512;
pub(crate) const MASTER: usize = BANKS;
pub(crate) const SUBKEY: usize = MASTER + 256;
pub(crate) const POLYKEY: usize = SUBKEY + 512;
pub(crate) const POLY: usize = POLYKEY + 512;
pub(crate) const POSEIDON: usize = POLY + pa::WIDTH;
pub(crate) const CHECKPOINT: usize = POSEIDON + poseidon::WIDTH;
pub(crate) const CARRY: usize = CHECKPOINT + 12;
pub(crate) const SALTS: usize = CARRY + 2;
pub(crate) const WIDTH: usize = SALTS + 8;
const _: () = assert!(WIDTH == 11079);

pub(crate) struct OpeningAir {
    pub(super) source: Statement,
    values: [Val; PUBLIC_VALUES],
    key_prefix: [Val; 14],
    open_prefix: [Val; 83],
    mac_fields: [[Val; 5]; 165],
}
impl OpeningAir {
    pub(crate) fn new(source: &Statement) -> Self {
        Self {
            source: source.clone(),
            values: source.public_values().try_into().unwrap(),
            key_prefix: commitment::key_fields(&source.heads[0], [0; 32], [Val::ZERO; 4])[..14]
                .try_into()
                .unwrap(),
            open_prefix: commitment::prefix(source, [Val::ZERO; 4])[..83]
                .try_into()
                .unwrap(),
            mac_fields: core::array::from_fn(|row| match schedule::mac(row) {
                Mac::Block { page, block } => {
                    crate::poly1305::air::message_limbs(source.mac_block(page, block), 128)
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
    pub(super) fn input<E: Algebra<Val>, T: Copy + Into<E>>(&self, row: &[T], job: Job) -> [E; 16] {
        let (page, h, counter) = match job {
            Job::H(page) => (page, true, 0),
            Job::Cha { page, counter } => (page, false, counter),
        };
        let nonce = self.source.nonce(page);
        core::array::from_fn(|word| match word {
            0..=3 => E::from_u32(chacha::CONSTANTS[word]),
            4..=11 => {
                let start = if h { MASTER } else { SUBKEY + page * 256 };
                pack_bits_le(
                    row[start + (word - 4) * 32..start + (word - 3) * 32]
                        .iter()
                        .copied(),
                )
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
    pub(super) fn plain_word<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        word: usize,
    ) -> E {
        (0..32).fold(E::ZERO, |sum, bit| {
            sum + self.plain_bit::<E, _>(row, word * 4 + bit / 8, bit % 8) * E::from_u64(1 << bit)
        })
    }
    pub(super) fn plain_bit<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        byte: usize,
        bit: usize,
    ) -> E {
        let word = byte / 4;
        let (_, lane, slot) = schedule::plain_location(word);
        let (page, index) = if byte < DATA_BYTES {
            (0, byte)
        } else {
            (1, byte - DATA_BYTES)
        };
        let c = E::from_u8((self.source.ciphertext(page)[index] >> bit) & 1);
        let s: E = row[BUFFERS + lane * 512 + slot * 32 + (byte % 4) * 8 + bit].into();
        c.clone() + s.clone() - c * s * E::TWO
    }
    pub(super) fn stream_field<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        key: bool,
        index: usize,
        physical_row: usize,
    ) -> E {
        if key {
            match index {
                0..=13 => self.key_prefix[index].into(),
                14..=21 => pack_bits_le(
                    row[MASTER + (index - 14) * 32..MASTER + (index - 13) * 32]
                        .iter()
                        .copied(),
                ),
                22..=25 => row[SALTS + index - 22].into(),
                _ => E::ZERO,
            }
        } else if index < 87 {
            if index >= 83 {
                row[SALTS + 4 + index - 83].into()
            } else {
                self.open_prefix[index].into()
            }
        } else if index < 674 {
            let word = index - 87;
            let (group, _, _) = schedule::plain_location(word);
            let overwritten_at = group * 81 + 161;
            if physical_row >= overwritten_at {
                let stale = [33, 34, 145, 146, 257, 258, 369, 370, 481, 482];
                let position = stale
                    .iter()
                    .position(|w| *w == word)
                    .expect("Fixed source schedule retains every stale word");
                return row[CARRY + position % 2].into();
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
        TRACE_HEIGHT
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Owned(schedule::columns())
    }
    // Upper bound only; actual selector-aware inference is a separate gate.
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(5)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for OpeningAir {
    fn eval(&self, builder: &mut AB) {
        let public: [AB::PublicVar; PUBLIC_VALUES] = builder.public_values().try_into().unwrap();
        for (actual, expected) in public.into_iter().zip(self.values) {
            builder.assert_eq(actual, expected);
        }
        let selectors: [AB::Expr; TRACE_HEIGHT] =
            core::array::from_fn(|r| builder.periodic_values()[r].into());
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        for cell in &row[..POSEIDON] {
            builder.assert_bool(*cell);
        }
        for index in BANKS..POLY {
            builder.when_transition().assert_eq(next[index], row[index]);
        }
        for index in SALTS..WIDTH {
            builder.when_transition().assert_eq(next[index], row[index]);
        }
        let qr: [AB::Expr; 8] = core::array::from_fn(|step| {
            Self::row_sum(
                &selectors,
                (0..486).filter(|r| r % 81 < 80 && r % 81 % 8 == step),
            )
        });
        let next_boundary = Self::row_sum(&selectors, (0..6).map(|g| schedule::boundary(g) - 1));
        for lane in 0..LANES {
            let offset = lane * ca::WIDTH;
            let local = &row[offset..offset + ca::WIDTH];
            let updated = chacha::arithmetic::updated_bits(builder, local, &qr);
            for group in 0..6 {
                let job = schedule::job(7 * group + lane);
                let input = self.input::<AB::Expr, _>(row, job);
                for word in 0..16 {
                    let actual: AB::Expr =
                        pack_bits_le(local[word * 32..word * 32 + 32].iter().copied());
                    builder.assert_zero(
                        selectors[group * 81].clone() * (actual - input[word].clone()),
                    );
                }
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
                            Job::H(_) => MASTER,
                            Job::Cha { page, .. } => SUBKEY + page * 256,
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
                        selectors[schedule::boundary(group)].clone() * (input_bit - local[bit]);
                }
                builder
                    .when_transition()
                    .assert_eq(next[offset + bit], expected);
                let buf = BUFFERS + lane * 512 + bit;
                builder.when_first_row().assert_zero(row[buf]);
                builder
                    .when_transition()
                    .assert_zero((AB::Expr::ONE - next_boundary.clone()) * (next[buf] - row[buf]));
            }
            let mut normal_boundary = AB::Expr::ZERO;
            for group in 0..6 {
                let selected = selectors[schedule::boundary(group)].clone();
                let job = schedule::job(7 * group + lane);
                match job {
                    Job::H(page) => {
                        for word in 0..16 {
                            let output: AB::Expr = pack_bits_le(
                                row[BUFFERS + lane * 512 + word * 32
                                    ..BUFFERS + lane * 512 + (word + 1) * 32]
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
                                    * (row[SUBKEY + page * 256 + bit]
                                        - row[BUFFERS + lane * 512 + bit]),
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
                                row[BUFFERS + lane * 512 + word * 32
                                    ..BUFFERS + lane * 512 + (word + 1) * 32]
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
                                        * (row[POLYKEY + page * 256 + bit]
                                            - row[BUFFERS + lane * 512 + bit]),
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
                selectors[80].clone()
                    * (self.plain_word::<AB::Expr, _>(row, 3 + word)
                        - self.values[statement::HEADS + word]),
            );
        }
        let cells = pa::Cells::packed(&row[POLY..POSEIDON]);
        let active = Self::row_sum(
            &selectors,
            (0..165).filter(|r| matches!(schedule::mac(*r), Mac::Block { .. })),
        );
        let finalizing = selectors[9].clone() + selectors[164].clone();
        let page1 = Self::row_sum(&selectors, 10..165);
        let key = core::array::from_fn(|bit| {
            row[POLYKEY + bit] + page1.clone() * (row[POLYKEY + 256 + bit] - row[POLYKEY + bit])
        });
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
                updated: pa::limbs(&next[POLY..POLY + pa::STATE]),
                key,
                message,
                active: active.clone(),
                finalize: finalizing.clone(),
                inactive_tag: AB::Expr::ONE - finalizing.clone(),
                tag: tags,
            },
        );
        for bit in 0..pa::STATE {
            builder.when_first_row().assert_zero(row[POLY + bit]);
            builder.assert_zero(
                (selectors[10].clone() + Self::row_sum(&selectors, 165..512)) * row[POLY + bit],
            );
            builder.when_transition().assert_zero(
                (AB::Expr::ONE - active.clone() - finalizing.clone())
                    * (next[POLY + bit] - row[POLY + bit]),
            );
        }
        let p2row = &row[POSEIDON..CHECKPOINT];
        let out = poseidon::evaluate(builder, p2row);
        let absorbs: Vec<_> = (0..512)
            .filter_map(|r| schedule::absorb(r).map(|(key, block)| (r, key, block)))
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
                    * row[CHECKPOINT + word],
            );
        }
        for word in 0..12 {
            builder.when_first_row().assert_zero(row[CHECKPOINT + word]);
            builder.when_transition().assert_eq(
                next[CHECKPOINT + word],
                p2active.clone() * out[word].clone()
                    + (AB::Expr::ONE - p2active.clone()) * row[CHECKPOINT + word],
            );
        }
        for (word, actual) in out.iter().take(4).enumerate() {
            builder.assert_zero(
                selectors[3].clone()
                    * (actual.clone() - self.values[statement::KEY_COMMITMENT + word]),
            );
            builder.assert_zero(
                selectors[499].clone()
                    * (actual.clone() - self.values[statement::OPEN_COMMITMENT + word]),
            );
        }
        let next_capture: AB::Expr = schedule::CAPTURES
            .into_iter()
            .map(|r| selectors[r - 1].clone())
            .sum();
        for word in 0..2 {
            builder.when_first_row().assert_zero(row[CARRY + word]);
            for (group, r) in schedule::CAPTURES.into_iter().enumerate() {
                let payload = [33, 145, 257, 369, 481][group] + word;
                builder.assert_zero(
                    selectors[r].clone()
                        * (row[CARRY + word] - self.plain_word::<AB::Expr, _>(row, payload)),
                );
            }
            // CURRENT capture is defined above; skip predecessor copy by NEXT capture.
            builder.when_transition().assert_zero(
                (AB::Expr::ONE - next_capture.clone()) * (next[CARRY + word] - row[CARRY + word]),
            );
        }
        if self.source.relation == super::Relation::CanonicalIndex {
            super::canonical::evaluate(self, builder, row, next, &selectors);
        }
    }
}
