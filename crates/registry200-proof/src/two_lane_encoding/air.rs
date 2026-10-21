//! Full private main-trace onehot/reversed-mask relations over the existing hiding engine.
use super::{Role, SCALE, T, commitment, layout::*, statement::Statement};
use crate::{
    lifecycle::{opening, ranges::pack},
    source,
};
use bfv_hiding_stark::{Val, poseidon};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};
pub struct EncodingAir {
    values: Vec<Val>,
    role: Role,
    context: [Val; 8],
    command_prefix: Vec<Val>,
    source_prefix: Vec<Val>,
    periodic: OnceLock<Vec<Vec<Val>>>,
}
impl EncodingAir {
    pub fn new(s: &Statement) -> Self {
        let e = &s.expected;
        Self {
            values: s.values(),
            role: e.role(),
            context: e.encoding_context(),
            command_prefix: source::statement::words(&super::COMMAND_DOMAIN)
                .chain([Val::ONE])
                .chain(source::statement::words(&super::profile_digest(
                    Role::PrivateMask,
                )))
                .chain(e.base_context())
                .chain(source::statement::words(&e.sql_identity()))
                .collect(),
            source_prefix: source::commitment::prefix(e.source_claim(), [Val::ZERO; 4]),
            periodic: OnceLock::new(),
        }
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn opening_field<E: Algebra<Val>, V: Copy + Into<E>>(
        &self,
        row: &[V],
        f: usize,
        word: usize,
    ) -> E {
        match self.role {
            Role::SourceAllOriginal => {
                opening::source_field(&self.source_prefix, row, WORDS, SOURCE_SALT, f, word)
            }
            Role::PrivateMask => match f {
                0..=28 => E::from(self.command_prefix[f]),
                29..=36 => pack(row, MASK + 32 * (f - 29), 32),
                37..=40 => row[COMMAND_SALT + f - 37].into(),
                _ => E::ZERO,
            },
        }
    }
}
impl BaseAir<Val> for EncodingAir {
    fn width(&self) -> usize {
        self.role.width()
    }
    fn num_public_values(&self) -> usize {
        self.role.public_values()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..self.width()).collect()
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODICS
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(self.periodic.get_or_init(source::schedule::columns))
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(5)
    }
}
fn lane_geometry(r: usize, l: usize) -> Option<(usize, usize, usize)> {
    let n = 8 * r + l;
    let lane = n / 512;
    let age = n % 512;
    if lane < 8 && age < 256 {
        Some((lane / 2, lane % 2, age))
    } else {
        None
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for EncodingAir {
    fn eval(&self, b: &mut AB) {
        let public = b.public_values().to_vec();
        assert_eq!(public.len(), self.values.len());
        for (v, wanted) in public.iter().zip(&self.values) {
            b.assert_eq(*v, *wanted);
        }
        let selectors: [AB::Expr; 512] = core::array::from_fn(|r| b.periodic_values()[r].into());
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let w: [AB::Expr; 8] = match self.role {
            Role::SourceAllOriginal => {
                for c in DATA..EQUALITY {
                    b.when_transition().assert_eq(next[c], row[c]);
                }
                for c in (WORDS..TABLE).chain(WEIGHTS..EQUALITY) {
                    b.assert_bool(row[c]);
                }
                let active_source: AB::Expr = selectors[..85].iter().cloned().sum();
                for bit in 0..256 {
                    b.assert_zero((AB::Expr::ONE - active_source.clone()) * row[WORDS + bit]);
                }
                for (r, sel) in selectors[..85].iter().enumerate() {
                    for word in 0..8 {
                        if !(87..674).contains(&(8 * r + word)) {
                            for bit in 0..32 {
                                b.assert_zero(sel.clone() * row[WORDS + 32 * word + bit]);
                            }
                        }
                    }
                }
                for byte in 0..12 {
                    let f = 87 + byte / 4;
                    for bit in 0..8 {
                        b.assert_zero(
                            selectors[f / 8].clone()
                                * (row[DATA + 8 * byte + bit]
                                    - row[WORDS + 32 * (f % 8) + 8 * (byte % 4) + bit]),
                        );
                    }
                }
                for (bank, first, count) in [(TABLE, 31, 8), (IDS, 555, 32)] {
                    for word in 0..count {
                        let f = 87 + first + word;
                        b.assert_zero(
                            selectors[f / 8].clone()
                                * (row[bank + word]
                                    - pack::<AB::Expr, _>(row, WORDS + 32 * (f % 8), 32)),
                        );
                    }
                }
                for i in 0..4 {
                    for f in 0..2 {
                        let at = weight(i, f);
                        let original: AB::Expr = pack(
                            row,
                            DATA + 24 * i + if f == 0 { 0 } else { 8 },
                            if f == 0 { 8 } else { 16 },
                        );
                        let original = original
                            + if f == 0 {
                                Val::from_u16(256)
                            } else {
                                Val::ZERO
                            };
                        let v: AB::Expr = pack(row, at, 17);
                        b.assert_eq(
                            original * Val::from_u64(SCALE),
                            v.clone() + pack::<AB::Expr, _>(row, at + 34, 15) * Val::from_u64(T),
                        );
                        b.assert_eq(
                            v + pack::<AB::Expr, _>(row, at + 17, 17),
                            Val::from_u64(T - 1),
                        );
                    }
                }
                core::array::from_fn(|l| {
                    let at = EQUALITY + 11 * l;
                    for v in &row[at..at + 10] {
                        b.assert_bool(*v);
                    }
                    let active: AB::Expr = (0..512)
                        .filter(|&r| lane_geometry(r, l).is_some())
                        .map(|r| selectors[r].clone())
                        .sum();
                    for v in &row[at..at + 11] {
                        b.assert_zero((AB::Expr::ONE - active.clone()) * *v);
                    }
                    let mut age = AB::Expr::ZERO;
                    let mut threshold = AB::Expr::ZERO;
                    let mut scaled = AB::Expr::ZERO;
                    for (r, s) in selectors.iter().enumerate() {
                        if let Some((i, f, j)) = lane_geometry(r, l) {
                            age += s.clone() * pack::<AB::Expr, _>(row, DATA + 24 * i, 8);
                            threshold += s.clone() * Val::from_usize(j);
                            let value = pack(row, weight(i, f), 17);
                            scaled += s.clone() * value;
                        }
                    }
                    let difference: AB::Expr = pack(row, at, 8);
                    let zero: AB::Expr = row[at + 9].into();
                    b.assert_zero(
                        active.clone()
                            * (age + Val::from_u16(256)
                                - threshold
                                - difference.clone()
                                - row[at + 8] * Val::from_u16(256)),
                    );
                    b.assert_zero(active.clone() * difference.clone() * zero.clone());
                    b.assert_zero(
                        active.clone()
                            * (difference * row[at + 10] - (AB::Expr::ONE - zero.clone())),
                    );
                    b.assert_zero(active * zero.clone() * row[at + 10]);
                    zero * scaled
                })
            }
            Role::PrivateMask => {
                for c in MASK..QUERY_WIDTH {
                    b.when_transition().assert_eq(next[c], row[c]);
                }
                for v in &row[MASK..MASK + 256] {
                    b.assert_bool(*v);
                }
                core::array::from_fn(|l| {
                    (0..32)
                        .map(|r| {
                            selectors[r].clone()
                                * row[MASK + 255 - (8 * r + l)]
                                * Val::from_u64(SCALE)
                        })
                        .sum()
                })
            }
        };
        let salt = if self.role == Role::SourceAllOriginal {
            SOURCE_ENC_SALT
        } else {
            QUERY_ENC_SALT
        };
        commitment::evaluate(
            b,
            row,
            next,
            selectors[0].clone(),
            selectors[511].clone(),
            &w,
            commitment::VectorBinding {
                context: self.context,
                salt,
                root: self.values[ENCODED..ENCODED + 4].try_into().unwrap(),
            },
        );
        let blocks = if self.role == Role::SourceAllOriginal {
            85
        } else {
            6
        };
        let active: AB::Expr = selectors[..blocks].iter().cloned().sum();
        let out = poseidon::evaluate(&mut b.when(active.clone()), &row[2 * P2..3 * P2]);
        for v in &row[2 * P2..3 * P2] {
            b.assert_zero((AB::Expr::ONE - active.clone()) * *v);
        }
        for word in 0..8 {
            let expected: AB::Expr = (0..blocks)
                .map(|r| {
                    selectors[r].clone()
                        * self.opening_field::<AB::Expr, _>(row, 8 * r + word, word)
                })
                .sum();
            b.assert_eq(row[2 * P2 + word], expected);
        }
        for word in 8..12 {
            b.assert_eq(
                row[2 * P2 + word],
                (active.clone() - selectors[0].clone()) * row[OPEN_CP + word],
            );
        }
        for (i, v) in out.iter().enumerate() {
            b.when_first_row().assert_zero(row[OPEN_CP + i]);
            b.when_transition().assert_eq(
                next[OPEN_CP + i],
                active.clone() * v.clone() + (AB::Expr::ONE - active.clone()) * row[OPEN_CP + i],
            );
        }
        let target = if self.role == Role::SourceAllOriginal {
            SOURCE_PV + source::statement::OPEN_COMMITMENT
        } else {
            COMMAND
        };
        for (i, v) in out.iter().take(4).enumerate() {
            b.assert_zero(selectors[blocks - 1].clone() * (v.clone() - self.values[target + i]));
        }
    }
}
