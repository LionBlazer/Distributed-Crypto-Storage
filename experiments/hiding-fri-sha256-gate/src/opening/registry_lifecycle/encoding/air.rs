//! Source680 + successful Result144 to compact originals and the full SIMD encoding.
use super::statement::Statement;
use crate::backend::{TRACE_HEIGHT, Val};
use crate::opening::{
    commitment, poseidon,
    selection::encoding::{air as old, kernel, matrix},
    statement as source,
};
use crate::primitive::PublicStatement;
pub(super) use old::{
    BANK, CARRY, COEFF, ENC_SALT, ENCODED_CP, P2, SEL_SALT, SOURCE_CP, TUPLE_BITS, lane, tuple,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};
pub(super) const SOURCE_SALT: usize = old::WIDTH;
pub(super) const DATA: usize = SOURCE_SALT + 4;
pub(super) const SCRATCH: usize = DATA + 96;
pub(super) const FLAGS: usize = SCRATCH + 256;
pub(super) const ID: usize = FLAGS + 12;
pub(super) const ROUTE: usize = ID + 64;
pub(crate) const WIDTH: usize = ROUTE + 16;
pub(super) const BLOCKS: usize = 103;
pub(super) const PERIODICS: usize = 297;
const _: () = assert!(WIDTH == 4028);
fn word<E: Algebra<Val>, T: Copy + Into<E>>(row: &[T], start: usize, n: usize) -> E {
    pack_bits_le(row[start..start + n].iter().copied())
}
pub(crate) struct EncodingAir {
    statement: Statement,
    values: Vec<Val>,
    context: [Val; 8],
    source_prefix: Vec<Val>,
    result_prefix: Vec<Val>,
    periodic: OnceLock<Vec<Vec<Val>>>,
}
impl EncodingAir {
    pub(super) fn new(s: &Statement) -> Self {
        let e = &s.expected.parent;
        let parent = &s.expected.producer;
        let mut prefix = source::words(&super::super::statement::RESULT_DOMAIN)
            .chain([Val::from_u8(2)])
            .chain(e.context())
            .collect::<Vec<_>>();
        let super::super::statement::Phase::Transition { old, command } = e.phase else {
            unreachable!()
        };
        prefix.extend(old);
        prefix.extend(command);
        prefix.extend(parent.next);
        prefix.extend([Val::ONE, Val::ZERO]); // Acquire + SUCCESS, not caller flags.
        assert_eq!(prefix.len(), 119);
        Self {
            statement: s.clone(),
            context: s.context(),
            values: s.public_values(),
            source_prefix: commitment::prefix(&e.source, [Val::ZERO; 4])[..83].to_vec(),
            result_prefix: prefix,
            periodic: OnceLock::new(),
        }
    }
    pub(super) fn context(&self) -> [Val; 8] {
        self.context
    }
    pub(super) fn opening_field<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        block: usize,
        part: usize,
    ) -> E {
        if block < 85 {
            let f = block * 8 + part;
            match f {
                0..83 => E::from(self.source_prefix[f]),
                83..87 => row[SOURCE_SALT + f - 83].into(),
                87..674 => word(row, SCRATCH + part * 32, 32),
                _ => E::ZERO,
            }
        } else {
            let f = (block - 85) * 8 + part;
            match f {
                0..119 => E::from(self.result_prefix[f]),
                119..121 => word(row, ID + 32 * (f - 119), 32),
                121..133 => row[FLAGS + f - 121].into(),
                133..137 => row[SEL_SALT + f - 133].into(),
                _ => E::ZERO,
            }
        }
    }
}
impl BaseAir<Val> for EncodingAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        super::statement::PUBLIC_VALUES
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..WIDTH).collect()
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODICS
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(5)
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(self.periodic.get_or_init(|| {
            let mut out = vec![vec![Val::ZERO; TRACE_HEIGHT]; PERIODICS];
            for (column, values) in out[..192].iter_mut().enumerate() {
                let (lane, input) = (column / 12, column % 12);
                for (r, v) in values.iter_mut().enumerate() {
                    *v = Val::from_u32(matrix::coefficients()[r * 16 + lane][input]);
                }
            }
            for (k, col) in out[192..296].iter_mut().enumerate() {
                col[k] = Val::ONE;
            }
            out[296][511] = Val::ONE;
            out
        }))
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for EncodingAir {
    fn eval(&self, b: &mut AB) {
        let public = b.public_values().to_vec();
        assert_eq!(public.len(), self.values.len());
        for (a, e) in public.into_iter().zip(&self.values) {
            b.assert_eq(a, *e);
        }
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        for range in [BANK..COEFF, SOURCE_SALT..SCRATCH, FLAGS..WIDTH] {
            for col in range {
                b.when_transition().assert_eq(next[col], row[col]);
            }
        }
        for &v in row[BANK..SEL_SALT]
            .iter()
            .chain(&row[DATA..SCRATCH])
            .chain(&row[SCRATCH..FLAGS])
            .chain(&row[FLAGS..WIDTH])
        {
            b.assert_bool(v);
        }
        kernel::assert_bits(b, row);
        for slot in 0..4 {
            let present: AB::Expr = tuple(row, slot, 0);
            for part in 0..12 {
                let value: AB::Expr = tuple(row, slot, part);
                b.assert_zero((AB::Expr::ONE - present.clone()) * value);
            }
            if slot < 3 {
                let q: AB::Expr = tuple(row, slot + 1, 0);
                b.assert_zero(q * (AB::Expr::ONE - present.clone()));
            }
            let sum: AB::Expr = (0..4).map(|i| row[ROUTE + slot * 4 + i].into()).sum();
            b.assert_eq(sum, present);
            let ordinal: AB::Expr = (0..4)
                .map(|i| {
                    let m: AB::Expr = row[ROUTE + slot * 4 + i].into();
                    m * Val::from_usize(i)
                })
                .sum();
            b.assert_eq(tuple::<AB::Expr, _>(row, slot, 1), ordinal);
            for (part, offset, len) in [(2, 0, 8), (3, 8, 16)] {
                let value: AB::Expr = (0..4)
                    .map(|i| {
                        let m: AB::Expr = row[ROUTE + slot * 4 + i].into();
                        m * word::<AB::Expr, _>(row, DATA + 24 * i + offset, len)
                    })
                    .sum();
                b.assert_eq(tuple::<AB::Expr, _>(row, slot, part), value);
            }
            for i in 0..4 {
                let prefix: AB::Expr = (0..i).map(|j| row[FLAGS + j].into()).sum();
                let m: AB::Expr = row[ROUTE + slot * 4 + i].into();
                b.assert_zero(m * (prefix - Val::from_usize(slot)));
            }
        }
        for i in 0..4 {
            let sum: AB::Expr = (0..4).map(|slot| row[ROUTE + slot * 4 + i].into()).sum();
            b.assert_eq(sum, row[FLAGS + i]);
        }
        let periodic = b.periodic_values().to_vec();
        kernel::evaluate(b, row, &periodic);
        // Each temporary source word is a canonical u32 and all unused scratch is zero.
        for part in 0..8 {
            let active: AB::Expr = (0..85)
                .filter(|block| (87..674).contains(&(block * 8 + part)))
                .map(|block| periodic[193 + block].into())
                .sum();
            for &v in &row[SCRATCH + part * 32..SCRATCH + (part + 1) * 32] {
                b.assert_zero((AB::Expr::ONE - active.clone()) * v);
            }
        }
        for bit in 0..96 {
            let f = 87 + bit / 32;
            let selector: AB::Expr = periodic[193 + f / 8].into();
            b.assert_zero(
                selector
                    * (AB::Expr::from(row[DATA + bit]) - row[SCRATCH + (f % 8) * 32 + bit % 32]),
            );
        }
        for i in 0..4 {
            for j in 0..8 {
                let f = 642 + i * 8 + j;
                let selector: AB::Expr = periodic[193 + f / 8].into();
                let value: AB::Expr = word(row, SCRATCH + (f % 8) * 32, 32);
                for slot in 0..4 {
                    let m: AB::Expr = row[ROUTE + slot * 4 + i].into();
                    b.assert_zero(
                        selector.clone()
                            * m
                            * (tuple::<AB::Expr, _>(row, slot, 4 + j) - value.clone()),
                    );
                }
            }
        }
        let first: AB::Expr = periodic[192].into();
        let last: AB::Expr = periodic[296].into();
        let src: AB::Expr = periodic[193..296].iter().map(|x| (*x).into()).sum();
        let third = first.clone() + last.clone() + src.clone();
        let a = poseidon::evaluate(b, &row[..P2]);
        let middle = poseidon::evaluate(b, &row[P2..2 * P2]);
        let c = poseidon::evaluate(&mut b.when(third.clone()), &row[2 * P2..3 * P2]);
        for &v in &row[2 * P2..3 * P2] {
            b.assert_zero((AB::Expr::ONE - third.clone()) * v);
        }
        for i in 0..8 {
            let carry: AB::Expr = row[CARRY + i].into();
            b.assert_eq(
                row[i],
                first.clone() * self.context()[i] + (AB::Expr::ONE - first.clone()) * carry,
            );
            let prefix: AB::Expr = if i < 4 {
                row[ENC_SALT + i].into()
            } else {
                AB::Expr::ZERO
            };
            b.assert_eq(
                row[P2 + i],
                first.clone() * prefix
                    + (AB::Expr::ONE - first.clone()) * lane::<AB::Expr, _>(row, i, 1),
            );
            let opened: AB::Expr = (0..BLOCKS)
                .map(|block| {
                    let selector: AB::Expr = periodic[193 + block].into();
                    selector * self.opening_field::<AB::Expr, _>(row, block, i)
                })
                .sum();
            b.assert_eq(
                row[2 * P2 + i],
                first.clone() * lane::<AB::Expr, _>(row, i, 1)
                    + last.clone() * lane::<AB::Expr, _>(row, 8 + i, 1)
                    + opened,
            );
            b.when_transition()
                .assert_eq(next[CARRY + i], lane::<AB::Expr, _>(row, 8 + i, 1));
            b.when_first_row().assert_zero(row[CARRY + i]);
        }
        for i in 8..12 {
            b.assert_eq(row[i], row[ENCODED_CP + i]);
            b.assert_eq(row[P2 + i], a[i].clone());
            b.assert_eq(
                row[2 * P2 + i],
                (first.clone() + last.clone()) * middle[i].clone()
                    + src.clone() * row[SOURCE_CP + i],
            );
        }
        let end_source: AB::Expr = periodic[277].into();
        for i in 0..12 {
            b.when_first_row().assert_zero(row[SOURCE_CP + i]);
            b.when_first_row().assert_zero(row[ENCODED_CP + i]);
            // Reset after the Source endpoint; Result starts with ZERO capacity on row86.
            b.when_transition().assert_eq(
                next[SOURCE_CP + i],
                (src.clone() - end_source.clone()) * c[i].clone()
                    + (AB::Expr::ONE - src.clone()) * row[SOURCE_CP + i],
            );
            b.when_transition().assert_eq(
                next[ENCODED_CP + i],
                first.clone() * c[i].clone() + (AB::Expr::ONE - first.clone()) * middle[i].clone(),
            );
        }
        let end_result: AB::Expr = periodic[295].into();
        for (i, v) in c[..4].iter().enumerate() {
            b.assert_zero(
                end_source.clone()
                    * (v.clone() - self.statement.expected.parent.source.open_commitment[i]),
            );
            b.assert_zero(
                end_result.clone() * (v.clone() - self.statement.expected.producer.result[i]),
            );
            b.assert_zero(last.clone() * (v.clone() - self.statement.encoded[i]));
        }
    }
}
