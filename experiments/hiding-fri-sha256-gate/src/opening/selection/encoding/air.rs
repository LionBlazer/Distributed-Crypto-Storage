//! Shared complete coefficient kernel with two sealed, typed source openings.
use super::{matrix, statement::Statement};
use crate::backend::{TRACE_HEIGHT, Val};
use crate::opening::{
    poseidon,
    selection::{SELECT_DOMAIN, VERSION},
};
use crate::primitive::PublicStatement;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::{Algebra, PrimeCharacteristicRing};
use std::{borrow::Cow, sync::OnceLock};

pub(in crate::opening) const P2: usize = poseidon::WIDTH;
pub(in crate::opening) const BANK: usize = 3 * P2;
pub(in crate::opening) const TUPLE_BITS: usize = 283;
pub(in crate::opening) const SEL_SALT: usize = BANK + 4 * TUPLE_BITS;
pub(in crate::opening) const ENC_SALT: usize = SEL_SALT + 4;
pub(in crate::opening) const COEFF: usize = ENC_SALT + 4;
pub(in crate::opening) const LANE_BITS: usize = 104;
pub(in crate::opening) const CARRY: usize = COEFF + 16 * LANE_BITS;
pub(in crate::opening) const SOURCE_CP: usize = CARRY + 8;
pub(in crate::opening) const ENCODED_CP: usize = SOURCE_CP + 12;
pub(crate) const WIDTH: usize = ENCODED_CP + 12;
pub(in crate::opening) const PERIODICS: usize = 205;
const _: () = assert!(WIDTH == 3580);

pub(in crate::opening) fn tuple<E: Algebra<Val>, T: Copy + Into<E>>(
    row: &[T],
    slot: usize,
    part: usize,
) -> E {
    let at = BANK + slot * TUPLE_BITS;
    let (start, bits) = match part {
        0 => (0, 1),
        1 => (1, 2),
        2 => (3, 8),
        3 => (11, 16),
        4..=11 => (27 + (part - 4) * 32, 32),
        _ => unreachable!(),
    };
    pack_bits_le(row[at + start..at + start + bits].iter().copied())
}
pub(in crate::opening) fn lane<E: Algebra<Val>, T: Copy + Into<E>>(
    row: &[T],
    number: usize,
    field: usize,
) -> E {
    let (start, bits) = [(0, 17), (17, 17), (34, 19), (53, 17), (70, 17), (87, 17)][field];
    let at = COEFF + number * LANE_BITS + start;
    pack_bits_le(row[at..at + bits].iter().copied())
}
pub(in crate::opening) fn original<E: Algebra<Val>, T: Copy + Into<E>>(
    row: &[T],
    slot: usize,
) -> E {
    tuple(row, slot % 4, [2, 3, 0][slot / 4])
}

enum SourceOpening {
    Selected(Box<Statement>),
    Returned(Box<crate::opening::locking::encoding::statement::Statement>),
}

pub(crate) struct EncodingAir {
    source: SourceOpening,
    values: Vec<Val>,
    context: [Val; 8],
    selected_prefix: Vec<Val>,
    periodic: OnceLock<Vec<Vec<Val>>>,
}
impl EncodingAir {
    pub(super) fn new(statement: &Statement) -> Self {
        let pv = statement.selection.public_values();
        let prefix: Vec<_> = crate::opening::statement::words(&SELECT_DOMAIN)
            .chain([Val::from_u32(VERSION)])
            .chain(pv[..16].iter().copied())
            .chain(pv[76..84].iter().copied())
            .chain([Val::from_u8(4)])
            .collect();
        Self {
            source: SourceOpening::Selected(Box::new(statement.clone())),
            values: statement.public_values(),
            context: statement.context(),
            selected_prefix: prefix,
            periodic: OnceLock::new(),
        }
    }
    /// Only the exact typed producer can define this 168-field source opening.
    pub(in crate::opening) fn returned(
        statement: &crate::opening::locking::encoding::statement::Statement,
    ) -> Self {
        let lock = statement.expected.lock();
        let prefix: Vec<_> = crate::opening::statement::words(lock.expected.output_domain(false))
            .chain([Val::ONE])
            .chain(lock.context())
            .chain(lock.expected.old)
            .chain(lock.expected.plan)
            .chain(lock.next)
            .chain([Val::from_u8(4), Val::ZERO]) // Success ONLY, not an untrusted outcome flag.
            .collect();
        assert_eq!(prefix.len(), 115);
        Self {
            source: SourceOpening::Returned(Box::new(statement.clone())),
            values: statement.public_values(),
            context: statement.context(),
            selected_prefix: prefix,
            periodic: OnceLock::new(),
        }
    }
    pub(in crate::opening) fn source_blocks(&self) -> usize {
        match &self.source {
            SourceOpening::Selected(_) => 11,
            SourceOpening::Returned(_) => 21,
        }
    }
    fn source_root(&self) -> [Val; 4] {
        match &self.source {
            SourceOpening::Selected(s) => s.selection.selected,
            SourceOpening::Returned(s) => s.expected.lock().returned,
        }
    }
    fn encoded_root(&self) -> [Val; 4] {
        match &self.source {
            SourceOpening::Selected(s) => s.encoded,
            SourceOpening::Returned(s) => s.encoded,
        }
    }
    pub(super) fn context(&self) -> [Val; 8] {
        self.context
    }
    pub(super) fn selected_field<E: Algebra<Val>, T: Copy + Into<E>>(
        &self,
        row: &[T],
        field: usize,
    ) -> E {
        let prefix = self.selected_prefix.len();
        if field < prefix {
            E::from(self.selected_prefix[field])
        } else if field < prefix + 4 {
            row[SEL_SALT + field - prefix].into()
        } else if field < prefix + 4 + 48 {
            let part = field - prefix - 4;
            tuple(row, part / 12, part % 12)
        } else {
            E::ZERO
        }
    }
}
impl BaseAir<Val> for EncodingAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        match &self.source {
            SourceOpening::Selected(_) => super::statement::PUBLIC_VALUES,
            SourceOpening::Returned(_) => {
                crate::opening::locking::encoding::statement::PUBLIC_VALUES
            }
        }
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..WIDTH).collect()
    }
    fn num_periodic_columns(&self) -> usize {
        match &self.source {
            SourceOpening::Selected(_) => PERIODICS,
            SourceOpening::Returned(_) => PERIODICS + 10,
        }
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(5)
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(self.periodic.get_or_init(|| {
            let blocks = self.source_blocks();
            let mut out = vec![vec![Val::ZERO; TRACE_HEIGHT]; 192 + blocks + 2];
            for (column, values) in out[..192].iter_mut().enumerate() {
                let (lane, input) = (column / 12, column % 12);
                for (row, value) in values.iter_mut().enumerate() {
                    *value = Val::from_u32(matrix::coefficients()[row * 16 + lane][input]);
                }
            }
            for (k, col) in out[192..193 + blocks].iter_mut().enumerate() {
                col[k] = Val::ONE;
            }
            out[193 + blocks][511] = Val::ONE;
            out
        }))
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for EncodingAir {
    fn eval(&self, b: &mut AB) {
        let public = b.public_values().to_vec();
        assert_eq!(public.len(), self.values.len());
        for (actual, expected) in public.into_iter().zip(self.values.iter().copied()) {
            b.assert_eq(actual, expected);
        }
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        for col in BANK..COEFF {
            b.when_transition().assert_eq(next[col], row[col]);
        }
        for &bit in &row[BANK..SEL_SALT] {
            b.assert_bool(bit);
        }
        super::kernel::assert_bits(b, row);
        for slot in 0..4 {
            let p: AB::Expr = tuple(row, slot, 0);
            for part in 0..12 {
                let v: AB::Expr = tuple(row, slot, part);
                b.assert_zero((AB::Expr::ONE - p.clone()) * v);
            }
            if slot < 3 {
                let q: AB::Expr = tuple(row, slot + 1, 0);
                b.assert_zero(q * (AB::Expr::ONE - p));
            }
        }
        let periodic = b.periodic_values().to_vec();
        super::kernel::evaluate(b, row, &periodic);
        let first: AB::Expr = periodic[192].into();
        let blocks = self.source_blocks();
        let last: AB::Expr = periodic[193 + blocks].into();
        let src: AB::Expr = periodic[193..193 + blocks]
            .iter()
            .map(|x| (*x).into())
            .sum();
        let third = first.clone() + last.clone() + src.clone();
        let a = poseidon::evaluate(b, &row[..P2]);
        let c_b = poseidon::evaluate(b, &row[P2..2 * P2]);
        let c = poseidon::evaluate(&mut b.when(third.clone()), &row[2 * P2..3 * P2]);
        for &value in &row[2 * P2..3 * P2] {
            b.assert_zero((AB::Expr::ONE - third.clone()) * value);
        }
        for i in 0..8 {
            let carry: AB::Expr = row[CARRY + i].into();
            b.assert_eq(
                row[i],
                first.clone() * self.context[i] + (AB::Expr::ONE - first.clone()) * carry,
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
            let selected: AB::Expr = (0..blocks)
                .map(|block| {
                    let selector: AB::Expr = periodic[193 + block].into();
                    selector * self.selected_field::<AB::Expr, _>(row, block * 8 + i)
                })
                .sum();
            b.assert_eq(
                row[2 * P2 + i],
                first.clone() * lane::<AB::Expr, _>(row, i, 1)
                    + last.clone() * lane::<AB::Expr, _>(row, 8 + i, 1)
                    + selected,
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
                (first.clone() + last.clone()) * c_b[i].clone() + src.clone() * row[SOURCE_CP + i],
            );
        }
        for i in 0..12 {
            b.when_first_row().assert_zero(row[SOURCE_CP + i]);
            b.when_first_row().assert_zero(row[ENCODED_CP + i]);
            b.when_transition().assert_eq(
                next[SOURCE_CP + i],
                src.clone() * c[i].clone() + (AB::Expr::ONE - src.clone()) * row[SOURCE_CP + i],
            );
            b.when_transition().assert_eq(
                next[ENCODED_CP + i],
                first.clone() * c[i].clone() + (AB::Expr::ONE - first.clone()) * c_b[i].clone(),
            );
        }
        let finish: AB::Expr = periodic[192 + blocks].into();
        for (i, value) in c[..4].iter().enumerate() {
            b.assert_zero(finish.clone() * (value.clone() - self.source_root()[i]));
            b.assert_zero(last.clone() * (value.clone() - self.encoded_root()[i]));
        }
    }
}
