//! Complete canonical N4 age index, inside the SAME authenticated byte opening.
//! No generic index validator, identity authority, history or SQL acceptance API.
use super::{
    air::{self, OpeningAir},
    layout::CanonicalColumns,
    schedule,
};
use crate::backend::{TRACE_HEIGHT, Val};
use p3_air::{AirBuilder, utils::pack_bits_le};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};

pub(super) const AGES: usize = air::WIDTH;
pub(super) const PERMUTATION: usize = AGES + 32;
pub(super) const SORT: usize = PERMUTATION + 16;
pub(super) const HEADER: usize = SORT + 3 * 10;
pub(super) const IDENTITY: usize = HEADER + 8 * 4 * 11;
pub(super) const TABLE_HALF: usize = IDENTITY + 11;
pub(crate) const WIDTH: usize = TABLE_HALF + 1;
const _: () = assert!(WIDTH == 11521 && WIDTH - air::WIDTH == 442);

#[derive(Clone, Copy)]
enum HeaderWord {
    Count(usize),
    Offset(usize),
}
fn header_slot(schedule: schedule::Schedule, row: usize, slot: usize) -> Option<HeaderWord> {
    let (key, block) = schedule.absorb(row)?;
    if key {
        return None;
    }
    // C_open prefix87 + three DATA words precede INDEX-relative words.
    match (block * 8 + slot).checked_sub(90)? {
        word @ 36..=291 => Some(HeaderWord::Count(word - 36)),
        word @ 292..=548 => Some(HeaderWord::Offset(word - 292)),
        _ => None,
    }
}
pub(super) fn columns(packed: bool) -> CanonicalColumns {
    if packed {
        CanonicalColumns::new(true)
    } else {
        CanonicalColumns {
            ages: AGES,
            permutation: PERMUTATION,
            sort: SORT,
            header: HEADER,
            identity: IDENTITY,
            table_half: TABLE_HALF,
            width: WIDTH,
        }
    }
}
fn age<E: PrimeCharacteristicRing, T: Copy + Into<E>>(
    row: &[T],
    i: usize,
    c: CanonicalColumns,
) -> E {
    pack_bits_le(row[c.ages + i * 8..c.ages + (i + 1) * 8].iter().copied())
}
fn popcount<AB: AirBuilder<F = Val>>(
    air: &OpeningAir,
    row: &[AB::Var],
    start: usize,
    bytes: usize,
) -> AB::Expr {
    (start..start + bytes)
        .flat_map(|byte| (0..8).map(move |bit| (byte, bit)))
        .map(|(byte, bit)| air.plain_bit::<AB::Expr, _>(row, 12 + byte, bit))
        .sum()
}

pub(super) fn evaluate<AB: AirBuilder<F = Val>>(
    air: &OpeningAir,
    b: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    selectors: &[AB::Expr; TRACE_HEIGHT],
) {
    let packed = air.columns().packed;
    let c = columns(packed);
    let schedule = air.schedule();
    let ages: [AB::Expr; 4] = core::array::from_fn(|i| age(row, i, c));
    for column in c.ages..c.sort {
        b.assert_bool(row[column]);
        // All-row private banks: no pre-capture zero ages/sorting trap.
        b.when_transition().assert_eq(next[column], row[column]);
    }
    for i in 0..4 {
        for bit in 0..8 {
            b.assert_zero(
                selectors[schedule.boundary(0)].clone()
                    * (row[c.ages + 8 * i + bit]
                        - air.age_source_bit::<AB::Expr, _>(row, i * 3, bit)),
            );
        }
        let row_sum: AB::Expr = (0..4).map(|j| row[c.permutation + i * 4 + j].into()).sum();
        let column_sum: AB::Expr = (0..4).map(|j| row[c.permutation + j * 4 + i].into()).sum();
        b.assert_eq(row_sum, AB::Expr::ONE);
        b.assert_eq(column_sum, AB::Expr::ONE);
    }
    let sorted: [AB::Expr; 4] = core::array::from_fn(|k| {
        (0..4)
            .map(|i| row[c.permutation + k * 4 + i] * ages[i].clone())
            .sum()
    });
    let ordinal: [AB::Expr; 4] = core::array::from_fn(|k| {
        (0..4)
            .map(|i| row[c.permutation + k * 4 + i] * Val::from_u32(i as u32))
            .sum()
    });
    for k in 0..3 {
        let start = c.sort + k * 10;
        for cell in &row[start..start + 9] {
            b.assert_bool(*cell);
        }
        let difference: AB::Expr = pack_bits_le(row[start..start + 8].iter().copied());
        let zero: AB::Expr = row[start + 8].into();
        let inverse: AB::Expr = row[start + 9].into();
        // S are integer bytes; a negative difference cannot equal d8 modulo p.
        b.assert_eq(
            sorted[k + 1].clone() - sorted[k].clone(),
            difference.clone(),
        );
        b.assert_zero(difference.clone() * zero.clone());
        b.assert_eq(difference * inverse.clone(), AB::Expr::ONE - zero.clone());
        b.assert_zero(zero.clone() * inverse);
        for i in 0..4 {
            for j in 0..i {
                b.assert_zero(
                    zero.clone()
                        * row[c.permutation + k * 4 + i]
                        * row[c.permutation + (k + 1) * 4 + j],
                );
            }
        }
    }
    let posting: AB::Expr = (0..4)
        .map(|k| {
            let value = if k == 0 {
                ordinal[k].clone()
            } else {
                ordinal[k].clone() - row[c.sort + (k - 1) * 10 + 8] * ordinal[k - 1].clone()
            };
            value * Val::from_u64(1 << (8 * k))
        })
        .sum();

    for slot in 0..8 {
        let mut counts = AB::Expr::ZERO;
        let mut offsets = AB::Expr::ZERO;
        let mut threshold = AB::Expr::ZERO;
        let mut postings = AB::Expr::ZERO;
        let mut padding = AB::Expr::ZERO;
        for (physical, selected) in selectors.iter().enumerate() {
            match header_slot(schedule, physical, slot) {
                Some(HeaderWord::Count(a)) => {
                    counts += selected.clone();
                    threshold += selected.clone() * Val::from_u32(a as u32);
                }
                Some(HeaderWord::Offset(a)) => {
                    offsets += selected.clone();
                    threshold += selected.clone() * Val::from_u32(a as u32);
                }
                None => {}
            }
            if let Some((false, block)) = schedule.absorb(physical) {
                match block * 8 + slot {
                    639 => postings += selected.clone(),
                    640 | 641 => padding += selected.clone(),
                    _ => {}
                }
            }
        }
        let active = counts.clone() + offsets.clone();
        let mut count = AB::Expr::ZERO;
        let mut offset = AB::Expr::ZERO;
        for (i, actual_age) in ages.iter().enumerate() {
            let start = c.header + (slot * 4 + i) * 11;
            for cell in &row[start..start + 10] {
                b.assert_bool(*cell);
            }
            for cell in &row[start..start + 11] {
                b.assert_zero((AB::Expr::ONE - active.clone()) * *cell);
            }
            let difference: AB::Expr = pack_bits_le(row[start..start + 8].iter().copied());
            let carry: AB::Expr = row[start + 8].into();
            let zero: AB::Expr = row[start + 9].into();
            let inverse: AB::Expr = row[start + 10].into();
            // Both integer sides are in [0,511], including offset threshold256.
            b.assert_zero(
                active.clone()
                    * (actual_age.clone() + Val::from_u32(256)
                        - threshold.clone()
                        - difference.clone()
                        - carry.clone() * Val::from_u32(256)),
            );
            b.assert_zero(counts.clone() * difference.clone() * zero.clone());
            b.assert_zero(
                counts.clone() * (difference * inverse.clone() - (AB::Expr::ONE - zero.clone())),
            );
            b.assert_zero(counts.clone() * zero.clone() * inverse.clone());
            b.assert_zero((AB::Expr::ONE - counts.clone()) * zero.clone());
            b.assert_zero((AB::Expr::ONE - counts.clone()) * inverse);
            count += zero;
            offset += AB::Expr::ONE - carry;
        }
        // These are the exact existing P2 input registers, already bound through
        // stream_field INCLUDING authenticated stale-word CARRY entries.
        let actual: AB::Expr = row[air.columns().poseidon + slot].into();
        b.assert_zero(counts * (actual.clone() - count));
        b.assert_zero(offsets * (actual.clone() - offset));
        b.assert_zero(postings * (actual.clone() - posting.clone()));
        b.assert_zero(padding * actual);
    }

    b.when_first_row().assert_zero(row[c.table_half]);
    b.assert_zero(
        selectors[schedule.boundary(0)].clone()
            * (row[c.table_half] - table_part::<AB>(air, row, 112)),
    );
    // Capture is the current boundary: suppress only its predecessor copy.
    b.when_transition().assert_zero(
        (AB::Expr::ONE - selectors[schedule.boundary(0) - 1].clone())
            * (next[c.table_half] - row[c.table_half]),
    );
    let table_inverse: AB::Expr = row[c.identity].into();
    b.assert_zero(
        selectors[schedule.boundary(1)].clone()
            * ((row[c.table_half] + table_part::<AB>(air, row, 128)) * table_inverse.clone()
                - AB::Expr::ONE),
    );
    b.assert_zero((AB::Expr::ONE - selectors[schedule.boundary(1)].clone()) * table_inverse);
    if packed {
        packed_identities(air, b, row, selectors);
        return;
    }
    // Four authentic private IDs fit together in final I35/36/37 output buffers.
    let ids: [[AB::Expr; 256]; 4] = core::array::from_fn(|i| {
        core::array::from_fn(|bit| {
            air.plain_bit::<AB::Expr, _>(row, 12 + 2208 + i * 32 + bit / 8, bit % 8)
        })
    });
    let mut check = 1;
    for (i, bits) in ids.iter().enumerate() {
        let sum: AB::Expr = bits.iter().cloned().sum();
        nonzero_at_final(air, b, row, selectors, sum, check);
        check += 1;
        for prior in &ids[..i] {
            let xor: AB::Expr = bits
                .iter()
                .zip(prior)
                .map(|(a, c)| a.clone() + c.clone() - a.clone() * c.clone() * Val::TWO)
                .sum();
            nonzero_at_final(air, b, row, selectors, xor, check);
            check += 1;
        }
    }
    assert_eq!(check, 11);
}
fn nonzero_at_final<AB: AirBuilder<F = Val>>(
    air: &OpeningAir,
    b: &mut AB,
    row: &[AB::Var],
    selectors: &[AB::Expr; TRACE_HEIGHT],
    value: AB::Expr,
    check: usize,
) {
    let c = columns(air.columns().packed);
    let schedule = air.schedule();
    let inverse: AB::Expr = row[c.identity + check].into();
    b.assert_zero(
        selectors[schedule.boundary(5)].clone() * (value * inverse.clone() - AB::Expr::ONE),
    );
    b.assert_zero((AB::Expr::ONE - selectors[schedule.boundary(5)].clone()) * inverse);
}
fn inverse(value: Val) -> Val {
    if value == Val::ZERO {
        Val::ZERO
    } else {
        value.inverse()
    }
}
fn write_bits(out: &mut [Val], value: u16) {
    for (bit, cell) in out.iter_mut().enumerate() {
        *cell = Val::from_u16((value >> bit) & 1);
    }
}
pub(super) fn write_template(row: &mut [Val], ages: [u8; 4], packed: bool) {
    let c = columns(packed);
    for (i, value) in ages.into_iter().enumerate() {
        write_bits(&mut row[c.ages + i * 8..c.ages + (i + 1) * 8], value as u16);
    }
    let mut order = [0_usize, 1, 2, 3];
    order.sort_by_key(|i| (ages[*i], *i));
    for (k, i) in order.into_iter().enumerate() {
        row[c.permutation + k * 4 + i] = Val::ONE;
    }
    for k in 0..3 {
        let difference = ages[order[k + 1]] - ages[order[k]];
        let start = c.sort + k * 10;
        write_bits(&mut row[start..start + 8], difference as u16);
        row[start + 8] = Val::from_bool(difference == 0);
        row[start + 9] = inverse(Val::from_u8(difference));
    }
}
pub(super) fn write_row(air: &OpeningAir, row: &mut [Val], physical: usize, half: &mut Val) {
    let packed = air.columns().packed;
    let c = columns(packed);
    let schedule = air.schedule();
    for slot in 0..8 {
        if let Some(kind) = header_slot(schedule, physical, slot) {
            let (threshold, count) = match kind {
                HeaderWord::Count(b) => (b, true),
                HeaderWord::Offset(b) => (b, false),
            };
            for i in 0..4 {
                let value = age::<Val, _>(row, i, c).as_canonical_u64() as u16;
                let difference = value + 256 - threshold as u16;
                let start = c.header + (slot * 4 + i) * 11;
                write_bits(&mut row[start..start + 8], difference % 256);
                row[start + 8] = Val::from_bool(difference >= 256);
                if count {
                    row[start + 9] = Val::from_bool(difference.is_multiple_of(256));
                    row[start + 10] = inverse(Val::from_u16(difference % 256));
                }
            }
        }
    }
    if physical == schedule.boundary(0) {
        *half = if packed {
            (0..4).map(|w| air.plain_word::<Val, _>(row, 31 + w)).sum()
        } else {
            (112..128)
                .flat_map(|byte| (0..8).map(move |bit| (byte, bit)))
                .map(|(byte, bit)| air.plain_bit::<Val, _>(row, 12 + byte, bit))
                .sum()
        };
    }
    row[c.table_half] = *half;
    if physical == schedule.boundary(1) {
        let second: Val = if packed {
            (0..4).map(|w| air.plain_word::<Val, _>(row, 35 + w)).sum()
        } else {
            (128..144)
                .flat_map(|byte| (0..8).map(move |bit| (byte, bit)))
                .map(|(byte, bit)| air.plain_bit::<Val, _>(row, 12 + byte, bit))
                .sum()
        };
        row[c.identity] = inverse(*half + second);
    }
    if physical == schedule.boundary(5) {
        if packed {
            write_packed_identities(air, row);
            return;
        }
        let ids: [[Val; 256]; 4] = core::array::from_fn(|i| {
            core::array::from_fn(|bit| {
                air.plain_bit::<Val, _>(row, 12 + 2208 + i * 32 + bit / 8, bit % 8)
            })
        });
        let mut check = 1;
        for (i, bits) in ids.iter().enumerate() {
            row[c.identity + check] = inverse(bits.iter().copied().sum());
            check += 1;
            for prior in &ids[..i] {
                let sum = bits
                    .iter()
                    .zip(prior)
                    .map(|(a, c)| *a + *c - *a * *c * Val::TWO)
                    .sum();
                row[c.identity + check] = inverse(sum);
                check += 1;
            }
        }
    }
}

fn table_part<AB: AirBuilder<F = Val>>(
    air: &OpeningAir,
    row: &[AB::Var],
    start: usize,
) -> AB::Expr {
    if air.columns().packed {
        // Four inherited u32 words sum to <2^34, so zero is not a field alias.
        (0..4)
            .map(|w| air.plain_word::<AB::Expr, _>(row, 3 + start / 4 + w))
            .sum()
    } else {
        popcount::<AB>(air, row, start, 16)
    }
}
fn packed_identities<AB: AirBuilder<F = Val>>(
    air: &OpeningAir,
    b: &mut AB,
    row: &[AB::Var],
    selectors: &[AB::Expr; TRACE_HEIGHT],
) {
    let c = columns(true);
    let active = selectors[air.schedule().boundary(5)].clone();
    let ids: [[AB::Expr; 8]; 4] =
        core::array::from_fn(|i| core::array::from_fn(|w| air.plain_word(row, 555 + 8 * i + w)));
    let mut check = 1;
    let mut pair = 0;
    for (i, words) in ids.iter().enumerate() {
        // Eight nonnegative u32 words sum to <2^35 < p. No cancellation.
        nonzero_at_final(air, b, row, selectors, words.iter().cloned().sum(), check);
        check += 1;
        for prior in &ids[..i] {
            let mut different = AB::Expr::ZERO;
            for word in 0..8 {
                let base = c.identity + 11 + pair * 16 + word * 2;
                let zero: AB::Expr = row[base].into();
                let inv: AB::Expr = row[base + 1].into();
                let difference = words[word].clone() - prior[word].clone();
                b.assert_bool(row[base]);
                b.assert_zero(active.clone() * difference.clone() * zero.clone());
                b.assert_zero(
                    active.clone() * (difference * inv.clone() - (AB::Expr::ONE - zero.clone())),
                );
                b.assert_zero(active.clone() * zero.clone() * inv.clone());
                b.assert_zero((AB::Expr::ONE - active.clone()) * zero.clone());
                b.assert_zero((AB::Expr::ONE - active.clone()) * inv);
                different += AB::Expr::ONE - zero;
            }
            nonzero_at_final(air, b, row, selectors, different, check);
            check += 1;
            pair += 1;
        }
    }
    assert_eq!((check, pair), (11, 6));
}
fn write_packed_identities(air: &OpeningAir, row: &mut [Val]) {
    let c = columns(true);
    let ids: [[Val; 8]; 4] =
        core::array::from_fn(|i| core::array::from_fn(|w| air.plain_word(row, 555 + 8 * i + w)));
    let mut check = 1;
    let mut pair = 0;
    for (i, words) in ids.iter().enumerate() {
        row[c.identity + check] = inverse(words.iter().copied().sum());
        check += 1;
        for prior in &ids[..i] {
            let mut different = Val::ZERO;
            for word in 0..8 {
                let base = c.identity + 11 + pair * 16 + word * 2;
                let difference = words[word] - prior[word];
                let zero = Val::from_bool(difference == Val::ZERO);
                row[base] = zero;
                row[base + 1] = inverse(difference);
                different += Val::ONE - zero;
            }
            row[c.identity + check] = inverse(different);
            check += 1;
            pair += 1;
        }
    }
}
