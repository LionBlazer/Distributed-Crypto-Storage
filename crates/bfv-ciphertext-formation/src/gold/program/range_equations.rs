//! Private exact range/value/secret-pack equations shared by TWO closed layouts.
//! No caller-selectable policy, AIR, producer, callback or mathematical capability.
use super::super::{geometry::Q, relation::RelationKind};
use super::pp::{EMIT, RANGE, RESET};
use bfv_hiding_stark::Val;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;

pub(super) struct Inputs<'a, AB: InteractionBuilder<F = Val>> {
    pub(super) kind: RelationKind,
    pub(super) bits: &'a [AB::Var],
    pub(super) values: &'a [AB::Expr],
    pub(super) constants: &'a [AB::Expr],
    pub(super) flags: &'a [AB::Expr; 16],
    pub(super) accumulator: AB::Expr,
    pub(super) next_accumulator: AB::Var,
}
pub(super) fn evaluate<AB: InteractionBuilder<F = Val>>(b: &mut AB, input: Inputs<'_, AB>) {
    let kind = input.kind;
    let range_layout = kind.range();
    let row = input.bits;
    let v = input.values;
    let c = input.constants;
    let f = input.flags;
    let r = f[RANGE].clone();
    for k in 0..2 {
        let base = range_layout.stride * k;
        let mut bit = range_layout.bits * k;
        for bank in 0..1 + kind.operands() {
            let x = packed::<AB>(&row[bit..bit + 6]);
            let slack = packed::<AB>(&row[bit + 6..bit + 12]);
            bit += 12;
            b.assert_zero(r.clone() * (v[base + bank].clone() + Val::from_u8(20) - x.clone()));
            b.assert_zero(r.clone() * (x + slack - Val::from_u8(40)));
        }
        for job in 0..kind.products() {
            let biased = packed::<AB>(&row[bit..bit + 20]);
            bit += 20;
            b.assert_zero(
                r.clone()
                    * (v[base + range_layout.k + job].clone() + Val::from_u32(524288)
                        - biased.clone()),
            );
            // Exclude -524288; preserve EXACT symmetric[-524287,+524287].
            b.assert_zero(
                r.clone() * (biased * v[base + range_layout.inverse + job].clone() - AB::Expr::ONE),
            );
        }
        for operand in 0..kind.operands() {
            let w = packed::<AB>(&row[bit..bit + 17]);
            let slack = packed::<AB>(&row[bit + 17..bit + 34]);
            bit += 34;
            b.assert_zero(r.clone() * (v[base + range_layout.w + operand].clone() - w.clone()));
            b.assert_zero(r.clone() * (w + slack - Val::from_u32(65536)));
        }
        for job in 0..kind.products() {
            let operand = job / 2;
            let basis = job % 2;
            let delta = [536854528, 282551134][basis];
            b.assert_zero(
                r.clone()
                    * (c[kind.products() * k + job].clone()
                        + v[base + range_layout.product + job].clone()
                        - v[base + range_layout.w + operand].clone() * Val::from_u64(delta)
                        - v[base + range_layout.e + operand].clone()
                        - v[base + range_layout.k + job].clone() * Val::from_u64(Q[basis])),
            );
        }
    }
    let acc = input.accumulator;
    let pair = v[0].clone()
        + Val::from_u8(20)
        + (v[range_layout.stride].clone() + Val::from_u8(20)) * Val::from_u8(64);
    let word = acc.clone() + pair * c[8].clone();
    b.assert_zero(f[RESET].clone() * acc.clone());
    b.assert_zero(
        r.clone() * (v[2 * range_layout.stride].clone() - f[EMIT].clone() * word.clone()),
    );
    b.when_transition().assert_zero(
        r.clone() * (input.next_accumulator - (AB::Expr::ONE - f[EMIT].clone()) * word),
    );
    b.assert_zero((AB::Expr::ONE - r.clone()) * acc);
}
fn packed<AB: InteractionBuilder<F = Val>>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .enumerate()
        .fold(AB::Expr::ZERO, |a, (i, v)| a + (*v) * Val::from_u64(1 << i))
}
