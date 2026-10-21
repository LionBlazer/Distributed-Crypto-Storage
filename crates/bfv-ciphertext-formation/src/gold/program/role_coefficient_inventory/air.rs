//! The only two AIR variants. Their eval captures static routing, never Expected.
use super::*;
use bfv_hiding_stark::poseidon;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_lookup::{Count, InteractionBuilder};
use std::sync::Arc;

#[derive(Clone)]
pub(super) enum MetadataAir {
    Data(Arc<plan::Plan>),
    PublicCoefficientHash,
}
impl MetadataAir {
    pub(super) fn closed() -> Result<[Self; 2]> {
        let plan = plan::Plan::new()?;
        plan::inventory(&plan)?;
        if poseidon::WIDTH != 248
            || FANOUT + SLOTS != PP
            || LABELS + 24 != 491
            || C0_VALUES != BITS + RANGE_BITS
            || CHECKPOINT != 496
            || HASH_W != 248 + 12
        {
            return Err(Error::Shape);
        }
        Ok([Self::Data(Arc::new(plan)), Self::PublicCoefficientHash])
    }
    pub(super) fn plan(&self) -> Result<&plan::Plan> {
        match self {
            Self::Data(p) => Ok(p),
            Self::PublicCoefficientHash => Err(Error::Shape),
        }
    }
}
impl BaseAir<Val> for MetadataAir {
    fn width(&self) -> usize {
        match self {
            Self::Data(_) => W,
            Self::PublicCoefficientHash => HASH_W,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Data(_) => PP,
            Self::PublicCoefficientHash => HASH_PP,
        }
    }
    fn num_public_values(&self) -> usize {
        match self {
            Self::Data(_) => PV,
            Self::PublicCoefficientHash => HASH_PV,
        }
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Data(_) => (CHECKPOINT..=ACCUMULATOR).collect(),
            Self::PublicCoefficientHash => (248..260).collect(),
        }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    // NO preprocessed_trace, MAIN factory, backend or accepting constructor.
}
impl<AB: InteractionBuilder<F = Val>> Air<AB> for MetadataAir {
    fn eval(&self, b: &mut AB) {
        match self {
            Self::Data(_) => data_eval(b),
            Self::PublicCoefficientHash => hash_eval(b),
        }
    }
}
fn data_eval<AB: InteractionBuilder<F = Val>>(b: &mut AB) {
    let main = b.main();
    let row = main.current_slice();
    let next = main.next_slice();
    let pre = b.preprocessed().clone();
    let p = pre.current_slice();
    let f: [AB::Expr; 16] = core::array::from_fn(|i| p[FLAGS + i].into());
    let h = f[old_pp::HASH].clone();
    let r = f[old_pp::RANGE].clone();
    for i in 0..24 {
        let pv = b.public_values()[i];
        b.assert_eq(row[LABELS + i], pv);
    }
    for slot in 0..SLOTS {
        let at = 4 * slot;
        let active: AB::Expr = p[ACTIVE + slot].into();
        let point: AB::Expr = p[POINTWISE + slot].into();
        let x: AB::Expr = row[at].into();
        let y: AB::Expr = row[at + 1].into();
        let linear = p[COEFFICIENTS + at] * x.clone() + p[COEFFICIENTS + at + 1] * y.clone();
        b.assert_zero(
            active.clone()
                * (row[at + 2]
                    - (AB::Expr::ONE - point.clone()) * linear
                    - point.clone() * x.clone() * y.clone()),
        );
        b.assert_zero(
            active.clone()
                * (row[at + 3] - p[COEFFICIENTS + at + 2] * x - p[COEFFICIENTS + at + 3] * y),
        );
        b.assert_zero(point * row[at + 3]);
        for value in &row[at..at + 4] {
            b.assert_zero((AB::Expr::ONE - h.clone() - active.clone()) * (*value));
        }
    }
    for value in &row[GRAPH_PORTS..248] {
        b.assert_zero((AB::Expr::ONE - h.clone()) * (*value));
    }
    for bit in &row[BITS..BITS + RANGE_BITS] {
        let value: AB::Expr = (*bit).into();
        b.when(r.clone()).assert_bool(value.clone());
        b.assert_zero((AB::Expr::ONE - r.clone()) * value);
    }
    let values: [AB::Expr; RANGE_PORTS] = core::array::from_fn(|i| row[RANGE_VALUES + i].into());
    let constants: [AB::Expr; 9] = core::array::from_fn(|i| {
        if i < 4 {
            row[C0_VALUES + i].into()
        } else if i == 8 {
            p[POWER].into()
        } else {
            AB::Expr::ZERO
        }
    });
    super::super::range_equations::evaluate(
        b,
        super::super::range_equations::Inputs {
            kind: RelationKind::Data,
            bits: &row[BITS..BITS + RANGE_BITS],
            values: &values,
            constants: &constants,
            flags: &f,
            accumulator: row[ACCUMULATOR].into(),
            next_accumulator: next[ACCUMULATOR],
        },
    );
    // Original salted Cw/Cs streams and ALL580 absorptions, unchanged overwrite-rate format.
    let hash = poseidon::evaluate(&mut b.when(h.clone()), &row[..poseidon::WIDTH]);
    for (i, value) in row.iter().take(8).enumerate() {
        let free = f[old_pp::PAYLOAD].clone()
            + if i < 4 {
                f[old_pp::SALT].clone()
            } else {
                AB::Expr::ZERO
            };
        let source: AB::Expr = b.public_values()[32 + i].into();
        let cs: AB::Expr = b.public_values()[40 + i].into();
        let expected = f[old_pp::SOURCE].clone() * source + f[old_pp::CS].clone() * cs;
        b.assert_zero(
            h.clone() * (AB::Expr::ONE - free) * (*value - f[old_pp::CONTEXT].clone() * expected),
        );
    }
    for i in 8..12 {
        b.assert_zero(h.clone() * (row[i] - row[CHECKPOINT + i]));
    }
    for i in 0..12 {
        b.assert_zero((AB::Expr::ONE - h.clone()) * row[CHECKPOINT + i]);
        b.assert_zero(f[old_pp::FIRST].clone() * row[CHECKPOINT + i]);
        b.when_transition().assert_zero(
            h.clone()
                * (next[CHECKPOINT + i]
                    - (AB::Expr::ONE - f[old_pp::LAST].clone()) * hash[i].clone()),
        );
    }
    for (i, value) in hash.iter().enumerate().take(4) {
        let source: AB::Expr = b.public_values()[28 + i].into();
        let cs: AB::Expr = b.public_values()[24 + i].into();
        let expected = f[old_pp::SOURCE].clone() * source + f[old_pp::CS].clone() * cs;
        b.assert_zero(f[old_pp::LAST].clone() * (value.clone() - expected));
    }
    for port in 0..GRAPH_PORTS {
        let active: AB::Expr = p[ACTIVE + port / 4].into();
        let point: AB::Expr = p[POINTWISE + port / 4].into();
        let fanout: AB::Expr = p[FANOUT + port / 4].into();
        let graph = match port % 4 {
            0 | 1 => -active,
            2 => active + fanout,
            3 => active - point + fanout,
            _ => AB::Expr::ZERO,
        };
        let payload = if port < 8 {
            f[old_pp::PAYLOAD].clone()
        } else {
            AB::Expr::ZERO
        };
        b.push_interaction(
            BUS,
            [p[port].into(), row[port].into()],
            Count::bounded(graph - payload, 4),
        );
    }
    let range = RelationKind::Data.range();
    for port in 0..RANGE_PORTS {
        let bank = port % range.stride;
        let count = if port == 18 {
            f[old_pp::EMIT].clone()
        } else if bank == 0 || bank == range.w {
            r.clone()
        } else if (range.product..range.product + 2).contains(&bank) {
            -r.clone()
        } else {
            AB::Expr::ZERO
        };
        b.push_interaction(
            BUS,
            [p[GRAPH_PORTS + port].into(), values[port].clone()],
            Count::bounded(count, 4),
        );
    }
    for i in 0..4 {
        b.push_interaction(
            BUS,
            [p[ORIGINAL_PORTS + i].into(), row[C0_VALUES + i].into()],
            Count::bounded(-AB::Expr::ONE, 4),
        );
    }
    for value in &row[491..CHECKPOINT] {
        b.assert_zero(*value);
    }
    for value in &row[509..512] {
        b.assert_zero(*value);
    }
}
fn hash_eval<AB: InteractionBuilder<F = Val>>(b: &mut AB) {
    let main = b.main();
    let row = main.current_slice();
    let next = main.next_slice();
    let pre = b.preprocessed().clone();
    let p = pre.current_slice();
    let hash = poseidon::evaluate(b, &row[..poseidon::WIDTH]);
    let iv = public::iv();
    for i in 0..12 {
        let initial = if i < 8 { Val::ZERO } else { iv[i - 8] };
        b.assert_zero(p[HASH_FIRST] * (row[248 + i] - initial));
        b.when_transition()
            .assert_eq(next[248 + i], hash[i].clone());
    }
    for i in 8..12 {
        b.assert_eq(row[i], row[248 + i]);
    }
    for i in 0..HASH_PORTS {
        // Rate is additive in this NEW fixed-IV format. This is the literal coefficient,
        // not the accumulated sponge state; no private value is disclosed.
        b.push_interaction(
            BUS,
            [p[i].into(), row[i] - row[248 + i]],
            Count::bounded(AB::Expr::ONE, 1),
        );
    }
    for (i, value) in hash.iter().enumerate().take(4) {
        let expected: AB::Expr = b.public_values()[i].into();
        b.assert_zero(p[HASH_LAST] * (value.clone() - expected));
    }
}
