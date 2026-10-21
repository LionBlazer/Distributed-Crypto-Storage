//! Metadata-only AIR for one fixed dense layout. No MAIN/PP factory is exposed.
use super::*;
use bfv_hiding_stark::poseidon;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_lookup::{Count, InteractionBuilder};
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct QueryAir<const STRUCTURED: bool> {
    pub(super) plan: Arc<plan::Plan>,
}
pub(super) type MetadataAir = QueryAir<true>;
// Constraint-only reference for the projection test. The fixed native backend
// accepts MetadataAir only; no legacy prover, codec or negotiation is exposed.
#[cfg(test)]
pub(super) type FullWordRangeAir = QueryAir<false>;
impl<const STRUCTURED: bool> QueryAir<STRUCTURED> {
    const MAIN_WIDTH: usize = if STRUCTURED { W } else { 512 };
    const WORD_RANGE_BITS: usize = if STRUCTURED { RANGE_BITS } else { 196 };
    const HASH_CHECKPOINT: usize = if STRUCTURED { CHECKPOINT } else { 496 };
    const SECRET_ACC: usize = if STRUCTURED { ACCUMULATOR } else { 508 };
    const PACKED_MASK_ACC: usize = if STRUCTURED { MASK_ACC } else { 509 };
    const PACKED_MASK_WORD: usize = if STRUCTURED { MASK_WORD } else { 510 };
    pub(super) fn new(expected: &Expected) -> Result<Self> {
        let this = Self {
            plan: plan::Plan::new(expected)?.shared(),
        };
        if poseidon::WIDTH != 248
            || W != 416
            || PP != 708
            || H != 2048
            || BITS + RANGE_BITS != 395
            || CHECKPOINT != 400
            || ACCUMULATOR != 412
            || PORTS != 248
        {
            return Err(Error::Shape);
        }
        this.inventory()?;
        Ok(this)
    }
    pub(super) fn kind(&self) -> RelationKind {
        RelationKind::Data
    }
    pub(super) fn inventory(&self) -> Result<()> {
        let inventory = self.plan.inventory()?;
        if inventory.gates != GATES
            || inventory.hash_rows != 592
            || inventory.coefficients != 4096
            || inventory.positive_uses != inventory.negative_uses
            || inventory.producers != 40 * 4096 + 512 + 8
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
impl<const STRUCTURED: bool> BaseAir<Val> for QueryAir<STRUCTURED> {
    fn width(&self) -> usize {
        Self::MAIN_WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        PP
    }
    fn num_public_values(&self) -> usize {
        PV
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (Self::HASH_CHECKPOINT..=Self::PACKED_MASK_ACC).collect()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    // Intentionally NO preprocessed_trace implementation, witness or prove entry.
}
impl<AB: InteractionBuilder<F = Val>, const STRUCTURED: bool> Air<AB> for QueryAir<STRUCTURED> {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let pre = b.preprocessed().clone();
        let p = pre.current_slice();
        let f: [AB::Expr; 16] = core::array::from_fn(|i| p[FLAGS + i].into());
        let h = f[old_pp::HASH].clone();
        let r = f[old_pp::RANGE].clone();
        for (i, expected) in self.plan.original.values.iter().enumerate() {
            let value = b.public_values()[i];
            b.assert_eq(value, *expected)
        }
        for slot in 0..SLOTS {
            let at = 4 * slot;
            let active: AB::Expr = p[ACTIVE + slot].into();
            let point: AB::Expr = p[POINTWISE + slot].into();
            let x: AB::Expr = row[at].into();
            let y: AB::Expr = row[at + 1].into();
            b.assert_zero(
                active.clone()
                    * (row[at + 2]
                        - p[COEFFICIENTS + at] * x.clone()
                        - p[COEFFICIENTS + at + 1] * y.clone()),
            );
            b.assert_zero(
                active.clone()
                    * (row[at + 3] - p[COEFFICIENTS + at + 2] * x - p[COEFFICIENTS + at + 3] * y),
            );
            b.assert_zero(point.clone() * row[at + 1]);
            b.assert_zero(point * row[at + 3]);
            // Hash owns these same columns ONLY on its disjoint fixed phase.
            for value in &row[at..at + 4] {
                b.assert_zero((AB::Expr::ONE - h.clone() - active.clone()) * (*value))
            }
        }
        for value in &row[GRAPH_PORTS..248] {
            b.assert_zero((AB::Expr::ONE - h.clone()) * (*value))
        }
        for bit in &row[BITS..BITS + Self::WORD_RANGE_BITS] {
            let value: AB::Expr = (*bit).into();
            b.when(r.clone()).assert_bool(value.clone());
            b.assert_zero((AB::Expr::ONE - r.clone()) * value);
        }
        let values: [AB::Expr; RANGE_PORTS] =
            core::array::from_fn(|i| row[RANGE_VALUES + i].into());
        let constants: [AB::Expr; 9] = core::array::from_fn(|i| {
            if i < 4 {
                p[RANGE_C0 + i].into()
            } else if i == 8 {
                p[POWER].into()
            } else {
                AB::Expr::ZERO
            }
        });
        let range_inputs = super::super::range_equations::Inputs {
            kind: RelationKind::Data,
            bits: &row[BITS..BITS + Self::WORD_RANGE_BITS],
            values: &values,
            constants: &constants,
            flags: &f,
            accumulator: row[Self::SECRET_ACC].into(),
            next_accumulator: next[Self::SECRET_ACC],
        };
        if STRUCTURED {
            super::super::range_equations::evaluate_query(b, range_inputs);
        } else {
            super::super::range_equations::evaluate(b, range_inputs);
        }
        // Same native Poseidon emitter: Cw514, Cs66 and Stmt12, exactly once. Rate inputs
        // live directly in the hash MAIN, eliminating duplicate payload storage only.
        let hash = poseidon::evaluate(&mut b.when(h.clone()), &row[..poseidon::WIDTH]);
        for i in 0..8 {
            let free = f[old_pp::MASK].clone()
                + f[old_pp::PAYLOAD].clone()
                + if i < 4 {
                    f[old_pp::SALT].clone()
                } else {
                    AB::Expr::ZERO
                };
            b.assert_zero(
                h.clone()
                    * (AB::Expr::ONE - free)
                    * (row[i] - f[old_pp::CONTEXT].clone() * p[CONTEXT + i]),
            );
        }
        for i in 8..12 {
            b.assert_zero(h.clone() * (row[i] - row[Self::HASH_CHECKPOINT + i]))
        }
        for i in 0..12 {
            b.assert_zero((AB::Expr::ONE - h.clone()) * row[Self::HASH_CHECKPOINT + i]);
            b.assert_zero(f[old_pp::FIRST].clone() * row[Self::HASH_CHECKPOINT + i]);
            b.when_transition().assert_zero(
                h.clone()
                    * (next[Self::HASH_CHECKPOINT + i]
                        - (AB::Expr::ONE - f[old_pp::LAST].clone()) * hash[i].clone()),
            );
        }
        for (i, value) in hash.iter().enumerate().take(4) {
            b.assert_zero(f[old_pp::LAST].clone() * (value.clone() - p[ROOT + i]))
        }
        for port in 0..GRAPH_PORTS {
            let active: AB::Expr = p[ACTIVE + port / 4].into();
            let point: AB::Expr = p[POINTWISE + port / 4].into();
            let fanout: AB::Expr = p[FANOUT + port / 4].into();
            let graph = match port % 4 {
                0 => -active,
                1 => -active + point,
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
                Count::bounded(
                    graph
                        - payload
                        - if port < 8 {
                            p[STMT_LOOKUP + port].into()
                        } else {
                            AB::Expr::ZERO
                        },
                    4,
                ),
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
        // Every W coefficient is constrained: low256 are scaled bits, high3840 zero.
        let mask: AB::Expr = p[MASK_ACTIVE].into();
        for k in 0..2 {
            let word: AB::Expr = row[RANGE_VALUES + k * range.stride + range.w].into();
            b.assert_zero(mask.clone() * word.clone() * (word.clone() - Val::from_u64(16389)));
            b.assert_zero((AB::Expr::ONE - mask.clone()) * word);
        }
        let inverse_scale = Val::from_u64(SCALE_INVERSE);
        let bit0: AB::Expr = row[RANGE_VALUES + range.w] * inverse_scale;
        let bit1: AB::Expr = row[RANGE_VALUES + range.stride + range.w] * inverse_scale;
        let packed: AB::Expr =
            row[Self::PACKED_MASK_ACC] + (bit0 * Val::from_u8(2) + bit1) * p[MASK_POWER];
        b.assert_zero(p[MASK_RESET] * row[Self::PACKED_MASK_ACC]);
        b.assert_zero((AB::Expr::ONE - mask.clone()) * row[Self::PACKED_MASK_ACC]);
        b.assert_zero(row[Self::PACKED_MASK_WORD] - p[MASK_EMIT] * packed.clone());
        b.when_transition().assert_zero(
            next[Self::PACKED_MASK_ACC] - mask * (AB::Expr::ONE - p[MASK_EMIT]) * packed,
        );
        b.push_interaction(
            BUS,
            [p[WORD_PORT].into(), row[Self::PACKED_MASK_WORD].into()],
            Count::bounded(p[MASK_EMIT].into(), 4),
        );
        for lane in 0..8 {
            b.assert_zero(p[FIXED + lane] * (row[lane] - p[FIXED_VALUE + lane]));
        }
        for value in &row[BITS + Self::WORD_RANGE_BITS..Self::HASH_CHECKPOINT] {
            b.assert_zero(*value)
        }
        b.assert_zero(row[Self::MAIN_WIDTH - 1]);
    }
}
