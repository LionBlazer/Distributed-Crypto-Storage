//! The complete immutable relation. No caller-selected gates, AIRs or bus layouts.
use super::super::relation::{ExpectedRef, RelationKind};
use super::pp::*;
use super::*;
use bfv_hiding_stark::{Val, poseidon};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

#[derive(Clone)]
pub(in crate::gold) struct ProgramAir {
    descriptor: Arc<Descriptor>,
}
impl ProgramAir {
    pub(in crate::gold) fn new(expected: super::super::Expected) -> Result<Self> {
        Self::from_expected(ExpectedRef::Pair(&expected))
    }
    pub(in crate::gold) fn data(expected: super::super::data::Expected) -> Result<Self> {
        Self::from_expected(ExpectedRef::Data(&expected))
    }
    fn from_expected(expected: ExpectedRef<'_>) -> Result<Self> {
        let descriptor = Descriptor::new(expected)?;
        if poseidon::WIDTH != 248
            || PORTS + 368 != CHECKPOINT
            || ACCUMULATOR != 508
            || WIDTH != 512
            || PP_WIDTH != 272
            || HEIGHT != 8192
            || descriptor.values.len() != descriptor.kind.public_values()
        {
            return Err(Error::Shape);
        }
        let this = Self {
            descriptor: descriptor.shared(),
        };
        this.inventory()?;
        Ok(this)
    }
    pub(in crate::gold) fn kind(&self) -> RelationKind {
        self.descriptor.kind
    }
    pub(super) fn inventory(&self) -> Result<()> {
        pp::inventory(&self.descriptor)
    }
    #[cfg(test)]
    pub(in crate::gold) fn first_gate_coefficients(&self) -> [Val; 4] {
        let row = pp::row(&self.descriptor, 0).expect("fixed public row");
        row[COEFFICIENTS..COEFFICIENTS + 4]
            .try_into()
            .expect("four coefficients")
    }
}
impl BaseAir<Val> for ProgramAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        PP_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        // Called only by actual native setup AFTER metadata/security/resource prescreen.
        let mut values = Vec::with_capacity(HEIGHT * PP_WIDTH);
        for r in 0..HEIGHT {
            values.extend(pp::row(&self.descriptor, r).expect("closed audited row metadata"));
        }
        Some(RowMajorMatrix::new(values, PP_WIDTH))
    }
    fn num_public_values(&self) -> usize {
        self.descriptor.kind.public_values()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (CHECKPOINT..=ACCUMULATOR).collect()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: InteractionBuilder<F = Val>> Air<AB> for ProgramAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let pre = b.preprocessed().clone();
        let p = pre.current_slice();
        let f: [AB::Expr; 16] = core::array::from_fn(|i| p[FLAGS + i].into());
        let kind = self.descriptor.kind;
        let range_layout = kind.range();
        let a = f[ARITH].clone();
        let r = f[RANGE].clone();
        let h = f[HASH].clone();
        let v: [AB::Expr; PORTS] = core::array::from_fn(|i| row[i].into());
        let c: [AB::Expr; FLAGS - COEFFICIENTS] =
            core::array::from_fn(|i| p[COEFFICIENTS + i].into());
        for (i, expected) in self.descriptor.values.iter().enumerate() {
            let value = b.public_values()[i];
            b.assert_eq(value, *expected);
        }
        for slot in 0..32 {
            let i = 4 * slot;
            b.assert_zero(
                a.clone()
                    * (v[i + 2].clone()
                        - c[i].clone() * v[i].clone()
                        - c[i + 1].clone() * v[i + 1].clone()),
            );
            b.assert_zero(
                a.clone()
                    * (v[i + 3].clone()
                        - c[i + 2].clone() * v[i].clone()
                        - c[i + 3].clone() * v[i + 1].clone()),
            );
            b.assert_zero(f[POINTWISE].clone() * v[i + 1].clone());
            b.assert_zero(f[POINTWISE].clone() * v[i + 3].clone());
        }
        // Full direct bit ranges share scratch with Poseidon only in disjoint PP phases.
        for bit in 0..368 {
            let value: AB::Expr = row[BITS + bit].into();
            if bit < 2 * range_layout.bits {
                b.when(r.clone()).assert_bool(value.clone());
            }
            let active = if bit < poseidon::WIDTH {
                if bit < 2 * range_layout.bits {
                    r.clone() + h.clone()
                } else {
                    h.clone()
                }
            } else if bit < 2 * range_layout.bits {
                r.clone()
            } else {
                AB::Expr::ZERO
            };
            b.assert_zero((AB::Expr::ONE - active) * value);
        }
        super::range_equations::evaluate(
            b,
            super::range_equations::Inputs {
                kind,
                bits: &row[BITS..BITS + 2 * range_layout.bits],
                values: &v,
                constants: &c,
                flags: &f,
                accumulator: row[ACCUMULATOR].into(),
                next_accumulator: next[ACCUMULATOR],
            },
        );
        let hash = poseidon::evaluate(&mut b.when(h.clone()), &row[BITS..BITS + poseidon::WIDTH]);
        for i in 0..8 {
            let salt_or_data = f[PAYLOAD].clone()
                + if i < 4 {
                    f[SALT].clone()
                } else {
                    AB::Expr::ZERO
                };
            b.assert_zero(
                h.clone()
                    * (row[BITS + i]
                        - f[CONTEXT].clone() * c[i].clone()
                        - salt_or_data.clone() * v[i].clone()),
            );
            b.assert_zero(h.clone() * (AB::Expr::ONE - salt_or_data) * v[i].clone());
        }
        for i in 8..12 {
            b.assert_zero(h.clone() * (row[BITS + i] - row[CHECKPOINT + i]));
        }
        for i in 0..12 {
            b.assert_zero((AB::Expr::ONE - h.clone()) * row[CHECKPOINT + i]);
            b.assert_zero(f[FIRST].clone() * row[CHECKPOINT + i]);
            b.when_transition().assert_zero(
                h.clone()
                    * (next[CHECKPOINT + i] - (AB::Expr::ONE - f[LAST].clone()) * hash[i].clone()),
            );
        }
        for i in 0..4 {
            b.assert_zero(f[LAST].clone() * (hash[i].clone() - c[8 + i].clone()));
        }
        for (port, value) in v.iter().enumerate() {
            b.assert_zero((AB::Expr::ONE - a.clone() - r.clone() - h.clone()) * value.clone());
            if port > 2 * range_layout.stride {
                b.assert_zero(r.clone() * value.clone());
            }
            if port >= 8 {
                b.assert_zero(h.clone() * value.clone());
            }
            let arith = match port % 4 {
                0 => -a.clone(),
                1 => -a.clone() + f[POINTWISE].clone(),
                2 => a.clone() + f[FANOUT].clone() * Val::from_usize(kind.products() - 1),
                3 => {
                    a.clone() - f[POINTWISE].clone()
                        + f[FANOUT].clone() * Val::from_usize(kind.products() - 1)
                }
                _ => AB::Expr::ZERO,
            };
            let range = if port < 2 * range_layout.stride {
                let bank = port % range_layout.stride;
                if bank == 0 || (range_layout.w..range_layout.w + kind.operands()).contains(&bank) {
                    r.clone()
                } else if (range_layout.product..range_layout.product + kind.products())
                    .contains(&bank)
                {
                    -r.clone()
                } else {
                    AB::Expr::ZERO
                }
            } else if port == 2 * range_layout.stride {
                f[EMIT].clone()
            } else {
                AB::Expr::ZERO
            };
            let input = if port < 8 {
                -f[PAYLOAD].clone()
            } else {
                AB::Expr::ZERO
            };
            // IDs are direct PP fields; no selector product enters payload degree.
            b.push_interaction(
                BUS,
                [p[port].into(), value.clone()],
                Count::bounded(arith + range + input, 4),
            );
        }
        for cell in &row[509..512] {
            b.assert_zero(*cell);
        }
    }
}
