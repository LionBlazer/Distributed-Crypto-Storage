//! The complete immutable relation. No caller-selected gates, AIRs or bus layouts.
use super::pp::*;
use super::*;
use bfv_hiding_stark::{Val, poseidon};
use bfv_unrelinearized_product::Q;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct ProgramAir {
    descriptor: Arc<Descriptor>,
}
impl ProgramAir {
    pub(super) fn new(descriptor: Descriptor) -> Result<Self> {
        if poseidon::WIDTH != 248
            || PORTS + 368 != CHECKPOINT
            || ACCUMULATOR != 508
            || WIDTH != 512
            || PP_WIDTH != 272
            || HEIGHT != 8192
            || descriptor.values.len() != PUBLIC_VALUES
        {
            return Err(Error::Shape);
        }
        let this = Self {
            descriptor: descriptor.shared(),
        };
        this.inventory()?;
        Ok(this)
    }
    pub(super) fn inventory(&self) -> Result<()> {
        pp::inventory(&self.descriptor)
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
        PUBLIC_VALUES
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
            b.when(r.clone()).assert_bool(value.clone());
            let active = if bit < poseidon::WIDTH {
                r.clone() + h.clone()
            } else {
                r.clone()
            };
            b.assert_zero((AB::Expr::ONE - active) * value);
        }
        for k in 0..2 {
            let base = 17 * k;
            let mut bit = BITS + 184 * k;
            for bank in 0..3 {
                let x = packed::<AB>(&row[bit..bit + 6]);
                let slack = packed::<AB>(&row[bit + 6..bit + 12]);
                bit += 12;
                b.assert_zero(r.clone() * (v[base + bank].clone() + Val::from_u8(20) - x.clone()));
                b.assert_zero(r.clone() * (x + slack - Val::from_u8(40)));
            }
            for job in 0..4 {
                let biased = packed::<AB>(&row[bit..bit + 20]);
                bit += 20;
                b.assert_zero(
                    r.clone()
                        * (v[base + 3 + job].clone() + Val::from_u32(524288) - biased.clone()),
                );
                // Exclude -524288; preserve EXACT symmetric[-524287,+524287].
                b.assert_zero(r.clone() * (biased * v[base + 13 + job].clone() - AB::Expr::ONE));
            }
            for operand in 0..2 {
                let w = packed::<AB>(&row[bit..bit + 17]);
                let slack = packed::<AB>(&row[bit + 17..bit + 34]);
                bit += 34;
                b.assert_zero(r.clone() * (v[base + 7 + operand].clone() - w.clone()));
                b.assert_zero(r.clone() * (w + slack - Val::from_u32(65536)));
            }
            for job in 0..4 {
                let operand = job / 2;
                let basis = job % 2;
                let delta = [536854528, 282551134][basis];
                b.assert_zero(
                    r.clone()
                        * (c[4 * k + job].clone() + v[base + 9 + job].clone()
                            - v[base + 7 + operand].clone() * Val::from_u64(delta)
                            - v[base + 1 + operand].clone()
                            - v[base + 3 + job].clone() * Val::from_u64(Q[basis])),
                );
            }
        }
        let acc: AB::Expr = row[ACCUMULATOR].into();
        let pair =
            v[0].clone() + Val::from_u8(20) + (v[17].clone() + Val::from_u8(20)) * Val::from_u8(64);
        let word = acc.clone() + pair * c[8].clone();
        b.assert_zero(f[RESET].clone() * acc.clone());
        b.assert_zero(r.clone() * (v[34].clone() - f[EMIT].clone() * word.clone()));
        b.when_transition().assert_zero(
            r.clone() * (next[ACCUMULATOR] - (AB::Expr::ONE - f[EMIT].clone()) * word),
        );
        b.assert_zero((AB::Expr::ONE - r.clone()) * acc);

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
            if port >= 35 {
                b.assert_zero(r.clone() * value.clone());
            }
            if port >= 8 {
                b.assert_zero(h.clone() * value.clone());
            }
            let arith = match port % 4 {
                0 => -a.clone(),
                1 => -a.clone() + f[POINTWISE].clone(),
                2 => a.clone() + f[FANOUT].clone() * Val::from_u8(3),
                3 => a.clone() - f[POINTWISE].clone() + f[FANOUT].clone() * Val::from_u8(3),
                _ => AB::Expr::ZERO,
            };
            let range = if port < 34 {
                match port % 17 {
                    0 | 7 | 8 => r.clone(),
                    9..=12 => -r.clone(),
                    _ => AB::Expr::ZERO,
                }
            } else if port == 34 {
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
fn packed<AB: InteractionBuilder<F = Val>>(bits: &[AB::Var]) -> AB::Expr {
    bits.iter()
        .enumerate()
        .fold(AB::Expr::ZERO, |a, (i, v)| a + (*v) * Val::from_u64(1 << i))
}
