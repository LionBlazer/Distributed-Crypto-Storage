//! One fixed arithmetic program with private values crossing two real LogUp edges.
use super::{Error, Expected, Result, Witness};
use bfv_hiding_stark::Val;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub(super) const WIDTH: usize = 19;
pub(super) const PP_WIDTH: usize = 3;
pub(super) const PUBLIC_VALUES: usize = 17;
pub(super) const HEIGHT: usize = 512;
pub(super) const LOG_HEIGHT: usize = 9;
pub(super) const DEGREE_BITS: usize = 10;
pub(super) const BUS: &str = "dcs/hiding-logup-wire/v1/node-value";

#[derive(Clone)]
pub(super) struct FixedAir {
    expected: Vec<Val>,
}
impl FixedAir {
    pub(super) fn new(expected: &Expected) -> Self {
        Self {
            expected: expected.values(),
        }
    }
    pub(super) fn preflight(&self) -> Result<()> {
        if self.expected.len() != PUBLIC_VALUES
            || HEIGHT != 1 << LOG_HEIGHT
            || DEGREE_BITS != LOG_HEIGHT + 1
            || WIDTH != 19
            || PP_WIDTH != 3
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(super) fn trace(&self, witness: &Witness) -> PrivateTrace {
        let mut values = vec![Val::ZERO; HEIGHT * WIDTH];
        let a = u32::from(witness.x).pow(2) + 3;
        let b = a + u32::from(witness.z);
        values[0] = Val::from_u8(witness.x);
        values[2] = Val::from_u32(a);
        values[WIDTH] = Val::from_u16(witness.z);
        values[WIDTH + 1] = Val::from_u32(a);
        values[WIDTH + 2] = Val::from_u32(b);
        values[2 * WIDTH + 1] = Val::from_u32(b);
        for bit in 0..16 {
            values[3 + bit] = Val::from_u8((u16::from(witness.x) >> bit & 1) as u8);
            values[WIDTH + 3 + bit] = Val::from_u8((witness.z >> bit & 1) as u8);
        }
        PrivateTrace(RowMajorMatrix::new(values, WIDTH))
    }
}

pub(super) struct PrivateTrace(pub(super) RowMajorMatrix<Val>);
impl Drop for PrivateTrace {
    fn drop(&mut self) {
        self.0.values.fill(Val::ZERO);
    }
}

impl BaseAir<Val> for FixedAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        PP_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        let mut values = vec![Val::ZERO; HEIGHT * PP_WIDTH];
        values[0] = Val::ONE;
        values[PP_WIDTH + 1] = Val::ONE;
        values[2 * PP_WIDTH + 2] = Val::ONE;
        Some(RowMajorMatrix::new(values, PP_WIDTH))
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB: InteractionBuilder<F = Val>> Air<AB> for FixedAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let prep = builder.preprocessed().clone();
        let flags = prep.current_slice();
        let g0: AB::Expr = flags[0].into();
        let g1: AB::Expr = flags[1].into();
        let g2: AB::Expr = flags[2].into();
        let scalar: AB::Expr = row[0].into();
        let input: AB::Expr = row[1].into();
        let output: AB::Expr = row[2].into();
        let active = g0.clone() + g1.clone();
        builder.assert_zero((AB::Expr::ONE - active.clone()) * scalar.clone());
        builder.assert_zero((AB::Expr::ONE - g1.clone() - g2.clone()) * input.clone());
        builder.assert_zero((AB::Expr::ONE - active.clone()) * output.clone());
        builder.assert_zero(
            g0.clone() * (output.clone() - scalar.clone() * scalar.clone() - Val::from_u8(3)),
        );
        builder.assert_zero(g1.clone() * (output.clone() - input.clone() - scalar.clone()));
        let public = builder.public_values().to_vec();
        builder.assert_zero(g2.clone() * (input.clone() - public[16].into()));
        let mut packed = AB::Expr::ZERO;
        for bit in 0..16 {
            let value: AB::Expr = row[3 + bit].into();
            builder.assert_bool(value.clone());
            builder.assert_zero((AB::Expr::ONE - active.clone()) * value.clone());
            if bit >= 8 {
                builder.assert_zero(g0.clone() * value.clone());
            }
            packed += value * Val::from_u32(1 << bit);
        }
        builder.assert_zero(scalar - packed);
        for (actual, expected) in public.iter().zip(&self.expected) {
            builder.assert_eq(*actual, *expected);
        }
        builder.push_interaction(BUS, [AB::Expr::ONE, output.clone()], Count::bounded(g0, 1));
        builder.push_interaction(
            BUS,
            [AB::Expr::ONE, input.clone()],
            Count::bounded(-g1.clone(), 1),
        );
        builder.push_interaction(BUS, [AB::Expr::from_u8(2), output], Count::bounded(g1, 1));
        builder.push_interaction(BUS, [AB::Expr::from_u8(2), input], Count::bounded(-g2, 1));
    }
}
