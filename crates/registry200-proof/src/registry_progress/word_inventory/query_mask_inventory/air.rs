//! Exact existing overwrite-rate8/capacity4 streams, with every inactive cell zero.
use super::{
    PUBLIC_CONTEXT, PUBLIC_COUNT, PUBLIC_ROLE, PUBLIC_STATEMENT, PUBLIC_VECTOR, QUERY_ROLE,
    layout::*, profile_words,
};
use crate::Val;
use bfv_hiding_stark::poseidon;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

#[derive(Clone)]
pub(super) struct QueryMaskAir {
    pub plan: Plan,
    profile_words: [Val; 8],
    statement_header: [Val; 13],
}
impl QueryMaskAir {
    pub(super) fn closed() -> Result<Self, String> {
        Ok(Self {
            plan: Plan::closed()?,
            profile_words: profile_words(),
            statement_header: super::super::header("statement")
                .try_into()
                .map_err(|_| "query-mask:statement-header")?,
        })
    }
}
impl BaseAir<Val> for QueryMaskAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_COUNT
    }
    fn preprocessed_width(&self) -> usize {
        PP_WIDTH
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        let mut values = Vec::with_capacity(HEIGHT * PP_WIDTH);
        for row in 0..HEIGHT {
            values.extend(self.plan.pp_row(row));
        }
        Some(RowMajorMatrix::new(values, PP_WIDTH))
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(4)
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for QueryMaskAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let pre = b.preprocessed().clone();
        let pp = pre.current_slice();
        let active: AB::Expr = pp[ACTIVE].into();
        let inactive = AB::Expr::ONE - active.clone();
        assert_eq!(b.public_values().len(), PUBLIC_COUNT);
        let public: [AB::Expr; PUBLIC_COUNT] =
            core::array::from_fn(|i| b.public_values()[i].into());
        for (i, word) in self.profile_words.iter().copied().enumerate() {
            b.assert_eq(public[i].clone(), word);
        }
        b.assert_eq(public[PUBLIC_ROLE].clone(), Val::from_u32(QUERY_ROLE));
        for i in 0..PUBLIC_COUNT {
            // Ordinary constraints bind every independently supplied PUBLIC label,
            // including nonce words which are not part of the existing Cw preimage.
            b.assert_eq(row[PUBLIC + i], active.clone() * public[i].clone());
        }
        for (i, value) in self.statement_header.iter().copied().enumerate() {
            b.assert_eq(row[STATEMENT + i], active.clone() * value);
        }
        b.assert_zero(row[STATEMENT + 95]);
        for word in 0..8 {
            let packed: AB::Expr = (0..32)
                .map(|bit| row[MASK + 32 * word + bit] * Val::from_u64(1u64 << bit))
                .sum();
            b.assert_eq(row[STATEMENT + 78 + word], packed);
        }
        for bit in 0..256 {
            b.assert_bool(row[MASK + bit]);
        }
        // These exact banks survive both streams, then reset at the last Cw row.
        // Every MAIN cell, including the complete padded tail, is constrained.
        let carry_private = active.clone() - pp[VECTOR_LAST];
        for column in STATEMENT..PUBLIC {
            b.when_transition()
                .assert_eq(next[column], carry_private.clone() * row[column]);
            b.assert_zero(inactive.clone() * row[column]);
        }
        let output = poseidon::evaluate(&mut b.when(active.clone()), &row[..P2]);
        for value in &row[..P2] {
            b.assert_zero(inactive.clone() * *value);
        }
        for lane in 0..8 {
            let statement: AB::Expr = (0..12)
                .map(|block| pp[STATEMENT_BLOCK + block] * row[STATEMENT + 8 * block + lane])
                .sum();
            let mask: AB::Expr = (0..32)
                .map(|block| {
                    pp[MASK_BLOCK + block]
                        * row[MASK + 255 - (8 * block + lane)]
                        * Val::from_u64(SCALE)
                })
                .sum();
            let salt: AB::Expr = if lane < 4 {
                row[VECTOR_SALT + lane].into()
            } else {
                AB::Expr::ZERO
            };
            // For all 3840 high W coefficients, every term is identically zero.
            b.assert_eq(
                row[lane],
                statement
                    + mask
                    + pp[VECTOR_CONTEXT] * row[PUBLIC + PUBLIC_CONTEXT + lane]
                    + pp[VECTOR_PREFIX_SALT] * salt,
            );
        }
        for lane in 8..12 {
            b.assert_eq(row[lane], row[CHECKPOINT + lane]);
        }
        let carry_hash = active.clone() - pp[STATEMENT_LAST] - pp[VECTOR_LAST];
        for lane in 0..12 {
            b.when_first_row().assert_zero(row[CHECKPOINT + lane]);
            b.when_transition().assert_eq(
                next[CHECKPOINT + lane],
                carry_hash.clone() * output[lane].clone(),
            );
            b.assert_zero(inactive.clone() * row[CHECKPOINT + lane]);
        }
        for lane in 0..4 {
            b.assert_zero(
                pp[STATEMENT_LAST] * (output[lane].clone() - row[PUBLIC + PUBLIC_STATEMENT + lane]),
            );
            b.assert_zero(
                pp[VECTOR_LAST] * (output[lane].clone() - row[PUBLIC + PUBLIC_VECTOR + lane]),
            );
        }
    }
}
