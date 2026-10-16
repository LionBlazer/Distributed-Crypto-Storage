use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, utils::pack_bits_le};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_sha256_air::{NUM_SHA256_COLS, Sha256Air, Sha256Cols, generate_trace_rows};

use crate::backend::{TRACE_HEIGHT, Val};
use crate::statement::{ID_WORDS, PUBLIC_VALUES, Statement};

/// Every row proves the same explicitly public compression. Repetition pads the
/// primitive to a fixed masking budget; it is not a claim about SHA chaining.
pub(crate) struct CompressionAir {
    identity: [Val; ID_WORDS],
}

impl CompressionAir {
    pub(crate) fn new(statement: &Statement) -> Self {
        Self {
            identity: statement.identity_values(),
        }
    }

    pub(crate) fn trace(statement: &Statement) -> RowMajorMatrix<Val> {
        generate_trace_rows(vec![statement.trace_input(); TRACE_HEIGHT], 0)
    }
}

impl BaseAir<Val> for CompressionAir {
    fn width(&self) -> usize {
        NUM_SHA256_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for CompressionAir {
    fn eval(&self, builder: &mut AB) {
        Sha256Air.eval(builder);
        let public: [AB::PublicVar; PUBLIC_VALUES] = builder.public_values().try_into().unwrap();
        for (actual, expected) in public[..ID_WORDS].iter().zip(self.identity) {
            builder.assert_eq(*actual, expected);
        }
        let main = builder.main();
        let row: &Sha256Cols<AB::Var> = main.current_slice().borrow();
        for (i, bits) in row.w[..16].iter().enumerate() {
            builder.assert_eq(
                pack_bits_le::<AB::Expr, _, _>(bits.iter().copied()),
                public[ID_WORDS + i],
            );
        }
        for (i, limbs) in row.h_in.iter().enumerate() {
            builder.assert_eq(
                limbs[0] + limbs[1] * Val::from_u64(1 << 16),
                public[ID_WORDS + 16 + i],
            );
        }
        for (i, bits) in row.h_out.iter().enumerate() {
            builder.assert_eq(
                pack_bits_le::<AB::Expr, _, _>(bits.iter().copied()),
                public[ID_WORDS + 24 + i],
            );
        }
    }
}
