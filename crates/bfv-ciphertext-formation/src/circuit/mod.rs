//! Low-level mathematical circuit. Explicit inputs are claims, never producer authority.
mod air;
mod trace;
use crate::{PUBLIC_VALUES, Q};
pub use air::*;
use bfv_hiding_stark::{Error, Val};
pub use trace::{refresh_contexts, trace_values};
/// Fixed public values, exact original stream contexts and canonical public B coefficients.
pub struct CircuitStatement {
    values: [Val; PUBLIC_VALUES],
    contexts: [[Val; 8]; 7],
    b: [Vec<u64>; 5],
}
impl CircuitStatement {
    pub fn new(
        values: [Val; PUBLIC_VALUES],
        contexts: [[Val; 8]; 7],
        b: [Vec<u64>; 5],
    ) -> Result<Self, Error> {
        if b.iter()
            .zip(Q)
            .any(|(v, q)| v.len() != crate::N || v.iter().any(|x| *x >= q))
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            values,
            contexts,
            b,
        })
    }
}
pub fn signed(v: i128) -> Val {
    use p3_field::PrimeCharacteristicRing;
    if v < 0 {
        -Val::from_u64((-v) as u64)
    } else {
        Val::from_u64(v as u64)
    }
}
pub fn centered(v: Val) -> Result<i128, Error> {
    use p3_field::PrimeField64;
    let n = i128::from(v.as_canonical_u64());
    let value = if n < (1i128 << 62) {
        n
    } else {
        n - i128::from(Val::ORDER_U64)
    };
    if !(-(1i128 << 62)..(1i128 << 62)).contains(&value) {
        return Err(Error::Shape);
    }
    Ok(value)
}
