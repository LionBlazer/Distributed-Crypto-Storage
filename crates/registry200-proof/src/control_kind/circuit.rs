//! Private caller-owned original Cmd160 fields, not an authority or transition model.
use super::{Expected, air::ControlKindAir, layout::*};
use crate::{
    BackendError as Error, Val,
    lifecycle::{opening, statement},
};
use bfv_hiding_stark::{TRACE_HEIGHT, poseidon};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use zeroize::Zeroizing;

/// Explicit caller-owned preimage. No Clone, Debug, serialization or opening getter.
/// Existing `command_fields_opening` supplies this ABI. Copies and native scratch
/// outside these guarded buffers are not promised erased.
///
/// ```compile_fail
/// use registry200_proof::control_kind::circuit::Opening;
/// fn clone<T:Clone>() {} fn forbidden() { clone::<Opening>(); }
/// ```
/// ```compile_fail
/// use registry200_proof::control_kind::circuit::Opening;
/// fn forbidden(opening:Opening) { let _ = opening.fields; }
/// ```
pub struct Opening {
    fields: Zeroizing<[u64; 160]>,
}
impl Opening {
    pub fn new(fields: [u64; 160]) -> Result<Self, Error> {
        let fields = Zeroizing::new(fields);
        if fields.iter().any(|v| *v >= Val::ORDER_U64) {
            return Err(Error::Shape);
        }
        Ok(Self { fields })
    }
}
pub struct Witness {
    expected: Expected,
    bank: Zeroizing<Vec<u64>>,
}
impl Witness {
    /// Fixed commitment association only. Typed prove still checks actual prerequisites.
    pub fn new(e: &Expected, opening: Opening) -> Result<Self, Error> {
        let fields = &opening.fields;
        let selector = CONTROL_OPCODES
            .iter()
            .position(|op| u64::from(*op) == fields[109])
            .ok_or(Error::Shape)?;
        if fields[159] != 0 {
            return Err(Error::Shape);
        }
        let context = e.lifecycle().expected.context();
        for (f, actual) in fields[..109].iter().enumerate() {
            let expected: Val =
                opening::command_prefix(&context, e.roots().0, f).ok_or(Error::Shape)?;
            if *actual != expected.as_canonical_u64() {
                return Err(Error::Shape);
            }
        }
        let values: Vec<_> = fields.iter().copied().map(Val::from_u64).collect();
        if statement::digest(&values) != e.roots().1 {
            return Err(Error::Shape);
        }
        let mut bank = Zeroizing::new(vec![0; WIDTH]);
        bank[OPCODE + selector] = 1;
        bank[SUFFIX..WIDTH].copy_from_slice(&fields[110..159]);
        Ok(Self {
            expected: e.clone(),
            bank,
        })
    }
    pub(crate) fn require_expected(&self, e: &Expected) -> Result<(), Error> {
        self.expected.require_same(e)
    }
    /// Low-level math trace permits a deliberately different claim for AIR attacks.
    /// The typed producer checks its FULL retained Expected before prerequisite work.
    pub fn trace(&self, e: &Expected) -> Result<RowMajorMatrix<Val>, Error> {
        let air = ControlKindAir::new(e);
        let mut trace = vec![Val::ZERO; WIDTH * TRACE_HEIGHT];
        let mut cp = [Val::ZERO; 12];
        for (r, row) in trace.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            for (cell, value) in row.iter_mut().zip(self.bank.iter()) {
                *cell = Val::from_u64(*value);
            }
            row[CP..CP + 12].copy_from_slice(&cp);
            let mut input = [Val::ZERO; 12];
            if r < END {
                for (i, v) in input[..8].iter_mut().enumerate() {
                    *v = air.field(row, 8 * r + i);
                }
                if r != 0 {
                    input[8..].copy_from_slice(&cp[8..]);
                }
            }
            let output = poseidon::write(&mut row[..CP], input);
            if r < END {
                cp = output;
            }
        }
        Ok(RowMajorMatrix::new(trace, WIDTH))
    }
}
