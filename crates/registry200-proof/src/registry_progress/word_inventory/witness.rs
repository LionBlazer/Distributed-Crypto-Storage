//! Complete MAIN writer for the fixed plan, guarded through success and errors.
use super::{
    Metadata,
    air::ProgramAir,
    complete_build,
    evaluate::{Error, Evaluator, Result},
    owner::PrimaryInputs,
    plan::*,
};
use crate::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
pub(super) struct PrivateTrace(pub RowMajorMatrix<Val>);
impl Drop for PrivateTrace {
    fn drop(&mut self) {
        self.0.values.fill(Val::ZERO);
    }
}
/// No PP/PCS/proof, accepting token or reusable verdict is constructed here.
/// PrimaryInputs stays owner-custodied; it is never a peer/validator argument.
pub(super) fn prepare(m: &Metadata, input: &PrimaryInputs) -> Result<(ProgramAir, PrivateTrace)> {
    let built = complete_build(m).map_err(|_| Error::Origin)?;
    let public = super::public_values::Expected::checked(m).map_err(|_| Error::Shape)?;
    let air = ProgramAir {
        plan: Plan::new(built.pool).map_err(|_| Error::Shape)?,
    };
    let trace = from_plan(&air, &built.origins, &public, input)?;
    Ok((air, trace))
}
/// Same closed writer for independently prepared immutable role setup. No private
/// trace, inputs, randomness or verdict is retained by that setup.
pub(super) fn from_plan(
    air: &ProgramAir,
    origins: &super::recipes::Origins,
    public: &super::public_values::Expected,
    input: &PrimaryInputs,
) -> Result<PrivateTrace> {
    let plan = &air.plan;
    plan.inventory().map_err(|_| Error::Shape)?;
    // ONE complete SSA execution, genuine 209 P2, SAME recipes and all MAIN cells.
    let values = Evaluator::new(&plan.pool, origins, input, public)?.finish()?;
    if plan.height != 512 || plan.rows.len() > 512 {
        return Err(Error::Resource);
    }
    let cells = plan.height.checked_mul(WIDTH).ok_or(Error::Resource)?;
    let mut trace = PrivateTrace(RowMajorMatrix::new(vec![Val::ZERO; cells], WIDTH));
    for (r, layout) in plan.rows.iter().enumerate() {
        let row = &mut trace.0.values[r * WIDTH..(r + 1) * WIDTH];
        for (i, port) in layout.ports.iter().enumerate() {
            row[248 + i] = values.values[port.id];
        }
        if let Some(hash) = layout.hash {
            row[..248].copy_from_slice(&values.hashes[hash]);
        }
        if layout.range {
            for slot in 0..8 {
                let n = row[248 + 12 + slot].as_canonical_u64();
                for bit in 0..32 {
                    if layout.bits[32 * slot + bit] {
                        row[248 + PORTS + 32 * slot + bit] = Val::from_bool(n & (1u64 << bit) != 0);
                    }
                }
            }
        }
        if layout.mask.is_some() {
            for slot in 0..8 {
                let n = row[248 + 8 + slot].as_canonical_u64();
                if n > 4 {
                    return Err(Error::Arithmetic);
                }
                for bit in 0..3 {
                    row[248 + PORTS + 3 * slot + bit] = Val::from_bool(n & (1 << bit) != 0);
                }
            }
        }
    }
    Ok(trace)
}
