//! Actual native BASE and original lookup-expression diagnostics, NOT verification.
//! No challenges, AUX, PCS, proof, accepted state or SQL result is produced.
use super::{
    air::ProgramAir,
    evaluate::{Error, Result},
    plan::{PP_WIDTH, WIDTH},
    witness::PrivateTrace,
};
use crate::Val;
use bfv_hiding_stark::Challenge;
use p3_air::{BaseAir, DebugConstraintBuilder, check_all_constraints};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{Kind, Lookups};
use p3_matrix::{Matrix, dense::RowMajorMatrixView, stack::ViewPair};
use std::collections::BTreeMap;
fn shape(air: &ProgramAir, trace: &PrivateTrace) -> Result<()> {
    if air.plan.height != 512
        || trace.0.width != WIDTH
        || trace.0.values.len() != 512 * WIDTH
        || air.preprocessed_width() != PP_WIDTH
    {
        return Err(Error::Shape);
    }
    air.plan.inventory().map_err(|_| Error::Shape)
}
pub(super) fn base(air: &ProgramAir, trace: &PrivateTrace) -> Result<()> {
    shape(air, trace)?;
    // Public SDK nonpanicking failure collection; never print a private row/value.
    let report = check_all_constraints(air, &trace.0, &[], Some(1));
    if !report.is_ok() {
        return Err(Error::Base);
    }
    Ok(())
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    bus: u8,
    len: usize,
    words: [u64; 5],
}
impl Drop for Key {
    fn drop(&mut self) {
        self.words.fill(0);
    }
}
struct Totals(BTreeMap<Key, Val>);
impl Drop for Totals {
    fn drop(&mut self) {
        for v in self.0.values_mut() {
            *v = Val::ZERO;
        }
    }
}
pub(super) fn lookups(air: &ProgramAir, trace: &PrivateTrace) -> Result<()> {
    shape(air, trace)?;
    let pp = air.preprocessed_trace().ok_or(Error::Shape)?;
    let original = Lookups::<Val>::from_air::<Challenge, ProgramAir>(air);
    p3_lookup::check_bus_widths(core::slice::from_ref(&original)).map_err(|_| Error::Shape)?;
    p3_lookup::check_multiplicity_height_bound(core::slice::from_ref(&original), &[512])
        .map_err(|_| Error::Shape)?;
    let mut totals = Totals(BTreeMap::new());
    for row in 0..512 {
        let next = (row + 1) % 512;
        let ml = trace.0.row_slice(row).ok_or(Error::Shape)?;
        let mn = trace.0.row_slice(next).ok_or(Error::Shape)?;
        let pl = pp.row_slice(row).ok_or(Error::Shape)?;
        let pn = pp.row_slice(next).ok_or(Error::Shape)?;
        let builder = DebugConstraintBuilder::<Val>::new(
            row,
            ViewPair::new(
                RowMajorMatrixView::new_row(&ml),
                RowMajorMatrixView::new_row(&mn),
            ),
            ViewPair::new(
                RowMajorMatrixView::new_row(&pl),
                RowMajorMatrixView::new_row(&pn),
            ),
            &[],
            Val::from_bool(row == 0),
            Val::from_bool(row == 511),
            Val::from_bool(row != 511),
            &[],
        );
        // Resolve the ACTUAL symbolic messages emitted by ProgramAir, including their
        // actual signed PP counts. This is not a handwritten alternative lookup table.
        for lookup in original.iter() {
            let bus = match &lookup.kind {
                Kind::Global(s) => match s.as_str() {
                    "DCS/research/word208/v1/ssa" => 0,
                    "DCS/research/word208/v1/policy25" => 1,
                    "DCS/research/word208/v1/mask256" => 2,
                    _ => return Err(Error::Shape),
                },
                Kind::Local => return Err(Error::Shape),
            };
            if lookup.elements.len() != lookup.multiplicities.len() {
                return Err(Error::Shape);
            }
            for (t, fields) in lookup.elements.iter().enumerate() {
                let mut count = lookup.multiplicities[t].resolve(&builder);
                if let Some(flags) = &lookup.flags {
                    count *= flags.get(t).ok_or(Error::Shape)?.resolve(&builder);
                }
                if count == Val::ZERO {
                    continue;
                }
                if fields.len() != if bus == 1 { 5 } else { 2 } {
                    return Err(Error::Shape);
                }
                let mut key = Key {
                    bus,
                    len: fields.len(),
                    words: [0; 5],
                };
                for (i, field) in fields.iter().enumerate() {
                    key.words[i] = field.resolve(&builder).as_canonical_u64();
                }
                if totals.0.len() >= 65_536 && !totals.0.contains_key(&key) {
                    return Err(Error::Resource);
                }
                *totals.0.entry(key).or_insert(Val::ZERO) += count;
            }
        }
    }
    if totals.0.values().any(|v| *v != Val::ZERO) {
        return Err(Error::Lookup);
    }
    Ok(())
}
pub(super) fn all(air: &ProgramAir, trace: &PrivateTrace) -> Result<()> {
    base(air, trace)?;
    lookups(air, trace)
}
