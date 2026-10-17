//! Prover-only conversion of the existing sealed full auxiliary certificate.
use super::{
    PreparedMachine, RANGES, RangeKind, TableKind,
    air::{R2_COLUMNS, R9_COLUMNS, R14_COLUMNS, R16_COLUMNS},
};
use crate::{Aux, DEGREE, Error, Result, codec, parameters::lane};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_matrix::dense::RowMajorMatrix;

fn put(out: &mut [u64], value: u128) {
    let n = out.len();
    for (slot, digit) in out.iter_mut().zip(crate::math::digits(value, n)) {
        *slot = u64::from(digit);
    }
}
pub(super) fn build(machine: &PreparedMachine, aux: &Aux) -> Result<Vec<RowMajorMatrix<Val>>> {
    codec::check_binding(&machine.request, &machine.output, aux)?;
    let mut counts: [Vec<u64>; 4] = RANGES.map(|range| vec![0; range.domain_size()]);
    let mut traces = Vec::with_capacity(machine.airs.len());
    let direction = machine.direction();
    let basis = machine.basis();
    for air in &machine.airs {
        match air.table_kind() {
            TableKind::Stage(stage) => {
                let previous = if stage == 0 {
                    machine.request.input()
                } else {
                    aux.stages()[stage - 1].coefficients()
                };
                let output = &aux.stages()[stage];
                let mut values = Vec::with_capacity(DEGREE * 35);
                for j in 0..DEGREE {
                    let l = lane(direction, basis, stage, j);
                    let certificate = &output.rows()[j];
                    let z = output.coefficients()[j];
                    let mut row = [0u64; 35];
                    put(&mut row[..4], previous[l.x] as u128);
                    put(
                        &mut row[4..8],
                        if l.b == 0 { 0 } else { previous[l.y] as u128 },
                    );
                    put(&mut row[8..12], z as u128);
                    put(&mut row[12..16], (basis.modulus() - 1 - z) as u128);
                    put(&mut row[16..21], certificate.biased_quotient());
                    for (i, &carry) in certificate.carries().iter().enumerate() {
                        row[21 + i] = u64::from(carry & 65535);
                        row[28 + i] = u64::from(carry >> 16);
                    }
                    for (range, columns) in [
                        (RangeKind::R16, &R16_COLUMNS[..]),
                        (RangeKind::R14, &R14_COLUMNS[..]),
                        (RangeKind::R9, &R9_COLUMNS[..]),
                        (RangeKind::R2, &R2_COLUMNS[..]),
                    ] {
                        for &column in columns {
                            let count = counts[range.index()]
                                .get_mut(row[column] as usize)
                                .ok_or(Error::AuxiliaryRange)?;
                            *count = count.checked_add(1).ok_or(Error::Arithmetic)?;
                        }
                    }
                    values.extend(row.into_iter().map(Val::from_u64));
                }
                traces.push(RowMajorMatrix::new(values, 35));
            }
            TableKind::Io => traces.push(RowMajorMatrix::new(vec![Val::ZERO; DEGREE], 1)),
            TableKind::Range(range) => {
                let mut values = Vec::with_capacity(range.height() * 2);
                for index in 0..range.height() {
                    let value = index % range.domain_size();
                    // R2 repeats0..3 fourtimes; place all frequency on the first copy.
                    let count = if index < range.domain_size() {
                        counts[range.index()][value]
                    } else {
                        0
                    };
                    values.extend([Val::from_usize(value), Val::from_u64(count)]);
                }
                traces.push(RowMajorMatrix::new(values, 2));
            }
        }
    }
    Ok(traces)
}
