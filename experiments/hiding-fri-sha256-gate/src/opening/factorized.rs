//! One fixed public periodic basis for the separate packed experiment.
//! Values are verifier-owned constants, never private witness columns.
use crate::backend::{TRACE_HEIGHT, Val};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};
use std::mem::size_of;

pub(crate) const LOW: usize = 32;
pub(crate) const HIGH: usize = 16;
pub(crate) const COLUMNS: usize = LOW + HIGH;
pub(crate) const PAYLOAD_BYTES: usize = (LOW * LOW + HIGH * TRACE_HEIGHT) * size_of::<Val>();
const _: () = assert!(LOW * HIGH == TRACE_HEIGHT && COLUMNS == 48 && PAYLOAD_BYTES == 73_728);

/// Low columns come first, each one period 32; high columns follow, period 512.
pub(super) fn columns() -> Vec<Vec<Val>> {
    (0..LOW)
        .map(|selected| {
            (0..LOW)
                .map(|row| Val::from_bool(row == selected))
                .collect()
        })
        .chain((0..HIGH).map(|selected| {
            (0..TRACE_HEIGHT)
                .map(|row| Val::from_bool(row / LOW == selected))
                .collect()
        }))
        .collect()
}

/// On the original trace rows this is the exact original 512 one-hot schedule.
/// At an OOD point these are products, so SDK weighted-degree inference is mandatory.
pub(super) fn selectors<E: PrimeCharacteristicRing, T: Copy + Into<E>>(
    values: &[T],
) -> [E; TRACE_HEIGHT] {
    assert_eq!(values.len(), COLUMNS);
    core::array::from_fn(|row| {
        let low: E = values[row % LOW].into();
        let high: E = values[LOW + row / LOW].into();
        low * high
    })
}

/// Distinct unreleased profile; the original packed profile remains unchanged.
pub(crate) fn profile(hash: &mut Sha256) {
    hash.update(b"DCS/experimental/factorized-packed-index-N4/v1/no-SQL-acceptance");
    super::packed_index_profile(hash);
    hash.update(b"public-only/low32-first-period32-onehot/high16-next-period512-block32");
    hash.update(b"selector[row]=low[row%32]*high[row/32]/original-domain512/no-OOD-shortcut");
    hash.update(b"same-packed82/declared-bound5/infer-actual-weighted-degree-before-trace");
    for value in [TRACE_HEIGHT, LOW, HIGH, COLUMNS, PAYLOAD_BYTES, 5] {
        hash.update((value as u64).to_le_bytes());
    }
    for low in 0..LOW {
        hash.update([0]);
        hash.update((low as u64).to_le_bytes());
        hash.update((LOW as u64).to_le_bytes());
    }
    for high in 0..HIGH {
        hash.update([1]);
        hash.update((high as u64).to_le_bytes());
        hash.update((TRACE_HEIGHT as u64).to_le_bytes());
    }
}
