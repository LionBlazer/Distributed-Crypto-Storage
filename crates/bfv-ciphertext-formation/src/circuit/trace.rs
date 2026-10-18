//! Exact fixed row writer for caller-owned mathematical inputs; native field buffers are not wiped.
use super::air::*;
use crate::{N, STREAMS};
use bfv_hiding_stark::{Error, TRACE_HEIGHT, Val, poseidon};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
fn bits(out: &mut [Val], v: u64) {
    for (i, b) in out.iter_mut().enumerate() {
        *b = Val::from_u64((v >> i) & 1);
    }
}
pub fn trace_values(
    r: [&[i128]; 5],
    k: [&[i128]; 5],
    error: &[i8],
    w: &[u64],
    salts: [[Val; 4]; 7],
) -> Result<RowMajorMatrix<Val>, Error> {
    if r.iter().chain(&k).any(|v| v.len() != N) || w.len() != N || error.len() != N {
        return Err(Error::Shape);
    }
    let mut t = RowMajorMatrix::new(Val::zero_vec(TRACE_HEIGHT * WIDTH), WIDTH);
    for (physical, row) in t.values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
        for stream in 0..STREAMS {
            row[SALTS + 4 * stream..SALTS + 4 * stream + 4].copy_from_slice(&salts[stream]);
        }
        for lane in 0..16 {
            let j = physical * 16 + lane;
            let at = COEFFICIENTS + lane * LANE_BITS;
            for i in 0..5 {
                let z = r[i][j] + (1i128 << 62);
                let k = k[i][j] + (1i128 << 19);
                if !(0..(1i128 << 63)).contains(&z) || !(0..(1i128 << 20)).contains(&k) {
                    return Err(Error::Shape);
                }
                bits(&mut row[at + i * 63..at + (i + 1) * 63], z as u64);
                bits(&mut row[at + 315 + i * 20..at + 335 + i * 20], k as u64);
            }
            let z = i16::from(error[j]) + 20;
            if !(0..=40).contains(&z) || w[j] > 114688 {
                return Err(Error::Shape);
            }
            for (start, len, v) in [
                (415, 6, z as u64),
                (421, 6, (40 - z) as u64),
                (427, 17, w[j]),
                (444, 17, 114688 - w[j]),
            ] {
                bits(&mut row[at + start..at + start + len], v);
            }
        }
    }
    Ok(t)
}
pub fn refresh_contexts(contexts: [[Val; 8]; 7], t: &mut RowMajorMatrix<Val>) -> [[Val; 4]; 7] {
    let mut cp = [[Val::ZERO; 12]; 7];
    let mut carry = [[Val::ZERO; 8]; 7];
    for (r, row) in t.values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
        for st in 0..STREAMS {
            row[CP + 12 * st..CP + 12 * st + 12].copy_from_slice(&cp[st]);
            row[CARRY + 8 * st..CARRY + 8 * st + 8].copy_from_slice(&carry[st]);
            for g in 0..3 {
                let active = r < 2 || g < 2;
                let mut input = [Val::ZERO; 12];
                if active {
                    for (slot, v) in input[..8].iter_mut().enumerate() {
                        *v = match (r, g) {
                            (0, 0) => contexts[st][slot],
                            (0, 1) => {
                                if slot < 4 {
                                    row[SALTS + 4 * st + slot]
                                } else {
                                    Val::ZERO
                                }
                            }
                            (0, 2) => value::<Val, _>(row, slot, st),
                            (1, 0) => carry[st][slot],
                            (1, 1) => value::<Val, _>(row, slot, st),
                            (_, 0) => value::<Val, _>(row, slot, st),
                            _ => value::<Val, _>(row, 8 + slot, st),
                        };
                    }
                    if !(r == 0 && g == 0) {
                        input[8..].copy_from_slice(&cp[st][8..]);
                    }
                }
                let out = poseidon::write(
                    &mut row[(st * 3 + g) * poseidon::WIDTH..(st * 3 + g + 1) * poseidon::WIDTH],
                    input,
                );
                if active {
                    cp[st] = out;
                }
            }
            carry[st] = if r == 0 {
                core::array::from_fn(|i| value::<Val, _>(row, 8 + i, st))
            } else {
                [Val::ZERO; 8]
            };
        }
    }
    core::array::from_fn(|i| cp[i][..4].try_into().unwrap())
}
