//! Private i128 witness construction; the AIR, not this constructor, enforces ranges.
use super::{
    DELTA, N, Q, STREAMS,
    air::*,
    basis, encoding,
    statement::{Expected, Statement},
};
use crate::backend::{Error, TRACE_HEIGHT, Val};
use crate::opening::{key_transform, poseidon};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;

pub(in crate::opening) struct Witness {
    pub(in crate::opening) r: [Vec<i128>; 5],
    pub(in crate::opening) k: [Vec<i128>; 5],
    pub(in crate::opening) error: Vec<i8>,
    pub(in crate::opening) w: Vec<u64>,
    pub(in crate::opening) salts: [[Val; 4]; 7],
}
pub(in crate::opening) fn signed(v: i128) -> Val {
    if v < 0 {
        -Val::from_u64((-v) as u64)
    } else {
        Val::from_u64(v as u64)
    }
}
pub(super) fn centered(v: Val) -> Result<i128, Error> {
    let n = i128::from(v.as_canonical_u64());
    let p = 18446744069414584321i128;
    let value = if n < (1i128 << 62) { n } else { n - p };
    if !(-(1i128 << 62)..(1i128 << 62)).contains(&value) {
        return Err(Error::Shape);
    }
    Ok(value)
}
fn bits(out: &mut [Val], v: u64) {
    for (i, b) in out.iter_mut().enumerate() {
        *b = Val::from_u64((v >> i) & 1);
    }
}
impl Witness {
    pub(super) fn new(
        expected: &Expected,
        key: &key_transform::trace::Witness,
        encoded: &encoding::trace::Witness,
        error: Vec<i8>,
        r_salts: [[Val; 4]; 5],
        noise_salt: [Val; 4],
    ) -> Result<Self, Error> {
        expected.validate()?;
        Self::from_bases(&expected.bases, key, encoded, error, r_salts, noise_salt)
    }
    pub(in crate::opening) fn returned(
        expected: &crate::opening::locking::formation::statement::Expected,
        key: &key_transform::trace::Witness,
        encoded: &encoding::trace::Witness,
        error: Vec<i8>,
        r_salts: [[Val; 4]; 5],
        noise_salt: [Val; 4],
    ) -> Result<Self, Error> {
        expected.validate()?;
        Self::from_bases(&expected.bases, key, encoded, error, r_salts, noise_salt)
    }
    fn from_bases(
        bases: &[basis::statement::Statement; 5],
        key: &key_transform::trace::Witness,
        encoded: &encoding::trace::Witness,
        error: Vec<i8>,
        r_salts: [[Val; 4]; 5],
        noise_salt: [Val; 4],
    ) -> Result<Self, Error> {
        if error.len() != N || error.iter().any(|e| !(-20..=20).contains(e)) {
            return Err(Error::Shape);
        }
        let w: Vec<_> = encoded.coefficients().into_iter().map(|(_, w)| w).collect();
        let shat = key_transform::trace::oracle(
            &key.coefficients
                .iter()
                .copied()
                .map(key_transform::signed)
                .collect::<Vec<_>>(),
        );
        let mut rs = Vec::new();
        let mut ks = Vec::new();
        for (i, s) in bases.iter().enumerate() {
            let values = basis::trace::oracle(&shat, s.expected.ciphertext().evaluations());
            let r = values
                .into_iter()
                .map(centered)
                .collect::<Result<Vec<_>, _>>()?;
            let mut k = Vec::with_capacity(N);
            for j in 0..N {
                let f = i128::from(s.expected.ciphertext().b_coefficients()[j]) + r[j]
                    - i128::from(error[j])
                    - i128::from(DELTA[i]) * i128::from(w[j]);
                if f % i128::from(Q[i]) != 0 {
                    return Err(Error::Shape);
                }
                let v = f / i128::from(Q[i]);
                if !(-(1 << 19)..(1 << 19)).contains(&v) {
                    return Err(Error::Shape);
                }
                k.push(v);
            }
            rs.push(r);
            ks.push(k);
        }
        let salts = core::array::from_fn(|s| match s {
            0..=4 => r_salts[s],
            5 => encoded.encoding_salt,
            _ => noise_salt,
        });
        Ok(Self {
            r: rs.try_into().map_err(|_| Error::Shape)?,
            k: ks.try_into().map_err(|_| Error::Shape)?,
            error,
            w,
            salts,
        })
    }
    pub(super) fn statement(&self, expected: Expected) -> Statement {
        let mut s = Statement {
            expected,
            noise: [Val::ZERO; 4],
        };
        s.noise = key_transform::trace::digest(
            s.noise_context(),
            self.salts[6],
            &self
                .error
                .iter()
                .map(|e| signed(i128::from(*e)))
                .collect::<Vec<_>>(),
        );
        s
    }
    pub(super) fn trace(&self, s: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        let mut t = self.trace_values()?;
        let _ = refresh_hashes(s, &mut t);
        Ok(t)
    }
    pub(in crate::opening) fn trace_returned(
        &self,
        s: &crate::opening::locking::formation::statement::Statement,
    ) -> Result<RowMajorMatrix<Val>, Error> {
        let mut t = self.trace_values()?;
        let _ = refresh_returned(s, &mut t);
        Ok(t)
    }
    fn trace_values(&self) -> Result<RowMajorMatrix<Val>, Error> {
        if self.r.iter().chain(&self.k).any(|v| v.len() != N)
            || self.w.len() != N
            || self.error.len() != N
        {
            return Err(Error::Shape);
        }
        let mut t = RowMajorMatrix::new(Val::zero_vec(TRACE_HEIGHT * WIDTH), WIDTH);
        for (physical, row) in t.values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            for stream in 0..STREAMS {
                row[SALTS + 4 * stream..SALTS + 4 * stream + 4]
                    .copy_from_slice(&self.salts[stream]);
            }
            for lane in 0..16 {
                let j = physical * 16 + lane;
                let at = COEFFICIENTS + lane * LANE_BITS;
                for i in 0..5 {
                    let z = self.r[i][j] + (1i128 << 62);
                    let k = self.k[i][j] + (1i128 << 19);
                    if !(0..(1i128 << 63)).contains(&z) || !(0..(1i128 << 20)).contains(&k) {
                        return Err(Error::Shape);
                    }
                    bits(&mut row[at + i * 63..at + (i + 1) * 63], z as u64);
                    bits(&mut row[at + 315 + i * 20..at + 335 + i * 20], k as u64);
                }
                let z = i16::from(self.error[j]) + 20;
                if !(0..=40).contains(&z) || self.w[j] > 114688 {
                    return Err(Error::Shape);
                }
                for (start, len, v) in [
                    (415, 6, z as u64),
                    (421, 6, (40 - z) as u64),
                    (427, 17, self.w[j]),
                    (444, 17, 114688 - self.w[j]),
                ] {
                    bits(&mut row[at + start..at + start + len], v);
                }
            }
        }
        Ok(t)
    }
}
pub(super) fn refresh_hashes(s: &Statement, t: &mut RowMajorMatrix<Val>) -> [[Val; 4]; 7] {
    refresh_contexts(s.contexts(), t)
}
pub(in crate::opening) fn refresh_returned(
    s: &crate::opening::locking::formation::statement::Statement,
    t: &mut RowMajorMatrix<Val>,
) -> [[Val; 4]; 7] {
    refresh_contexts(s.contexts(), t)
}
fn refresh_contexts(contexts: [[Val; 8]; 7], t: &mut RowMajorMatrix<Val>) -> [[Val; 4]; 7] {
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
