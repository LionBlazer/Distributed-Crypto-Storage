//! Private i128 witness construction; the AIR, not this constructor, enforces ranges.
use super::{
    DELTA, N, Q, basis, encoding,
    statement::{Expected, Statement},
};
use crate::backend::{Error, Val};
use crate::opening::key_transform;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

pub(in crate::opening) struct Witness {
    pub(in crate::opening) r: [Vec<i128>; 5],
    pub(in crate::opening) k: [Vec<i128>; 5],
    pub(in crate::opening) error: Vec<i8>,
    pub(in crate::opening) w: Vec<u64>,
    pub(in crate::opening) salts: [[Val; 4]; 7],
}
pub(in crate::opening) fn signed(v: i128) -> Val {
    bfv_ciphertext_formation::circuit::signed(v)
}
pub(super) fn centered(v: Val) -> Result<i128, Error> {
    bfv_ciphertext_formation::circuit::centered(v)
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
        bfv_ciphertext_formation::circuit::trace_values(
            core::array::from_fn(|i| self.r[i].as_slice()),
            core::array::from_fn(|i| self.k[i].as_slice()),
            &self.error,
            &self.w,
            self.salts,
        )
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
    bfv_ciphertext_formation::circuit::refresh_contexts(contexts, t)
}
