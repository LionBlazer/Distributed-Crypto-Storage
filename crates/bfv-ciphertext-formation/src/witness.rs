//! Explicit caller-owned opening and private integer witness preparation; never derives W by decryption.
use crate::{DELTA, EncodedCommitment, Expected, N, Q, Statement, circuit};
use bfv_hiding_stark::{Error, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use zeroize::Zeroizing;

/// Caller-owned mathematical W opening. It has no producer authority or private getters.
pub struct EncodedOpening {
    pub(crate) w: Zeroizing<Vec<u64>>,
    pub(crate) salt: Zeroizing<[u64; 4]>,
    pub(crate) commitment: EncodedCommitment,
}
impl EncodedOpening {
    pub fn new(
        w: Zeroizing<Vec<u64>>,
        salt: [u64; 4],
        commitment: EncodedCommitment,
    ) -> Result<Self, Error> {
        if w.len() != N
            || w.iter().any(|x| *x >= 114689)
            || salt.iter().any(|x| *x >= Val::ORDER_U64)
        {
            return Err(Error::Shape);
        }
        let values: Vec<_> = w.iter().copied().map(Val::from_u64).collect();
        let root = bfv_key_transform::circuit::digest(
            commitment.context().map(Val::from_u64),
            salt.map(Val::from_u64),
            &values,
        )
        .map(|v| v.as_canonical_u64());
        if root != commitment.root() {
            return Err(Error::Shape);
        }
        Ok(Self {
            w,
            salt: Zeroizing::new(salt),
            commitment,
        })
    }
}
/// Borrows explicit caller-owned Shat and opening. Owner APIs never export either through this type.
pub struct ProverWitness<'a> {
    opening: &'a EncodedOpening,
    shat: &'a [u64],
    salts: Zeroizing<[[u64; 4]; 6]>,
}
impl<'a> ProverWitness<'a> {
    pub fn new(
        opening: &'a EncodedOpening,
        shat: &'a [u64],
        result_salts: [[u64; 4]; 5],
        noise_salt: [u64; 4],
    ) -> Result<Self, Error> {
        if shat.len() != N
            || shat
                .iter()
                .chain(result_salts.iter().flatten())
                .chain(&noise_salt)
                .any(|x| *x >= Val::ORDER_U64)
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            opening,
            shat,
            salts: Zeroizing::new(core::array::from_fn(|i| {
                if i < 5 { result_salts[i] } else { noise_salt }
            })),
        })
    }
    pub(crate) fn prepare(
        &self,
        expected: &Expected,
        full_setup_id: [u8; 32],
    ) -> Result<Prepared<'_>, Error> {
        expected.validate()?;
        if self.opening.commitment != *expected.encoding() {
            return Err(Error::Shape);
        }
        let shat: Vec<_> = self.shat.iter().copied().map(Val::from_u64).collect();
        let mut r: [Zeroizing<Vec<i128>>; 5] =
            core::array::from_fn(|_| Zeroizing::new(Vec::with_capacity(N)));
        let mut k: [Zeroizing<Vec<i128>>; 5] =
            core::array::from_fn(|_| Zeroizing::new(Vec::with_capacity(N)));
        let mut error = Zeroizing::new(vec![0i8; N]);
        for i in 0..5 {
            let base = &expected.bases[i];
            let values = bfv_basis_convolution::circuit::oracle(
                &shat,
                base.expected.ciphertext().evaluations(),
            );
            let root = bfv_key_transform::circuit::digest(
                base.contexts()[1],
                self.salts[i].map(Val::from_u64),
                &values,
            );
            if root != base.result {
                return Err(Error::Shape);
            }
            for (j, v) in values.into_iter().enumerate() {
                let integer = circuit::centered(v)?;
                let d = i128::from(base.expected.ciphertext().b_coefficients()[j]) + integer
                    - i128::from(DELTA[i]) * i128::from(self.opening.w[j]);
                let residue = d.rem_euclid(i128::from(Q[i]));
                let e = if residue <= i128::from(Q[i]) / 2 {
                    residue
                } else {
                    residue - i128::from(Q[i])
                };
                if !(-20..=20).contains(&e) {
                    return Err(Error::Shape);
                }
                let e = i8::try_from(e).map_err(|_| Error::Shape)?;
                if i == 0 {
                    error[j] = e;
                } else if error[j] != e {
                    return Err(Error::Shape);
                }
                let numerator = d - i128::from(e);
                if numerator % i128::from(Q[i]) != 0 {
                    return Err(Error::Shape);
                }
                let quotient = numerator / i128::from(Q[i]);
                if !(-(1i128 << 19)..(1i128 << 19)).contains(&quotient) {
                    return Err(Error::Shape);
                }
                r[i].push(integer);
                k[i].push(quotient);
            }
        }
        let mut statement = Statement {
            expected: expected.clone(),
            full_setup_id,
            noise: [Val::ZERO; 4],
        };
        let signed: Vec<_> = error
            .iter()
            .map(|e| circuit::signed(i128::from(*e)))
            .collect();
        statement.noise = bfv_key_transform::circuit::digest(
            statement.contexts()[6],
            self.salts[5].map(Val::from_u64),
            &signed,
        );
        Ok(Prepared {
            r,
            k,
            error,
            w: &self.opening.w,
            salts: core::array::from_fn(|i| match i {
                0..=4 => self.salts[i].map(Val::from_u64),
                5 => (*self.opening.salt).map(Val::from_u64),
                _ => self.salts[5].map(Val::from_u64),
            }),
            statement,
        })
    }
}
pub(crate) struct Prepared<'a> {
    pub r: [Zeroizing<Vec<i128>>; 5],
    pub k: [Zeroizing<Vec<i128>>; 5],
    pub error: Zeroizing<Vec<i8>>,
    pub w: &'a [u64],
    pub salts: [[Val; 4]; 7],
    pub statement: Statement,
}
impl Prepared<'_> {
    pub fn trace(&self) -> Result<RowMajorMatrix<Val>, Error> {
        let mut trace = circuit::trace_values(
            core::array::from_fn(|i| self.r[i].as_slice()),
            core::array::from_fn(|i| self.k[i].as_slice()),
            &self.error,
            self.w,
            self.salts,
        )?;
        let _ = circuit::refresh_contexts(self.statement.contexts(), &mut trace);
        Ok(trace)
    }
}
