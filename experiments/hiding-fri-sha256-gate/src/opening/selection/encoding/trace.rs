//! Private bounded witness. No Owner import/export or serialized secret handle.
use super::{air::*, matrix, statement::Statement};
use crate::backend::{Error, TRACE_HEIGHT, Val};
use crate::opening::{
    poseidon,
    selection::{statement as selection, trace::Witness as SelectedWitness},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;

pub(in crate::opening) struct Witness {
    pub(in crate::opening) tuples: [[u32; 12]; 4],
    pub(in crate::opening) selected_salt: [Val; 4],
    pub(in crate::opening) encoding_salt: [Val; 4],
}
pub(in crate::opening) fn bits(out: &mut [Val], v: u64) {
    for (i, x) in out.iter_mut().enumerate() {
        *x = Val::from_u64((v >> i) & 1);
    }
}
impl Witness {
    pub(in crate::opening) fn from_selection(
        s: &selection::Statement,
        w: &SelectedWitness,
        salt: [Val; 4],
    ) -> Result<Self, Error> {
        let fields = selection::selected_fields(s, w);
        let mut tuples = [[0; 12]; 4];
        for (i, tuple) in tuples.iter_mut().enumerate() {
            for (j, value) in tuple.iter_mut().enumerate() {
                *value = u32::try_from(fields[34 + i * 12 + j].as_canonical_u64())
                    .map_err(|_| Error::Shape)?;
            }
        }
        Ok(Self {
            tuples,
            selected_salt: w.salts[2],
            encoding_salt: salt,
        })
    }
    pub(in crate::opening) fn original(&self) -> [u64; 12] {
        core::array::from_fn(|k| u64::from(self.tuples[k % 4][[2, 3, 0][k / 4]]))
    }
    pub(in crate::opening) fn coefficients(&self) -> Vec<(u64, u64)> {
        let original = self.original();
        matrix::coefficients()
            .iter()
            .map(|a| {
                let dot: u64 = a.iter().zip(original).map(|(a, x)| u64::from(*a) * x).sum();
                let m = dot % matrix::T;
                (m, m * matrix::Q_MOD_T % matrix::T)
            })
            .collect()
    }
    pub(in crate::opening) fn statement(&self, selection: &selection::Statement) -> Statement {
        let mut s = Statement::new(selection, [Val::ZERO; 4]);
        s.encoded = self.digest(s.context());
        s
    }
    fn digest(&self, context: [Val; 8]) -> [Val; 4] {
        let mut fields: Vec<_> = context
            .into_iter()
            .chain(self.encoding_salt)
            .chain([Val::ZERO; 4])
            .collect();
        fields.extend(
            self.coefficients()
                .into_iter()
                .map(|(_, w)| Val::from_u64(w)),
        );
        assert_eq!(fields.len(), 8208);
        let permutation = default_goldilocks_poseidon2_12();
        let mut state = [Val::ZERO; 12];
        for block in fields.as_chunks::<8>().0 {
            state[..8].copy_from_slice(block);
            permutation.permute_mut(&mut state);
        }
        state[..4].try_into().unwrap()
    }
    pub(in crate::opening) fn from_lock(
        s: &crate::opening::locking::encoding::statement::Statement,
        w: &crate::opening::locking::trace::Witness,
        salt: [Val; 4],
    ) -> Result<Self, Error> {
        let fields =
            crate::opening::locking::statement::output_fields(s.expected.lock(), w, false)?;
        let mut tuples = [[0; 12]; 4];
        for (i, tuple) in tuples.iter_mut().enumerate() {
            for (j, value) in tuple.iter_mut().enumerate() {
                *value = u32::try_from(fields[119 + i * 12 + j].as_canonical_u64())
                    .map_err(|_| Error::Shape)?;
            }
        }
        Ok(Self {
            tuples,
            selected_salt: w.salts[5],
            encoding_salt: salt,
        })
    }
    pub(in crate::opening) fn returned_statement(
        &self,
        expected: crate::opening::locking::encoding::statement::Expected,
    ) -> crate::opening::locking::encoding::statement::Statement {
        let mut s =
            crate::opening::locking::encoding::statement::Statement::new(expected, [Val::ZERO; 4]);
        s.encoded = self.digest(s.context());
        s
    }
    pub(in crate::opening) fn trace_returned(
        &self,
        s: &crate::opening::locking::encoding::statement::Statement,
    ) -> Result<RowMajorMatrix<Val>, Error> {
        self.trace_with_air(EncodingAir::returned(s))
    }
    pub(super) fn trace(&self, s: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        self.trace_with_air(EncodingAir::new(s))
    }
    fn trace_with_air(&self, air: EncodingAir) -> Result<RowMajorMatrix<Val>, Error> {
        let mut values = Val::zero_vec(TRACE_HEIGHT * WIDTH);
        let original = self.original();
        let coefficients = self.coefficients();
        for (r, row) in values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            for (slot, tuple) in self.tuples.iter().enumerate() {
                let at = BANK + slot * TUPLE_BITS;
                for (part, (start, len)) in [(0, 1), (1, 2), (3, 8), (11, 16)]
                    .into_iter()
                    .chain((0..8).map(|i| (27 + 32 * i, 32)))
                    .enumerate()
                {
                    bits(
                        &mut row[at + start..at + start + len],
                        u64::from(tuple[part]),
                    );
                }
            }
            row[SEL_SALT..ENC_SALT].copy_from_slice(&self.selected_salt);
            row[ENC_SALT..COEFF].copy_from_slice(&self.encoding_salt);
            for l in 0..16 {
                let dot: u64 = matrix::coefficients()[r * 16 + l]
                    .iter()
                    .zip(original)
                    .map(|(a, x)| u64::from(*a) * x)
                    .sum();
                let (m, w) = coefficients[r * 16 + l];
                let fields = [
                    m,
                    w,
                    dot / matrix::T,
                    m * matrix::Q_MOD_T / matrix::T,
                    matrix::T - 1 - m,
                    matrix::T - 1 - w,
                ];
                for ((start, len), v) in [(0, 17), (17, 17), (34, 19), (53, 17), (70, 17), (87, 17)]
                    .into_iter()
                    .zip(fields)
                {
                    let at = COEFF + l * LANE_BITS + start;
                    bits(&mut row[at..at + len], v);
                }
            }
        }
        let mut trace = RowMajorMatrix::new(values, WIDTH);
        let _ = refresh_with_air(&air, &mut trace);
        Ok(trace)
    }
}
/// One producer implementation also lets rebuilt tests recompute every genuine
/// sponge/carry cell after deliberately substituting a forbidden original word.
#[cfg(test)]
pub(super) fn refresh_hashes(s: &Statement, trace: &mut RowMajorMatrix<Val>) -> [Val; 4] {
    refresh_with_air(&EncodingAir::new(s), trace)
}
#[cfg(test)]
pub(in crate::opening) fn refresh_returned(
    s: &crate::opening::locking::encoding::statement::Statement,
    trace: &mut RowMajorMatrix<Val>,
) -> [Val; 4] {
    refresh_with_air(&EncodingAir::returned(s), trace)
}
fn refresh_with_air(air: &EncodingAir, trace: &mut RowMajorMatrix<Val>) -> [Val; 4] {
    let blocks = air.source_blocks();
    let mut source = [Val::ZERO; 12];
    let mut encoded = [Val::ZERO; 12];
    let mut carry = [Val::ZERO; 8];
    let mut final_digest = [Val::ZERO; 4];
    for (r, row) in trace
        .values
        .as_chunks_mut::<WIDTH>()
        .0
        .iter_mut()
        .enumerate()
    {
        row[SOURCE_CP..ENCODED_CP].copy_from_slice(&source);
        row[ENCODED_CP..WIDTH].copy_from_slice(&encoded);
        row[CARRY..SOURCE_CP].copy_from_slice(&carry);
        let mut a = [Val::ZERO; 12];
        if r == 0 {
            a[..8].copy_from_slice(&air.context());
        } else {
            a[..8].copy_from_slice(&carry);
        }
        a[8..].copy_from_slice(&encoded[8..]);
        let a_out = poseidon::write(&mut row[..P2], a);
        let mut b = [Val::ZERO; 12];
        if r == 0 {
            b[..4].copy_from_slice(&row[ENC_SALT..COEFF]);
        } else {
            for (i, v) in b[..8].iter_mut().enumerate() {
                *v = lane(row, i, 1);
            }
        }
        b[8..].copy_from_slice(&a_out[8..]);
        let b_out = poseidon::write(&mut row[P2..2 * P2], b);
        let mut c = [Val::ZERO; 12];
        if r == 0 || r == 511 {
            for (i, v) in c[..8].iter_mut().enumerate() {
                *v = lane(row, if r == 0 { i } else { i + 8 }, 1);
            }
            c[8..].copy_from_slice(&b_out[8..]);
        } else if (1..=blocks).contains(&r) {
            for (i, v) in c[..8].iter_mut().enumerate() {
                *v = air.selected_field(row, (r - 1) * 8 + i);
            }
            c[8..].copy_from_slice(&source[8..]);
        }
        let active = r <= blocks || r == 511;
        row[2 * P2..3 * P2].fill(Val::ZERO);
        let c_out = if active {
            poseidon::write(&mut row[2 * P2..3 * P2], c)
        } else {
            [Val::ZERO; 12]
        };
        if (1..=blocks).contains(&r) {
            source = c_out;
        }
        encoded = if r == 0 { c_out } else { b_out };
        if r == 511 {
            final_digest = c_out[..4].try_into().unwrap();
        }
        for (i, v) in carry.iter_mut().enumerate() {
            *v = lane(row, i + 8, 1);
        }
    }
    final_digest
}
