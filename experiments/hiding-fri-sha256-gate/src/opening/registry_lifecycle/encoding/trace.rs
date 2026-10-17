//! Owner-local trace construction, never called by proof verification.
use super::super::{model::Operation, trace::Witness as ParentWitness};
use super::{
    air::*,
    statement::{Expected, Statement},
};
use crate::backend::{Error, TRACE_HEIGHT, Val};
use crate::opening::{poseidon, selection::encoding::kernel};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;
#[derive(Clone)]
pub(super) struct Witness {
    pub tuples: [[u32; 12]; 4],
    pub plain: [u8; 2348],
    pub source_salt: [Val; 4],
    pub result_salt: [Val; 4],
    pub encoding_salt: [Val; 4],
    pub flags: [bool; 12],
    pub transaction: u64,
    pub routing: [[bool; 4]; 4],
}
fn bits(out: &mut [Val], value: u64) {
    for (i, x) in out.iter_mut().enumerate() {
        *x = Val::from_u64((value >> i) & 1);
    }
}
impl Witness {
    pub(super) fn from_parent(
        e: &Expected,
        w: &ParentWitness,
        salt: [Val; 4],
    ) -> Result<Self, Error> {
        e.require_contract()?;
        let c = w.command.as_ref().ok_or(Error::Shape)?;
        if c.operation != Operation::Acquire {
            return Err(Error::Shape);
        }
        let step = w.old.step(c, e.parent.parent, w.ages())?;
        if step.outcome != 0
            || w.statement(&e.parent)?.public_values() != e.producer.public_values()
        {
            return Err(Error::Shape);
        }
        let mut tuples = [[0; 12]; 4];
        let mut routing = [[false; 4]; 4];
        for (slot, i) in (0..4).filter(|i| step.returned[*i]).enumerate() {
            routing[slot][i] = true;
            tuples[slot][..4].copy_from_slice(&[
                1,
                i as u32,
                u32::from(w.plain[3 * i]),
                u32::from(u16::from_le_bytes([w.plain[3 * i + 1], w.plain[3 * i + 2]])),
            ]);
            for (j, v) in tuples[slot][4..].iter_mut().enumerate() {
                *v = u32::from_le_bytes(
                    w.plain[2220 + i * 32 + j * 4..2224 + i * 32 + j * 4]
                        .try_into()
                        .unwrap(),
                );
            }
        }
        let flags = step
            .returned
            .into_iter()
            .chain(step.skipped)
            .chain(step.visit)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Ok(Self {
            tuples,
            plain: w.plain,
            source_salt: w.salts[0],
            result_salt: w.salts[5],
            encoding_salt: salt,
            flags,
            transaction: c.transaction,
            routing,
        })
    }
    pub(super) fn original(&self) -> [u64; 12] {
        core::array::from_fn(|k| u64::from(self.tuples[k % 4][[2, 3, 0][k / 4]]))
    }
    pub(super) fn coefficients(&self) -> Vec<(u64, u64)> {
        kernel::coefficients(self.original())
    }
    pub(super) fn statement(&self, e: Expected) -> Statement {
        let mut s = Statement::new(e, [Val::ZERO; 4]);
        let mut fields = s
            .context()
            .into_iter()
            .chain(self.encoding_salt)
            .chain([Val::ZERO; 4])
            .collect::<Vec<_>>();
        fields.extend(
            self.coefficients()
                .into_iter()
                .map(|(_, w)| Val::from_u64(w)),
        );
        let permutation = default_goldilocks_poseidon2_12();
        let mut state = [Val::ZERO; 12];
        for block in fields.as_chunks::<8>().0 {
            state[..8].copy_from_slice(block);
            permutation.permute_mut(&mut state);
        }
        s.encoded = state[..4].try_into().unwrap();
        s
    }
    pub(super) fn trace(&self, s: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        s.expected.require_contract()?;
        let mut values = Val::zero_vec(TRACE_HEIGHT * WIDTH);
        for (r, row) in values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            for (slot, tuple) in self.tuples.iter().enumerate() {
                for (part, (start, len)) in [(0, 1), (1, 2), (3, 8), (11, 16)]
                    .into_iter()
                    .chain((0..8).map(|j| (27 + 32 * j, 32)))
                    .enumerate()
                {
                    bits(
                        &mut row[BANK + slot * TUPLE_BITS + start
                            ..BANK + slot * TUPLE_BITS + start + len],
                        u64::from(tuple[part]),
                    );
                }
            }
            row[SEL_SALT..ENC_SALT].copy_from_slice(&self.result_salt);
            row[ENC_SALT..COEFF].copy_from_slice(&self.encoding_salt);
            row[SOURCE_SALT..DATA].copy_from_slice(&self.source_salt);
            for (i, v) in self.plain[..12].iter().enumerate() {
                bits(&mut row[DATA + i * 8..DATA + (i + 1) * 8], u64::from(*v));
            }
            for (v, flag) in row[FLAGS..ID].iter_mut().zip(self.flags) {
                *v = Val::from_bool(flag);
            }
            bits(&mut row[ID..ROUTE], self.transaction);
            for (v, flag) in row[ROUTE..WIDTH]
                .iter_mut()
                .zip(self.routing.into_iter().flatten())
            {
                *v = Val::from_bool(flag);
            }
            if (1..=85).contains(&r) {
                for part in 0..8 {
                    let f = (r - 1) * 8 + part;
                    if (87..674).contains(&f) {
                        let at = (f - 87) * 4;
                        let value = u32::from_le_bytes(self.plain[at..at + 4].try_into().unwrap());
                        bits(
                            &mut row[SCRATCH + part * 32..SCRATCH + (part + 1) * 32],
                            u64::from(value),
                        );
                    }
                }
            }
            kernel::write_lanes(row, r, self.original());
        }
        let mut trace = RowMajorMatrix::new(values, WIDTH);
        let _ = refresh(s, &mut trace);
        Ok(trace)
    }
}
/// Producer refresh used by owning rebuilt-claim tests, not by any verifier.
pub(super) fn refresh(s: &Statement, trace: &mut RowMajorMatrix<Val>) -> [Val; 4] {
    let air = EncodingAir::new(s);
    let context = air.context();
    let mut source_cp = [Val::ZERO; 12];
    let mut encoded = [Val::ZERO; 12];
    let mut carry = [Val::ZERO; 8];
    let mut digest = [Val::ZERO; 4];
    for (r, row) in trace
        .values
        .as_chunks_mut::<WIDTH>()
        .0
        .iter_mut()
        .enumerate()
    {
        row[SOURCE_CP..ENCODED_CP].copy_from_slice(&source_cp);
        row[ENCODED_CP..old_width()].copy_from_slice(&encoded);
        row[CARRY..SOURCE_CP].copy_from_slice(&carry);
        let mut a = [Val::ZERO; 12];
        a[..8].copy_from_slice(if r == 0 { &context } else { &carry });
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
        } else if r <= BLOCKS {
            for (i, v) in c[..8].iter_mut().enumerate() {
                *v = air.opening_field(row, r - 1, i);
            }
            c[8..].copy_from_slice(&source_cp[8..]);
        }
        row[2 * P2..3 * P2].fill(Val::ZERO);
        let c_out = if r <= BLOCKS || r == 511 {
            poseidon::write(&mut row[2 * P2..3 * P2], c)
        } else {
            [Val::ZERO; 12]
        };
        if (1..=BLOCKS).contains(&r) {
            source_cp = if r == 85 { [Val::ZERO; 12] } else { c_out };
        }
        encoded = if r == 0 { c_out } else { b_out };
        if r == 511 {
            digest = c_out[..4].try_into().unwrap();
        }
        for (i, v) in carry.iter_mut().enumerate() {
            *v = lane(row, 8 + i, 1);
        }
    }
    digest
}
fn old_width() -> usize {
    crate::opening::selection::encoding::air::WIDTH
}
use crate::primitive::PublicStatement;
