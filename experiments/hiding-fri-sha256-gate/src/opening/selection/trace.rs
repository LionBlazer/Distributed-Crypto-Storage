//! Non-Clone/nonserializable private opening. No key or secret-export API.
use super::{
    air::*,
    statement::{Plan, Statement},
};
use crate::backend::{Error, TRACE_HEIGHT, Val};
use crate::opening::{poseidon, statement::words};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

pub(super) struct Witness {
    pub(super) plain: [u8; 2348],
    pub(super) plan: Plan,
    pub(super) salts: [[Val; 4]; 3],
}
fn bits(out: &mut [Val], value: u64) {
    for (bit, cell) in out.iter_mut().enumerate() {
        *cell = Val::from_u64((value >> bit) & 1);
    }
}
fn inverse(value: Val) -> Val {
    if value == Val::ZERO {
        Val::ZERO
    } else {
        value.inverse()
    }
}
impl Witness {
    pub(super) fn new(plain: [u8; 2348], plan: Plan, salts: [[Val; 4]; 3]) -> Self {
        Self { plain, plan, salts }
    }
    pub(super) fn trace(&self, statement: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        let air = SelectionAir::new(statement);
        let mut template = Val::zero_vec(WIDTH);
        for (i, byte) in self.plan.mask.iter().enumerate() {
            bits(
                &mut template[MASK + i * 8..MASK + (i + 1) * 8],
                u64::from(*byte),
            );
        }
        let mut matches = [false; 4];
        let mut retained = [false; 4];
        let mut rank = 0;
        for i in 0..4 {
            let age = self.plain[i * 3];
            bits(
                &mut template[AGES + i * 8..AGES + (i + 1) * 8],
                u64::from(age),
            );
            template[AMOUNTS + i] = Val::from_u16(u16::from_le_bytes([
                self.plain[i * 3 + 1],
                self.plain[i * 3 + 2],
            ]));
            matches[i] = self.plan.mask[usize::from(age) / 8] & (1 << (age % 8)) != 0;
            let prefix = matches[..i].iter().filter(|v| **v).count() as u64;
            let difference = prefix + 8 - u64::from(self.plan.limit);
            bits(
                &mut template[COMPARE + i * 4..COMPARE + i * 4 + 3],
                difference % 8,
            );
            template[COMPARE + i * 4 + 3] = Val::from_bool(difference >= 8);
            retained[i] = matches[i] && rank < self.plan.limit as usize;
            template[MATCHES + i] = Val::from_bool(matches[i]);
            template[RETAIN + i] = Val::from_bool(retained[i]);
            if retained[i] {
                template[COMPACT + rank * 4 + i] = Val::ONE;
                template[PRESENCE + rank] = Val::ONE;
                rank += 1;
            }
        }
        // The expected private TableId is independent, then constrained against
        // the authenticated source stream. No host acceptance check replaces AIR.
        template[TABLE..IDS].copy_from_slice(&words(&self.plan.table).collect::<Vec<_>>());
        template[IDS..MATCHES]
            .copy_from_slice(&words(&self.plain[12 + 2208..]).collect::<Vec<_>>());
        bits(&mut template[LIMIT..PROJECTION], u64::from(self.plan.limit));
        bits(
            &mut template[PROJECTION..COMPARE],
            u64::from(self.plan.projection),
        );
        template[SALTS..EQUALITY].copy_from_slice(self.salts.as_flattened());
        let mut values = Val::zero_vec(TRACE_HEIGHT * WIDTH);
        let mut checkpoint = [Val::ZERO; 12];
        let mut accumulated = [Val::ZERO; 4];
        for (physical, row) in values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            row[MASK..ACCUMULATOR].copy_from_slice(&template[MASK..ACCUMULATOR]);
            row[RETAIN..EQUALITY].copy_from_slice(&template[RETAIN..EQUALITY]);
            row[ACCUMULATOR..RETAIN].copy_from_slice(&accumulated);
            if physical < 256 {
                for (i, accumulator) in accumulated.iter_mut().enumerate() {
                    let difference = u16::from(self.plain[i * 3]) + 256 - physical as u16;
                    let start = EQUALITY + i * 11;
                    bits(&mut row[start..start + 8], u64::from(difference % 256));
                    row[start + 8] = Val::from_bool(difference >= 256);
                    row[start + 9] = Val::from_bool(difference.is_multiple_of(256));
                    row[start + 10] = inverse(Val::from_u16(difference % 256));
                    if usize::from(self.plain[i * 3]) == physical
                        && self.plan.mask[physical / 8] & (1 << (physical % 8)) != 0
                    {
                        *accumulator += Val::ONE;
                    }
                }
            }
            row[CHECKPOINT..WORDS].copy_from_slice(&checkpoint);
            let mut input = [Val::ZERO; 12];
            if let Some((stream, block)) = absorb(physical) {
                if matches!(stream, Stream::Source) {
                    for slot in 0..8 {
                        let field = block * 8 + slot;
                        if (87..674).contains(&field) {
                            let word = field - 87;
                            let value = u32::from_le_bytes(
                                self.plain[word * 4..word * 4 + 4].try_into().unwrap(),
                            );
                            bits(
                                &mut row[WORDS + slot * 32..WORDS + (slot + 1) * 32],
                                u64::from(value),
                            );
                        }
                    }
                }
                for (slot, cell) in input[..8].iter_mut().enumerate() {
                    *cell = air.field(row, stream, block * 8 + slot, slot);
                }
                if !reset(physical) {
                    input[8..].copy_from_slice(&checkpoint[8..]);
                }
            }
            let output = poseidon::write(&mut row[..CHECKPOINT], input);
            if absorb(physical).is_some() {
                checkpoint = output;
            }
        }
        Ok(RowMajorMatrix::new(values, WIDTH))
    }
}
