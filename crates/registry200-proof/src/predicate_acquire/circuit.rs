//! Caller-owned private openings. No DATA, Owner getter, predicate execution or Registry model.
use super::{Expected, air::PredicateAcquireAir, layout::*};
use crate::{BackendError as Error, Val};
use bfv_hiding_stark::{TRACE_HEIGHT, poseidon};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use zeroize::{Zeroize, Zeroizing};

/// Explicit private inputs owned by this caller; no Clone/Debug/serialization.
/// Drop clears these fields, not caller copies or native trace/SDK scratch.
pub struct Opening {
    pub mask: [u8; 32],
    pub transaction: u64,
    pub principal: u8,
    pub controller: [u8; 32],
    pub revision: u64,
    pub sequence: u64,
    pub mode: u8,
    pub wait: u8,
    pub offset: u8,
    pub limit: u8,
    pub projection: u8,
    /// Returned, skipped, visited in original ordinal order.
    pub flags: [[bool; 4]; 3],
    /// Cmd48, Cmd160, Result144 salts, canonical Gold words.
    pub salts: [[u64; 4]; 3],
}
impl Drop for Opening {
    fn drop(&mut self) {
        self.mask.zeroize();
        self.transaction.zeroize();
        self.principal.zeroize();
        self.controller.zeroize();
        self.revision.zeroize();
        self.sequence.zeroize();
        self.mode.zeroize();
        self.wait.zeroize();
        self.offset.zeroize();
        self.limit.zeroize();
        self.projection.zeroize();
        self.flags.zeroize();
        self.salts.zeroize();
    }
}
pub struct Witness {
    expected: Expected,
    bank: Zeroizing<Vec<u64>>,
}
fn bits(bank: &mut [u64], start: usize, count: usize, value: u64) {
    for i in 0..count {
        bank[start + i] = (value >> i) & 1;
    }
}
impl Witness {
    /// Reconstruct all three private preimages; this checks association only,
    /// never Source, query, Lifecycle proofs, authorization or fresh state.
    pub fn new(e: &Expected, opening: Opening) -> Result<Self, Error> {
        if opening.transaction == 0
            || !(1..=2).contains(&opening.principal)
            || opening.controller == [0; 32]
            || opening.sequence == 0
            || !(1..=4).contains(&opening.mode)
            || opening.wait > 2
            || opening.offset > 4
            || opening.limit > 4
            || !(1..=3).contains(&opening.projection)
            || opening.salts.iter().flatten().any(|v| *v >= Val::ORDER_U64)
        {
            return Err(Error::Shape);
        }
        let mut bank = Zeroizing::new(vec![0; WIDTH]);
        for (i, byte) in opening.mask.iter().enumerate() {
            bits(&mut bank, MASK + 8 * i, 8, u64::from(*byte));
        }
        bits(&mut bank, TX, 64, opening.transaction);
        bits(&mut bank, REV, 64, opening.revision);
        bits(&mut bank, SEQ, 64, opening.sequence);
        for (i, byte) in opening.controller.iter().enumerate() {
            bits(&mut bank, CONTROLLER + 8 * i, 8, u64::from(*byte));
        }
        bank[PRINCIPAL + usize::from(opening.principal - 1)] = 1;
        bank[MODE + usize::from(opening.mode - 1)] = 1;
        bank[WAIT + usize::from(opening.wait)] = 1;
        bits(&mut bank, OFFSET, 3, u64::from(opening.offset));
        bits(&mut bank, LIMIT, 3, u64::from(opening.limit));
        bits(&mut bank, PROJECTION, 2, u64::from(opening.projection));
        for (i, flag) in opening.flags.iter().flatten().enumerate() {
            bank[FLAGS + i] = u64::from(*flag);
        }
        for (i, salt) in opening.salts.iter().flatten().enumerate() {
            bank[SALTS + i] = *salt;
        }
        let witness = Self {
            expected: e.clone(),
            bank,
        };
        let air = PredicateAcquireAir::new(e);
        let row: Vec<_> = witness.bank.iter().copied().map(Val::from_u64).collect();
        for (stream, fields, root) in [
            (Stream::Mask, 48, e.query().expected.command()),
            (Stream::Command, 160, e.roots()[4..8].try_into().unwrap()),
            (Stream::Result, 144, e.lifecycle().result),
        ] {
            let mut state = [Val::ZERO; 12];
            let p = p3_goldilocks::default_goldilocks_poseidon2_12();
            use p3_symmetric::Permutation;
            for block in 0..fields / 8 {
                for (i, value) in state[..8].iter_mut().enumerate() {
                    *value = air.field(&row, stream, 8 * block + i);
                }
                p.permute_mut(&mut state);
            }
            if state[..4] != root {
                return Err(Error::Shape);
            }
        }
        Ok(witness)
    }
    pub(crate) fn require_expected(&self, e: &Expected) -> Result<(), Error> {
        self.expected.require_same(e)
    }
    /// Low-level mathematical trace: a deliberately different Expected may
    /// produce a false trace for genuine AIR-rejection controls. Typed prove
    /// always checks the FULL retained Expected before any prerequisite work.
    pub fn trace(&self, e: &Expected) -> Result<RowMajorMatrix<Val>, Error> {
        let air = PredicateAcquireAir::new(e);
        let mut trace = vec![Val::ZERO; WIDTH * TRACE_HEIGHT];
        let mut cp = [Val::ZERO; 12];
        for (r, row) in trace.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            for (cell, value) in row.iter_mut().zip(self.bank.iter()) {
                *cell = Val::from_u64(*value);
            }
            row[CP..CP + 12].copy_from_slice(&cp);
            let mut input = [Val::ZERO; 12];
            if let Some((stream, block)) = absorb(r) {
                for (i, value) in input[..8].iter_mut().enumerate() {
                    *value = air.field(row, stream, 8 * block + i);
                }
                if !reset(r) {
                    input[8..].copy_from_slice(&cp[8..]);
                }
            }
            let output = poseidon::write(&mut row[..CP], input);
            if absorb(r).is_some() {
                cp = output;
            }
        }
        Ok(RowMajorMatrix::new(trace, WIDTH))
    }
}
