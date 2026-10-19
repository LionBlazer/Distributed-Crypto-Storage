//! Owner-only witnesses and trace construction. Public verification never calls this module.
use super::{
    commitment as statement,
    model::{Command, Operation, Registry, Step},
};
use crate::lifecycle::{
    air::{self, LifecycleAir},
    bootstrap,
    layout::*,
    statement::{Expected, Phase, Statement},
};
use crate::source::poseidon;
use bfv_hiding_stark::{Error, TRACE_HEIGHT, Val};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use zeroize::Zeroize;
#[derive(Clone)]
pub struct Witness {
    pub plain: [u8; 2348],
    pub controllers: [[u8; 32]; 2],
    /// Source, enrollment, old, command, next and result salts.
    pub salts: [[Val; 4]; 6],
    pub old: Registry,
    pub command: Option<Command>,
}
impl Drop for Witness {
    fn drop(&mut self) {
        self.plain.zeroize();
        self.controllers.zeroize();
        self.old.zeroize();
        if let Some(command) = &mut self.command {
            command.zeroize();
        }
        self.salts.fill([Val::ZERO; 4]);
        // Native field traces, salts and temporary SDK buffers have no erasure guarantee.
    }
}
pub fn bits(out: &mut [Val], value: u64) {
    for (i, v) in out.iter_mut().enumerate() {
        *v = Val::from_bool((value >> i) & 1 != 0);
    }
}
pub fn inverse(value: Val) -> Val {
    if value == Val::ZERO {
        Val::ZERO
    } else {
        value.inverse()
    }
}
fn bytes(out: &mut [Val], value: &[u8]) {
    for (i, byte) in value.iter().enumerate() {
        bits(&mut out[8 * i..8 * (i + 1)], u64::from(*byte));
    }
}
pub fn write_state(row: &mut [Val], base: usize, state: &Registry) {
    bits(&mut row[base + REV..base + REV + 64], state.revision);
    bits(&mut row[base + ALLOC..base + ALLOC + 64], state.allocator);
    for t in 0..2 {
        let at = slot(base, t);
        for r in 0..4 {
            row[at + HELD + 5 * r] = Val::ONE;
            for f in 0..2 {
                row[frame(at, f) + SAVED + 5 * r] = Val::ONE;
            }
        }
        if let Some(tx) = state.transactions.get(t) {
            row[at + PRESENT] = Val::ONE;
            bits(&mut row[at + ID..at + ID + 64], tx.id);
            row[at + PRINCIPAL + usize::from(tx.principal - 1)] = Val::ONE;
            bits(&mut row[at + SEQ..at + SEQ + 64], tx.sequence);
            row[at + FAILED] = Val::from_bool(tx.failed);
            bytes(&mut row[at + SNAPSHOT..at + SNAPSHOT + 256], &tx.snapshot);
            for r in 0..4 {
                row[at + HELD + 5 * r] = Val::ZERO;
                row[at + HELD + 5 * r + usize::from(tx.held[r])] = Val::ONE;
            }
            for (f, s) in tx.savepoints.iter().enumerate() {
                let a = frame(at, f);
                row[a] = Val::ONE;
                bytes(&mut row[a + NAME..a + NAME + 256], &s.name);
                for r in 0..4 {
                    row[a + SAVED + 5 * r] = Val::ZERO;
                    row[a + SAVED + 5 * r + usize::from(s.held[r])] = Val::ONE;
                }
            }
        }
    }
}
pub fn subtraction(row: &mut [Val], at: usize, left: u64, right: u64) {
    let mut borrow = 0i8;
    for bit in 0..64 {
        let difference = ((left >> bit) & 1) as i8 - ((right >> bit) & 1) as i8 - borrow;
        borrow = i8::from(difference < 0);
        row[at + bit + 1] = Val::from_bool(borrow != 0);
    }
}
impl Witness {
    fn require_trace_shape(&self, next: Option<&Registry>) -> Result<(), Error> {
        let bounded = |state: &Registry| {
            state.transactions.len() <= 2
                && state.transactions.iter().all(|tx| {
                    (1..=2).contains(&tx.principal)
                        && tx.held.iter().all(|m| *m <= 4)
                        && tx.savepoints.len() <= 2
                        && tx.savepoints.iter().all(|f| f.held.iter().all(|m| *m <= 4))
                })
        };
        if !bounded(&self.old) || next.is_some_and(|s| !bounded(s)) {
            return Err(Error::Shape);
        }
        if let Some(c) = &self.command
            && (!(1..=2).contains(&c.principal)
                || (c.operation == Operation::Acquire
                    && (!(1..=4).contains(&c.mode) || c.wait > 2)))
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(crate) fn require_source(&self, e: &Expected) -> Result<(), Error> {
        self.require_trace_shape(None)?;
        e.require_contract()?;
        let fields =
            crate::source::commitment::opening_fields(&e.source, self.salts[0], &self.plain);
        if crate::source::commitment::digest(&fields) != e.source.open_commitment {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub fn table(&self) -> [u8; 32] {
        self.plain[124..156].try_into().unwrap()
    }
    pub fn ages(&self) -> [u8; 4] {
        core::array::from_fn(|i| self.plain[3 * i])
    }
    pub fn statement(&self, e: &Expected) -> Result<Statement, Error> {
        self.require_trace_shape(None)?;
        statement::proposed(e, self)
    }
    fn common(
        &self,
        row: &mut [Val],
        table: usize,
        ids: usize,
        controllers: usize,
        inverses: usize,
    ) {
        for (i, word) in crate::source::statement::words(&self.table()).enumerate() {
            row[table + i] = word;
        }
        for (i, word) in crate::source::statement::words(&self.plain[2220..2348]).enumerate() {
            row[ids + i] = word;
        }
        for (t, c) in self.controllers.iter().enumerate() {
            bytes(
                &mut row[controllers + 256 * t..controllers + 256 * (t + 1)],
                c,
            );
            row[inverses + t] = inverse(Val::from_u32(c.iter().map(|b| b.count_ones()).sum()));
        }
    }
    fn bootstrap_trace(&self, s: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        let air = bootstrap::BootstrapAir::new(s);
        let mut bank = Val::zero_vec(bootstrap::WIDTH);
        self.common(
            &mut bank,
            bootstrap::TABLE,
            bootstrap::IDS,
            bootstrap::CONTROLLERS,
            bootstrap::INVERSES,
        );
        for (i, source) in [0, 1, 4].into_iter().enumerate() {
            bank[bootstrap::SALTS + 4 * i..bootstrap::SALTS + 4 * (i + 1)]
                .copy_from_slice(&self.salts[source]);
        }
        let mut values = Val::zero_vec(bootstrap::WIDTH * TRACE_HEIGHT);
        let mut checkpoint = [Val::ZERO; 12];
        for (physical, row) in values
            .as_chunks_mut::<{ bootstrap::WIDTH }>()
            .0
            .iter_mut()
            .enumerate()
        {
            row.copy_from_slice(&bank);
            self.source_words(row, physical, bootstrap::WORDS);
            row[bootstrap::CHECKPOINT..bootstrap::WORDS].copy_from_slice(&checkpoint);
            let mut input = [Val::ZERO; 12];
            if let Some((stream, block)) = bootstrap::absorb(physical) {
                for (word, v) in input[..8].iter_mut().enumerate() {
                    *v = air.field(row, stream, 8 * block + word, word);
                }
                if !bootstrap::reset(physical) {
                    input[8..].copy_from_slice(&checkpoint[8..]);
                }
            }
            let output = poseidon::write(&mut row[..bootstrap::CHECKPOINT], input);
            if bootstrap::absorb(physical).is_some() {
                checkpoint = output;
            }
        }
        Ok(RowMajorMatrix::new(values, bootstrap::WIDTH))
    }
    fn source_words(&self, row: &mut [Val], physical: usize, start: usize) {
        if physical < 85 {
            for word in 0..8 {
                let field = 8 * physical + word;
                if (87..674).contains(&field) {
                    let at = 4 * (field - 87);
                    bits(
                        &mut row[start + 32 * word..start + 32 * (word + 1)],
                        u64::from(u32::from_le_bytes(
                            self.plain[at..at + 4].try_into().unwrap(),
                        )),
                    );
                }
            }
        }
    }
    pub fn trace(&self, s: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        self.require_trace_shape(None)?;
        s.expected.require_contract()?;
        if matches!(s.expected.phase, Phase::Bootstrap) {
            return self.bootstrap_trace(s);
        }
        let command = self.command.as_ref().ok_or(Error::Shape)?;
        let step = self.old.step(command, s.expected.parent, self.ages())?;
        self.trace_step(s, &step)
    }
    /// Explicit low-level mathematical writer for coherent hostile Step claims.
    /// This never verifies the Step or grants application permission.
    pub fn trace_step(&self, s: &Statement, step: &Step) -> Result<RowMajorMatrix<Val>, Error> {
        self.require_trace_shape(Some(&step.next))?;
        s.expected.require_contract()?;
        let command = self.command.as_ref().ok_or(Error::Shape)?;
        let air = LifecycleAir::new(s);
        let mut bank = Val::zero_vec(WIDTH);
        self.common(&mut bank, TABLE, IDS, CONTROLLERS, CTRL_INV);
        bank[SALTS..SALTS + 24].copy_from_slice(self.salts.as_flattened());
        let success = step.outcome != 1 && step.outcome != 2;
        if !success {
            bank[SALTS + 16..SALTS + 20].copy_from_slice(&self.salts[2]);
        }
        write_state(&mut bank, OLD, &self.old);
        write_state(&mut bank, NEW, &step.next);
        for operation in Operation::ALL {
            bank[OP + operation as usize] = Val::from_bool(command.operation == operation);
        }
        bank[PRINCIPAL_CMD + usize::from(command.principal - 1)] = Val::ONE;
        bits(&mut bank[ID_CMD..ID_CMD + 64], command.transaction);
        bytes(&mut bank[NAME_CMD..NAME_CMD + 256], &command.name);
        bytes(&mut bank[MASK..MASK + 256], &command.mask);
        let actor = self
            .old
            .transactions
            .iter()
            .position(|t| t.id == command.transaction);
        if command.operation != Operation::Begin {
            bank[ACTOR + actor.ok_or(Error::Shape)?] = Val::ONE;
        }
        for (i, age) in self.ages().into_iter().enumerate() {
            bits(&mut bank[AGES + 8 * i..AGES + 8 * (i + 1)], u64::from(age));
            bank[MATCHES + i] =
                Val::from_bool(command.mask[usize::from(age) / 8] & (1 << (age % 8)) != 0);
        }
        if command.operation == Operation::Acquire {
            bank[MODE + usize::from(command.mode - 1)] = Val::ONE;
            bank[WAIT + usize::from(command.wait)] = Val::ONE;
        }
        bits(&mut bank[OFFSET..OFFSET + 3], u64::from(command.offset));
        bits(&mut bank[LIMIT..LIMIT + 3], u64::from(command.limit));
        bits(
            &mut bank[PROJECTION..PROJECTION + 2],
            u64::from(command.projection),
        );
        bank[ABORT] = Val::from_bool(command.abort);
        bank[SUCCESS] = Val::from_bool(success);
        let revision = self.old.revision.checked_add(1).ok_or(Error::Shape)?;
        bits(&mut bank[CAND_REV..CAND_REV + 64], revision);
        bank[CARRY] = Val::from_bool(self.old.revision as u32 == u32::MAX);
        if command.operation == Operation::Begin {
            let id = self.old.allocator.checked_add(1).ok_or(Error::Shape)?;
            bits(&mut bank[CAND_ALLOC..CAND_ALLOC + 64], id);
            bank[CARRY + 1] = Val::from_bool(self.old.allocator as u32 == u32::MAX);
        }
        if !matches!(command.operation, Operation::Begin | Operation::End) {
            let sequence = self.old.transactions[actor.unwrap()].sequence;
            bits(
                &mut bank[CAND_SEQ..CAND_SEQ + 64],
                sequence.checked_add(1).ok_or(Error::Shape)?,
            );
            bank[CARRY + 2] = Val::from_bool(sequence as u32 == u32::MAX);
        }
        for (si, state) in [&self.old, &step.next].into_iter().enumerate() {
            let ids =
                core::array::from_fn::<_, 2, _>(|i| state.transactions.get(i).map_or(0, |t| t.id));
            for (i, (left, right)) in [
                (state.revision, state.allocator),
                (state.allocator, ids[0]),
                (state.allocator, ids[1]),
                (ids[0], ids[1]),
            ]
            .into_iter()
            .enumerate()
            {
                subtraction(&mut bank, COMPARE + (si * 4 + i) * 65, left, right);
            }
            for (t, tx) in state.transactions.iter().enumerate() {
                bank[NONZERO + si * 4 + t * 2] = inverse(Val::from_u32(tx.id.count_ones()));
                bank[NONZERO + si * 4 + t * 2 + 1] =
                    inverse(Val::from_u32(tx.sequence.count_ones()));
            }
        }
        for f in 0..2 {
            let name = actor
                .and_then(|a| self.old.transactions[a].savepoints.get(f))
                .map_or([0; 32], |s| s.name);
            let at = EQ_NAME + 25 * f;
            bank[at + 16] = Val::ONE;
            for i in 0..8 {
                let x = u32::from_le_bytes(name[4 * i..4 * i + 4].try_into().unwrap());
                let y = u32::from_le_bytes(command.name[4 * i..4 * i + 4].try_into().unwrap());
                let delta = Val::from_u32(x) - Val::from_u32(y);
                bank[at + 2 * i] = Val::from_bool(x == y);
                bank[at + 2 * i + 1] = inverse(delta);
                bank[at + 17 + i] = bank[at + 16 + i] * bank[at + 2 * i];
            }
        }
        if let Some(a) = actor
            && let Some(f) = self.old.transactions[a]
                .savepoints
                .iter()
                .rposition(|s| s.name == command.name)
        {
            bank[TARGET + f] = Val::ONE;
        }
        for (start, flags) in [
            (SEARCH, step.search),
            (ATTEMPT, step.attempt),
            (CONFLICT, step.conflict),
            (VISIT, step.visit),
            (SKIP, step.skipped),
            (RETURN, step.returned),
            (BLOCK, step.block),
        ] {
            for (i, flag) in flags.into_iter().enumerate() {
                bank[start + i] = Val::from_bool(flag);
            }
        }
        for i in 0..4 {
            for (start, prefix, bound) in [
                (
                    LIMIT_CMP,
                    step.returned[..i].iter().filter(|b| **b).count(),
                    command.limit,
                ),
                (
                    OFFSET_CMP,
                    step.visit[..i].iter().filter(|b| **b).count(),
                    command.offset,
                ),
            ] {
                let difference = prefix as u64 + 8 - u64::from(bound);
                bits(&mut bank[start + 4 * i..start + 4 * i + 3], difference % 8);
                bank[start + 4 * i + 3] = Val::from_bool(difference >= 8);
            }
            if let Some(a) = actor {
                let old = self.old.transactions[a].held[i];
                let desired = if command.operation == Operation::Acquire {
                    old.max(command.mode)
                } else {
                    old
                };
                bank[DESIRED + 5 * i + usize::from(desired)] = Val::ONE;
            }
        }
        let mut values = Val::zero_vec(WIDTH * TRACE_HEIGHT);
        let mut checkpoint = [Val::ZERO; 12];
        let mut accumulated = [Val::ZERO; 4];
        for (physical, row) in values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            row.copy_from_slice(&bank);
            row[ACC..ACC + 4].copy_from_slice(&accumulated);
            if physical < 256 {
                for (i, age) in self.ages().into_iter().enumerate() {
                    let d = u16::from(age) + 256 - physical as u16;
                    let at = EQUALITY + 11 * i;
                    bits(&mut row[at..at + 8], u64::from(d % 256));
                    row[at + 8] = Val::from_bool(d >= 256);
                    row[at + 9] = Val::from_bool(d.is_multiple_of(256));
                    row[at + 10] = inverse(Val::from_u16(d % 256));
                    if physical == usize::from(age)
                        && command.mask[physical / 8] & (1 << (physical % 8)) != 0
                    {
                        accumulated[i] += Val::ONE;
                    }
                }
            }
            self.source_words(row, physical, WORDS);
            row[CP..WORDS].copy_from_slice(&checkpoint);
            let mut input = [Val::ZERO; 12];
            if let Some((stream, block)) = air::absorb(physical) {
                for (word, v) in input[..8].iter_mut().enumerate() {
                    *v = air.field(row, stream, 8 * block + word, word);
                }
                if !air::reset(physical) {
                    input[8..].copy_from_slice(&checkpoint[8..]);
                }
            }
            let output = poseidon::write(&mut row[..CP], input);
            if air::absorb(physical).is_some() {
                checkpoint = output;
            }
        }
        Ok(RowMajorMatrix::new(values, WIDTH))
    }
}
