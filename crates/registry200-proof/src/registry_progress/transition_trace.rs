//! Guarded actual producer inputs and a single new fixed trace writer.
use super::{
    circuit::{State, StatementOpening, Status, Step},
    transition::{Expected, Statement},
    transition_fields::{self, Fields},
    transition_layout::*,
};
use crate::{
    BackendError as Error, Val,
    lifecycle::{
        self,
        circuit::{
            Witness as BaseWitness, bits, commitment, inverse,
            model::{Command, Operation, Step as BaseStep},
            subtraction,
        },
    },
    source,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use zeroize::{Zeroize, Zeroizing};
fn vals(s: [u64; 4]) -> Result<[Val; 4], Error> {
    if s.iter().any(|v| *v >= Val::ORDER_U64) {
        return Err(Error::Shape);
    }
    Ok(s.map(Val::from_u64))
}
pub(super) fn command_fields(
    e: &Expected,
    c: &Command,
    revision: u64,
    controllers: &[[u8; 32]; 2],
    salt: [Val; 4],
) -> Result<Vec<Val>, Error> {
    c.require_shape()?;
    let legacy = lifecycle::statement::Expected::transition(
        e.source(),
        e.base.genesis,
        e.base.parent,
        source::statement::encode_digest(e.base.enrollment),
        source::statement::encode_digest(e.old),
        [0; 32],
    )?;
    let mut out = commitment::command_fields_opening(
        &legacy,
        c,
        &commitment::CommandFieldsOpening {
            controller: controllers[usize::from(c.principal - 1)],
            revision,
            salt,
        },
    );
    out[5..105].copy_from_slice(&e.context());
    Ok(out)
}
/// Move-only captured Expected and private banks. Never grants ownership/finality.
/// ```compile_fail
/// fn clone<T:Clone>() {} fn forbidden() { clone::<registry200_proof::registry_progress::transition::Witness>(); }
/// ```
/// ```compile_fail
/// fn forbidden(w: registry200_proof::registry_progress::transition::Witness) { let _ = w.plain; }
/// ```
pub struct Witness {
    pub(super) statement: Statement,
    plain: Zeroizing<[u8; 2348]>,
    controllers: Zeroizing<[[u8; 32]; 2]>,
    salts: Zeroizing<[[u64; 4]; 6]>,
    old: Zeroizing<State>,
    next: Zeroizing<State>,
    command: Zeroizing<Command>,
    hidden: Option<Zeroizing<StatementOpening>>,
    step: Option<Zeroizing<Step>>,
    mask_salt: Zeroizing<[u64; 4]>,
}
impl Witness {
    fn common(
        e: &Expected,
        plain: &[u8; 2348],
        controllers: &[[u8; 32]; 2],
        old: &State,
        salts: &[[u64; 4]; 6],
    ) -> Result<(), Error> {
        e.require_same(e)?;
        old.require_canonical()?;
        if controllers.contains(&[0; 32]) {
            return Err(Error::Shape);
        }
        for s in salts {
            let _ = vals(*s)?;
        }
        if source::commitment::digest(&source::commitment::opening_fields(
            e.source(),
            vals(salts[0])?,
            plain,
        )) != e.source().open_commitment
        {
            return Err(Error::Shape);
        }
        let table: Zeroizing<[u8; 32]> = Zeroizing::new(plain[124..156].try_into().unwrap());
        if source::commitment::digest(&commitment::enrollment_fields_opening(
            &e.base.legacy(),
            &table,
            controllers,
            vals(salts[1])?,
        )) != e.base.enrollment
            || old.root(&e.base, plain, controllers, salts[2])? != e.old
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub fn control(
        e: &Expected,
        plain: Zeroizing<[u8; 2348]>,
        controllers: Zeroizing<[[u8; 32]; 2]>,
        old: Zeroizing<State>,
        command: Zeroizing<Command>,
        salts: Zeroizing<[[u64; 4]; 6]>,
    ) -> Result<Self, Error> {
        if e.is_predicate() {
            return Err(Error::Shape);
        }
        Self::common(e, &plain, &controllers, &old, &salts)?;
        let next = Zeroizing::new(old.control(&command, e.base.parent)?);
        if super::fields::digest(&command_fields(
            e,
            &command,
            old.registry.revision,
            &controllers,
            vals(salts[3])?,
        )?) != e.command
        {
            return Err(Error::Shape);
        }
        let root = next.root(&e.base, &plain, &controllers, salts[4])?;
        let mut out = Self {
            statement: Statement {
                expected: e.clone(),
                next: root,
                result: [Val::ZERO; 4],
            },
            plain,
            controllers,
            salts,
            old,
            next,
            command,
            hidden: None,
            step: None,
            mask_salt: Zeroizing::new([0; 4]),
        };
        out.finish()?;
        Ok(out)
    }
    /// Exact original StatementOpening is retained across fresh attempts. A
    /// different scope/source/setup/key/client/call/mask/projection cannot resume.
    /// Salt order: Source, enrollment, old registry, Cmd160, new registry,
    /// Result160, new Progress48 and current Encoding Cmd48.
    pub fn predicate(
        e: &Expected,
        plain: Zeroizing<[u8; 2348]>,
        controllers: Zeroizing<[[u8; 32]; 2]>,
        old: Zeroizing<State>,
        hidden: Zeroizing<StatementOpening>,
        all_salts: Zeroizing<[[u64; 4]; 8]>,
    ) -> Result<Self, Error> {
        let salts = Zeroizing::new(core::array::from_fn(|i| all_salts[i]));
        let progress_salt = Zeroizing::new(all_salts[6]);
        let mask_salt = Zeroizing::new(all_salts[7]);
        let q = e.query().ok_or(Error::Shape)?;
        Self::common(e, &plain, &controllers, &old, &salts)?;
        hidden.require_shape()?;
        let _ = vals(*progress_salt)?;
        let mask_native = vals(*mask_salt)?;
        let is_start = !old
            .progress
            .iter()
            .flatten()
            .any(|p| p.statement.transaction == hidden.transaction);
        if hidden.scope != e.scope()
            || hidden.enrollment != e.base.enrollment.map(|v| v.as_canonical_u64())
            || (is_start && hidden.sql_identity != q.expected.sql_identity())
            || hidden.controller != controllers[usize::from(hidden.principal - 1)]
        {
            return Err(Error::Shape);
        }
        if crate::coefficient_encoding::commitment::command_digest(
            &crate::coefficient_encoding::commitment::command_fields(
                &q.expected,
                hidden.mask,
                mask_native,
            ),
        ) != q.expected.command()
        {
            return Err(Error::Shape);
        }
        let actor = old
            .registry
            .transactions
            .iter()
            .position(|t| t.id == hidden.transaction)
            .ok_or(Error::Shape)?;
        let mut c = Command::control(
            Operation::Acquire,
            hidden.transaction,
            hidden.principal,
            old.registry.transactions[actor].sequence,
        );
        c.mask = hidden.mask;
        c.mode = hidden.mode;
        c.wait = hidden.wait;
        c.offset = hidden.offset;
        c.limit = hidden.limit;
        c.projection = hidden.projection;
        let command = Zeroizing::new(c);
        if super::fields::digest(&command_fields(
            e,
            &command,
            old.registry.revision,
            &controllers,
            vals(salts[3])?,
        )?) != e.command
        {
            return Err(Error::Shape);
        }
        let mut step = Zeroizing::new(old.predicate(
            &hidden,
            core::array::from_fn(|i| plain[3 * i]),
            *progress_salt,
        )?);
        let next = Zeroizing::new(core::mem::take(&mut step.next));
        let root = next.root(&e.base, &plain, &controllers, salts[4])?;
        let mut out = Self {
            statement: Statement {
                expected: e.clone(),
                next: root,
                result: [Val::ZERO; 4],
            },
            plain,
            controllers,
            salts,
            old,
            next,
            command,
            hidden: Some(hidden),
            step: Some(step),
            mask_salt,
        };
        out.finish()?;
        Ok(out)
    }
    fn result_fields(&self) -> Result<Vec<Val>, Error> {
        let e = &self.statement.expected;
        let actor = self
            .old
            .registry
            .transactions
            .iter()
            .position(|t| t.id == self.command.transaction);
        let old_p = actor
            .and_then(|t| self.old.progress[t].as_ref())
            .map(|p| p.root())
            .transpose()?
            .unwrap_or([Val::ZERO; 4]);
        let new_p = if self.command.operation == Operation::End {
            [Val::ZERO; 4]
        } else {
            actor
                .and_then(|t| self.next.progress[t].as_ref())
                .map(|p| p.root())
                .transpose()?
                .unwrap_or([Val::ZERO; 4])
        };
        let values = if let (Some(hidden), Some(step)) = (&self.hidden, &self.step) {
            step.result_fields(
                &e.context().try_into().unwrap(),
                [e.old, self.statement.next, hidden.root()?],
                hidden,
                [old_p, new_p],
                self.salts[5],
            )?
        } else {
            let abort = self.command.operation == Operation::End
                && (self.command.abort
                    || actor.is_some_and(|t| self.old.registry.transactions[t].failed));
            let mut out = source::statement::words(&super::fields::RESULT_DOMAIN)
                .chain([Val::ONE])
                .chain(e.context())
                .chain(e.old)
                .chain(self.statement.next)
                .chain([Val::ZERO; 4])
                .collect::<Vec<_>>();
            out.extend([
                Val::from_u8(2 + self.command.operation as u8),
                Val::from_u8(if abort { 3 } else { 1 }),
            ]);
            out.extend([
                Val::from_u32(self.command.transaction as u32),
                Val::from_u32((self.command.transaction >> 32) as u32),
            ]);
            out.extend([Val::ZERO; 14]);
            out.extend(old_p);
            out.extend(new_p);
            out.extend([Val::ZERO; 7]);
            out.extend(vals(self.salts[5])?);
            out.extend([Val::ZERO; 6]);
            assert_eq!(out.len(), 160);
            out
        };
        Ok(values)
    }
    fn finish(&mut self) -> Result<(), Error> {
        let mut values = self.result_fields()?;
        self.statement.result = super::fields::digest(&values);
        values.fill(Val::ZERO);
        Ok(())
    }
    /// Caller-owned PRIVATE canonical Result160 preimage for encrypted custody.
    /// This uses the exact same builder as the claimed proof result. It is not a
    /// verified opening and grants no SQL, finality, or installed-state authority.
    pub fn result_opening_fields(&self) -> Result<Zeroizing<[u64; 160]>, Error> {
        let mut values = self.result_fields()?;
        let out = Zeroizing::new(core::array::from_fn(|i| values[i].as_canonical_u64()));
        values.fill(Val::ZERO);
        Ok(out)
    }
    #[cfg(test)]
    pub(super) fn result_opening_inputs_for_test(&self) -> Option<ResultOpeningInputsForTest<'_>> {
        let original = self.hidden.as_deref()?;
        let previous = self
            .old
            .registry
            .transactions
            .iter()
            .position(|t| t.id == original.transaction)
            .and_then(|t| self.old.progress[t].as_ref());
        let parked = self
            .next
            .registry
            .transactions
            .iter()
            .position(|t| t.id == original.transaction)
            .and_then(|t| self.next.progress[t].as_ref());
        Some(ResultOpeningInputsForTest {
            original,
            previous,
            parked,
            step: self.step.as_deref()?,
        })
    }
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub(super) fn require_expected(&self, e: &Expected) -> Result<(), Error> {
        self.statement.require_expected(e)
    }
    fn bank(&self) -> Result<Vec<Val>, Error> {
        let e = &self.statement.expected;
        let mut internal = Zeroizing::new((*self.command).clone());
        if self
            .step
            .as_ref()
            .is_some_and(|s| s.status == Status::Error)
        {
            internal.operation = Operation::FailCurrent;
            internal.mask = [0; 32];
            internal.mode = 0;
            internal.wait = 0;
            internal.offset = 0;
            internal.limit = 0;
            internal.projection = 0;
        }
        let w = BaseWitness {
            plain: *self.plain,
            controllers: *self.controllers,
            salts: (*self.salts).map(|s| s.map(Val::from_u64)),
            old: self.old.registry.clone(),
            command: Some((*internal).clone()),
        };
        let legacy = lifecycle::statement::Expected::transition(
            e.source(),
            e.base.genesis,
            e.base.parent,
            source::statement::encode_digest(e.base.enrollment),
            source::statement::encode_digest(e.old),
            source::statement::encode_digest(e.command),
        )?;
        let claim = lifecycle::statement::Statement {
            expected: legacy,
            next: [Val::ZERO; 4],
            result: [Val::ZERO; 4],
        };
        let step = GuardedBaseStep(BaseStep {
            next: self.next.registry.clone(),
            outcome: 0,
            search: [false; 4],
            attempt: [false; 4],
            conflict: [false; 4],
            visit: self.step.as_ref().map_or([false; 4], |s| s.delta),
            skipped: [false; 4],
            returned: [false; 4],
            block: [false; 4],
        });
        // Reuse only the existing owner-side mathematical base-bank writer.
        // Every hash, equality scan and new semantic equation is owned below.
        let base = w.trace_step(&claim, &step.0)?;
        let mut bank = Val::zero_vec(TRACE_WIDTH);
        bank[..WIDTH].copy_from_slice(&base.values[..WIDTH]);
        bank[WORDS..TABLE].fill(Val::ZERO);
        bank[ACC..SEARCH].fill(Val::ZERO);
        bank[SEARCH..DESIRED].fill(Val::ZERO);
        for (at, state) in [(OLD_PROGRESS, &*self.old), (NEW_PROGRESS, &*self.next)] {
            for t in 0..2 {
                if let Some(p) = &state.progress[t] {
                    bank[progress(at, t)] = Val::ONE;
                    bank[progress(at, t) + 1..progress(at, t) + 5].copy_from_slice(&p.root()?);
                }
            }
        }
        if let (Some(hidden), Some(step)) = (&self.hidden, &self.step) {
            let actor = self
                .old
                .registry
                .transactions
                .iter()
                .position(|t| t.id == hidden.transaction)
                .ok_or(Error::Shape)?;
            let prior = self.old.progress[actor].as_ref();
            let old_v = prior.map_or([false; 4], |p| p.visited);
            let old_s = prior.map_or([false; 4], |p| p.selected);
            write_bytes(&mut bank, CLIENT, &hidden.client);
            bits(&mut bank[CALL..CALL + 64], hidden.call);
            write_bytes(&mut bank, INVOCATION, &hidden.invocation);
            write_bytes(&mut bank, ORIGINAL_SQL, &hidden.sql_identity);
            write_bytes(&mut bank, QUERY_MASK, &hidden.mask);
            bank[QUERY_MODE + usize::from(hidden.mode - 1)] = Val::ONE;
            bank[QUERY_WAIT + usize::from(hidden.wait)] = Val::ONE;
            bits(
                &mut bank[QUERY_OFFSET..QUERY_OFFSET + 3],
                u64::from(hidden.offset),
            );
            bits(
                &mut bank[QUERY_LIMIT..QUERY_LIMIT + 3],
                u64::from(hidden.limit),
            );
            bits(
                &mut bank[QUERY_PROJECTION..QUERY_PROJECTION + 2],
                u64::from(hidden.projection),
            );
            bank[STMT_ROOT..STMT_ROOT + 4].copy_from_slice(&hidden.root()?);
            bank[EXTRA_SALTS..EXTRA_SALTS + 4].copy_from_slice(&vals(hidden.salt)?);
            bank[EXTRA_SALTS + 12..EXTRA_SALTS + 16].copy_from_slice(&vals(*self.mask_salt)?);
            bank[RESUME] = Val::from_bool(prior.is_some());
            bank[STATUS
                + match step.status {
                    Status::Parked => 0,
                    Status::Done => 1,
                    Status::Error => 2,
                }] = Val::ONE;
            bank[OLD_CURSOR + usize::from(step.old_cursor)] = Val::ONE;
            bank[NEW_CURSOR + usize::from(step.cursor)] = Val::ONE;
            let old_micro = prior.map_or(0, |p| p.microstep);
            bits(&mut bank[OLD_MICRO..OLD_MICRO + 64], old_micro);
            bits(&mut bank[NEW_MICRO..NEW_MICRO + 64], step.microstep);
            bank[MICRO_CARRY] = Val::from_bool(old_micro as u32 == u32::MAX);
            for (start, flags) in [
                (OLD_VISITED, old_v),
                (OLD_SELECTED, old_s),
                (NEW_VISITED, step.visited),
                (NEW_SELECTED, step.selected),
            ] {
                for (i, v) in flags.into_iter().enumerate() {
                    bank[start + i] = Val::from_bool(v);
                }
            }
            if let Some(p) = prior {
                bits(&mut bank[OLD_HOLDER..OLD_HOLDER + 64], p.holder);
                bank[OLD_HOLDER_MODE + usize::from(p.holder_mode - 1)] = Val::ONE;
                bits(
                    &mut bank[OLD_BLOCK_REV..OLD_BLOCK_REV + 64],
                    p.blocked_revision,
                );
                subtraction(
                    &mut bank,
                    BLOCK_REV_COMPARE,
                    p.blocked_revision,
                    self.old.registry.revision,
                );
                bank[EXTRA_SALTS + 4..EXTRA_SALTS + 8].copy_from_slice(&vals(p.salt)?);
            }
            if let Some(p) = &self.next.progress[actor] {
                bank[EXTRA_SALTS + 8..EXTRA_SALTS + 12].copy_from_slice(&vals(p.salt)?);
            }
            for i in 0..4 {
                let matched = hidden.mask[usize::from(self.plain[3 * i]) / 8]
                    & (1 << (self.plain[3 * i] % 8))
                    != 0;
                let conflict = self
                    .old
                    .registry
                    .transactions
                    .get(1 - actor)
                    .is_some_and(|t| lifecycle::conflicts(hidden.mode, t.held[i]));
                let search = i >= usize::from(step.old_cursor)
                    && !step.block[..i].iter().any(|v| *v)
                    && step.selected[..i].iter().filter(|v| **v).count()
                        < usize::from(hidden.limit);
                for (start, v) in [
                    (MATCHES, matched),
                    (SEARCH, search),
                    (ATTEMPT, search && matched),
                    (CONFLICT, conflict),
                    (VISIT, step.delta[i]),
                    (SKIP, step.skipped[i]),
                    (RETURN, step.selected[i] && !old_s[i]),
                    (BLOCK, step.block[i]),
                ] {
                    bank[start + i] = Val::from_bool(v);
                }
                for (start, prefix, bound) in [
                    (
                        OLD_OFFSET_CMP,
                        old_v[..i].iter().filter(|v| **v).count(),
                        hidden.offset,
                    ),
                    (
                        LIMIT_CMP,
                        step.selected[..i].iter().filter(|v| **v).count(),
                        hidden.limit,
                    ),
                    (
                        OFFSET_CMP,
                        step.visited[..i].iter().filter(|v| **v).count(),
                        hidden.offset,
                    ),
                ] {
                    write_cmp(&mut bank, start + 4 * i, prefix, bound);
                }
            }
            write_cmp(
                &mut bank,
                OLD_LIMIT_CMP,
                old_s.iter().filter(|v| **v).count(),
                hidden.limit,
            );
            for (at, n, index) in [
                (CLIENT, 256, 0),
                (CALL, 64, 1),
                (INVOCATION, 256, 2),
                (OLD_MICRO, 64, 3),
                (OLD_HOLDER, 64, 4),
            ] {
                let pop: Val = bank[at..at + n].iter().copied().sum();
                bank[POP_INVERSES + index] = inverse(pop);
            }
            if prior.is_some() {
                let delta: Val = (0..64)
                    .map(|i| {
                        let d = bank[OLD_HOLDER + i] - bank[ID_CMD + i];
                        d * d
                    })
                    .sum();
                bank[POP_INVERSES + 5] = inverse(delta);
            }
        }
        Ok(bank)
    }
    pub(super) fn trace(&self) -> Result<RowMajorMatrix<Val>, Error> {
        let bank = self.bank()?;
        let fields = Fields::new(&self.statement);
        let mut values = Val::zero_vec(TRACE_WIDTH * bfv_hiding_stark::TRACE_HEIGHT);
        let mut checkpoint = [Val::ZERO; 12];
        let mut acc = [Val::ZERO; 4];
        let mask = self.hidden.as_ref().map_or([0; 32], |s| s.mask);
        for (r, row) in values
            .as_chunks_mut::<TRACE_WIDTH>()
            .0
            .iter_mut()
            .enumerate()
        {
            row.copy_from_slice(&bank);
            row[WORDS..TABLE].fill(Val::ZERO);
            row[ACC..SEARCH].fill(Val::ZERO);
            row[ACC..ACC + 4].copy_from_slice(&acc);
            if r < 256 {
                for (i, accumulator) in acc.iter_mut().enumerate() {
                    let age = self.plain[3 * i];
                    let d = u16::from(age) + 256 - r as u16;
                    let at = EQUALITY + 11 * i;
                    bits(&mut row[at..at + 8], u64::from(d % 256));
                    row[at + 8] = Val::from_bool(d >= 256);
                    row[at + 9] = Val::from_bool(d.is_multiple_of(256));
                    row[at + 10] = inverse(Val::from_u16(d % 256));
                    if usize::from(age) == r && mask[r / 8] & (1 << (r % 8)) != 0 {
                        *accumulator += Val::ONE;
                    }
                }
            }
            if r < 85 {
                for word in 0..8 {
                    let f = 8 * r + word;
                    if (87..674).contains(&f) {
                        let at = 4 * (f - 87);
                        bits(
                            &mut row[WORDS + 32 * word..WORDS + 32 * (word + 1)],
                            u64::from(u32::from_le_bytes(
                                self.plain[at..at + 4].try_into().unwrap(),
                            )),
                        );
                    }
                }
            }
            row[CP..WORDS].copy_from_slice(&checkpoint);
            let mut input = [Val::ZERO; 12];
            if let Some((stream, block)) = transition_fields::absorb(r) {
                for (w, v) in input[..8].iter_mut().enumerate() {
                    *v = fields.field(row, stream, 8 * block + w, w);
                }
                if !transition_fields::RESETS.contains(&r) {
                    input[8..].copy_from_slice(&checkpoint[8..]);
                }
            }
            let output = crate::poseidon::write(&mut row[..CP], input);
            if transition_fields::absorb(r).is_some() {
                checkpoint = output;
            }
        }
        Ok(RowMajorMatrix::new(values, TRACE_WIDTH))
    }
}
fn write_bytes(row: &mut [Val], at: usize, bytes: &[u8]) {
    for (i, v) in bytes.iter().enumerate() {
        bits(&mut row[at + 8 * i..at + 8 * (i + 1)], u64::from(*v));
    }
}
fn write_cmp(row: &mut [Val], at: usize, prefix: usize, bound: u8) {
    let d = prefix as u64 + 8 - u64::from(bound);
    bits(&mut row[at..at + 3], d % 8);
    row[at + 3] = Val::from_bool(d >= 8);
}
struct GuardedBaseStep(BaseStep);
impl Drop for GuardedBaseStep {
    fn drop(&mut self) {
        self.0.next.zeroize();
    }
}

#[cfg(test)]
pub(super) struct ResultOpeningInputsForTest<'a> {
    pub(super) original: &'a StatementOpening,
    pub(super) previous: Option<&'a super::circuit::ProgressOpening>,
    pub(super) parked: Option<&'a super::circuit::ProgressOpening>,
    pub(super) step: &'a Step,
}
