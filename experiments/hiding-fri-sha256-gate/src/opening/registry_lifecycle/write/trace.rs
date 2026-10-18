//! Private owner inputs and trace writer; never a verifier or network authority.
use super::super::{
    statement as lifecycle,
    trace::{self as old_trace, Witness as LifecycleWitness},
};
use super::{
    compiler::{self, Command},
    statement::{Expected, Statement},
};
use crate::{
    backend::{Error, TRACE_HEIGHT, Val},
    opening::{commitment, poseidon, statement as source},
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use registry200_proof::write::{
    air::{self, WriteAir},
    layout::*,
    statement as fixed,
};
#[derive(Clone)]
pub(in crate::opening::registry_lifecycle) struct Witness {
    pub opening: LifecycleWitness,
    pub command: Command,
    pub image_salt: [Val; 4],
}
fn amount(plain: &[u8; 2348], i: usize) -> u16 {
    u16::from_le_bytes(plain[3 * i + 1..3 * i + 3].try_into().unwrap())
}
fn write_bytes(out: &mut [Val], bytes: &[u8]) {
    for (i, byte) in bytes.iter().enumerate() {
        old_trace::bits(&mut out[8 * i..8 * (i + 1)], u64::from(*byte));
    }
}
/// Owner-only independent opening match, before computing the new command commitment.
pub(in crate::opening::registry_lifecycle) fn require_parent_openings(
    e: &Expected,
    w: &LifecycleWitness,
) -> Result<(), Error> {
    let anchor = e.lifecycle_anchor()?;
    if commitment::digest(&commitment::opening_fields(
        e.source(),
        w.salts[0],
        &w.plain,
    )) != e.source().open_commitment
        || commitment::digest(&lifecycle::enrollment_fields(&anchor, w)) != e.enrollment()
        || lifecycle::digest(&lifecycle::registry_fields(&anchor, w, &w.old, w.salts[2]))
            != e.registry()
    {
        return Err(Error::Shape);
    }
    Ok(())
}
impl Witness {
    pub(super) fn outputs(&self) -> Result<([u16; 4], [bool; 4]), Error> {
        self.command.require_shape()?;
        self.opening.old.require_canonical()?;
        let c = &self.command;
        let state = &self.opening.old;
        let actor = state
            .transactions
            .iter()
            .find(|t| t.id == c.transaction)
            .ok_or(Error::Shape)?;
        if actor.principal != c.principal
            || actor.failed
            || actor.sequence != c.sequence
            || state.revision != c.revision
            || self.opening.controllers[usize::from(c.principal - 1)] != c.controller
            || state.revision.checked_add(1).is_none()
            || actor.sequence.checked_add(1).is_none()
        {
            return Err(Error::Shape);
        }
        let matched = core::array::from_fn(|i| {
            let age = self.opening.plain[3 * i] as usize;
            self.command.mask[age / 8] & (1 << (age % 8)) != 0
        });
        let mut output = core::array::from_fn(|i| amount(&self.opening.plain, i));
        for i in 0..4 {
            if matched[i] {
                if !matches!(actor.held[i], 3 | 4) {
                    return Err(Error::Shape);
                }
                output[i] = output[i].checked_add(c.delta).ok_or(Error::Shape)?;
            }
        }
        Ok((output, matched))
    }
    pub(super) fn require_openings(&self, e: &Expected) -> Result<(), Error> {
        require_parent_openings(e, &self.opening)?;
        if fixed::command_digest(&compiler::command_fields(e, &self.command)) != e.command() {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(in crate::opening::registry_lifecycle) fn statement(
        &self,
        e: &Expected,
    ) -> Result<Statement, Error> {
        self.require_openings(e)?;
        let (new, _) = self.outputs()?;
        Ok(Statement {
            expected: e.clone(),
            image: fixed::image_digest(&self.image_fields(e, new)),
        })
    }
    pub(super) fn image_fields(&self, e: &Expected, new: [u16; 4]) -> [Val; fixed::IMAGE_FIELDS] {
        let mut fields = source::words(&fixed::IMAGE_DOMAIN)
            .chain([Val::ONE])
            .chain(e.context())
            .chain(e.registry())
            .chain(e.command())
            .chain([Val::from_u8(4)])
            .chain(source::words(&self.opening.table()))
            .collect::<Vec<_>>();
        for (i, value) in new.into_iter().enumerate() {
            fields.push(Val::from_usize(i));
            fields.extend(source::words(
                &self.opening.plain[2220 + 32 * i..2220 + 32 * (i + 1)],
            ));
            fields.extend([
                Val::from_u8(self.opening.plain[3 * i]),
                Val::from_u16(value),
            ]);
        }
        fields.extend(self.image_salt);
        fields.extend([Val::ZERO; 6]);
        fields.try_into().unwrap()
    }
    pub(super) fn trace(&self, s: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        self.require_openings(&s.expected)?;
        let (new, matched) = self.outputs()?;
        self.trace_with_outputs(s, new, matched)
    }
    /// Low-level caller-owned rebuilt trace for owning adversarial tests. Not proof admission.
    pub(super) fn trace_with_outputs(
        &self,
        s: &Statement,
        new: [u16; 4],
        matched: [bool; 4],
    ) -> Result<RowMajorMatrix<Val>, Error> {
        let mut bank = Val::zero_vec(WIDTH);
        let c = &self.command;
        let old = &self.opening.old;
        write_bytes(&mut bank[DATA..TABLE], &self.opening.plain[..12]);
        for (i, word) in source::words(&self.opening.table()).enumerate() {
            bank[TABLE + i] = word;
        }
        for (i, word) in source::words(&self.opening.plain[2220..2348]).enumerate() {
            bank[IDS + i] = word;
        }
        for (t, controller) in self.opening.controllers.iter().enumerate() {
            write_bytes(
                &mut bank[CONTROLLERS + 256 * t..CONTROLLERS + 256 * (t + 1)],
                controller,
            );
            bank[CTRL_INV + t] = old_trace::inverse(Val::from_u32(
                controller.iter().map(|b| b.count_ones()).sum(),
            ));
        }
        for (i, salt) in [
            self.opening.salts[0],
            self.opening.salts[1],
            self.opening.salts[2],
            c.salt,
            self.image_salt,
        ]
        .into_iter()
        .enumerate()
        {
            bank[SALTS + 4 * i..SALTS + 4 * (i + 1)].copy_from_slice(&salt);
        }
        old_trace::write_state(&mut bank, STATE, old);
        let ids =
            core::array::from_fn::<_, 2, _>(|t| old.transactions.get(t).map_or(0, |tx| tx.id));
        for (i, (left, right)) in [
            (old.revision, old.allocator),
            (old.allocator, ids[0]),
            (old.allocator, ids[1]),
            (ids[0], ids[1]),
        ]
        .into_iter()
        .enumerate()
        {
            old_trace::subtraction(&mut bank, COMPARE + 65 * i, left, right);
        }
        for t in 0..2 {
            for (part, value) in [ids[t], old.transactions.get(t).map_or(0, |tx| tx.sequence)]
                .into_iter()
                .enumerate()
            {
                bank[STATE_INV + 2 * t + part] =
                    old_trace::inverse(Val::from_u32(value.count_ones()));
            }
        }
        let actor = old
            .transactions
            .iter()
            .position(|t| t.id == c.transaction)
            .unwrap_or(0);
        bank[ACTOR + actor] = Val::ONE;
        if (1..=2).contains(&c.principal) {
            bank[PRINCIPAL + usize::from(c.principal - 1)] = Val::ONE;
        }
        for (at, value) in [(TXID, c.transaction), (REV, c.revision), (SEQ, c.sequence)] {
            old_trace::bits(&mut bank[at..at + 64], value);
        }
        write_bytes(&mut bank[MASK..DELTA], &c.mask);
        old_trace::bits(&mut bank[DELTA..NEW_AMOUNTS], u64::from(c.delta));
        for (i, value) in new.into_iter().enumerate() {
            old_trace::bits(
                &mut bank[NEW_AMOUNTS + 16 * i..NEW_AMOUNTS + 16 * (i + 1)],
                u64::from(value),
            );
            bank[MATCHES + i] = Val::from_bool(matched[i]);
        }
        for (at, carry, value) in [
            (NEXT_REV, CARRY, c.revision),
            (NEXT_SEQ, CARRY + 1, c.sequence),
        ] {
            old_trace::bits(&mut bank[at..at + 64], value.wrapping_add(1));
            bank[carry] = Val::from_bool(value as u32 == u32::MAX);
        }
        let mut values = Val::zero_vec(WIDTH * TRACE_HEIGHT);
        let mut accum = [Val::ZERO; 4];
        for (physical, row) in values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            row.copy_from_slice(&bank);
            row[ACC..ACC + 4].copy_from_slice(&accum);
            if physical < 85 {
                for word in 0..8 {
                    let f = 8 * physical + word;
                    if (87..674).contains(&f) {
                        let at = 4 * (f - 87);
                        old_trace::bits(
                            &mut row[WORDS + 32 * word..WORDS + 32 * (word + 1)],
                            u64::from(u32::from_le_bytes(
                                self.opening.plain[at..at + 4].try_into().unwrap(),
                            )),
                        );
                    }
                }
            }
            if physical < 256 {
                let mask = c.mask[physical / 8] & (1 << (physical % 8)) != 0;
                for (i, total) in accum.iter_mut().enumerate() {
                    let value = usize::from(self.opening.plain[3 * i]) + 256 - physical;
                    let difference = value % 256;
                    let at = EQUALITY + 11 * i;
                    old_trace::bits(&mut row[at..at + 8], difference as u64);
                    row[at + 8] = Val::from_bool(value >= 256);
                    row[at + 9] = Val::from_bool(difference == 0);
                    row[at + 10] = old_trace::inverse(Val::from_usize(difference));
                    if mask && difference == 0 {
                        *total += Val::ONE;
                    }
                }
            }
        }
        let mut trace = RowMajorMatrix::new(values, WIDTH);
        let _ = refresh(s, &mut trace);
        Ok(trace)
    }
}
/// Refresh ONLY genuine permutation/checkpoint rows after a caller-owned rebuilt bank.
/// This does not repair semantic constraints, source/command roots or validate a witness.
pub(super) fn refresh(s: &Statement, trace: &mut RowMajorMatrix<Val>) -> [Val; 4] {
    let air = WriteAir::new(s);
    let mut checkpoint = [Val::ZERO; 12];
    let mut image = [Val::ZERO; 4];
    for (physical, row) in trace
        .values
        .as_chunks_mut::<WIDTH>()
        .0
        .iter_mut()
        .enumerate()
    {
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
        if physical == 161 {
            image = output[..4].try_into().unwrap();
        }
    }
    image
}
