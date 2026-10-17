//! Bounded owner-witness trace factory. Never a peer/key-export interface.
use super::{air::*, statement::Statement};
use crate::backend::{Error, TRACE_HEIGHT, Val};
use crate::opening::{poseidon, statement::words};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

#[derive(Clone)]
pub(in crate::opening) struct Transaction {
    pub(in crate::opening) id: u32,
    pub(in crate::opening) controller: [u8; 32],
    pub(in crate::opening) sequence: u32,
    pub(in crate::opening) failed: bool,
    pub(in crate::opening) held: [u8; 4],
}
#[derive(Clone)]
pub(in crate::opening) struct Registry {
    pub(in crate::opening) revision: u32,
    pub(in crate::opening) tx: [Transaction; 2],
}
pub(in crate::opening) struct Plan {
    pub(in crate::opening) table: [u8; 32],
    pub(in crate::opening) mask: [u8; 32],
    pub(in crate::opening) actor: u8,
    pub(in crate::opening) mode: u8,
    pub(in crate::opening) wait: u8,
    pub(in crate::opening) offset: u8,
    pub(in crate::opening) limit: u8,
    pub(in crate::opening) projection: u8,
}
impl Plan {
    pub(in crate::opening) fn checked(
        table: [u8; 32],
        mask: [u8; 32],
        actor: u8,
        mode: u8,
        wait: u8,
        window: (usize, Option<usize>),
        projection: u8,
    ) -> Result<Self, Error> {
        if actor > 1 || !(1..=4).contains(&mode) || wait > 2 || projection > 3 {
            return Err(Error::Shape);
        }
        Ok(Self {
            table,
            mask,
            actor,
            mode,
            wait,
            offset: window.0.min(4) as u8,
            limit: window.1.unwrap_or(4).min(4) as u8,
            projection,
        })
    }
}
pub(in crate::opening) struct Witness {
    pub(in crate::opening) plain: [u8; 2348],
    pub(in crate::opening) old: Registry,
    pub(in crate::opening) plan: Plan,
    pub(in crate::opening) salts: [[Val; 4]; 6],
}
pub(in crate::opening) struct Walk {
    pub(in crate::opening) next: Registry,
    pub(in crate::opening) outcome: u8,
    pub(in crate::opening) search: [bool; 4],
    pub(in crate::opening) attempt: [bool; 4],
    pub(in crate::opening) conflict: [bool; 4],
    pub(in crate::opening) visit: [bool; 4],
    pub(in crate::opening) skip: [bool; 4],
    pub(in crate::opening) returned: [bool; 4],
    pub(in crate::opening) block: [bool; 4],
    pub(in crate::opening) candidate_revision: u32,
    pub(in crate::opening) candidate_sequence: [u32; 2],
}
pub(super) fn conflicts(request: u8, held: u8) -> bool {
    match request {
        1 => held == 4,
        2 => held >= 3,
        3 => held >= 2,
        4 => held != 0,
        _ => false,
    }
}
pub(super) fn bits(out: &mut [Val], value: u64) {
    for (bit, cell) in out.iter_mut().enumerate() {
        *cell = Val::from_u64((value >> bit) & 1);
    }
}
pub(super) fn inverse(v: Val) -> Val {
    if v == Val::ZERO {
        Val::ZERO
    } else {
        v.inverse()
    }
}
impl Witness {
    pub(in crate::opening) fn walk(&self) -> Result<Walk, Error> {
        let a = usize::from(self.plan.actor);
        if a > 1 {
            return Err(Error::Shape);
        }
        let candidate_revision = self.old.revision.checked_add(1).ok_or(Error::Shape)?;
        let mut candidate_sequence = self.old.tx.each_ref().map(|t| t.sequence);
        candidate_sequence[a] = candidate_sequence[a].checked_add(1).ok_or(Error::Shape)?;
        let mut result = Walk {
            next: self.old.clone(),
            outcome: 0,
            search: [false; 4],
            attempt: [false; 4],
            conflict: [false; 4],
            visit: [false; 4],
            skip: [false; 4],
            returned: [false; 4],
            block: [false; 4],
            candidate_revision,
            candidate_sequence,
        };
        let (mut returned, mut passed, mut stopped) = (0, 0, false);
        for i in 0..4 {
            result.conflict[i] = conflicts(self.plan.mode, self.old.tx[1 - a].held[i]);
            result.search[i] = !stopped && returned < self.plan.limit;
            let age = self.plain[3 * i];
            let matches = self.plan.mask[usize::from(age) / 8] & (1 << (age % 8)) != 0;
            result.attempt[i] = result.search[i] && matches;
            if !result.attempt[i] {
                continue;
            }
            if result.conflict[i] {
                if self.plan.wait == 2 {
                    result.skip[i] = true;
                    continue;
                }
                result.block[i] = true;
                result.outcome = if self.plan.wait == 0 { 1 } else { 2 };
                stopped = true;
                continue;
            }
            result.visit[i] = true;
            if passed >= self.plan.offset {
                result.returned[i] = true;
                returned += 1;
            }
            passed += 1;
        }
        if result.outcome == 0 {
            result.next.revision = candidate_revision;
            result.next.tx[a].sequence = candidate_sequence[a];
            for i in 0..4 {
                if result.visit[i] {
                    result.next.tx[a].held[i] = result.next.tx[a].held[i].max(self.plan.mode);
                }
            }
        }
        Ok(result)
    }
    pub(in crate::opening) fn trace(&self, s: &Statement) -> Result<RowMajorMatrix<Val>, Error> {
        let air = LockingAir::new(s);
        let result = self.walk()?;
        let a = usize::from(self.plan.actor);
        let mut bank = Val::zero_vec(WIDTH);
        for (i, byte) in self.plan.mask.iter().enumerate() {
            bits(
                &mut bank[MASK + i * 8..MASK + (i + 1) * 8],
                u64::from(*byte),
            );
        }
        for i in 0..4 {
            bits(
                &mut bank[AGES + i * 8..AGES + (i + 1) * 8],
                u64::from(self.plain[3 * i]),
            );
            bank[AMOUNTS + i] = Val::from_u16(u16::from_le_bytes([
                self.plain[3 * i + 1],
                self.plain[3 * i + 2],
            ]));
            let age = self.plain[3 * i];
            bank[MATCHES + i] =
                Val::from_bool(self.plan.mask[usize::from(age) / 8] & (1 << (age % 8)) != 0);
        }
        bank[TABLE..IDS].copy_from_slice(&words(&self.plan.table).collect::<Vec<_>>());
        bank[IDS..MATCHES].copy_from_slice(&words(&self.plain[2220..2348]).collect::<Vec<_>>());
        for t in 0..2 {
            bits(
                &mut bank[TX_IDS + 32 * t..TX_IDS + 32 * (t + 1)],
                u64::from(self.old.tx[t].id),
            );
            for (i, byte) in self.old.tx[t].controller.iter().enumerate() {
                bits(
                    &mut bank[CONTROLLERS + t * 256 + i * 8..CONTROLLERS + t * 256 + (i + 1) * 8],
                    u64::from(*byte),
                );
            }
            bank[FAILED + t] = Val::from_bool(self.old.tx[t].failed);
            bits(
                &mut bank[SEQUENCES + 32 * t..SEQUENCES + 32 * (t + 1)],
                u64::from(self.old.tx[t].sequence),
            );
            bits(
                &mut bank[CANDIDATE_SEQUENCES + 32 * t..CANDIDATE_SEQUENCES + 32 * (t + 1)],
                u64::from(result.candidate_sequence[t]),
            );
            for i in 0..4 {
                bank[HELD + (t * 4 + i) * 5 + usize::from(self.old.tx[t].held[i])] = Val::ONE;
                bank[NEXT_HELD + (t * 4 + i) * 5 + usize::from(result.next.tx[t].held[i])] =
                    Val::ONE;
            }
            bank[INVERSES + t] = inverse(Val::from_u32(self.old.tx[t].id));
            bank[INVERSES + 3 + t] = inverse(Val::from_u32(self.old.tx[t].sequence));
            bank[INVERSES + 5 + t] = inverse(Val::from_u32(
                self.old.tx[t]
                    .controller
                    .iter()
                    .map(|b| b.count_ones())
                    .sum(),
            ));
        }
        bank[INVERSES + 2] =
            inverse(Val::from_u32(self.old.tx[1].id) - Val::from_u32(self.old.tx[0].id));
        bits(
            &mut bank[REVISION..CANDIDATE_REVISION],
            u64::from(self.old.revision),
        );
        bits(
            &mut bank[CANDIDATE_REVISION..HELD],
            u64::from(result.candidate_revision),
        );
        bank[ACTOR] = Val::from_u8(self.plan.actor);
        bank[MODE + usize::from(self.plan.mode) - 1] = Val::ONE;
        bank[WAIT + usize::from(self.plan.wait)] = Val::ONE;
        bits(&mut bank[OFFSET..LIMIT], u64::from(self.plan.offset));
        bits(&mut bank[LIMIT..PROJECTION], u64::from(self.plan.limit));
        bits(
            &mut bank[PROJECTION..INVERSES],
            u64::from(self.plan.projection),
        );
        for i in 0..4 {
            for (start, flags) in [
                (SEARCH, result.search),
                (ATTEMPT, result.attempt),
                (CONFLICT, result.conflict),
                (VISIT, result.visit),
                (SKIP, result.skip),
                (RETURN, result.returned),
                (BLOCK, result.block),
            ] {
                bank[start + i] = Val::from_bool(flags[i]);
            }
            let rp = result.returned[..i].iter().filter(|v| **v).count() as u64;
            let pp = result.visit[..i].iter().filter(|v| **v).count() as u64;
            for (start, prefix, bound) in [
                (LIMIT_CMP + 4 * i, rp, self.plan.limit),
                (OFFSET_CMP + 4 * i, pp, self.plan.offset),
            ] {
                let d = prefix + 8 - u64::from(bound);
                bits(&mut bank[start..start + 3], d % 8);
                bank[start + 3] = Val::from_bool(d >= 8);
            }
            bank[OWN_MODES + i * 5 + usize::from(self.old.tx[a].held[i])] = Val::ONE;
            bank[DESIRED + i * 5 + usize::from(self.old.tx[a].held[i].max(self.plan.mode))] =
                Val::ONE;
            bank[TARGETS + a * 4 + i] = Val::from_bool(result.outcome == 0 && result.visit[i]);
        }
        bank[OUTCOME + usize::from(result.outcome)] = Val::ONE;
        for (matrix, presence, flags) in [
            (COMPACT_RETURN, PRESENT_RETURN, result.returned),
            (COMPACT_OWNED, PRESENT_OWNED, result.visit),
        ] {
            for (slot, i) in (0..4)
                .filter(|i| result.outcome == 0 && flags[*i])
                .enumerate()
            {
                bank[matrix + slot * 4 + i] = Val::ONE;
                bank[presence + slot] = Val::ONE;
            }
        }
        bank[SALTS..WIDTH].copy_from_slice(self.salts.as_flattened());
        if result.outcome != 0 {
            bank[SALTS + 12..SALTS + 16].copy_from_slice(&self.salts[1]);
        }
        let mut values = Val::zero_vec(TRACE_HEIGHT * WIDTH);
        let mut checkpoint = [Val::ZERO; 12];
        let mut accumulated = [Val::ZERO; 4];
        for (physical, row) in values.as_chunks_mut::<WIDTH>().0.iter_mut().enumerate() {
            row.copy_from_slice(&bank);
            row[ACCUMULATOR..EQUALITY].copy_from_slice(&accumulated);
            if physical < 256 {
                for (i, acc) in accumulated.iter_mut().enumerate() {
                    let d = u16::from(self.plain[3 * i]) + 256 - physical as u16;
                    let at = EQUALITY + 11 * i;
                    bits(&mut row[at..at + 8], u64::from(d % 256));
                    row[at + 8] = Val::from_bool(d >= 256);
                    row[at + 9] = Val::from_bool(d.is_multiple_of(256));
                    row[at + 10] = inverse(Val::from_u16(d % 256));
                    if physical == usize::from(self.plain[3 * i])
                        && self.plan.mask[physical / 8] & (1 << (physical % 8)) != 0
                    {
                        *acc += Val::ONE;
                    }
                }
            }
            if physical < 85 {
                for slot in 0..8 {
                    let f = physical * 8 + slot;
                    if (87..674).contains(&f) {
                        let k = f - 87;
                        bits(
                            &mut row[WORDS + slot * 32..WORDS + (slot + 1) * 32],
                            u64::from(u32::from_le_bytes(
                                self.plain[4 * k..4 * k + 4].try_into().unwrap(),
                            )),
                        );
                    }
                }
            }
            if physical == 300 {
                bits(
                    &mut row[WORDS..WORDS + 32],
                    u64::from(
                        self.old.tx[1]
                            .id
                            .wrapping_sub(self.old.tx[0].id)
                            .wrapping_sub(1),
                    ),
                );
            }
            row[CHECKPOINT..WORDS].copy_from_slice(&checkpoint);
            let mut input = [Val::ZERO; 12];
            if let Some((stream, block)) = absorb(physical) {
                for (slot, v) in input[..8].iter_mut().enumerate() {
                    *v = air.field(row, stream, block * 8 + slot, slot);
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
