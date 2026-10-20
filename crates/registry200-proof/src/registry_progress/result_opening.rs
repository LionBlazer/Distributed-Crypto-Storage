//! Owner-private opening of one genuinely verified predicate Result160.
//!
//! This checks commitment mathematics only. The owner must independently check
//! its exact operation, fresh agreed parent and actual finality receipt before
//! using an opening. It grants no SQL success, rows, lock, or installed bank.
use super::{
    RESULT_FIELDS,
    bootstrap::Error,
    circuit::{ProgressOpening, StatementOpening, Status},
    fields,
    transition::VerifiedStep,
};
use crate::{Val, source::statement};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use zeroize::{Zeroize, Zeroizing};

const OLD_ROOT: usize = 105;
const NEXT_ROOT: usize = 109;
const STATEMENT_ROOT: usize = 113;
const ACTION: usize = 117;
const STATUS: usize = 118;
const TRANSACTION: usize = 119;
const OLD_CURSOR: usize = 121;
const CURSOR: usize = 122;
const VISITED: usize = 123;
const SELECTED: usize = 127;
const BLOCK: usize = 131;
const OLD_PROGRESS: usize = 135;
const PARKED_PROGRESS: usize = 139;
const HOLDER: usize = 143;
const HOLDER_MODE: usize = 145;
const CALL: usize = 146;
const MICROSTEP: usize = 148;
const PADDING: usize = 154;

/// Private conflict association from the opened, proof-bound result.
/// It is neither a peer-visible status nor authority to release a lock.
pub struct BlockedOn {
    ordinal: u8,
    transaction: u64,
    mode: u8,
}
impl BlockedOn {
    pub fn ordinal(&self) -> u8 {
        self.ordinal
    }
    pub fn transaction(&self) -> u64 {
        self.transaction
    }
    pub fn mode(&self) -> u8 {
        self.mode
    }
}
impl Drop for BlockedOn {
    fn drop(&mut self) {
        self.ordinal.zeroize();
        self.transaction.zeroize();
        self.mode.zeroize();
    }
}

/// A checked PRIVATE predicate preimage, never a finality or SQL capability.
/// The fixed 1,280-byte field array is zeroized on drop; no raw-field getter,
/// serialization, unchecked constructor, Clone, or Debug implementation is provided.
/// Control Result160 has a different action/status grammar and is rejected.
///
/// ```compile_fail
/// fn forge() {
///     let _ = registry200_proof::registry_progress::result_opening::ResultOpening {
///         fields: zeroize::Zeroizing::new([0; 160]),
///     };
/// }
/// ```
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// fn copy() {
///     require_clone::<registry200_proof::registry_progress::result_opening::ResultOpening>();
/// }
/// ```
pub struct ResultOpening {
    fields: Zeroizing<[u64; RESULT_FIELDS]>,
}
impl ResultOpening {
    /// Consume canonical private fields and check their entire commitment against
    /// this actual VerifiedStep, the independently retained original Statement,
    /// and the exact previous/parked progress openings. No predicate or window is
    /// reevaluated. Source correctness, SQL admission, QC and bank installation
    /// remain separate responsibilities of their actual owning boundaries.
    pub fn open(
        verified: &VerifiedStep,
        fields: Zeroizing<[u64; RESULT_FIELDS]>,
        original: &StatementOpening,
        previous: Option<&ProgressOpening>,
        parked: Option<&ProgressOpening>,
    ) -> Result<Self, Error> {
        if !verified.statement().expected().is_predicate() {
            return Err(Error::Shape);
        }
        // Reject modular aliases BEFORE converting any caller-controlled word.
        if fields.iter().any(|word| *word >= Val::ORDER_U64) {
            return Err(Error::Encoding);
        }
        original.require_shape().map_err(|_| Error::Shape)?;
        Self::require_shape(&fields, original)?;
        let mut values = core::array::from_fn::<_, RESULT_FIELDS, _>(|i| Val::from_u64(fields[i]));
        let checked = (|| {
            let statement = verified.statement();
            let expected = statement.expected();
            let domain =
                crate::source::statement::words(&fields::RESULT_DOMAIN).collect::<Vec<_>>();
            if &values[..4] != domain.as_slice()
                || values[4] != Val::ONE
                || values[5..OLD_ROOT] != expected.context()
                || values[OLD_ROOT..NEXT_ROOT] != expected.old
                || values[NEXT_ROOT..STATEMENT_ROOT] != statement.next
                || values[STATEMENT_ROOT..ACTION] != original.root().map_err(|_| Error::Shape)?
                || original.scope != expected.statement_scope()
                || original.enrollment
                    != expected
                        .registry_context()
                        .enrollment()
                        .map(|v| v.as_canonical_u64())
                || (fields[ACTION] == 0
                    && original.sql_identity
                        != expected
                            .query()
                            .ok_or(Error::Shape)?
                            .expected
                            .sql_identity())
            {
                return Err(Error::Shape);
            }
            Self::require_progress(&fields, &values, original, previous, parked)?;
            if super::fields::digest(&values) != statement.result {
                return Err(Error::Verification);
            }
            Ok(())
        })();
        values.fill(Val::ZERO);
        checked?;
        Ok(Self { fields })
    }
    fn require_shape(
        fields: &[u64; RESULT_FIELDS],
        original: &StatementOpening,
    ) -> Result<(), Error> {
        if fields[ACTION] > 1
            || fields[STATUS] > 2
            || fields[OLD_CURSOR] > fields[CURSOR]
            || fields[CURSOR] > 4
            || fields[PADDING..].iter().any(|word| *word != 0)
        {
            return Err(Error::Shape);
        }
        for at in [TRANSACTION, HOLDER, CALL, MICROSTEP] {
            if fields[at] > u64::from(u32::MAX) || fields[at + 1] > u64::from(u32::MAX) {
                return Err(Error::Shape);
            }
        }
        if word(fields, TRANSACTION) != original.transaction
            || word(fields, CALL) != original.call
            || word(fields, MICROSTEP) == 0
            || fields[VISITED..OLD_PROGRESS].iter().any(|flag| *flag > 1)
        {
            return Err(Error::Shape);
        }
        for i in 0..4 {
            if (fields[SELECTED + i] == 1 && fields[VISITED + i] == 0)
                || (i >= fields[CURSOR] as usize
                    && (fields[VISITED + i] != 0 || fields[SELECTED + i] != 0))
            {
                return Err(Error::Shape);
            }
        }
        let selected = fields[SELECTED..BLOCK].iter().filter(|v| **v == 1).count();
        if selected > usize::from(original.limit) {
            return Err(Error::Shape);
        }
        let blocked = fields[BLOCK..OLD_PROGRESS]
            .iter()
            .filter(|v| **v == 1)
            .count();
        if fields[STATUS] == 1 {
            if blocked != 0 || word(fields, HOLDER) != 0 || fields[HOLDER_MODE] != 0 {
                return Err(Error::Shape);
            }
        } else if blocked != 1
            || fields[CURSOR] >= 4
            || fields[BLOCK + fields[CURSOR] as usize] != 1
            || word(fields, HOLDER) == 0
            || word(fields, HOLDER) == original.transaction
            || !(1..=4).contains(&fields[HOLDER_MODE])
            || !crate::lifecycle::conflicts(original.mode, fields[HOLDER_MODE] as u8)
            || selected >= usize::from(original.limit)
            || (fields[STATUS] == 0 && original.wait != 0)
            || (fields[STATUS] == 2 && original.wait != 1)
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    fn require_progress(
        raw: &[u64; RESULT_FIELDS],
        values: &[Val; RESULT_FIELDS],
        original: &StatementOpening,
        previous: Option<&ProgressOpening>,
        parked: Option<&ProgressOpening>,
    ) -> Result<(), Error> {
        match (raw[ACTION], previous) {
            (0, None)
                if raw[OLD_CURSOR] == 0
                    && word(raw, MICROSTEP) == 1
                    && values[OLD_PROGRESS..PARKED_PROGRESS] == [Val::ZERO; 4] => {}
            (1, Some(p)) => {
                p.require_shape().map_err(|_| Error::Shape)?;
                if p.statement != *original
                    || raw[OLD_CURSOR] != u64::from(p.cursor)
                    || p.microstep.checked_add(1) != Some(word(raw, MICROSTEP))
                    || values[OLD_PROGRESS..PARKED_PROGRESS]
                        != p.root().map_err(|_| Error::Shape)?
                {
                    return Err(Error::Shape);
                }
            }
            _ => return Err(Error::Shape),
        }
        match (raw[STATUS], parked) {
            (0, Some(p)) => {
                p.require_shape().map_err(|_| Error::Shape)?;
                if p.statement != *original
                    || raw[CURSOR] != u64::from(p.cursor)
                    || word(raw, MICROSTEP) != p.microstep
                    || flags(raw, VISITED) != p.visited
                    || flags(raw, SELECTED) != p.selected
                    || word(raw, HOLDER) != p.holder
                    || raw[HOLDER_MODE] != u64::from(p.holder_mode)
                    || values[PARKED_PROGRESS..HOLDER] != p.root().map_err(|_| Error::Shape)?
                {
                    return Err(Error::Shape);
                }
            }
            (1 | 2, None) if values[PARKED_PROGRESS..HOLDER] == [Val::ZERO; 4] => {}
            _ => return Err(Error::Shape),
        }
        Ok(())
    }
    pub fn status(&self) -> Status {
        match self.fields[STATUS] {
            0 => Status::Parked,
            1 => Status::Done,
            2 => Status::Error,
            _ => unreachable!("predicate status was checked at construction"),
        }
    }
    pub fn resumed(&self) -> bool {
        self.fields[ACTION] == 1
    }
    pub fn transaction(&self) -> u64 {
        word(&self.fields, TRANSACTION)
    }
    pub fn call(&self) -> u64 {
        word(&self.fields, CALL)
    }
    pub fn microstep(&self) -> u64 {
        word(&self.fields, MICROSTEP)
    }
    pub fn old_cursor(&self) -> u8 {
        self.fields[OLD_CURSOR] as u8
    }
    pub fn cursor(&self) -> u8 {
        self.fields[CURSOR] as u8
    }
    pub fn visited(&self) -> [bool; 4] {
        flags(&self.fields, VISITED)
    }
    pub fn selected(&self) -> [bool; 4] {
        flags(&self.fields, SELECTED)
    }
    pub fn blocked(&self) -> Option<BlockedOn> {
        (self.fields[STATUS] != 1).then(|| BlockedOn {
            ordinal: self.cursor(),
            transaction: word(&self.fields, HOLDER),
            mode: self.fields[HOLDER_MODE] as u8,
        })
    }
    pub fn old_registry_root(&self) -> [u8; 32] {
        self.root(OLD_ROOT)
    }
    pub fn next_registry_root(&self) -> [u8; 32] {
        self.root(NEXT_ROOT)
    }
    pub fn statement_root(&self) -> [u8; 32] {
        self.root(STATEMENT_ROOT)
    }
    pub fn previous_progress_root(&self) -> Option<[u8; 32]> {
        self.resumed().then(|| self.root(OLD_PROGRESS))
    }
    pub fn parked_progress_root(&self) -> Option<[u8; 32]> {
        (self.fields[STATUS] == 0).then(|| self.root(PARKED_PROGRESS))
    }
    fn root(&self, at: usize) -> [u8; 32] {
        statement::encode_digest(core::array::from_fn(|i| Val::from_u64(self.fields[at + i])))
    }
}
fn word(fields: &[u64; RESULT_FIELDS], at: usize) -> u64 {
    fields[at] | (fields[at + 1] << 32)
}
fn flags(fields: &[u64; RESULT_FIELDS], at: usize) -> [bool; 4] {
    core::array::from_fn(|i| fields[at + i] == 1)
}
