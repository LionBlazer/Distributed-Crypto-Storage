//! Owner-private mathematics for one genuinely verified Control Result160.
//!
//! This is not a QC, SQL outcome, current lock or installed private bank.
use super::{
    RESULT_FIELDS,
    bootstrap::Error,
    circuit::ProgressOpening,
    fields,
    transition::{Expected, VerifiedStep},
    transition_trace,
};
use crate::{
    Val,
    lifecycle::circuit::model::{Command, Operation},
    source::statement,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use zeroize::Zeroizing;

const OLD: usize = 105;
const NEXT: usize = 109;
const STATEMENT: usize = 113;
const ACTION: usize = 117;
const STATUS: usize = 118;
const TRANSACTION: usize = 119;
const OLD_PROGRESS: usize = 135;
const NEXT_PROGRESS: usize = 139;
const TAIL: usize = 143;
const SALT: usize = 150;
const PADDING: usize = 154;

/// Private mathematical Control status. Aborted is possible only for End.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlStatus {
    Applied,
    Aborted,
}

/// Independently retained current intent/openings, still unverified metadata.
/// Borrowed inputs do not duplicate or serialize their private custody material.
/// A valid context alone grants no proof, finality, SQL or bank authority.
pub struct ControlOpeningContext<'a> {
    expected: &'a Expected,
    command: &'a Command,
    previous: Option<&'a ProgressOpening>,
}
impl<'a> ControlOpeningContext<'a> {
    pub fn new(
        expected: &'a Expected,
        command: &'a Command,
        revision: u64,
        controllers: &[[u8; 32]; 2],
        command_salt: &[u64; 4],
        previous: Option<&'a ProgressOpening>,
    ) -> Result<Self, Error> {
        if expected.is_predicate()
            || matches!(
                command.operation,
                Operation::Acquire | Operation::FailCurrent
            )
        {
            return Err(Error::Shape);
        }
        expected.require_same(expected)?;
        command.require_shape()?;
        if controllers.contains(&[0; 32]) {
            return Err(Error::Shape);
        }
        if command_salt.iter().any(|word| *word >= Val::ORDER_U64) {
            return Err(Error::Encoding);
        }
        if let Some(progress) = previous {
            progress.require_shape()?;
            let original = &progress.statement;
            // The actual relation only permits End(abort) on its parked actor.
            if command.operation != Operation::End
                || !command.abort
                || original.transaction != command.transaction
                || original.principal != command.principal
                || original.controller != controllers[usize::from(command.principal - 1)]
                || original.enrollment
                    != expected
                        .registry_context()
                        .enrollment()
                        .map(|v| v.as_canonical_u64())
            {
                return Err(Error::Shape);
            }
        }
        let mut opening = transition_trace::command_fields(
            expected,
            command,
            revision,
            controllers,
            command_salt.map(Val::from_u64),
        )?;
        let matches = fields::digest(&opening) == expected.command;
        opening.fill(Val::ZERO);
        if !matches {
            return Err(Error::Verification);
        }
        Ok(Self {
            expected,
            command,
            previous,
        })
    }
}

/// Checked PRIVATE Control preimage. No raw getter, serialization, unchecked
/// constructor, Clone or Debug is provided; the full backing array is zeroized.
/// Predicate has a different grammar and is unconditionally rejected.
///
/// ```compile_fail
/// fn forge() {
///     let _ = registry200_proof::registry_progress::control_result_opening::ControlResultOpening {
///         fields: zeroize::Zeroizing::new([0; 160]),
///     };
/// }
/// ```
/// ```compile_fail
/// fn copy<T: Clone>() {}
/// fn forbidden() {
///     copy::<registry200_proof::registry_progress::control_result_opening::ControlResultOpening>();
/// }
/// ```
pub struct ControlResultOpening {
    fields: Zeroizing<[u64; RESULT_FIELDS]>,
}
impl ControlResultOpening {
    pub fn open(
        verified: &VerifiedStep,
        fields: Zeroizing<[u64; RESULT_FIELDS]>,
        context: &ControlOpeningContext<'_>,
    ) -> Result<Self, Error> {
        let statement = verified.statement();
        if statement.expected().is_predicate() {
            return Err(Error::Shape);
        }
        statement.require_expected(context.expected)?;
        if fields.iter().any(|word| *word >= Val::ORDER_U64) {
            return Err(Error::Encoding);
        }
        let command = context.command;
        if fields[ACTION] != 2 + command.operation as u64
            || !matches!(fields[STATUS], 1 | 3)
            || (fields[STATUS] == 3 && command.operation != Operation::End)
            || (command.abort && fields[STATUS] != 3)
            || fields[TRANSACTION] > u64::from(u32::MAX)
            || fields[TRANSACTION + 1] > u64::from(u32::MAX)
            || (fields[TRANSACTION] | (fields[TRANSACTION + 1] << 32)) != command.transaction
            || fields[STATEMENT..ACTION] != [0; 4]
            || fields[TRANSACTION + 2..OLD_PROGRESS]
                .iter()
                .any(|word| *word != 0)
            || fields[TAIL..SALT].iter().any(|word| *word != 0)
            || fields[PADDING..].iter().any(|word| *word != 0)
        {
            return Err(Error::Shape);
        }
        let mut values = core::array::from_fn::<_, RESULT_FIELDS, _>(|i| Val::from_u64(fields[i]));
        let checked = (|| {
            let domain = statement::words(&fields::RESULT_DOMAIN).collect::<Vec<_>>();
            let previous = context
                .previous
                .map(|p| p.root())
                .transpose()?
                .unwrap_or([Val::ZERO; 4]);
            let next_progress = if command.operation == Operation::End {
                [Val::ZERO; 4]
            } else {
                previous
            };
            if &values[..4] != domain.as_slice()
                || values[4] != Val::ONE
                || values[5..OLD] != context.expected.context()
                || values[OLD..NEXT] != context.expected.old
                || values[NEXT..STATEMENT] != statement.next
                || values[OLD_PROGRESS..NEXT_PROGRESS] != previous
                || values[NEXT_PROGRESS..TAIL] != next_progress
            {
                return Err(Error::Shape);
            }
            if fields::digest(&values) != statement.result {
                return Err(Error::Verification);
            }
            Ok(())
        })();
        values.fill(Val::ZERO);
        checked?;
        Ok(Self { fields })
    }
    pub fn status(&self) -> ControlStatus {
        match self.fields[STATUS] {
            1 => ControlStatus::Applied,
            3 => ControlStatus::Aborted,
            _ => unreachable!("Control status was checked at construction"),
        }
    }
    pub fn operation(&self) -> Operation {
        match self.fields[ACTION] {
            2 => Operation::Begin,
            5 => Operation::Savepoint,
            6 => Operation::RollbackTo,
            7 => Operation::Release,
            8 => Operation::End,
            _ => unreachable!("Control operation was checked at construction"),
        }
    }
    pub fn transaction(&self) -> u64 {
        self.fields[TRANSACTION] | (self.fields[TRANSACTION + 1] << 32)
    }
    pub fn old_registry_root(&self) -> [u8; 32] {
        self.root(OLD)
    }
    pub fn next_registry_root(&self) -> [u8; 32] {
        self.root(NEXT)
    }
    /// Zero is the fixed absent-progress encoding; the caller retains presence.
    pub fn previous_progress_root(&self) -> [u8; 32] {
        self.root(OLD_PROGRESS)
    }
    pub fn next_progress_root(&self) -> [u8; 32] {
        self.root(NEXT_PROGRESS)
    }
    fn root(&self, at: usize) -> [u8; 32] {
        statement::encode_digest(core::array::from_fn(|i| Val::from_u64(self.fields[at + i])))
    }
}
