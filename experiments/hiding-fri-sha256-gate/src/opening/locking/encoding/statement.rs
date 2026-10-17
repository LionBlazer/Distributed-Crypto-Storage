//! Exact typed parent statement, not a verified marker or an old Selection88 label.
use super::air;
use crate::backend::{Error, Val, profile_digest};
use crate::opening::{locking::statement as lock, state::locking as version};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};

pub(in crate::opening) const PUBLIC_VALUES: usize = 128;
#[derive(Clone)]
pub(super) enum Producer {
    Canonical {
        expected: lock::Expected,
        statement: lock::Statement,
    },
    Certified {
        expected: version::Expected,
        statement: version::Statement,
    },
}
/// Independently expected parent inputs AND exact proposed output roots. A
/// constructor checks identity/shape only. Actual proof verification is mandatory.
#[derive(Clone)]
pub(in crate::opening) struct Expected {
    pub(super) producer: Producer,
}
impl Expected {
    pub(in crate::opening) fn canonical(
        expected: &lock::Expected,
        statement: &lock::Statement,
    ) -> Result<Self, Error> {
        let out = Self {
            producer: Producer::Canonical {
                expected: expected.clone(),
                statement: statement.clone(),
            },
        };
        out.validate()?;
        Ok(out)
    }
    pub(in crate::opening) fn certified(
        expected: &version::Expected,
        statement: &version::Statement,
    ) -> Result<Self, Error> {
        let out = Self {
            producer: Producer::Certified {
                expected: expected.clone(),
                statement: statement.clone(),
            },
        };
        out.validate()?;
        Ok(out)
    }
    pub(super) fn validate(&self) -> Result<(), Error> {
        match &self.producer {
            Producer::Canonical {
                expected,
                statement,
            } => {
                if statement.kind() != Kind::LockingSelection {
                    return Err(Error::Shape);
                }
                statement.require_expected(expected)?;
            }
            Producer::Certified {
                expected,
                statement,
            } => {
                if statement.kind() != Kind::VersionLockingSelection {
                    return Err(Error::Shape);
                }
                statement.require_expected(expected)?;
            }
        }
        // Make malformed packet boundaries total before any parent AIR/public
        // conversion. The real parent proof still establishes the full source.
        let raw = self.lock();
        if raw.expected.source.packets[0].len() != 60
            || raw.expected.source.packets[1].len() != 2384
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(in crate::opening) fn lock(&self) -> &lock::Statement {
        match &self.producer {
            Producer::Canonical { statement, .. } => statement,
            Producer::Certified { statement, .. } => statement.source(),
        }
    }
    pub(in crate::opening) fn require_same(&self, expected: &Self) -> Result<(), Error> {
        self.same(expected)
    }
    fn same(&self, expected: &Self) -> Result<(), Error> {
        self.validate()?;
        expected.validate()?;
        match (&self.producer, &expected.producer) {
            (Producer::Canonical { statement, .. }, Producer::Canonical { expected, .. }) => {
                statement.require_expected(expected)?
            }
            (Producer::Certified { statement, .. }, Producer::Certified { expected, .. }) => {
                statement.require_expected(expected)?
            }
            _ => return Err(Error::Shape),
        }
        if self.lock().public_values() != expected.lock().public_values() {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(in crate::opening) struct Statement {
    pub(in crate::opening) expected: Expected,
    pub(in crate::opening) encoded: [Val; 4],
}
impl Statement {
    pub(in crate::opening) fn new(expected: Expected, encoded: [Val; 4]) -> Self {
        Self { expected, encoded }
    }
    pub(in crate::opening) fn require_expected(&self, expected: &Expected) -> Result<(), Error> {
        self.expected.same(expected)
    }
    pub(in crate::opening) fn context(&self) -> [Val; 8] {
        let mut h = Sha256::new();
        h.update(b"DCS/N4-successful-lock-return-encoding-context/v1");
        h.update(profile_digest(Kind::LockReturnedEncoding));
        let values = self.expected.lock().public_values();
        h.update((values.len() as u64).to_le_bytes());
        for value in values {
            h.update(value.as_canonical_u64().to_le_bytes());
        }
        crate::opening::statement::words(&h.finalize())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::LockReturnedEncoding
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::Encoding(Box::new(air::EncodingAir::returned(self)))
    }
    fn public_values(&self) -> Vec<Val> {
        crate::opening::statement::words(&profile_digest(self.kind()))
            .chain(self.expected.lock().public_values())
            .chain(self.encoded)
            .collect()
    }
}
