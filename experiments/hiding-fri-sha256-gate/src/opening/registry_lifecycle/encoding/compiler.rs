//! Client-owned SQL-to-Command160 binding; never decoded from a peer.
use super::super::{
    model::{Command, Operation},
    statement::{self as lifecycle, Phase},
};
use super::statement::Expected;
use crate::backend::{Error, Val};
use crate::primitive::PublicStatement;
use sha2::{Digest, Sha256};
use sql_plan::{
    LockStrength, LockWait, LockingClause, Predicate, Projection, QueryPlan, RowWindow,
};

/// Private client metadata consumed only while matching an independently pinned C_cmd.
/// No signature, enrollment authority, agreed-head or controller-possession assertion.
pub(in crate::opening) struct CommandOpening {
    pub transaction: u64,
    pub principal: u8,
    pub controller: [u8; 32],
    pub revision: u64,
    pub sequence: u64,
    pub salt: [Val; 4],
}
pub(in crate::opening) struct CompiledQuery {
    query: [u8; 32],
    identity: [u8; 32],
    predicate: Predicate,
    projection: Projection,
    window: RowWindow,
    locking: LockingClause,
}
impl CompiledQuery {
    /// `query` is the existing, independently chosen lifecycle request, not this SQL hash.
    pub(in crate::opening) fn compile(
        sql: &str,
        nonce: [u8; 32],
        query: [u8; 32],
    ) -> Result<Self, Error> {
        let QueryPlan::LockingSelect {
            predicate,
            projection,
            window,
            locking,
        } = sql_plan::parse_sql(sql).map_err(|_| Error::Shape)?
        else {
            return Err(Error::Shape);
        };
        if window.offset > 4
            || window.limit.is_some_and(|x| x > 4)
            || projection == Projection::AmountAge
        {
            return Err(Error::Shape);
        }
        let mut h = Sha256::new();
        h.update(b"DCS/Registry200/exact-client-SQL-and-nonce/v1");
        h.update((sql.len() as u64).to_le_bytes());
        h.update(sql.as_bytes());
        h.update(nonce);
        Ok(Self {
            query,
            identity: h.finalize().into(),
            predicate,
            projection,
            window,
            locking,
        })
    }
    pub(super) fn command(&self, o: &CommandOpening) -> Result<Command, Error> {
        if o.transaction == 0
            || !(1..=2).contains(&o.principal)
            || o.controller == [0; 32]
            || o.revision == u64::MAX
            || o.sequence == 0
            || o.sequence == u64::MAX
        {
            return Err(Error::Shape);
        }
        let mut c = Command::control(Operation::Acquire, o.transaction, o.principal, o.sequence);
        c.mask = self.predicate.age_mask();
        c.mode = match self.locking.strength {
            LockStrength::KeyShare => 1,
            LockStrength::Share => 2,
            LockStrength::NoKeyUpdate => 3,
            LockStrength::Update => 4,
        };
        c.wait = match self.locking.wait {
            LockWait::Wait => 0,
            LockWait::NoWait => 1,
            LockWait::SkipLocked => 2,
        };
        c.offset = self.window.offset as u8;
        c.limit = self.window.limit.unwrap_or(4) as u8;
        c.projection = match self.projection {
            Projection::Age => 1,
            Projection::Amount => 2,
            Projection::AgeAmount => 3,
            Projection::AmountAge => return Err(Error::Shape),
        };
        c.require_shape()?;
        Ok(c)
    }
    pub(in crate::opening) fn bind(
        &self,
        e: &lifecycle::Expected,
        s: &lifecycle::Statement,
        o: CommandOpening,
    ) -> Result<Expected, Error> {
        e.require_contract()?;
        s.require_expected(e)?;
        let Phase::Transition { command, .. } = e.phase else {
            return Err(Error::Shape);
        };
        if e.source.request != self.query {
            return Err(Error::Shape);
        }
        let c = self.command(&o)?;
        let fields = lifecycle::command_fields_opening(
            e,
            &c,
            &lifecycle::CommandFieldsOpening {
                controller: o.controller,
                revision: o.revision,
                salt: o.salt,
            },
        );
        if lifecycle::digest(&fields) != command {
            return Err(Error::Shape);
        }
        // Only public identity, projection and the full independent producer survive.
        // o (including controller and salt) is not retained in Expected.
        Ok(Expected {
            parent: e.clone(),
            producer: s.clone(),
            sql_identity: self.identity,
            projection: c.projection,
        })
    }
}
pub(super) fn require_same(a: &Expected, b: &Expected) -> Result<(), Error> {
    a.require_contract()?;
    b.require_contract()?;
    a.producer.require_expected(&b.parent)?;
    if a.producer.public_values() != b.producer.public_values()
        || a.sql_identity != b.sql_identity
        || a.projection != b.projection
    {
        return Err(Error::Shape);
    }
    Ok(())
}
