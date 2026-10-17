//! Client-owned SQL compilation into the existing private N4 locking contract.
//! No parser output authenticates an actor, source, registry or agreed head.
use super::{statement::Expected, trace::Plan};
use crate::backend::Error;
use crate::opening::statement as source;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use sha2::{Digest, Sha256};
use sql_plan::{
    LockStrength, LockWait, LockingClause, Predicate, Projection, QueryPlan, RowWindow,
};

/// Immutable owner/client plan, never a value decoded from a peer proof.
/// Its request binds the EXACT SQL bytes and caller nonce, not only a predicate mask.
pub(in crate::opening) struct CompiledLockPlan {
    request: [u8; 32],
    predicate: Predicate,
    projection: Projection,
    window: RowWindow,
    locking: LockingClause,
}
impl CompiledLockPlan {
    /// Caller nonce is an independently chosen request identity; this method
    /// proves no entropy or controller authorization. Fixtures use public nonces.
    pub(in crate::opening) fn compile(sql: &str, nonce: [u8; 32]) -> Result<Self, Error> {
        let QueryPlan::LockingSelect {
            predicate,
            projection,
            window,
            locking,
        } = sql_plan::parse_sql(sql).map_err(|_| Error::Shape)?
        else {
            return Err(Error::Shape);
        };
        // The relation has exactly four source rows and window fields0..4.
        // Unlike the old fixture constructor, this adapter never silently clamps.
        if window.offset > 4
            || window.limit.is_some_and(|n| n > 4)
            || projection == Projection::AmountAge
        {
            return Err(Error::Shape);
        }
        let mut h = Sha256::new();
        h.update(b"DCS/SQL-LOCK-REQUEST/N4/v1");
        h.update((sql.len() as u64).to_le_bytes());
        h.update(sql.as_bytes());
        h.update(nonce);
        Ok(Self {
            request: h.finalize().into(),
            predicate,
            projection,
            window,
            locking,
        })
    }
    /// Fresh owner-local request nonce. No Owner/key export or prover callback.
    pub(in crate::opening) fn fresh(sql: &str) -> Result<Self, Error> {
        let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
        Self::compile(sql, rng.random())
    }
    pub(in crate::opening) fn request(&self) -> [u8; 32] {
        self.request
    }
    pub(in crate::opening) fn plan(&self, table: [u8; 32], actor: u8) -> Result<Plan, Error> {
        let mode = match self.locking.strength {
            LockStrength::KeyShare => 1,
            LockStrength::Share => 2,
            LockStrength::NoKeyUpdate => 3,
            LockStrength::Update => 4,
        };
        let wait = match self.locking.wait {
            LockWait::Wait => 0,
            LockWait::NoWait => 1,
            LockWait::SkipLocked => 2,
        };
        let projection = match self.projection {
            Projection::Age => 1,
            Projection::Amount => 2,
            Projection::AgeAmount => 3,
            Projection::AmountAge => return Err(Error::Shape),
        };
        Plan::checked(
            table,
            self.predicate.age_mask(),
            actor,
            mode,
            wait,
            (self.window.offset, self.window.limit),
            projection,
        )
    }
    /// All identities/roots come from the independently owned caller context.
    /// The request-specific canonical source must already open this query identity.
    pub(super) fn expected(
        &self,
        source: &source::Statement,
        genesis: [u8; 32],
        parent: [u8; 32],
        old: [u8; 32],
        plan: [u8; 32],
    ) -> Result<Expected, Error> {
        if source.request != self.request {
            return Err(Error::Shape);
        }
        Expected::checked(source, genesis, parent, old, plan)
    }
}
