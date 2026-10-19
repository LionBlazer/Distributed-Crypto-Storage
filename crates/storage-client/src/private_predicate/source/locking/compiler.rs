//! Fixed local LockingSelect compiler. It never reads stored rows or selects answers.
#[cfg(test)]
use super::LockingParent;
use super::{LockingControl, PreparationParent};
use p3_field::PrimeField64;
use registry200_journal::{Operation, intent_query};
use registry200_proof::{
    BackendError as Error, Val,
    admission::CanonicalSource,
    coefficient_encoding::{
        commitment,
        statement::{BfvBinding, Expected},
    },
    source::statement as source,
};
use sha2::{Digest, Sha256};
use sql_plan::{LockStrength, LockWait, Projection, QueryPlan};
use zeroize::{Zeroize, Zeroizing};

/// Exact SQL is privately blinded and not retained. The 256-bit TRUE set remains
/// owner-private until it has been encrypted. Public nonce is not the SQL blind.
pub struct CompiledLockingSelect {
    pub(super) identity: [u8; 32],
    pub(super) public_nonce: [u8; 32],
    pub(super) query_id: [u8; 16],
    pub(super) mask: Zeroizing<[u8; 32]>,
    pub(super) mode: u8,
    pub(super) wait: u8,
    pub(super) offset: u8,
    pub(super) limit: u8,
    pub(super) projection: u8,
}
impl Drop for CompiledLockingSelect {
    fn drop(&mut self) {
        self.identity.zeroize();
        self.public_nonce.zeroize();
        self.query_id.zeroize();
        self.mask.zeroize();
        self.mode.zeroize();
        self.wait.zeroize();
        self.offset.zeroize();
        self.limit.zeroize();
        self.projection.zeroize();
    }
}
impl CompiledLockingSelect {
    pub fn compile(
        sql: &str,
        private_blind: Zeroizing<[u8; 32]>,
        public_nonce: [u8; 32],
        query_id: [u8; 16],
    ) -> Result<Self, Error> {
        if *private_blind == [0; 32] || *private_blind == public_nonce {
            return Err(Error::Shape);
        }
        let QueryPlan::LockingSelect {
            predicate,
            projection,
            window,
            locking,
        } = sql_plan::parse_sql(sql).map_err(|_| Error::Shape)?
        else {
            return Err(Error::Shape);
        };
        let projection = match projection {
            Projection::Age => 1,
            Projection::Amount => 2,
            Projection::AgeAmount => 3,
            Projection::AmountAge => return Err(Error::Shape),
        };
        if window.offset > 4 || window.limit.is_some_and(|v| v > 4) {
            return Err(Error::Shape);
        }
        let mode = match locking.strength {
            LockStrength::KeyShare => 1,
            LockStrength::Share => 2,
            LockStrength::NoKeyUpdate => 3,
            LockStrength::Update => 4,
        };
        let wait = match locking.wait {
            LockWait::Wait => 0,
            LockWait::NoWait => 1,
            LockWait::SkipLocked => 2,
        };
        let mut h = Sha256::new();
        h.update(b"DCS/PRIVATE-LOCKING-SELECT/exact-SQL-private-blind/v1");
        h.update((sql.len() as u64).to_le_bytes());
        h.update(sql.as_bytes());
        h.update(*private_blind);
        Ok(Self {
            identity: h.finalize().into(),
            public_nonce,
            query_id,
            mask: Zeroizing::new(predicate.age_mask()),
            mode,
            wait,
            offset: window.offset as u8,
            limit: window.limit.unwrap_or(4) as u8,
            projection,
        })
    }
    /// No Copen/Cmask/Cw/Ccmd/output is used, so this route has no proof fixed point.
    fn inner_nonce_for(
        &self,
        s: &source::Statement,
        binding: &BfvBinding,
        object: [u8; 32],
        parent: &PreparationParent<'_>,
        control: &LockingControl,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"DCS/PRIVATE-LOCKING-SELECT/inner-intent/stableKeyExpected29/v1");
        h.update(self.identity);
        h.update(self.public_nonce);
        h.update(self.query_id);
        h.update(binding.full_setup());
        for value in binding.key().public_values().into_iter().take(29) {
            h.update(value.as_canonical_u64().to_le_bytes());
        }
        h.update(object);
        for head in &s.heads {
            h.update(head);
        }
        for value in s.key_commitment {
            h.update(value.as_canonical_u64().to_le_bytes());
        }
        h.update(parent.head().genesis);
        h.update(parent.application().id());
        h.update(parent.application().network);
        h.update(parent.application().database);
        h.update(parent.head().database);
        h.update(parent.head().block);
        h.update(parent.head().height.to_le_bytes());
        h.update(parent.head().state_root);
        h.update(parent.enrollment());
        h.update(parent.registry());
        let actor = &control.actor;
        h.update(actor.transaction.to_le_bytes());
        h.update([actor.principal]);
        h.update(actor.revision.to_le_bytes());
        h.update(actor.sequence.to_le_bytes());
        h.update(control.controllers[usize::from(actor.principal - 1)]);
        h.finalize().into()
    }
    pub(super) fn intent_for(
        &self,
        s: &source::Statement,
        binding: &BfvBinding,
        object: [u8; 32],
        parent: &PreparationParent<'_>,
        control: &LockingControl,
    ) -> ([u8; 32], [u8; 32]) {
        let nonce = self.inner_nonce_for(s, binding, object, parent, control);
        let q = intent_query(
            parent.application(),
            parent.head().genesis,
            parent.head().block,
            nonce,
            parent.enrollment(),
            Operation::Transition,
        );
        (nonce, q)
    }
    pub(super) fn bind_for(
        &self,
        source: &CanonicalSource,
        binding: BfvBinding,
        object: [u8; 32],
        parent: &PreparationParent<'_>,
        control: &LockingControl,
        salt: [Val; 4],
    ) -> Result<(Expected, Expected), Error> {
        if source.claim().request
            != self
                .intent_for(source.claim(), &binding, object, parent, control)
                .1
        {
            return Err(Error::Shape);
        }
        let original = Expected::source(source, binding.clone())?;
        let draft = Expected::private_mask(
            source,
            binding.clone(),
            self.identity,
            self.public_nonce,
            [0; 32],
        )?;
        let root =
            commitment::command_digest(&commitment::command_fields(&draft, *self.mask, salt));
        let query = Expected::private_mask(
            source,
            binding,
            self.identity,
            self.public_nonce,
            source::encode_digest(root),
        )?;
        Ok((original, query))
    }
    #[cfg(test)]
    pub(super) fn intent(
        &self,
        s: &source::Statement,
        binding: &BfvBinding,
        object: [u8; 32],
        parent: &LockingParent,
        control: &LockingControl,
    ) -> ([u8; 32], [u8; 32]) {
        self.intent_for(
            s,
            binding,
            object,
            &PreparationParent::Legacy(parent),
            control,
        )
    }
    #[cfg(test)]
    pub(super) fn bind(
        &self,
        source: &CanonicalSource,
        binding: BfvBinding,
        object: [u8; 32],
        parent: &LockingParent,
        control: &LockingControl,
        salt: [Val; 4],
    ) -> Result<(Expected, Expected), Error> {
        self.bind_for(
            source,
            binding,
            object,
            &PreparationParent::Legacy(parent),
            control,
            salt,
        )
    }
    pub(super) fn command(
        &self,
        control: &LockingControl,
    ) -> registry200_proof::lifecycle::circuit::model::Command {
        use registry200_proof::lifecycle::circuit::model::{Command, Operation};
        let mut c = Command::control(
            Operation::Acquire,
            control.actor.transaction,
            control.actor.principal,
            control.actor.sequence,
        );
        c.mask = *self.mask;
        c.mode = self.mode;
        c.wait = self.wait;
        c.offset = self.offset;
        c.limit = self.limit;
        c.projection = self.projection;
        c
    }
}
