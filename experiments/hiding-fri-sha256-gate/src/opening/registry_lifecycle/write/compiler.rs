//! Client-only exact SQL binding. No row execution and no controller-signature assertion.
use super::statement::{Expected, Parent};
use crate::backend::{Error, Val};
use crate::opening::statement as source;
use p3_field::PrimeCharacteristicRing;
use registry200_proof::{
    admission::CanonicalSource,
    write::statement::{self as fixed, COMMAND_FIELDS},
};
use sha2::{Digest, Sha256};
use sql_plan::{Predicate, QueryPlan};
/// Caller-owned private mathematical command opening, never decoded from a peer.
#[derive(Clone)]
pub(in crate::opening::registry_lifecycle) struct Command {
    pub transaction: u64,
    pub principal: u8,
    pub controller: [u8; 32],
    pub revision: u64,
    pub sequence: u64,
    pub mask: [u8; 32],
    pub delta: u16,
    pub salt: [Val; 4],
}
impl Command {
    pub(super) fn require_shape(&self) -> Result<(), Error> {
        if self.transaction == 0
            || !(1..=2).contains(&self.principal)
            || self.controller == [0; 32]
            || self.revision == u64::MAX
            || self.sequence == 0
            || self.sequence == u64::MAX
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
}
pub(in crate::opening::registry_lifecycle) struct ActorOpening {
    pub transaction: u64,
    pub principal: u8,
    pub controller: [u8; 32],
    pub revision: u64,
    pub sequence: u64,
    pub salt: [Val; 4],
}
pub(in crate::opening::registry_lifecycle) struct CompiledWrite {
    identity: [u8; 32],
    nonce: [u8; 32],
    predicate: Predicate,
    delta: u16,
}
impl CompiledWrite {
    pub(in crate::opening::registry_lifecycle) fn compile(
        sql: &str,
        nonce: [u8; 32],
    ) -> Result<Self, Error> {
        let QueryPlan::AddAmount { predicate, delta } =
            sql_plan::parse_sql(sql).map_err(|_| Error::Shape)?
        else {
            return Err(Error::Shape);
        };
        let mut h = Sha256::new();
        h.update(b"DCS/Registry200/AddAmount/exact-client-SQL-and-nonce/v1");
        h.update((sql.len() as u64).to_le_bytes());
        h.update(sql.as_bytes());
        h.update(nonce);
        Ok(Self {
            identity: h.finalize().into(),
            nonce,
            predicate,
            delta,
        })
    }
    pub(in crate::opening::registry_lifecycle) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(in crate::opening::registry_lifecycle) fn query(&self, parent: &Parent) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"DCS/Registry200/AddAmount/preproof-intent/v1");
        h.update(parent.application);
        h.update(parent.genesis);
        h.update(parent.block);
        h.update(self.nonce);
        h.update(self.identity);
        h.finalize().into()
    }
    pub(super) fn command(&self, o: ActorOpening) -> Result<Command, Error> {
        let command = Command {
            transaction: o.transaction,
            principal: o.principal,
            controller: o.controller,
            revision: o.revision,
            sequence: o.sequence,
            mask: self.predicate.age_mask(),
            delta: self.delta,
            salt: o.salt,
        };
        command.require_shape()?;
        Ok(command)
    }
    pub(in crate::opening::registry_lifecycle) fn bind(
        &self,
        source: &CanonicalSource,
        parent: Parent,
        opening: ActorOpening,
    ) -> Result<(Expected, Command), Error> {
        if source.claim().request != self.query(&parent) {
            return Err(Error::Shape);
        }
        let c = self.command(opening)?;
        let draft = Expected::checked(source, parent, self.identity, [0; 32])?;
        let digest = fixed::command_digest(&command_fields(&draft, &c));
        let expected = Expected::checked(
            source,
            draft.parent().clone(),
            self.identity,
            source::encode_digest(digest),
        )?;
        Ok((expected, c))
    }
}
fn limbs(x: u64) -> [Val; 2] {
    [Val::from_u32(x as u32), Val::from_u32((x >> 32) as u32)]
}
pub(super) fn command_fields(e: &Expected, c: &Command) -> [Val; COMMAND_FIELDS] {
    source::words(&fixed::COMMAND_DOMAIN)
        .chain([Val::ONE])
        .chain(e.context())
        .chain(e.registry())
        .chain([Val::ONE])
        .chain(limbs(c.transaction))
        .chain([Val::from_u8(c.principal)])
        .chain(source::words(&c.controller))
        .chain(limbs(c.revision))
        .chain(limbs(c.sequence))
        .chain(source::words(&c.mask))
        .chain([Val::from_u16(c.delta)])
        .chain(c.salt)
        .chain([Val::ZERO; 6])
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
