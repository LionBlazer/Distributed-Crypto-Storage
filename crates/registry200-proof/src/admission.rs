//! Checked immutable independent public expectations. No peer-provided receipt is authority.
use crate::{
    BackendError as Error,
    lifecycle::statement as lifecycle,
    source::{self, Relation, Statement},
};
use compact_store::Commitment;
#[derive(Clone)]
pub struct CanonicalSource {
    claim: Statement,
}
impl CanonicalSource {
    pub fn checked(
        images: [&[u8]; 2],
        heads: [&Commitment; 2],
        query: [u8; 32],
        key: [u8; 32],
        opening: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            claim: Statement::checked_relation(
                Relation::CanonicalIndex,
                images,
                heads,
                query,
                key,
                opening,
            )?,
        })
    }
    pub fn checked_claim(s: &Statement) -> Result<Self, Error> {
        if s.relation != Relation::CanonicalIndex
            || s.packets[0].len() != 60
            || s.packets[1].len() != 2384
        {
            return Err(Error::Shape);
        }
        let h = [
            Commitment::decode(&s.heads[0], source::statement::limits())
                .map_err(|_| Error::Shape)?,
            Commitment::decode(&s.heads[1], source::statement::limits())
                .map_err(|_| Error::Shape)?,
        ];
        let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
            s.heads[i]
                .iter()
                .chain(s.packets[i].iter())
                .copied()
                .collect()
        });
        Self::checked(
            [&images[0], &images[1]],
            [&h[0], &h[1]],
            s.request,
            source::statement::encode_digest(s.key_commitment),
            source::statement::encode_digest(s.open_commitment),
        )
    }
    pub fn claim(&self) -> &Statement {
        &self.claim
    }
}
#[derive(Clone)]
pub struct Expected {
    claim: lifecycle::Expected,
}
impl Expected {
    pub fn bootstrap(
        source: &CanonicalSource,
        genesis: [u8; 32],
        parent: [u8; 32],
        enrollment: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            claim: lifecycle::Expected::bootstrap(source.claim(), genesis, parent, enrollment)?,
        })
    }
    pub fn transition(
        source: &CanonicalSource,
        genesis: [u8; 32],
        parent: [u8; 32],
        enrollment: [u8; 32],
        old: [u8; 32],
        command: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            claim: lifecycle::Expected::transition(
                source.claim(),
                genesis,
                parent,
                enrollment,
                old,
                command,
            )?,
        })
    }
    pub fn checked_claim(e: &lifecycle::Expected) -> Result<Self, Error> {
        let source = CanonicalSource::checked_claim(&e.source)?;
        let root = source::statement::encode_digest;
        match e.phase {
            lifecycle::Phase::Bootstrap => {
                Self::bootstrap(&source, e.genesis, e.parent, root(e.enrollment))
            }
            lifecycle::Phase::Transition { old, command } => Self::transition(
                &source,
                e.genesis,
                e.parent,
                root(e.enrollment),
                root(old),
                root(command),
            ),
        }
    }
    pub fn claim(&self) -> &lifecycle::Expected {
        &self.claim
    }
}
