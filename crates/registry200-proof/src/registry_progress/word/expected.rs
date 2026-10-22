//! Public mathematical metadata, independent of private openings and proof bytes.
use super::super::word_inventory::{self, Metadata};
use super::{Error, Result, Role};
use crate::{
    Val,
    source::{self, version::SourceVersionExpected},
};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha512};

/// Complete independently retained transition claims. Construction verifies no proof.
#[derive(Clone, Copy)]
pub struct Claims {
    pub old: [Val; 4],
    pub command: [Val; 4],
    pub statement: [Val; 4],
    pub next: [Val; 4],
    pub result: [Val; 4],
    pub blind_sql: [Val; 8],
}
#[derive(Clone)]
pub struct Expected {
    pub(super) inner: Metadata,
    genesis: [u8; 32],
    parent: [u8; 32],
}
impl Expected {
    /// Derive original headers/scope/context from the complete immutable Source.
    /// Source, genesis, parent and enrollment must be independently retained;
    /// this authenticates none of them and cannot establish OldRoot or currentness.
    pub fn checked(
        source: &SourceVersionExpected,
        role: Role,
        genesis: [u8; 32],
        parent: [u8; 32],
        enrollment: [Val; 4],
        claims: Claims,
    ) -> Result<Self> {
        source.statement().reaudit().map_err(|_| Error::Shape)?;
        if role == Role::Control && claims.statement != [Val::ZERO; 4] {
            return Err(Error::Binding);
        }
        let s = source.statement();
        let make_header = |label: &str| {
            let mut v = word_inventory::header(label);
            v.extend(source::statement::words(&genesis));
            v.extend(source::statement::words(&s.heads[0][8..40]));
            v.extend(s.key_commitment);
            v.try_into().map_err(|_| Error::Shape)
        };
        let registry_header = make_header("registry")?;
        let enrollment_header = make_header("enrollment")?;
        let mut h = Sha512::new();
        h.update(word_inventory::PROFILE_DOMAIN);
        h.update(source.version_id());
        h.update(source.state_commitment());
        for (head, packet) in s.heads.iter().zip(&s.packets) {
            h.update(((head.len() + packet.len()) as u64).to_le_bytes());
            h.update(head);
            h.update(packet);
        }
        h.update(source::statement::encode_digest(s.key_commitment));
        let scope = source::statement::words(&h.finalize())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::Shape)?;
        let parent_words: [Val; 8] = source::statement::words(&parent)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::Shape)?;
        let mut ctx = source::statement::words(&super::profile_digest()).collect::<Vec<_>>();
        ctx.extend(source::statement::words(&genesis));
        ctx.extend(parent_words);
        ctx.extend(source::statement::words(&source.version_id()));
        ctx.extend(s.key_commitment);
        ctx.extend(s.open_commitment);
        ctx.extend(enrollment);
        ctx.extend(scope);
        ctx.extend(source::statement::words(&s.heads[0][8..40]));
        for head in &s.heads {
            ctx.extend(source::statement::words(&Sha512::digest(head)));
        }
        let context = ctx.try_into().map_err(|_| Error::Shape)?;
        Ok(Self {
            inner: Metadata {
                source: source.clone(),
                predicate: role.predicate(),
                registry_header,
                enrollment_header,
                context,
                scope,
                parent: parent_words,
                enrollment,
                old: claims.old,
                command: claims.command,
                statement: claims.statement,
                next: claims.next,
                result: claims.result,
                blind_sql: claims.blind_sql,
            },
            genesis,
            parent,
        })
    }
    pub fn role(&self) -> Role {
        if self.inner.predicate {
            Role::Predicate
        } else {
            Role::Control
        }
    }
    pub fn source(&self) -> &SourceVersionExpected {
        &self.inner.source
    }
    pub fn genesis(&self) -> [u8; 32] {
        self.genesis
    }
    pub fn parent(&self) -> [u8; 32] {
        self.parent
    }
    pub fn binding(&self) -> [u8; 64] {
        word_inventory::probe::binding(&self.inner)
    }
    pub fn claims(&self) -> Claims {
        Claims {
            old: self.inner.old,
            command: self.inner.command,
            statement: self.inner.statement,
            next: self.inner.next,
            result: self.inner.result,
            blind_sql: self.inner.blind_sql,
        }
    }
    /// Original PUBLIC encoding context for caller-owned serializers; no authority.
    pub fn context(&self) -> &[Val; 100] {
        &self.inner.context
    }
    pub fn scope(&self) -> &[Val; 16] {
        &self.inner.scope
    }
    /// Public serialization domain only; it authenticates no source or enrollment.
    pub fn statement_domain(&self) -> super::StatementDomain {
        super::StatementDomain {
            scope: self.inner.scope,
            enrollment: self.inner.enrollment,
        }
    }
    pub fn registry_header(&self) -> &[Val; 33] {
        &self.inner.registry_header
    }
    pub fn enrollment_header(&self) -> &[Val; 33] {
        &self.inner.enrollment_header
    }
}
