//! Fixed canonical PUBLIC request. Controllers, plan openings and plaintext stay private.
use super::{Error, Hash, Result, control::Application};
use crate::opening::{Relation, statement as source};
use compact_store::Commitment;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"DCSPJR01";
pub(super) const REQUEST_BYTES: usize = 272 + 60 + 2384;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    Bootstrap,
    Acquire,
}
#[derive(Clone)]
pub(super) struct Request {
    pub(super) operation: Operation,
    pub(super) genesis: Hash,
    pub(super) parent: Hash,
    pub(super) application: Hash,
    pub(super) nonce: Hash,
    pub(super) query: Hash,
    pub(super) enrollment: Hash,
    pub(super) opening: Hash,
    pub(super) plan: Hash,
    pub(super) packets: [Vec<u8>; 2],
}
pub(super) fn bootstrap_query(
    app: &Application,
    genesis: Hash,
    parent: Hash,
    nonce: Hash,
    enrollment: Hash,
) -> Hash {
    let mut h = Sha256::new();
    h.update(b"DCS/PRIVATE-JOURNAL/BOOTSTRAP-INTENT/v1");
    h.update(app.id());
    h.update(genesis);
    h.update(parent);
    h.update(nonce);
    h.update(enrollment);
    // Deliberately excludes query itself, C_open, C_registry, proof and signature.
    h.finalize().into()
}
impl Request {
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        if self.packets[0].len() != 60 || self.packets[1].len() != 2384 {
            return Err(Error::InvalidEncoding);
        }
        let mut out = Vec::with_capacity(REQUEST_BYTES);
        out.extend_from_slice(MAGIC);
        out.push(match self.operation {
            Operation::Bootstrap => 1,
            Operation::Acquire => 2,
        });
        out.extend_from_slice(&[0; 7]);
        for bytes in [
            self.genesis,
            self.parent,
            self.application,
            self.nonce,
            self.query,
            self.enrollment,
            self.opening,
            self.plan,
        ] {
            out.extend_from_slice(&bytes);
        }
        for packet in &self.packets {
            out.extend_from_slice(packet);
        }
        Ok(out)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != REQUEST_BYTES || &bytes[..8] != MAGIC || bytes[9..16] != [0; 7] {
            return Err(Error::InvalidEncoding);
        }
        let operation = match bytes[8] {
            1 => Operation::Bootstrap,
            2 => Operation::Acquire,
            _ => return Err(Error::InvalidEncoding),
        };
        let field = |i: usize| bytes[16 + 32 * i..48 + 32 * i].try_into().unwrap();
        let value = Self {
            operation,
            genesis: field(0),
            parent: field(1),
            application: field(2),
            nonce: field(3),
            query: field(4),
            enrollment: field(5),
            opening: field(6),
            plan: field(7),
            packets: [bytes[272..332].to_vec(), bytes[332..].to_vec()],
        };
        if operation == Operation::Bootstrap && value.plan != [0; 32] {
            return Err(Error::InvalidEncoding);
        }
        for root in [value.enrollment, value.opening, value.plan] {
            let _ = source::decode_digest(root).map_err(|_| Error::InvalidEncoding)?;
        }
        Ok(value)
    }
    pub(super) fn source(&self, app: &Application) -> Result<source::Statement> {
        let data = Commitment::decode(&app.source.data, source::limits())
            .map_err(|_| Error::InvalidEncoding)?;
        let index = Commitment::decode(&app.source.index, source::limits())
            .map_err(|_| Error::InvalidEncoding)?;
        let images = [
            [&app.source.data[..], &self.packets[0]].concat(),
            [&app.source.index[..], &self.packets[1]].concat(),
        ];
        let s = source::Statement::checked_relation(
            Relation::CanonicalIndex,
            [&images[0], &images[1]],
            [&data, &index],
            self.query,
            app.key,
            self.opening,
        )
        .map_err(|_| Error::RejectedComputationProof)?;
        app.require_source(&s)?;
        Ok(s)
    }
}
