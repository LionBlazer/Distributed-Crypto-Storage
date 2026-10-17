//! Canonical Request200. It authorizes an opaque C_cmd, not public SQL parsing.
use super::{Error, Hash, Result, control::Application};
use crate::opening::{Relation, statement as source};
use compact_store::Commitment;
use sha2::{Digest, Sha256};
const MAGIC: &[u8; 8] = b"DCSLFJ01";
pub(super) const REQUEST_BYTES: usize = 272 + 60 + 2384;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    Bootstrap,
    Transition,
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
    pub(super) command: Hash,
    pub(super) packets: [Vec<u8>; 2],
}
impl Operation {
    fn tag(self) -> u8 {
        match self {
            Self::Bootstrap => 1,
            Self::Transition => 2,
        }
    }
}
/// Chosen before C_open/C_cmd; all excluded values are bound by the final owner signature.
pub(super) fn intent_query(
    app: &Application,
    genesis: Hash,
    parent: Hash,
    nonce: Hash,
    enrollment: Hash,
    operation: Operation,
) -> Hash {
    let mut h = Sha256::new();
    h.update(b"DCS/PRIVATE-LIFECYCLE-JOURNAL/PREPROOF-INTENT/v1");
    h.update(app.id());
    h.update(genesis);
    h.update(parent);
    h.update(nonce);
    h.update(enrollment);
    h.update([operation.tag()]);
    h.finalize().into()
}
impl Request {
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        if self.packets[0].len() != 60
            || self.packets[1].len() != 2384
            || (self.operation == Operation::Bootstrap && self.command != [0; 32])
        {
            return Err(Error::InvalidEncoding);
        }
        for root in [self.enrollment, self.opening, self.command] {
            let _ = source::decode_digest(root).map_err(|_| Error::InvalidEncoding)?;
        }
        let mut out = Vec::with_capacity(REQUEST_BYTES);
        out.extend_from_slice(MAGIC);
        out.push(self.operation.tag());
        out.extend_from_slice(&[0; 7]);
        for field in [
            self.genesis,
            self.parent,
            self.application,
            self.nonce,
            self.query,
            self.enrollment,
            self.opening,
            self.command,
        ] {
            out.extend_from_slice(&field);
        }
        out.extend_from_slice(&self.packets[0]);
        out.extend_from_slice(&self.packets[1]);
        Ok(out)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != REQUEST_BYTES || &bytes[..8] != MAGIC || bytes[9..16] != [0; 7] {
            return Err(Error::InvalidEncoding);
        }
        let operation = match bytes[8] {
            1 => Operation::Bootstrap,
            2 => Operation::Transition,
            _ => return Err(Error::InvalidEncoding),
        };
        let field = |i: usize| bytes[16 + 32 * i..48 + 32 * i].try_into().unwrap();
        let out = Self {
            operation,
            genesis: field(0),
            parent: field(1),
            application: field(2),
            nonce: field(3),
            query: field(4),
            enrollment: field(5),
            opening: field(6),
            command: field(7),
            packets: [bytes[272..332].to_vec(), bytes[332..].to_vec()],
        };
        if out.encode()?.as_slice() != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(out)
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
