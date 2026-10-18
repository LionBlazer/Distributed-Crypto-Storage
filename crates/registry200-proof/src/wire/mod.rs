//! Exact DCSLFPW1 bounded codec; no peer-selected configuration or authority receipt.
pub mod frame;
use crate::{
    BackendError, Val,
    admission::{CanonicalSource, Expected as CheckedExpected},
    fixed::Backend,
    lifecycle::statement::{Expected, Statement},
    source,
};
use bfv_hiding_stark::{Config, codec};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;
pub const MAX_SEQUENCE_ELEMENTS: usize = 16384;
pub const SOURCE_SLOTS: usize = 24 * 1024 * 1024;
pub const CHILD_SLOTS: usize = 16 * 1024 * 1024;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    ResourceLimit,
    Profile,
    Shape,
    Proof(BackendError),
    Verification,
}
impl From<BackendError> for Error {
    fn from(e: BackendError) -> Self {
        Self::Proof(e)
    }
}
impl From<codec::Error> for Error {
    fn from(e: codec::Error) -> Self {
        match e {
            codec::Error::Encoding => Self::Encoding,
            codec::Error::ResourceLimit => Self::ResourceLimit,
            codec::Error::Shape => Self::Shape,
        }
    }
}
pub struct CompositeProof {
    pub source: Option<Proof<Config>>,
    pub child: Proof<Config>,
}
pub fn role(e: &Expected) -> frame::Role {
    if e.is_bootstrap() {
        frame::Role::Bootstrap
    } else {
        frame::Role::Transition
    }
}
pub fn encode_claim(e: &Expected, s: &Statement, p: &CompositeProof) -> Result<Vec<u8>, Error> {
    s.require_expected(e)?;
    let _ = CheckedExpected::checked_claim(e)?;
    let source = codec::serialize(
        p.source.as_ref().ok_or(Error::Shape)?,
        &Backend::source(&e.source)?.shape,
        frame::MAX_SOURCE_BYTES,
    )?;
    let child = codec::serialize(&p.child, &Backend::child(s)?.shape, frame::MAX_CHILD_BYTES)?;
    let mut roots = vec![source::statement::encode_digest(s.next)];
    if !e.is_bootstrap() {
        roots.push(source::statement::encode_digest(s.result))
    }
    frame::join(role(e), &roots, &source, &child)
}
fn statement(e: &Expected, f: &frame::Frame<'_>) -> Result<Statement, Error> {
    let roots = f.outputs.as_chunks::<32>().0;
    Ok(Statement {
        expected: e.clone(),
        next: source::statement::decode_digest(roots[0])?,
        result: if e.is_bootstrap() {
            [Val::ZERO; 4]
        } else {
            source::statement::decode_digest(roots[1])?
        },
    })
}
/// Low-level claim API for mathematical producers, not an application grant.
pub fn verify_pair(e: &Expected, s: &Statement, p: &CompositeProof) -> Result<(), BackendError> {
    CanonicalSource::checked_claim(&e.source)?;
    e.require_contract()?;
    Backend::source(&e.source)?.verify(p.source.as_ref().ok_or(BackendError::Verification)?)?;
    s.require_expected(e)?;
    Backend::child(s)?.verify(&p.child)
}
/// Actual proof objects for consumers composing further genuine relations.
pub fn decode_and_verify_claim(
    e: &Expected,
    bytes: &[u8],
) -> Result<(Statement, CompositeProof), Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = CheckedExpected::checked_claim(e)?;
        let f = frame::Frame::parse(role(e), bytes)?;
        let s = statement(e, &f)?;
        let sb = Backend::source(&e.source)?;
        let source = codec::decode(f.source, &sb.shape, MAX_SEQUENCE_ELEMENTS, SOURCE_SLOTS)?;
        sb.verify(&source)?;
        drop(sb);
        let cb = Backend::child(&s)?;
        let child = codec::decode(f.child, &cb.shape, MAX_SEQUENCE_ELEMENTS, CHILD_SLOTS)?;
        cb.verify(&child)?;
        Ok((
            s,
            CompositeProof {
                source: Some(source),
                child,
            },
        ))
    }))
    .map_err(|_| Error::Verification)?
}
pub fn verify_claim(e: &Expected, bytes: &[u8]) -> Result<Statement, Error> {
    let checked = CheckedExpected::checked_claim(e)?;
    verify_statement(&checked, bytes)
}
/// Sealed independent expectation; decoded Source proof is dropped before child allocation.
fn verify_statement(e: &CheckedExpected, bytes: &[u8]) -> Result<Statement, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let e = e.claim();
        let f = frame::Frame::parse(role(e), bytes)?;
        let s = statement(e, &f)?;
        {
            let sb = Backend::source(&e.source)?;
            let p = codec::decode(f.source, &sb.shape, MAX_SEQUENCE_ELEMENTS, SOURCE_SLOTS)?;
            sb.verify(&p)?;
        }
        let cb = Backend::child(&s)?;
        let p = codec::decode(f.child, &cb.shape, MAX_SEQUENCE_ELEMENTS, CHILD_SLOTS)?;
        cb.verify(&p)?;
        Ok(s)
    }))
    .map_err(|_| Error::Verification)?
}
pub fn contract_digest() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"DCS/REGISTRY200-WIRE-CONTRACT/v1/canonical-Postcard/source-first/mandatory-pair");
    frame::contract(&mut h);
    h.update(source::profile_digest(source::Relation::CanonicalIndex));
    for n in [MAX_SEQUENCE_ELEMENTS, SOURCE_SLOTS, CHILD_SLOTS] {
        h.update((n as u64).to_le_bytes())
    }
    h.finalize().into()
}
pub fn maximum_bundle_bytes() -> usize {
    frame::MAX_BUNDLE_BYTES
}

/// Genuine computation outputs, not SQL, ownership or freshness authority.
pub struct VerifiedOutputs {
    next: [u8; 32],
    result: Option<[u8; 32]>,
}
impl VerifiedOutputs {
    pub fn next_root(&self) -> [u8; 32] {
        self.next
    }
    pub fn result_root(&self) -> Option<[u8; 32]> {
        self.result
    }
}
pub fn verify(e: &CheckedExpected, bytes: &[u8]) -> Result<VerifiedOutputs, Error> {
    let s = verify_statement(e, bytes)?;
    Ok(VerifiedOutputs {
        next: source::statement::encode_digest(s.next),
        result: if e.claim().is_bootstrap() {
            None
        } else {
            Some(source::statement::encode_digest(s.result))
        },
    })
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Registry200 evidence: {self:?}")
    }
}
impl std::error::Error for Error {}
