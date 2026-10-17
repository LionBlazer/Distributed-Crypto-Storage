//! Actual bounded Source+Registry200 proofs. Independent Expected is never on wire.
mod frame;
#[cfg(test)]
mod tests;
mod transport;
use super::{
    CompositeProof,
    fixture::Fixture,
    prove,
    statement::{self, Expected, Phase, Statement},
};
use crate::backend::{Error as BackendError, analyze};
use crate::opening::{
    proof_codec::{self, Topology},
    statement::decode_digest,
};
use crate::primitive::{Kind, PublicStatement};
use frame::{Frame, Role};
use p3_air::BaseAir;
use p3_field::PrimeCharacteristicRing;
const MAX_SEQUENCE_ELEMENTS: usize = 16384;
const SOURCE_SLOTS: usize = 24 * 1024 * 1024;
const CHILD_SLOTS: usize = 16 * 1024 * 1024;
#[derive(Debug, PartialEq, Eq)]
pub(in crate::opening) enum Error {
    Encoding,
    ResourceLimit,
    Profile,
    Shape,
    Proof(BackendError),
    Verification,
}
impl From<BackendError> for Error {
    fn from(error: BackendError) -> Self {
        Self::Proof(error)
    }
}
impl From<proof_codec::Error> for Error {
    fn from(error: proof_codec::Error) -> Self {
        match error {
            proof_codec::Error::Encoding => Self::Encoding,
            proof_codec::Error::ResourceLimit => Self::ResourceLimit,
            proof_codec::Error::Shape => Self::Shape,
        }
    }
}
fn role(e: &Expected) -> Role {
    match e.phase {
        Phase::Bootstrap => Role::Bootstrap,
        Phase::Transition { .. } => Role::Transition,
    }
}
fn topology(s: &impl PublicStatement) -> Result<Topology, Error> {
    let wanted = match s.kind() {
        Kind::CanonicalIndexOpening => (11521, 691),
        Kind::RegistryLifecycleBootstrap => (1082, 104),
        Kind::RegistryLifecycle => (6741, 116),
        _ => return Err(Error::Profile),
    };
    let air = s.air();
    let (_, report) = analyze(&air)?;
    let report = report.require_target()?;
    if (air.width(), air.num_public_values()) != wanted
        || air.preprocessed_width() != 0
        || air.main_next_row_columns().is_empty()
        || report.degree > 5
        || report.quotient_chunks <= 1
        || report.quotient_chunks > 16
    {
        return Err(Error::Shape);
    }
    Topology::checked(wanted.0, report.quotient_chunks).map_err(Error::from)
}
/// Original typed pair only. No caller-provided dimensions or proof fallback.
pub(in crate::opening) fn encode(
    e: &Expected,
    s: &Statement,
    p: &CompositeProof,
) -> Result<Vec<u8>, Error> {
    s.require_expected(e)?;
    let role = role(e);
    let source = proof_codec::serialize(
        p.source.as_ref().ok_or(Error::Shape)?,
        &topology(&e.source)?,
        frame::MAX_SOURCE_BYTES,
    )?;
    let child = proof_codec::serialize(&p.child, &topology(s)?, frame::MAX_CHILD_BYTES)?;
    let mut outputs = vec![statement::encoded(s.next)];
    if role == Role::Transition {
        outputs.push(statement::encoded(s.result));
    }
    frame::join(role, &outputs, &source, &child)
}
pub(in crate::opening) fn verify(e: &Expected, bytes: &[u8]) -> Result<Statement, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e.require_contract()?;
        let role = role(e);
        let frame = Frame::parse(role, bytes)?;
        let roots = frame.outputs.as_chunks::<32>().0;
        let s = Statement {
            expected: e.clone(),
            next: decode_digest(roots[0])?,
            result: if role == Role::Transition {
                decode_digest(roots[1])?
            } else {
                [crate::backend::Val::ZERO; 4]
            },
        };
        let source = proof_codec::decode(
            frame.source,
            &topology(&e.source)?,
            MAX_SEQUENCE_ELEMENTS,
            SOURCE_SLOTS,
        )?;
        let child = proof_codec::decode(
            frame.child,
            &topology(&s)?,
            MAX_SEQUENCE_ELEMENTS,
            CHILD_SLOTS,
        )?;
        let p = CompositeProof {
            source: Some(source),
            child,
        };
        super::verify(e, &s, &p)?;
        Ok(s)
    }))
    .map_err(|_| Error::Verification)?
}
pub(super) fn gate(mode: &str, bootstrap: bool) -> Result<(), BackendError> {
    if !matches!(mode, "security" | "prove") {
        return Err(BackendError::Shape);
    }
    let fixture = Fixture::new()?;
    let (e, w) = if bootstrap {
        fixture.bootstrap()?
    } else {
        fixture.begin()?
    };
    let s = w.statement(&e)?;
    crate::security(&e.source, "public-nonsecret-lifecycle-canonical-source")?;
    crate::security(
        &s,
        if bootstrap {
            "public-nonsecret-registry200-bootstrap-wire"
        } else {
            "public-nonsecret-registry200-transition-wire"
        },
    )?;
    if mode == "prove" {
        let bytes = {
            if !bootstrap {
                let (initial, w) = fixture.bootstrap()?;
                let (s, p) = prove(&initial, &fixture.source_witness, &w)?;
                super::verify(&initial, &s, &p)?;
                let Phase::Transition { old, .. } = e.phase else {
                    unreachable!()
                };
                if old != s.next {
                    return Err(BackendError::Shape);
                }
            }
            let (s, p) = prove(&e, &fixture.source_witness, &w)?;
            encode(&e, &s, &p).map_err(|_| BackendError::Verification)?
        };
        let parsed = Frame::parse(role(&e), &bytes).map_err(|_| BackendError::Verification)?;
        let started = std::time::Instant::now();
        let body =
            transport::roundtrip(&e, &bytes, 2716).map_err(|_| BackendError::Verification)?;
        println!(
            "{{\"stage\":\"verified_experimental_registry200_wire_body\",\"role\":\"{}\",\"source_proof_bytes\":{},\"child_proof_bytes\":{},\"bundle_bytes\":{},\"body_bytes\":{},\"request_bytes\":{},\"update_count\":1,\"signed_body_roundtrip_and_fresh_verification_ms\":{},\"live_sql_grant\":false}}",
            if bootstrap { "bootstrap" } else { "transition" },
            parsed.source.len(),
            parsed.child.len(),
            bytes.len(),
            body,
            2716,
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    Ok(())
}
