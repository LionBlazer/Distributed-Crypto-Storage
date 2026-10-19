//! Experiment producer/gates around the real shared bounded verifier.
#[cfg(test)]
mod tests;
mod transport;
#[cfg(test)]
use super::prove;
#[cfg(test)]
use super::{
    CompositeProof,
    statement::{self, Statement},
};
use super::{
    fixture::Fixture,
    statement::{Expected, Phase},
};
use crate::backend::Error as BackendError;
#[cfg(test)]
use crate::opening::proof_codec;
#[cfg(test)]
use crate::primitive::PublicStatement;
#[cfg(test)]
use crate::{backend::analyze, opening::proof_codec::Topology, primitive::Kind};
#[cfg(test)]
use p3_air::BaseAir;
#[cfg(test)]
pub(in crate::opening) use registry200_proof::wire::encode_claim as encode;
#[cfg(test)]
use registry200_proof::wire::frame::Role;
use registry200_proof::wire::frame::{self, Frame};
#[cfg(test)]
use registry200_proof::wire::{CHILD_SLOTS, MAX_SEQUENCE_ELEMENTS, SOURCE_SLOTS};
pub(in crate::opening) use registry200_proof::wire::{Error, verify_claim as verify};
pub(super) use registry200_proof::wire::{
    decode_and_verify_claim as decode_and_verify, maximum_bundle_bytes, role,
};
#[cfg(test)]
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
                let checked = registry200_proof::admission::Expected::checked_claim(&initial)?;
                let source = registry200_proof::source::prove(
                    &registry200_proof::admission::CanonicalSource::checked_claim(&initial.source)?,
                    &fixture.source_witness,
                )
                .map_err(|_| BackendError::Verification)?;
                let prepared = registry200_proof::lifecycle::PreparedWitness::new(&checked, w)
                    .map_err(|_| BackendError::Verification)?;
                let evidence =
                    registry200_proof::lifecycle::prove(&checked, &prepared, source.as_bytes())
                        .map_err(|_| BackendError::Verification)?;
                let s = registry200_proof::wire::verify_claim(&initial, evidence.as_bytes())
                    .map_err(|_| BackendError::Verification)?;
                let Phase::Transition { old, .. } = e.phase else {
                    unreachable!()
                };
                if old != s.next {
                    return Err(BackendError::Shape);
                }
            }
            let checked = registry200_proof::admission::Expected::checked_claim(&e)?;
            let source = registry200_proof::source::prove(
                &registry200_proof::admission::CanonicalSource::checked_claim(&e.source)?,
                &fixture.source_witness,
            )
            .map_err(|_| BackendError::Verification)?;
            let prepared = registry200_proof::lifecycle::PreparedWitness::new(&checked, w)
                .map_err(|_| BackendError::Verification)?;
            registry200_proof::lifecycle::prove(&checked, &prepared, source.as_bytes())
                .map_err(|_| BackendError::Verification)?
                .into_parts()
                .1
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
