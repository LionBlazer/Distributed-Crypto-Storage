//! Distinct private lifecycle relation and experimental typed transport.
//! Legacy Registry112 consumers and production live grants do not accept these roots.
pub(crate) use registry200_proof::lifecycle::air;
pub(crate) use registry200_proof::lifecycle::bootstrap;
#[cfg(test)]
use registry200_proof::source::circuit as source_trace;
pub(crate) mod encoding;
mod fixture;
mod formation;
mod journal;
use registry200_proof::lifecycle::circuit::model;
use registry200_proof::lifecycle::layout;
mod statement;
#[cfg(test)]
mod tests;
use registry200_proof::lifecycle::circuit as trace;
mod wire;
mod write;
use crate::backend::Error;
#[cfg(test)]
use crate::backend::{Backend, Config, Val};

use crate::primitive::Kind;
#[cfg(test)]
use p3_matrix::dense::RowMajorMatrix;
#[cfg(test)]
use p3_uni_stark::Proof;
pub(super) use registry200_proof::wire::CompositeProof;
pub(super) use registry200_proof::wire::verify_pair as verify;
#[cfg(test)]
use statement::{Expected, Statement};
#[cfg(test)]
use trace::Witness;
#[cfg(test)]
fn prove_child_with_trace(
    e: &Expected,
    s: &Statement,
    source: &Proof<Config>,
    factory: impl FnOnce() -> Result<RowMajorMatrix<Val>, Error>,
) -> Result<Proof<Config>, Error> {
    e.require_contract()?;
    Backend::new(&e.source)?.verify(&e.source, source)?;
    s.require_expected(e)?;
    Backend::new(s)?.prove_with_trace(s, factory)
}
#[cfg(test)]
pub(super) fn prove(
    e: &Expected,
    source_witness: &source_trace::Witness,
    w: &Witness,
) -> Result<(Statement, CompositeProof), Error> {
    // Test consumer needs real decoded proof objects for coherent hostile controls.
    let expected = registry200_proof::admission::Expected::checked_claim(e)?;
    let source = registry200_proof::source::prove(
        &registry200_proof::admission::CanonicalSource::checked_claim(&e.source)?,
        source_witness,
    )
    .map_err(|_| Error::Verification)?;
    let witness = registry200_proof::lifecycle::PreparedWitness::new(&expected, w.clone())
        .map_err(|_| Error::Verification)?;
    let evidence = registry200_proof::lifecycle::prove(&expected, &witness, source.as_bytes())
        .map_err(|_| Error::Verification)?;
    registry200_proof::wire::decode_and_verify_claim(e, evidence.as_bytes())
        .map_err(|_| Error::Verification)
}
pub(crate) fn air_width() -> usize {
    layout::WIDTH
}
pub(crate) use registry200_proof::lifecycle::profile;
pub(crate) fn gate(mode: &str, bootstrap: bool) -> Result<(), Error> {
    if !matches!(mode, "security" | "prove") {
        return Err(Error::Shape);
    }
    let fixture = fixture::Fixture::new()?;
    let (expected, witness) = if bootstrap {
        fixture.bootstrap()?
    } else {
        fixture.begin()?
    };
    let statement = witness.statement(&expected)?;
    // Security mode is analytical only: no Backend, trace factory, proof or Journal append.
    crate::security(
        &expected.source,
        "public-nonsecret-lifecycle-canonical-source",
    )?;
    crate::security(
        &statement,
        if bootstrap {
            "public-nonsecret-empty-registry200-bootstrap"
        } else {
            "public-nonsecret-registry200-lifecycle"
        },
    )?;
    if mode == "prove" {
        let started = std::time::Instant::now();
        // A fresh application must establish the NEW empty root with a genuine proof.
        if !bootstrap {
            let (initial, witness) = fixture.bootstrap()?;
            let checked = registry200_proof::admission::Expected::checked_claim(&initial)?;
            let source = registry200_proof::source::prove(
                &registry200_proof::admission::CanonicalSource::checked_claim(&initial.source)?,
                &fixture.source_witness,
            )
            .map_err(|_| Error::Verification)?;
            let prepared = registry200_proof::lifecycle::PreparedWitness::new(&checked, witness)
                .map_err(|_| Error::Verification)?;
            let evidence =
                registry200_proof::lifecycle::prove(&checked, &prepared, source.as_bytes())
                    .map_err(|_| Error::Verification)?;
            let s = registry200_proof::wire::verify_claim(&initial, evidence.as_bytes())
                .map_err(|_| Error::Verification)?;
            let statement::Phase::Transition { old, .. } = expected.phase else {
                unreachable!()
            };
            if old != s.next {
                return Err(Error::Shape);
            }
        }
        let checked = registry200_proof::admission::Expected::checked_claim(&expected)?;
        let source = registry200_proof::source::prove(
            &registry200_proof::admission::CanonicalSource::checked_claim(&expected.source)?,
            &fixture.source_witness,
        )
        .map_err(|_| Error::Verification)?;
        let prepared = registry200_proof::lifecycle::PreparedWitness::new(&checked, witness)
            .map_err(|_| Error::Verification)?;
        let evidence = registry200_proof::lifecycle::prove(&checked, &prepared, source.as_bytes())
            .map_err(|_| Error::Verification)?;
        let proving = started.elapsed();
        let started = std::time::Instant::now();
        registry200_proof::wire::verify_claim(&expected, evidence.as_bytes())
            .map_err(|_| Error::Verification)?;
        let verification = started.elapsed();
        let frame = registry200_proof::wire::frame::Frame::parse(
            registry200_proof::wire::role(&expected),
            evidence.as_bytes(),
        )
        .map_err(|_| Error::Verification)?;
        let source_bytes = frame.source.len();
        let child_bytes = frame.child.len();
        println!(
            "{{\"stage\":\"verified_experimental_registry_lifecycle\",\"primitive\":\"{}\",\"proving_ms\":{},\"verification_ms\":{},\"source_proof_bytes\":{},\"child_proof_bytes\":{},\"live_sql_grant\":false}}",
            if bootstrap {
                Kind::RegistryLifecycleBootstrap.name()
            } else {
                Kind::RegistryLifecycle.name()
            },
            proving.as_secs_f64() * 1000.0,
            verification.as_secs_f64() * 1000.0,
            source_bytes,
            child_bytes
        );
    }
    Ok(())
}

pub(crate) fn wire_gate(mode: &str, bootstrap: bool) -> Result<(), Error> {
    wire::gate(mode, bootstrap)
}

pub(crate) fn journal_gate(mode: &str) -> Result<(), Error> {
    journal::gate(mode)
}

pub(crate) fn encoding_gate(mode: &str) -> Result<(), Error> {
    encoding::gate(mode)
}

pub(crate) fn formation_gate(mode: &str) -> Result<(), Error> {
    formation::gate(mode)
}

pub(crate) fn peer_projection_gate(
    mode: &str,
    executable: &std::path::Path,
) -> Result<(), crate::backend::Error> {
    formation::job::gate(mode, executable).map_err(|error| {
        eprintln!("Registry200 peer projection: {error}");
        crate::backend::Error::Verification
    })
}

pub(crate) fn peer_control_gate(
    mode: &str,
    executable: Option<&std::path::Path>,
) -> Result<(), Error> {
    journal::peer_control_gate(mode, executable)
}

pub(crate) fn write_image_gate(mode: &str) -> Result<(), Error> {
    journal::write_image_gate(mode)
}
