//! Distinct private lifecycle relation and experimental typed transport.
//! Legacy Registry112 consumers and production live grants do not accept these roots.
pub(crate) use registry200_proof::lifecycle::air;
pub(crate) use registry200_proof::lifecycle::bootstrap;
pub(crate) mod encoding;
mod fixture;
mod formation;
mod journal;
use registry200_proof::lifecycle::layout;
mod model;
mod statement;
#[cfg(test)]
mod tests;
mod trace;
mod wire;
mod write;
use crate::backend::{Backend, Config, Error, Val};
use crate::opening::trace as source_trace;
use crate::primitive::Kind;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
pub(super) use registry200_proof::wire::CompositeProof;
pub(super) use registry200_proof::wire::verify_pair as verify;
use statement::{Expected, Statement};
use trace::Witness;
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
pub(super) fn prove(
    e: &Expected,
    source_witness: &source_trace::Witness,
    w: &Witness,
) -> Result<(Statement, CompositeProof), Error> {
    e.require_contract()?;
    let source = {
        let backend = Backend::new(&e.source)?;
        backend.prove_with_trace(&e.source, || source_witness.trace(&e.source))?
    };
    let s = w.statement(e)?;
    let child = prove_child_with_trace(e, &s, &source, || w.trace(&s))?;
    Ok((
        s,
        CompositeProof {
            source: Some(source),
            child,
        },
    ))
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
            let (s, p) = prove(&initial, &fixture.source_witness, &witness)?;
            verify(&initial, &s, &p)?;
            let statement::Phase::Transition { old, .. } = expected.phase else {
                unreachable!()
            };
            if old != s.next {
                return Err(Error::Shape);
            }
        }
        let (s, p) = prove(&expected, &fixture.source_witness, &witness)?;
        let proving = started.elapsed();
        let started = std::time::Instant::now();
        verify(&expected, &s, &p)?;
        let verification = started.elapsed();
        let source_bytes = postcard::to_allocvec(p.source.as_ref().ok_or(Error::Shape)?)
            .map_err(|_| Error::Shape)?
            .len();
        let child_bytes = postcard::to_allocvec(&p.child)
            .map_err(|_| Error::Shape)?
            .len();
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
