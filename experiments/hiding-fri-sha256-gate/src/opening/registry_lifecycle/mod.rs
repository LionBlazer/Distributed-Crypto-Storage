//! Distinct private lifecycle relation and experimental typed transport.
//! Legacy Registry112 consumers and production live grants do not accept these roots.
mod acquire;
pub(crate) mod air;
pub(crate) mod bootstrap;
mod control;
mod fixture;
mod journal;
mod layout;
mod model;
mod ranges;
mod statement;
#[cfg(test)]
mod tests;
mod trace;
mod wire;
use crate::backend::{Backend, Config, Error, Val};
use crate::opening::trace as source_trace;
use crate::primitive::Kind;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use sha2::{Digest, Sha256};
use statement::{Expected, Statement};
use trace::Witness;
pub(super) struct CompositeProof {
    source: Option<Proof<Config>>,
    child: Proof<Config>,
}
pub(super) fn verify(e: &Expected, s: &Statement, p: &CompositeProof) -> Result<(), Error> {
    e.require_contract()?;
    // No cache flag, owner-local state evaluator, plaintext registry or receipt enters verification.
    Backend::new(&e.source)?.verify(&e.source, p.source.as_ref().ok_or(Error::Verification)?)?;
    s.require_expected(e)?;
    Backend::new(s)?.verify(s, &p.child)
}
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
pub(crate) fn profile(h: &mut Sha256, bootstrap: bool) {
    h.update(b"DCS/private-registry-lifecycle/v2/N4-T2-D2/owner-authorized-externally/canonical-source-first/no-live-grant");
    h.update(statement::enrollment_profile());
    h.update(statement::registry_profile());
    if bootstrap {
        h.update(b"Source680/Enrollment64/EMPTYRegistry200/revision0/allocator0/no112cast");
    } else {
        h.update(b"Source680/Enrollment64/Old200/Command160/New200/Result144/181absorbs");
        h.update(b"Begin/Acquire/FailCurrent/Savepoint/RollbackTo/Release/End/u64-limb-carries-and-borrows/newest-exact-name/compact-by-ID/failed-EndAbort/no-MVCC/no-controller-signature");
    }
    for n in [
        if bootstrap {
            bootstrap::WIDTH
        } else {
            layout::WIDTH
        },
        if bootstrap {
            statement::BOOTSTRAP_VALUES
        } else {
            statement::STEP_VALUES
        },
        512,
        2,
        4,
        2,
    ] {
        h.update((n as u64).to_le_bytes());
    }
}
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
