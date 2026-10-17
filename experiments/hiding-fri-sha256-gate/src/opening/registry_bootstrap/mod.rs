//! SOURCE ONLY private registry initialization, not a live lock grant.
pub(crate) mod air;
pub(in crate::opening) mod statement;
#[cfg(test)]
mod tests;
pub(in crate::opening) mod trace;
pub(in crate::opening) mod wire;
use crate::backend::{Backend, Config, Error, Val};
use crate::opening::{
    Relation, commitment, fixture as source_fixture, locking::statement as registry,
    trace as source_trace,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use sha2::Digest;
use sha2::Sha256;
use statement::{Expected, Statement};
use trace::Witness;

pub(in crate::opening) struct CompositeProof {
    source: Option<Proof<Config>>,
    bootstrap: Proof<Config>,
}
pub(in crate::opening) fn verify(
    expected: &Expected,
    s: &Statement,
    p: &CompositeProof,
) -> Result<(), Error> {
    expected.require_contract()?;
    // A real source proof is the first cryptographic gate. Enrollment authority
    // and the agreed fresh parent must still be established independently.
    Backend::new(&expected.source)?.verify(
        &expected.source,
        p.source.as_ref().ok_or(Error::Verification)?,
    )?;
    s.require_expected(expected)?;
    Backend::new(s)?.verify(s, &p.bootstrap)
}
fn prove_child_with_trace(
    expected: &Expected,
    s: &Statement,
    source: &Proof<Config>,
    factory: impl FnOnce() -> Result<RowMajorMatrix<Val>, Error>,
) -> Result<Proof<Config>, Error> {
    expected.require_contract()?;
    Backend::new(&expected.source)?.verify(&expected.source, source)?;
    s.require_expected(expected)?;
    Backend::new(s)?.prove_with_trace(s, factory)
}
pub(in crate::opening) fn prove(
    expected: &Expected,
    source_witness: &source_trace::Witness,
    witness: &Witness,
) -> Result<(Statement, CompositeProof), Error> {
    expected.require_contract()?;
    let source = {
        let b = Backend::new(&expected.source)?;
        b.prove_with_trace(&expected.source, || source_witness.trace(&expected.source))?
    };
    let s = witness.statement(expected)?;
    let bootstrap = prove_child_with_trace(expected, &s, &source, || witness.trace(&s))?;
    Ok((
        s,
        CompositeProof {
            source: Some(source),
            bootstrap,
        },
    ))
}
pub(crate) fn profile(h: &mut Sha256) {
    h.update(b"PRIVATE-REGISTRY-BOOTSTRAP/N4-T2/v1/canonical-source-first/no-live-grant");
    h.update(statement::ENROLLMENT_DOMAIN);
    h.update(registry::registry_profile());
    h.update(
        b"enroll64/new-profile/genesis/DB-keyDomain/Ckey/Table/cap2/ids1-2/controllers256/salt4",
    );
    h.update(b"same-stable-registry112/all4ordinalRowIds/revision2/Active-seq1/failed0/no-held");
    h.update(b"P2-12/overwrite-rate8-cap4/reset0/source680/enroll64/registry112/hold-through511");
    for x in [
        air::WIDTH,
        statement::PUBLIC_VALUES,
        0,
        84,
        85,
        92,
        93,
        106,
        512,
    ] {
        h.update((x as u64).to_le_bytes());
    }
}
fn salt() -> Result<[Val; 4], Error> {
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    Ok(core::array::from_fn(|_| rng.random()))
}
/// PUBLIC NONSECRET fixture only. Its expected enrollment is independently
/// prepared by the fixture client; prove/verify never select a replacement root.
fn fixture() -> Result<(Expected, source_trace::Witness, Witness), Error> {
    let salts = [salt()?, salt()?, salt()?];
    let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
    let suffix = source_fixture::canonical_suffix();
    let (source, source_witness) = source_fixture::from_suffix(
        Relation::CanonicalIndex,
        [0x71; 32],
        (salt()?, salts[0]),
        [0x83; 32],
        data,
        &suffix,
    )?;
    let mut plain = [0; 2348];
    plain[..12].copy_from_slice(&data);
    plain[12..124].copy_from_slice(&source.heads[0]);
    plain[124..].copy_from_slice(&suffix);
    let witness = Witness {
        plain,
        controllers: [[0x41; 32], [0x42; 32]],
        salts,
    };
    let mut expected = Expected::checked(&source, [0xA1; 32], [0xB1; 32], [0; 32])?;
    expected.enrollment = commitment::digest(&statement::enrollment_fields(&expected, &witness));
    Ok((expected, source_witness, witness))
}
pub(crate) fn gate(mode: &str) -> Result<(), Error> {
    if !matches!(mode, "security" | "prove") {
        return Err(Error::Shape);
    }
    let (expected, source_witness, witness) = fixture()?;
    let s = witness.statement(&expected)?;
    crate::security(&s, "public-nonsecret-private-registry-bootstrap")?;
    if mode == "prove" {
        let started = std::time::Instant::now();
        let (s, proof) = prove(&expected, &source_witness, &witness)?;
        let proving = started.elapsed();
        let started = std::time::Instant::now();
        verify(&expected, &s, &proof)?;
        println!(
            "{{\"stage\":\"verified_experimental_registry_bootstrap\",\"proving_ms\":{},\"verification_ms\":{},\"live_sql_grant\":false}}",
            proving.as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    Ok(())
}

/// Independent wire gate; the original proof/profile/CLI behavior is unchanged.
pub(crate) fn wire_gate(mode: &str) -> Result<(), Error> {
    wire::gate(mode)
}
