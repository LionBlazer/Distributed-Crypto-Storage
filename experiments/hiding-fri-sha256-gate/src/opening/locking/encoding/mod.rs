//! Successful Return168 -> exact8192 scaled plaintext. No SQL/FHE acceptance.
pub(crate) mod air;
pub(in crate::opening) mod statement;
#[cfg(test)]
mod tests;
pub(in crate::opening) mod trace;
use crate::backend::{Backend, Config, Error, Val, profile_digest};
use crate::opening::{selection::encoding, state::certificate::StateLease};
use crate::primitive::Kind;
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use sha2::{Digest, Sha256};
use statement::{Expected, Producer, Statement};
use trace::Witness;

/// Borrowed actual evidence; no caller boolean or cloned verified-state token.
pub(in crate::opening) enum Evidence<'p, 'state> {
    Canonical(&'p super::CompositeProof),
    Certified {
        lease: &'p StateLease<'state>,
        proof: &'p Proof<Config>,
    },
}
fn verify_parent(expected: &Expected, proof: Option<Evidence<'_, '_>>) -> Result<(), Error> {
    expected.validate()?;
    match (&expected.producer, proof.ok_or(Error::Verification)?) {
        (
            Producer::Canonical {
                expected,
                statement,
            },
            Evidence::Canonical(proof),
        ) => super::verify_composite(expected, statement, proof),
        (
            Producer::Certified {
                expected,
                statement,
            },
            Evidence::Certified { lease, proof },
        ) => lease.verify_lock(expected, statement, proof),
        _ => Err(Error::Shape),
    }
}
pub(in crate::opening) fn prove_with_trace(
    expected: &Expected,
    statement: &Statement,
    parent: Option<Evidence<'_, '_>>,
    factory: impl FnOnce() -> Result<p3_matrix::dense::RowMajorMatrix<Val>, Error>,
) -> Result<Proof<Config>, Error> {
    statement.require_expected(expected)?;
    verify_parent(expected, parent)?; // ACTUAL whole source/lock verification BEFORE Backend/factory.
    Backend::new(statement)?.prove_with_trace(statement, factory)
}
pub(in crate::opening) fn verify(
    expected: &Expected,
    statement: &Statement,
    parent: Option<Evidence<'_, '_>>,
    proof: &Proof<Config>,
) -> Result<(), Error> {
    statement.require_expected(expected)?;
    verify_parent(expected, parent)?;
    Backend::new(statement)?.verify(statement, proof)
}
pub(crate) fn profile(h: &mut Sha256) {
    h.update(b"DCS/experimental/N4-successful-lock-return-encoding/v1/no-grant");
    h.update(profile_digest(Kind::LockingSelection));
    h.update(profile_digest(Kind::VersionLockingSelection));
    h.update(super::statement::RETURN_DOMAIN);
    h.update(crate::opening::state::locking::RETURN_DOMAIN);
    h.update(b"sealed-canonical-or-actual-StateLease/whole-parent-first/fullPV116/outcome0");
    h.update(b"Return168:prefix115-salt4-tuples48-zero1/rows1..21/finish21");
    h.update(
        b"encoded-contextSHA8-salt4-zero4-W8192/old12-original-sparse-SIMD/3P2/16lanes/row511",
    );
    h.update(encoding::matrix::digest());
    for x in [512, air::WIDTH as u64, 128, 215, 5, 114689, 78307] {
        h.update(x.to_le_bytes());
    }
}
/// PUBLIC NONSECRET fixture. The caller/client pins roots before proving; this
/// does not authenticate a production registry, controller, key or agreed head.
pub(in crate::opening) struct Fixture {
    pub(in crate::opening) expected: super::statement::Expected,
    pub(in crate::opening) source: crate::opening::trace::Witness,
    pub(in crate::opening) lock: super::trace::Witness,
    pub(in crate::opening) encoding_expected: Expected,
    pub(in crate::opening) statement: Statement,
    pub(in crate::opening) witness: Witness,
}
pub(in crate::opening) fn fixture() -> Result<Fixture, Error> {
    let plan = super::sql::CompiledLockPlan::fresh(
        "SELECT amount FROM records WHERE age>=128 OFFSET 1 LIMIT 1 FOR UPDATE SKIP LOCKED",
    )?;
    let (mut expected, source, mut lock) = super::sql_fixture(&plan)?;
    lock.old.tx[1].held[0] = 4;
    expected.old = crate::opening::commitment::digest(&super::statement::registry_fields(
        &expected,
        &lock,
        &lock.old,
        lock.salts[1],
    ));
    expected.plan =
        crate::opening::commitment::digest(&super::statement::plan_fields(&expected, &lock));
    let producer = super::statement::proposed(&expected, &lock)?;
    let e = Expected::canonical(&expected, &producer)?;
    let shape = Statement::new(e.clone(), [Val::ZERO; 4]);
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    let witness = Witness::from_lock(&shape, &lock, core::array::from_fn(|_| rng.random()))?;
    let statement = witness.returned_statement(e.clone());
    Ok(Fixture {
        expected,
        source,
        lock,
        encoding_expected: e,
        statement,
        witness,
    })
}
pub(crate) fn gate(mode: &str) -> Result<(), Error> {
    if !matches!(mode, "security" | "prove") {
        return Err(Error::Shape);
    }
    let Fixture {
        expected,
        source,
        lock,
        encoding_expected: e,
        statement: s,
        witness: w,
    } = fixture()?;
    crate::security(&s, "public-nonsecret-successful-LockReturn168")?;
    if mode == "security" {
        return Ok(());
    }
    let started = std::time::Instant::now();
    let (_, parent) = super::prove_composite(&expected, &source, &lock)?;
    let proof = prove_with_trace(&e, &s, Some(Evidence::Canonical(&parent)), || {
        w.trace_returned(&s)
    })?;
    let proving = started.elapsed();
    let started = std::time::Instant::now();
    verify(&e, &s, Some(Evidence::Canonical(&parent)), &proof)?;
    println!(
        "{{\"stage\":\"verified_experimental_successful_lock_return_encoding\",\"proving_ms\":{},\"verification_ms\":{},\"live_sql_grant\":false}}",
        proving.as_secs_f64() * 1000.0,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}
