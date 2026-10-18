//! Closed N4/private-two-transaction proof experiment. No live SQL lock grant.
use registry200_proof::source::circuit as source_trace;
pub(crate) mod air;
pub(crate) mod encoding;
pub(crate) mod formation;
pub(in crate::opening) mod sql;
#[cfg(test)]
mod sql_tests;
pub(in crate::opening) mod statement;
#[cfg(test)]
mod tests;
pub(in crate::opening) mod trace;
pub(in crate::opening) mod wire;
use crate::backend::{Backend, Config, Error, Val};
use crate::opening::{Relation, commitment, fixture as source_fixture};
use p3_uni_stark::Proof;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use sha2::{Digest, Sha256};
use statement::{Expected, Statement};
use trace::{Plan, Registry, Transaction, Witness};

pub(in crate::opening) struct CompositeProof {
    source: Option<Proof<Config>>,
    locking: Proof<Config>,
}
fn verify_composite(expected: &Expected, s: &Statement, p: &CompositeProof) -> Result<(), Error> {
    if expected.source.relation != Relation::CanonicalIndex
        || s.expected.source.relation != Relation::CanonicalIndex
    {
        return Err(Error::Shape);
    }
    // These are independently expected input identities, not receipt fields trusted
    // from the submitter. Same-parent authority/finality remains an external gate.
    Backend::new(&expected.source)?.verify(
        &expected.source,
        p.source.as_ref().ok_or(Error::Verification)?,
    )?;
    s.require_expected(expected)?;
    Backend::new(s)?.verify(s, &p.locking)
}
pub(in crate::opening) fn prove_composite(
    expected: &Expected,
    source_witness: &source_trace::Witness,
    witness: &Witness,
) -> Result<(Statement, CompositeProof), Error> {
    if expected.source.relation != Relation::CanonicalIndex {
        return Err(Error::Shape);
    }
    let source_backend = Backend::new(&expected.source)?;
    let source = source_backend
        .prove_with_trace(&expected.source, || source_witness.trace(&expected.source))?;
    source_backend.verify(&expected.source, &source)?;
    let s = statement::proposed(expected, witness)?;
    s.require_expected(expected)?;
    let locking = Backend::new(&s)?.prove_with_trace(&s, || witness.trace(&s))?;
    Ok((
        s,
        CompositeProof {
            source: Some(source),
            locking,
        },
    ))
}
pub(crate) fn profile(h: &mut Sha256) {
    h.update(b"PRIVATE-LOCKING/N4-T2/v1/no-SQL-grant/no-finality");
    h.update(statement::registry_profile());
    h.update(b"PV116/source-first/exact-Copen/all-four-RowIds/whole-two-tx-registry");
    h.update(b"Wait-NoWait-atomic-old-root-and-salt/Skip/offset-locks/limit-counts-returned");
    h.update(b"u32-candidate-counters-admitted-before-conflict/closed-effective-state-not-events");
    for value in [
        112,
        144,
        168,
        116,
        air::WIDTH,
        0,
        84,
        85,
        98,
        99,
        116,
        117,
        130,
        257,
        277,
        278,
        298,
        300,
    ] {
        h.update((value as u64).to_le_bytes());
    }
}
fn salt() -> Result<[Val; 4], Error> {
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    Ok(core::array::from_fn(|_| rng.random()))
}
/// Every fixture key/row/controller is explicitly PUBLIC NONSECRET. Values are
/// original source records; no fixture-generated FHE/SQL answer is accepted.
pub(super) fn fixture() -> Result<(Expected, source_trace::Witness, Witness), Error> {
    let salts = [salt()?, salt()?, salt()?, salt()?, salt()?, salt()?];
    let (source, source_witness) = source_fixture::from_suffix(
        Relation::CanonicalIndex,
        [0x71; 32],
        (salt()?, salts[0]),
        [0x83; 32],
        [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0],
        &source_fixture::canonical_suffix(),
    )?;
    let mut plain = [0; 2348];
    plain[..12].copy_from_slice(&[255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0]);
    plain[12..124].copy_from_slice(&source.heads[0]);
    plain[124..].copy_from_slice(&source_fixture::canonical_suffix());
    let plan = Plan::checked([0x31; 32], [255; 32], 0, 4, 2, (0, Some(2)), 2)?;
    let old = Registry {
        revision: 2,
        tx: core::array::from_fn(|t| Transaction {
            id: t as u32 + 1,
            controller: [0x41 + t as u8; 32],
            sequence: 1,
            failed: false,
            held: [0; 4],
        }),
    };
    let witness = Witness {
        plain,
        old,
        plan,
        salts,
    };
    let mut expected = Expected::checked(&source, [0xA1; 32], [0xB1; 32], [0; 32], [0; 32])?;
    // Client fixture anchors the old snapshot before preparing its query plan.
    // Prove/verify do NOT construct or substitute these expected commitments.
    expected.old = commitment::digest(&statement::registry_fields(
        &expected,
        &witness,
        &witness.old,
        witness.salts[1],
    ));
    expected.plan = commitment::digest(&statement::plan_fields(&expected, &witness));
    Ok((expected, source_witness, witness))
}
/// PUBLIC NONSECRET client setup, not an accepting source/control authority.
fn sql_fixture(
    compiled: &sql::CompiledLockPlan,
) -> Result<(Expected, source_trace::Witness, Witness), Error> {
    let (old_expected, source_witness, mut witness) = fixture()?;
    let mut source = old_expected.source;
    source.request = compiled.request();
    source.open_commitment = commitment::digest(&commitment::opening_fields(
        &source,
        witness.salts[0],
        &witness.plain,
    ));
    witness.plan = compiled.plan(witness.plan.table, witness.plan.actor)?;
    let mut expected = compiled.expected(
        &source,
        old_expected.genesis,
        old_expected.parent,
        statement::encoded(old_expected.old),
        [0; 32],
    )?;
    // Fixture client pins its actual compiled plan. Verification never chooses it.
    expected.plan = commitment::digest(&statement::plan_fields(&expected, &witness));
    Ok((expected, source_witness, witness))
}
pub(crate) fn gate(mode: &str) -> Result<(), Error> {
    use std::time::Instant;
    let compiled =
        sql::CompiledLockPlan::fresh("SELECT amount FROM records LIMIT 2 FOR UPDATE SKIP LOCKED")?;
    let (expected, source_witness, witness) = sql_fixture(&compiled)?;
    let s = statement::proposed(&expected, &witness)?;
    crate::security(&s, "closed-private-locking-N4-T2")?;
    if mode == "prove" {
        let started = Instant::now();
        let (s, proof) = prove_composite(&expected, &source_witness, &witness)?;
        let proving = started.elapsed();
        let started = Instant::now();
        verify_composite(&expected, &s, &proof)?;
        println!(
            "{{\"stage\":\"verified_experimental_private_locking_composite\",\"proving_ms\":{},\"verification_ms\":{},\"live_sql_grant\":false}}",
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
