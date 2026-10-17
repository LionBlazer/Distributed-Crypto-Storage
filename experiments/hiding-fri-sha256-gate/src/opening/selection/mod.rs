//! Private nonaccepting composition: authenticated canonical source FIRST, then
//! complete bounded original-row selection. No SQL/FHE/key-custody acceptance API.
pub(crate) mod air;
pub(crate) mod encoding;
pub(super) mod statement;
#[cfg(test)]
mod tests;
pub(super) mod trace;

use crate::backend::{Backend, Config, Error, Val};
use crate::opening::{
    Relation, fixture as source_fixture, statement as source, trace as source_trace,
};
use p3_uni_stark::Proof;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use statement::{Plan, Statement};
use trace::Witness;

pub(super) const VERSION: u32 = 1;
pub(super) const PLAN_DOMAIN: [u8; 16] = *b"DCS/PLAN/N4/v1!!";
pub(super) const SELECT_DOMAIN: [u8; 16] = *b"DCS/SELECT/N4/v1";

/// Private completed proofs only. No Serialize, Clone, trusted marker or cache.
/// Optional source models an absent/untrusted composite envelope, never acceptance.
struct CompositeProof {
    source: Option<Proof<Config>>,
    selection: Proof<Config>,
}
fn prove_composite(
    source: &source::Statement,
    source_witness: &source_trace::Witness,
    statement: &Statement,
    witness: &Witness,
) -> Result<CompositeProof, Error> {
    if source.relation != Relation::CanonicalIndex {
        return Err(Error::Shape);
    }
    let source_backend = Backend::new(source)?;
    let source_proof = source_backend.prove_with_trace(source, || source_witness.trace(source))?;
    // A real source verification precedes selection trace generation, too.
    source_backend.verify(source, &source_proof)?;
    drop(source_backend);
    statement.require_source(source)?;
    let selection =
        Backend::new(statement)?.prove_with_trace(statement, || witness.trace(statement))?;
    Ok(CompositeProof {
        source: Some(source_proof),
        selection,
    })
}
fn verify_composite(
    independently_expected_source: &source::Statement,
    statement: &Statement,
    proof: &CompositeProof,
) -> Result<(), Error> {
    let source_proof = proof.source.as_ref().ok_or(Error::Shape)?;
    if independently_expected_source.relation != Relation::CanonicalIndex {
        return Err(Error::Shape);
    }
    // Ordering is deliberate: no metadata equality or selection proof replaces
    // cryptographic source verification against independently expected context.
    Backend::new(independently_expected_source)?
        .verify(independently_expected_source, source_proof)?;
    statement.require_source(independently_expected_source)?;
    Backend::new(statement)?.verify(statement, &proof.selection)
}

pub(crate) fn profile(hash: &mut sha2::Sha256) {
    use sha2::Digest;
    hash.update(b"DCS/experimental/private-selection-N4/v1/no-SQL-FHE-acceptance");
    hash.update(crate::backend::profile_digest(
        crate::primitive::Kind::CanonicalIndexOpening,
    ));
    hash.update(PLAN_DOMAIN);
    hash.update(SELECT_DOMAIN);
    hash.update(b"old-C_open-680/source-proof-first/plan107-pad5/selected82-pad6");
    hash.update(b"TRUE-mask256/privateTableId/ordinal-order/limit-min4/projection0..3");
    hash.update(b"all587-u32/capture-data10-11/table14-15/RowIds80-84/immutable-all-rows");
    hash.update(b"scan0..255/final256/compact-rank/original-age-amount-ID/inactive-zero");
    for n in [air::WIDTH, 88, 512, 85, 98, 257, 267, 5] {
        hash.update((n as u64).to_le_bytes());
    }
}

fn random_salt() -> Result<[Val; 4], Error> {
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    Ok(core::array::from_fn(|_| rng.random::<Val>()))
}
pub(in crate::opening) fn fixture(
    mask: [u8; 32],
    limit: Option<usize>,
) -> Result<(source::Statement, source_trace::Witness, Statement, Witness), Error> {
    let key = core::array::from_fn(|i| i as u8); // Explicitly PUBLIC NONSECRET.
    let source_key_salt = random_salt()?;
    let source_open_salt = random_salt()?;
    let data = [255, 0, 0, 0, 255, 255, 255, 0, 1, 128, 255, 0];
    let suffix = source_fixture::canonical_suffix();
    let (source, source_witness) = source_fixture::from_suffix(
        Relation::CanonicalIndex,
        key,
        (source_key_salt, source_open_salt),
        [0x83; 32],
        data,
        &suffix,
    )?;
    let mut plain = [0_u8; 2348];
    plain[..12].copy_from_slice(&data);
    plain[12..124].copy_from_slice(&source.heads[0]);
    plain[124..].copy_from_slice(&suffix);
    let plan = Plan::new([0x31; 32], mask, 2, limit)?;
    let witness = Witness::new(
        plain,
        plan,
        [source_open_salt, random_salt()?, random_salt()?],
    );
    let statement = statement::commitments(&source, &witness)?;
    Ok((source, source_witness, statement, witness))
}

pub(crate) fn gate(mode: &str) -> Result<(), Error> {
    use std::time::Instant;
    let mut mask = [0; 32];
    mask[0] = 1;
    mask[31] = 128;
    let (source, source_witness, statement, witness) = fixture(mask, Some(2))?;
    crate::security(&statement, "canonical-private-selection")?;
    if mode == "prove" {
        let started = Instant::now();
        let proof = prove_composite(&source, &source_witness, &statement, &witness)?;
        let proving = started.elapsed();
        let started = Instant::now();
        verify_composite(&source, &statement, &proof)?;
        println!(
            "{{\"stage\":\"verified_experimental_private_selection_composite\",\"proving_ms\":{},\"verification_ms\":{}}}",
            proving.as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    Ok(())
}
