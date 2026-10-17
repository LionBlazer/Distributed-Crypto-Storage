//! Nonaccepting private selected-originals -> complete scaled BFV plaintext gate.
pub(crate) mod air;
pub(in crate::opening) mod kernel;
pub(in crate::opening) mod matrix;
pub(in crate::opening) mod statement;
#[cfg(test)]
mod tests;
pub(in crate::opening) mod trace;

use super::{statement::Statement as Selection, trace::Witness as SelectedWitness};
use crate::backend::{Backend, Config, Error, Val};
use crate::opening::{statement as source, trace as source_trace};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::Proof;
use rand::{
    RngExt, SeedableRng,
    rngs::{StdRng, SysRng},
};
use statement::Statement;
pub(crate) use statement::profile;
use trace::Witness;

pub(in crate::opening) struct CompositeProof {
    selection: super::CompositeProof,
    encoding: Proof<Config>,
}
pub(in crate::opening) fn prove_composite(
    source: &source::Statement,
    source_witness: &source_trace::Witness,
    selection: &Selection,
    selected_witness: &SelectedWitness,
    statement: &Statement,
    witness: &Witness,
) -> Result<CompositeProof, Error> {
    let selected = super::prove_composite(source, source_witness, selection, selected_witness)?;
    // Both real prerequisite proofs verify before this private trace factory.
    super::verify_composite(source, selection, &selected)?;
    statement.require_selection(selection)?;
    let encoding =
        Backend::new(statement)?.prove_with_trace(statement, || witness.trace(statement))?;
    Ok(CompositeProof {
        selection: selected,
        encoding,
    })
}
pub(in crate::opening) fn verify_composite(
    source: &source::Statement,
    independently_expected: &Selection,
    statement: &Statement,
    proof: &CompositeProof,
) -> Result<(), Error> {
    super::verify_composite(source, independently_expected, &proof.selection)?;
    statement.require_selection(independently_expected)?;
    Backend::new(statement)?.verify(statement, &proof.encoding)
}
fn salt() -> Result<[Val; 4], Error> {
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|_| Error::Randomness)?;
    Ok(core::array::from_fn(|_| rng.random::<Val>()))
}
pub(crate) fn gate(mode: &str) -> Result<(), Error> {
    let mut mask = [0; 32];
    mask[0] = 1;
    mask[31] = 128;
    let (source, source_witness, selection, selected_witness) = super::fixture(mask, Some(2))?;
    if mode == "security" {
        // Public shape only: no encoded-vector witness, trace or proof factory.
        return crate::security(
            &Statement::new(&selection, [Val::ZERO; 4]),
            "selected-encoding-public-shape",
        );
    }
    let witness = Witness::from_selection(&selection, &selected_witness, salt()?)?;
    let statement = witness.statement(&selection);
    crate::security(&statement, "selected-encoding-composite")?;
    let started = std::time::Instant::now();
    let proof = prove_composite(
        &source,
        &source_witness,
        &selection,
        &selected_witness,
        &statement,
        &witness,
    )?;
    let proving = started.elapsed();
    let started = std::time::Instant::now();
    verify_composite(&source, &selection, &statement, &proof)?;
    println!(
        "{{\"stage\":\"verified_experimental_selected_encoding_composite\",\"proving_ms\":{},\"verification_ms\":{}}}",
        proving.as_secs_f64() * 1000.0,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}
