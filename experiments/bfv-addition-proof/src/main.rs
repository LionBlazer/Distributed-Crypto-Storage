use bfv_addition_proof::{prove, verify};
use bfv_query_core::{
    Geometry, HEAD_BYTES, Owner, PublicUpdateEvaluator, QueryContext, SelectedField,
    UnverifiedUpdateOutcome,
};
use std::{error::Error, time::Instant};

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::args().len() != 1 {
        return Err(
            "Usage: bfv-addition-proof (all data is an explicitly public in-memory fixture)".into(),
        );
    }
    // Explicitly public diagnostic data. Fresh secret keys never leave this process.
    // These opaque heads are fixture bytes, not certificates of agreement/freshness.
    let fields = [
        SelectedField {
            age: 18,
            amount: 20,
            active: true,
        },
        SelectedField {
            age: 42,
            amount: 30,
            active: true,
        },
    ];
    let total = Instant::now();
    let (owner, setup) = Owner::generate(Geometry::Rows256)?;
    let pending = owner.prepare_indexed_update_for_experiment(
        QueryContext::new([7; 16], [2; HEAD_BYTES], [3; HEAD_BYTES]),
        &fields,
        5,
    )?;
    let evaluator = PublicUpdateEvaluator::from_parameters(&setup.update_parameters()?)?;
    let input = evaluator.circuit_request(&pending.request)?;

    let generated = prove(&input)?;
    // Deliberately cross the serialized proof boundary, even in this local CLI.
    let checked = verify(&input, generated.output(), generated.proof())?;
    let response = evaluator.restore_circuit_output(&pending.request, generated.output())?;
    let UnverifiedUpdateOutcome::Values(values) =
        owner.decrypt_indexed_update_unverified_for_experiment(pending.pending, &response)?
    else {
        return Err("public fixture unexpectedly overflowed".into());
    };
    let amounts: Vec<_> = values.rows.iter().map(|row| row.amount).collect();
    if amounts != [25, 35] {
        return Err(
            "verified FHE arithmetic did not decrypt to the public fixture expectation".into(),
        );
    }

    let prover = generated.timings();
    let verifier = checked.timings();
    println!("Full BFV addition: N8192, Q218, 81,920 residues; Plonky3 0.8.0");
    println!("FRI blowup 8, 192 queries, Goldilocks degree-5 extension, model floor 128 bits");
    println!(
        "Input {} B; encrypted output {} B; serialized proof {} B",
        input.len(),
        generated.output().len(),
        generated.proof().len()
    );
    println!("Prover encrypted addition: {:?}", prover.encrypted_addition);
    println!(
        "Prover public preprocessing: {:?}",
        prover.public_preprocessing
    );
    println!(
        "Proving and serialization: {:?}; complete prover: {:?}",
        prover.proving_and_encoding, prover.total
    );
    println!(
        "Verifier independent public preprocessing: {:?}",
        verifier.public_preprocessing
    );
    println!(
        "Verifier proof verification: {:?}",
        verifier.proof_verification
    );
    println!(
        "Verifier preprocessing + verification: {:?}; full verification including decoding: {:?}",
        verifier.public_preprocessing + verifier.proof_verification,
        verifier.total
    );
    println!(
        "Owner fixture round trip including fresh keys: {:?}; decrypted amounts: {amounts:?}",
        total.elapsed()
    );
    println!(
        "Arithmetic proof only. SQL selection completeness, fresh agreed heads and network mutation acceptance remain unimplemented."
    );
    Ok(())
}
