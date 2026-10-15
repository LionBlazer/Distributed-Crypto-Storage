use bfv_addition_proof::{Error, prove, verify};
use bfv_query_core::{PublicSetup, PublicUpdateEvaluator};
use compact_query::{AgeRange, PlainRow, bfv::Owner};
use sha2::{Digest, Sha256};

#[test]
fn authenticated_compact_selection_binds_the_real_addition_proof_to_its_pending_update() {
    // Public diagnostic records, fresh owner keys only in memory. Sparse matching
    // buckets cross encrypted index pages; selected records occupy many data pages.
    let rows: Vec<_> = (0..6040)
        .map(|ordinal| PlainRow {
            age: match ordinal % 50 {
                0 => 18,
                1 => 42,
                _ => 7,
            },
            amount: ordinal as u16,
        })
        .collect();
    let (owner, evaluator) = Owner::generate([19; 16]).unwrap();
    let table = owner.seal(&rows, 32, Default::default()).unwrap();
    let predicate = AgeRange {
        lower: 18,
        upper: 42,
    };
    let prepared = owner
        .prepare_exact_update_for_experiment(&table, predicate, 5, 256, Default::default())
        .unwrap();
    assert_eq!(prepared.selected_rows(), 242);
    // This is a real owner-built/authenticated encrypted index, not fixture heads.
    assert!(table.encrypted_index().commitment().layout().row_count > 8192);
    assert_ne!(table.commitment().root(), [0; 32]);
    assert_ne!(table.index_commitment().root(), [0; 32]);
    let setup =
        PublicSetup::from_bytes(&evaluator.encode_public_setup_for_experiment().unwrap()).unwrap();
    let bridge =
        PublicUpdateEvaluator::from_parameters(&setup.update_parameters().unwrap()).unwrap();
    let input = bridge.circuit_request(prepared.request()).unwrap();

    // The original opaque PreparedUpdate remains alive across proof generation
    // and serialized verification. No reconstructed SelectedField fixture is used.
    let generated = prove(&input).unwrap();
    let checked = verify(&input, generated.output(), generated.proof()).unwrap();

    assert_eq!(
        checked.input_digest(),
        <[u8; 32]>::from(Sha256::digest(&input))
    );
    assert_eq!(
        checked.output_digest(),
        <[u8; 32]>::from(Sha256::digest(generated.output()))
    );
    assert_eq!(prepared.selected_rows(), 242);

    // A new pending operation has fresh request binding even for the same SQL
    // inputs. A different delta and a genuinely different pair of data/index
    // heads must not reuse the old arithmetic proof either.
    let fresh_pending = owner
        .prepare_exact_update_for_experiment(&table, predicate, 5, 256, Default::default())
        .unwrap();
    let different_query = owner
        .prepare_exact_update_for_experiment(&table, predicate, 9, 256, Default::default())
        .unwrap();
    let mut other_rows = rows;
    other_rows[0].amount = 9000;
    let other_table = owner.seal(&other_rows, 32, Default::default()).unwrap();
    assert_ne!(other_table.commitment(), table.commitment());
    assert_ne!(other_table.index_commitment(), table.index_commitment());
    let different_data_and_heads = owner
        .prepare_exact_update_for_experiment(&other_table, predicate, 5, 256, Default::default())
        .unwrap();
    for other in [&fresh_pending, &different_query, &different_data_and_heads] {
        assert_ne!(other.request(), prepared.request());
        let other_input = bridge.circuit_request(other.request()).unwrap();
        let mut rebound_output = generated.output().to_vec();
        // Rebind BOTH matching canonical headers so rejection comes from the
        // cryptographic proof, not merely the cheap header equality check.
        rebound_output[8..40].copy_from_slice(&other_input[8..40]);

        assert_eq!(
            verify(&other_input, &rebound_output, generated.proof()).unwrap_err(),
            Error::Verification
        );
    }
    // Keep the opaque owner preparation; do not call apply/recompute as a verifier.
    assert_eq!(prepared.selected_rows(), 242);
}
