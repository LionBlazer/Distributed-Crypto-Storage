//! Explicit PUBLIC NONSECRET inputs; actual Owner tests live at the core owner boundary.
use super::*;
use bfv_hiding_stark::{Error, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use zeroize::Zeroizing;
fn descriptor() -> SetupDescriptor {
    SetupDescriptor {
        database: [1; 16],
        key_domain: [2; 16],
        public_setup_digest: [3; 32],
        key_epoch: 1,
    }
}
#[test]
fn explicit_witness_support_and_canonical_salts_are_checked_without_disclosing_values() {
    assert!(matches!(
        ProverWitness::new(Zeroizing::new(vec![0; N - 1]), [0; 4], [1; 4]),
        Err(Error::Shape)
    ));
    for value in [-21, 21] {
        assert!(matches!(
            ProverWitness::new(Zeroizing::new(vec![value; N]), [0; 4], [1; 4]),
            Err(Error::Shape)
        ));
    }
    assert!(matches!(
        ProverWitness::new(Zeroizing::new(vec![0; N]), [Val::ORDER_U64; 4], [1; 4]),
        Err(Error::Shape)
    ));
    ProverWitness::new(Zeroizing::new(vec![-20; N]), [0; 4], [1; 4]).unwrap();
    ProverWitness::new(Zeroizing::new(vec![20; N]), [0; 4], [1; 4]).unwrap();
}
#[test]
fn fixed_commitment_binds_the_last_coefficient_scope_and_private_salt() {
    let mut coefficients = vec![0; N];
    let baseline = input_commitment(&descriptor(), &coefficients, [7; 4]).unwrap();
    coefficients[N - 1] = 1;
    assert_ne!(
        baseline,
        input_commitment(&descriptor(), &coefficients, [7; 4]).unwrap()
    );
    coefficients[N - 1] = 0;
    assert_ne!(
        baseline,
        input_commitment(&descriptor(), &coefficients, [8; 4]).unwrap()
    );
    let mut foreign = descriptor();
    foreign.database[15] ^= 1;
    assert_ne!(
        baseline,
        input_commitment(&foreign, &coefficients, [7; 4]).unwrap()
    );
}
#[test]
fn input_commitment_matches_the_real_shared_witness_statement() {
    let coefficients: Vec<_> = (0..N).map(|i| (i % 41) as i8 - 20).collect();
    let expected = input_commitment(&descriptor(), &coefficients, [9; 4]).unwrap();
    let witness = ProverWitness::new(Zeroizing::new(coefficients), [9; 4], [11; 4]).unwrap();
    let statement = witness.statement(descriptor());
    assert_eq!(
        statement
            .expected
            .coefficients
            .map(|v| v.as_canonical_u64()),
        expected
    );
    assert_eq!(statement.public_values().len(), 33);
    assert_eq!(circuit::WIDTH, 9932);
}
#[test]
fn bounded_evidence_rejects_missing_truncated_and_oversized_frames_before_sdk() {
    let expected = Expected {
        descriptor: descriptor(),
        coefficients: [Val::ZERO; 4],
    };
    for bytes in [
        vec![],
        vec![0; HEADER_BYTES - 1],
        vec![0; HEADER_BYTES + MAX_PROOF_BYTES + 1],
    ] {
        assert!(verify([4; 32], &expected, &bytes).is_err());
    }
}

#[test]
fn explicit_wrong_coefficient_and_transform_claims_cannot_be_proved_by_another_opening() {
    let coefficients = Zeroizing::new(vec![0i8; N]);
    let witness = ProverWitness::new(coefficients, [7; 4], [11; 4]).unwrap();
    let honest = witness.statement(descriptor());
    for attack in 0..2 {
        let mut claim = honest.clone();
        if attack == 0 {
            claim.expected.coefficients[3] += Val::ONE;
        } else {
            claim.transformed[3] += Val::ONE;
        }
        // This reaches the actual fixed Key trace/prover, not a local root comparison alone.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_statement([4; 32], &claim.expected, &claim, &witness)
        }));
        assert!(
            !matches!(result, Ok(Ok(_))),
            "wrong explicit claim {attack}"
        );
    }
}
