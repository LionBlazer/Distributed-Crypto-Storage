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

#[test]
fn owned_evidence_requires_genuine_verification_and_preserves_exact_original_bytes() {
    let witness = ProverWitness::new(
        Zeroizing::new((0..N).map(|i| (i % 41) as i8 - 20).collect()),
        [7; 4],
        [11; 4],
    )
    .unwrap();
    let statement = witness.statement(descriptor());
    let setup = [107; 32];
    let frame = prove_statement(setup, &statement.expected, &statement, &witness)
        .unwrap()
        .into_bytes();
    let owned = Evidence::verify_owned(setup, &statement.expected, frame.clone()).unwrap();
    assert_eq!(owned.as_bytes(), frame);
    assert_eq!(
        verify(setup, &statement.expected, owned.as_bytes())
            .unwrap()
            .statement()
            .public_values(),
        statement.public_values()
    );
    let mut foreign = statement.expected.clone();
    foreign.descriptor.key_epoch += 1;
    assert!(Evidence::verify_owned(setup, &foreign, frame.clone()).is_err());
    assert!(Evidence::verify_owned([108; 32], &statement.expected, frame.clone()).is_err());
    for cut in [0, HEADER_BYTES - 1, frame.len() - 1] {
        assert!(Evidence::verify_owned(setup, &statement.expected, frame[..cut].to_vec()).is_err());
    }
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(Evidence::verify_owned(setup, &statement.expected, trailing).is_err());
    // Preserve the canonical proof shape but damage a real trace commitment.
    let air = statement.air();
    let (_, report) = bfv_hiding_stark::analyze(&air).unwrap();
    let shape =
        bfv_hiding_stark::codec::Topology::checked(circuit::WIDTH, report.quotient_chunks).unwrap();
    let mut proof: p3_uni_stark::Proof<bfv_hiding_stark::Config> = bfv_hiding_stark::codec::decode(
        &frame[HEADER_BYTES..],
        &shape,
        MAX_SEQUENCE_ELEMENTS,
        MAX_TOTAL_ELEMENTS,
    )
    .unwrap();
    let mut roots = proof.commitments.trace.roots().to_vec();
    roots[0][0] += Val::ONE;
    proof.commitments.trace = p3_symmetric::MerkleCap::new(roots);
    let body = bfv_hiding_stark::codec::serialize(&proof, &shape, MAX_PROOF_BYTES).unwrap();
    let mut damaged = frame[..HEADER_BYTES].to_vec();
    damaged[204..208].copy_from_slice(&(body.len() as u32).to_le_bytes());
    damaged.extend_from_slice(&body);
    assert!(matches!(
        Evidence::verify_owned(setup, &statement.expected, damaged),
        Err(Error::Verification)
    ));
}
