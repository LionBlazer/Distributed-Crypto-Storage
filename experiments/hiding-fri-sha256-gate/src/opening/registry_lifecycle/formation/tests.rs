//! Genuine accepted local history and independent R200 pins; no SQL or network freshness token.
use super::*;
use crate::primitive::{Kind, PublicStatement};
use std::{cell::Cell, time::Instant};
fn reject_before_factory(expected: &Expected, bytes: &[u8], case: &str) {
    let entered = Cell::new(false);
    let result = prove_with_factory(expected, bytes, || {
        entered.set(true);
        Err(Error::Verification)
    });
    assert!(
        !entered.get(),
        "{case}: encoding must reject before formation factory"
    );
    assert!(result.is_err(), "{case}: invalid encoding was accepted");
}
#[test]
fn accepted_signed_history_actual_owner_formation_rejects_full136_and_genuine_fresh_cenc_swaps() {
    let generation = Instant::now();
    let mut input = super::super::journal::formation_input_with_alternate(1).unwrap();
    let (alternate, alternate_frame) = input.alternate.take().unwrap();
    // BOTH encodings have the SAME genuinely accepted Source/Lifecycle/SQL/W, but fresh salts/Cenc.
    let original = input.statement.clone();
    let decoded =
        encoding::decode_and_verify(alternate.formation_expected(), &alternate_frame).unwrap();
    assert_eq!(decoded.public_values(), alternate.public_values());
    assert_eq!(
        &original.public_values()[..132],
        &alternate.public_values()[..132]
    );
    assert_ne!(
        &original.public_values()[132..],
        &alternate.public_values()[132..]
    );
    let product = fixture::produce_from_encoding(input, generation).unwrap();
    // The producer returns PUBLIC-ONLY material: actual Owner, key handle and jobs were dropped.
    let setup = PublicSetup::from_bytes(&product.setup_bytes).unwrap();
    let p = product.prerequisites();
    let checked = verify(
        &setup,
        &product.anchor,
        &product.expected,
        &product.encoding_frame,
        &p,
        &product.evidence,
    )
    .unwrap();
    assert_eq!(
        checked.statement().expected.encoding(),
        product.expected.mathematical.encoding()
    );
    assert_eq!(checked.statement().public_values().len(), 44);
    assert_eq!(
        crate::backend::profile_digest(Kind::BfvCiphertextFormation),
        bfv_ciphertext_formation::profile_digest()
    );
    // Original independently pinned Cenc must reject the genuinely valid alternate frame.
    reject_before_factory(&product.expected, &alternate_frame, "fresh Cenc");
    let foreign = Expected::new(alternate, product.expected.mathematical.bases().clone()).unwrap();
    assert!(
        verify(
            &setup,
            &product.anchor,
            &foreign,
            &alternate_frame,
            &p,
            &product.evidence
        )
        .is_err()
    );
    let attacks = original.formation_context_attack_cases();
    // A cached projection change leaves the original Encoding statement unchanged.
    assert_eq!(original.public_values(), attacks[4].public_values());
    let original_commitment = original.formation_commitment().unwrap();
    let changed_commitment = attacks[4].formation_commitment().unwrap();
    assert_eq!(original_commitment.context(), changed_commitment.context());
    assert_eq!(original_commitment.root(), changed_commitment.root());
    assert_ne!(
        original_commitment.producer_identity(),
        changed_commitment.producer_identity()
    );
    for (case, claim) in attacks.into_iter().enumerate() {
        let mut bad = product.expected.clone();
        bad.encoding = claim;
        reject_before_factory(
            &bad,
            &product.encoding_frame,
            &format!("retained context {case}"),
        );
    }
    // Neither a legacy magic nor missing evidence can substitute for the complete R200 triple.
    reject_before_factory(&product.expected, &[], "missing frame");
    let mut legacy = product.encoding_frame.clone();
    legacy[..8].copy_from_slice(b"DCSLKPW1");
    reject_before_factory(&product.expected, &legacy, "legacy magic");
    for i in 0..5 {
        let mut parts = p.bases;
        parts[i] = &[];
        assert!(
            verify(
                &setup,
                &product.anchor,
                &product.expected,
                &product.encoding_frame,
                &Prerequisites {
                    key: p.key,
                    bases: parts
                },
                &product.evidence
            )
            .is_err()
        );
    }
    let mut duplicate = p.bases;
    duplicate[4] = duplicate[0];
    assert!(
        verify(
            &setup,
            &product.anchor,
            &product.expected,
            &product.encoding_frame,
            &Prerequisites {
                key: p.key,
                bases: duplicate
            },
            &product.evidence
        )
        .is_err()
    );
    let mut foreign_q = product.expected.mathematical.bases().clone();
    for (i, claim) in foreign_q.iter_mut().enumerate() {
        let e = &claim.expected;
        let mut q = e.request();
        q[31] ^= 1;
        claim.expected = bfv_basis_convolution::Expected::new(
            e.key().clone(),
            e.ciphertext().parameter_bytes(),
            e.ciphertext().bytes(),
            q,
            i,
        )
        .unwrap();
    }
    // q is Lifecycle intent; substituting another identity cannot pass actual Basis evidence.
    let foreign_math = bfv_ciphertext_formation::Expected::new(
        product.expected.mathematical.encoding().clone(),
        foreign_q,
    )
    .unwrap();
    assert!(
        setup
            .verify_ciphertext_formation(&product.anchor, &foreign_math, &p, &product.evidence)
            .is_err()
    );
}
#[test]
fn accepted_limit_zero_counter_transition_forms_zero_scaled_plaintext_without_grant() {
    let generation = Instant::now();
    let input = super::super::journal::formation_input(0).unwrap();
    assert!(input.coefficients.iter().all(|w| *w == 0));
    let product = fixture::produce_from_encoding(input, generation).unwrap();
    let setup = PublicSetup::from_bytes(&product.setup_bytes).unwrap();
    verify(
        &setup,
        &product.anchor,
        &product.expected,
        &product.encoding_frame,
        &product.prerequisites(),
        &product.evidence,
    )
    .unwrap();
}

#[test]
fn genuine_all_skipped_acquire_forms_zero_words_under_its_explicit_private_old_root() {
    // Conditional old-root proof case, separate from the accepted-history case above.
    let generation = Instant::now();
    let input = encoding::all_skipped_formation_input().unwrap();
    assert!(input.coefficients.iter().all(|w| *w == 0));
    let product = fixture::produce_from_encoding(input, generation).unwrap();
    let setup = PublicSetup::from_bytes(&product.setup_bytes).unwrap();
    verify(
        &setup,
        &product.anchor,
        &product.expected,
        &product.encoding_frame,
        &product.prerequisites(),
        &product.evidence,
    )
    .unwrap();
}
