//! PUBLIC NONSECRET input16 -> exact full BFV product, independently reverified.
use super::{Instant, PublicFiles, PublicSetup, Statement};
use bfv_mul_relin_proof::{
    Error, Expected, GraphClaims, InputEvidence, MAX_ATTEMPTS, MAX_PROOF_BYTES, MAX_SESSION_BYTES,
    PROOF_RECORDS, Provenance, Prover, RECORD_HEADER, Verifier,
};
use bfv_relinearization_key_source::PreparedKey;

fn verify_inputs(verifier: &mut Verifier<'_>, files: &PublicFiles) {
    // Only the original public frames survive Owner drop. No receipt bypass.
    let key = files.read("key");
    let encodings: [Vec<u8>; 2] =
        core::array::from_fn(|i| files.read(&format!("{i}-encoding-pair")));
    let bases: [[Vec<u8>; 5]; 2] =
        core::array::from_fn(|i| core::array::from_fn(|b| files.read(&format!("{i}-basis-{b}"))));
    let formations: [Vec<u8>; 2] = core::array::from_fn(|i| files.read(&format!("{i}-formation")));
    verifier
        .verify_inputs(&InputEvidence {
            key: &key,
            encodings: encodings.each_ref().map(Vec::as_slice),
            bases: bases.each_ref().map(|r| r.each_ref().map(Vec::as_slice)),
            formations: formations.each_ref().map(Vec::as_slice),
        })
        .unwrap();
    // All decoded proof data and all input frame buffers are dropped here.
}

fn reject_unproved_endpoints_and_exhausted_sessions(
    expected: &Expected,
    key: &PreparedKey,
    claims: &[u8],
) {
    let mut incomplete = Verifier::new(expected, key);
    assert!(incomplete.accept_claims(&[0]).is_err());
    assert_eq!(incomplete.attempted_bytes(), 1);
    incomplete.accept_claims(claims).unwrap();
    assert_eq!(incomplete.accept(&[0]), Err(Error::Incomplete));
    assert!(matches!(incomplete.finish(), Err(Error::Incomplete)));

    let mut changed_last = claims.to_vec();
    let end = changed_last.len();
    let value = u64::from_le_bytes(changed_last[end - 8..].try_into().unwrap());
    let modulus = bfv_fixed_geometry::MODULI[4];
    changed_last[end - 8..].copy_from_slice(&((value + 1) % modulus).to_le_bytes());
    // This is still a completely canonical 134-node claim stream.
    GraphClaims::decode(bfv_mul_relin_proof::profile_digest(), &changed_last).unwrap();
    assert!(
        Verifier::new(expected, key)
            .accept_claims(&changed_last)
            .is_err()
    );
    let mut changed_binding = claims.to_vec();
    // First NTT Output's binding, outside the raw coefficient identity.
    changed_binding[96 + 20 * 8192 * 8 + 8 + 40] ^= 1;
    GraphClaims::decode(bfv_mul_relin_proof::profile_digest(), &changed_binding).unwrap();
    assert!(
        Verifier::new(expected, key)
            .accept_claims(&changed_binding)
            .is_err()
    );

    let mut exhausted = Verifier::new(expected, key);
    for _ in 0..MAX_ATTEMPTS {
        assert!(exhausted.accept_claims(&[0]).is_err());
    }
    assert_eq!(exhausted.attempted_bytes(), MAX_ATTEMPTS);
    assert_eq!(exhausted.accept_claims(claims), Err(Error::ResourceLimit));
    assert!(matches!(exhausted.finish(), Err(Error::ResourceLimit)));

    let mut exhausted = Verifier::new(expected, key);
    let oversized_session = vec![0; RECORD_HEADER + MAX_PROOF_BYTES];
    let attempts = MAX_SESSION_BYTES / oversized_session.len() + 1;
    assert!(attempts < MAX_ATTEMPTS);
    for _ in 1..attempts {
        assert_eq!(exhausted.accept(&oversized_session), Err(Error::Incomplete));
    }
    assert_eq!(
        exhausted.accept(&oversized_session),
        Err(Error::ResourceLimit)
    );
    assert!(exhausted.attempted_bytes() > MAX_SESSION_BYTES);
    assert_eq!(exhausted.accept_claims(claims), Err(Error::ResourceLimit));
    assert!(matches!(exhausted.finish(), Err(Error::ResourceLimit)));

    let mut cancelled = Verifier::new(expected, key);
    cancelled.accept_claims(claims).unwrap();
    cancelled.cancel();
    assert_eq!(cancelled.accept_claims(claims), Err(Error::Cancelled));
    assert_eq!(cancelled.accept(&[0]), Err(Error::Cancelled));
    assert!(matches!(cancelled.finish(), Err(Error::Cancelled)));
}

fn reject_genuine_foreign_ntt(
    verifier: &mut Verifier<'_>,
    claims: &GraphClaims,
    honest_record: &[u8],
) {
    use bfv_ntt_circuit::{Basis, Direction, decode_request, encode_request};
    let bfv_mul_relin_proof::NodeOutput::Ntt(honest) = claims.node(0).unwrap() else {
        panic!("node0 must be the original c0 inverse");
    };
    let mut input = claims.native_component(0).unwrap()[..8192].to_vec();
    let honest_request = decode_request(
        &encode_request(
            Direction::Inverse,
            Basis::new(0).unwrap(),
            honest.binding(),
            &input,
        )
        .unwrap(),
    )
    .unwrap();
    input[8191] = (input[8191] + 1) % bfv_fixed_geometry::MODULI[0];
    let request = decode_request(
        &encode_request(
            Direction::Inverse,
            Basis::new(0).unwrap(),
            honest.binding(),
            &input,
        )
        .unwrap(),
    )
    .unwrap();
    let foreign = bfv_ntt_witness_proof::prove(&request).unwrap();
    let checked = bfv_ntt_witness_proof::verify(&request, &foreign.output, &foreign.proof).unwrap();
    assert!(checked.matches(&request, &foreign.output));
    assert!(checked.security_report().whole_security_bits >= 144.);
    // Repair both graph and inner NTT headers to honest statements, retaining
    // the actual foreign SDK proof payload. The child must reach SDK rejection.
    const NTT_HEADER: usize = 256;
    let mut repaired = honest_record[RECORD_HEADER..RECORD_HEADER + NTT_HEADER].to_vec();
    repaired[240..248].copy_from_slice(&((foreign.proof.len() - NTT_HEADER) as u64).to_le_bytes());
    repaired.extend(&foreign.proof[NTT_HEADER..]);
    assert!(matches!(
        bfv_ntt_witness_proof::verify(&honest_request, honest, &repaired),
        Err(bfv_ntt_witness_proof::Error::Verification),
    ));
    let mut substituted = honest_record[..RECORD_HEADER].to_vec();
    substituted[140..144].copy_from_slice(&(repaired.len() as u32).to_le_bytes());
    substituted.extend(&repaired);
    let progress = verifier.progress();
    assert_eq!(verifier.accept(&substituted), Err(Error::Proof));
    assert_eq!(verifier.progress(), progress);
}

pub(super) fn verify(
    setup: PublicSetup,
    anchor: bfv_query_core::BfvKeyAnchor,
    statements: Vec<Statement>,
    ciphertexts: [Vec<u8>; 2],
    output: Vec<u8>,
    files: &PublicFiles,
) {
    let started = Instant::now();
    let statements: [Statement; 2] = statements.try_into().ok().unwrap();
    let setup_bytes = setup.to_bytes().unwrap();
    let provenance = Provenance::new(
        setup,
        anchor.clone(),
        statements.clone(),
        ciphertexts.clone(),
    )
    .unwrap();
    let expected = Expected::new(provenance, output.clone()).unwrap();
    let key =
        PreparedKey::from_original(expected.provenance().setup(), anchor.full_setup_id()).unwrap();
    let mut prover = Prover::new(&expected, &key).unwrap();
    let claims = prover
        .graph()
        .claims()
        .encode(bfv_mul_relin_proof::profile_digest());
    let identity = prover.graph().identity();
    files.write("product-claims", &claims);
    let prepare_ms = started.elapsed().as_secs_f64() * 1000.;
    reject_unproved_endpoints_and_exhausted_sessions(&expected, &key, &claims);
    // Change the actual last PB q4/c1 ciphertext coefficient, preserving valid
    // packed protobuf syntax and every other coefficient/metadata field.
    let mut changed_output = output.clone();
    let parsed = bfv_ciphertext_wire::parse(&changed_output).unwrap();
    let bfv_ciphertext_wire::SecondComponent::Stored(c1) = parsed.second() else {
        panic!("actual product is unseeded");
    };
    let last = c1.row(4).unwrap().last().unwrap();
    let replacement = if last == 0 { 1 } else { last - 1 };
    let width = (u64::BITS - (bfv_fixed_geometry::MODULI[4] - 1).leading_zeros()) as usize;
    let first_bit = (changed_output.len() - 2) * 8 - width;
    for bit in 0..width {
        let position = first_bit + bit;
        let mask = 1 << (position % 8);
        changed_output[position / 8] =
            (changed_output[position / 8] & !mask) | (((replacement >> bit) & 1) as u8 * mask);
    }
    let parsed = bfv_ciphertext_wire::parse(&changed_output).unwrap();
    let bfv_ciphertext_wire::SecondComponent::Stored(c1) = parsed.second() else {
        unreachable!()
    };
    assert_eq!(c1.row(4).unwrap().last(), Some(replacement));
    let changed_expected = Expected::new(
        Provenance::new(
            PublicSetup::from_bytes(&setup_bytes).unwrap(),
            anchor.clone(),
            statements.clone(),
            ciphertexts.clone(),
        )
        .unwrap(),
        changed_output,
    )
    .unwrap();
    assert!(
        Verifier::new(&changed_expected, &key)
            .accept_claims(&claims)
            .is_err()
    );
    drop(changed_expected);

    let mut verifier = Verifier::new(&expected, &key);
    verifier.accept_claims(&claims).unwrap();
    let verify_started = Instant::now();
    verify_inputs(&mut verifier, files);
    let input_verify_ms = verify_started.elapsed().as_secs_f64() * 1000.;
    let generation = Instant::now();
    let mut sizes = Vec::new();
    let mut verify_ms = 0.;
    loop {
        let prove_started = Instant::now();
        let Some(component) = prover.prove_next().unwrap() else {
            break;
        };
        let prove_ms = prove_started.elapsed().as_secs_f64() * 1000.;
        let ordinal = sizes.len();
        files.write(&format!("product-{ordinal}"), &component);
        let mut wrong = component.clone();
        wrong[138] ^= 1;
        let progress = verifier.progress();
        assert!(verifier.accept(&wrong).is_err());
        assert_eq!(verifier.progress(), progress);
        if ordinal == 1 {
            reject_genuine_foreign_ntt(&mut verifier, prover.graph().claims(), &component);
        }
        let now = Instant::now();
        verifier.accept(&component).unwrap();
        let component_verify_ms = now.elapsed().as_secs_f64() * 1000.;
        verify_ms += component_verify_ms;
        sizes.push(component.len());
        println!(
            "{}",
            serde_json::json!({
                "stage":"full_product_component", "ordinal":ordinal,
                "bytes":component.len(), "verified":true,
                "prove_ms":prove_ms, "verify_ms":component_verify_ms,
            })
        );
    }
    assert_eq!(sizes.len(), PROOF_RECORDS);
    drop(prover);
    assert_eq!(verifier.progress(), PROOF_RECORDS);
    // 2 initial calls +118 honest +118 wrong-node +1 genuine foreign =239.
    // Attempt240 cannot add a119th record. Exceeding the lifetime cap must
    // invalidate finish even though every mathematical proof already passed.
    assert_eq!(verifier.accept(&[0]), Err(Error::Stage));
    assert_eq!(verifier.accept(&[0]), Err(Error::ResourceLimit));
    assert!(matches!(verifier.finish(), Err(Error::ResourceLimit)));
    let generation_ms = generation.elapsed().as_secs_f64() * 1000.;
    drop(claims);
    drop(key);
    drop(expected);

    // Rebuild setup, key, all requests and the actual verifier AFTER prover and
    // every prior decoded statement/result/claims buffer have been dropped.
    let fresh_started = Instant::now();
    let fresh = PublicSetup::from_bytes(&setup_bytes).unwrap();
    drop(setup_bytes);
    let provenance = Provenance::new(fresh, anchor, statements, ciphertexts).unwrap();
    let expected = Expected::new(provenance, output.clone()).unwrap();
    let key = PreparedKey::from_original(
        expected.provenance().setup(),
        expected.provenance().anchor().full_setup_id(),
    )
    .unwrap();
    let mut verifier = Verifier::new(&expected, &key);
    let claims = files.read("product-claims");
    let claims_bytes = claims.len();
    verifier.accept_claims(&claims).unwrap();
    drop(claims);
    verify_inputs(&mut verifier, files);
    for ordinal in 0..PROOF_RECORDS {
        let frame = files.read(&format!("product-{ordinal}"));
        verifier.accept(&frame).unwrap();
    }
    let checked = verifier.finish().unwrap();
    assert_eq!(checked.identity(), identity);
    assert_eq!(checked.output_ciphertext(), output);
    assert!(checked.output_sdk_security_bits() >= 144.);
    println!(
        "{}",
        serde_json::json!({
            "stage":"verified_input16_exact_full_product", "nodes":134,
            "output_proof_records":sizes.len(), "output_sdk_proofs":120, "input_unique_proofs":16,
            "claims_bytes":claims_bytes, "proof_bytes":sizes.iter().sum::<usize>(),
            "prepare_ms":prepare_ms, "input_verify_ms":input_verify_ms,
            "prove_and_verify_ms":generation_ms, "output_verify_ms":verify_ms,
            "fresh_after_prover_drop_ms":fresh_started.elapsed().as_secs_f64()*1000.,
            "output_sdk_bits":checked.output_sdk_security_bits(),
            "sql_grant":false, "fresh_agreed_head":false, "whole128_claim":false,
        })
    );
}
