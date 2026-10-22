//! Bounded PUBLIC example. Actual encrypted arithmetic precedes owner-only assertions.
use super::query as formation;
use super::*;
use crate::registry_progress::{word, word_inventory::probe};
use crate::{
    Val,
    registry_progress::word_inventory::owner_cases::{self, Kind},
    source,
    two_lane_encoding::{self as encoding, circuit::Witness, statement::KeyBinding},
};
use bfv_hiding_stark::{Challenge, Config, codec};
use bfv_query_core::gold as protected;
use fhe_math::zq::Modulus;
use p3_batch_stark::BatchProof;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use std::time::Instant;
use zeroize::Zeroizing;

fn word_expected(case: &owner_cases::Case) -> word::Expected {
    let m = &case.metadata;
    word::Expected::checked(
        &m.source,
        if m.predicate {
            word::Role::Predicate
        } else {
            word::Role::Control
        },
        [0xa7; 32],
        m.parent
            .into_iter()
            .flat_map(|v| u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        m.enrollment,
        word::Claims {
            old: m.old,
            command: m.command,
            statement: m.statement,
            next: m.next,
            result: m.result,
            blind_sql: m.blind_sql,
        },
    )
    .unwrap()
}
// Public metadata pins for this bounded example; no compiler/rights/freshness claim.
fn input_binding(case: &owner_cases::Case, data: &installed::Expected) -> protected::InputBinding {
    let words = |fields: [Val; 8]| -> [u8; 32] {
        fields
            .into_iter()
            .flat_map(|v| u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    };
    let m = &case.metadata;
    let input = &case.input;
    let actor = input.command.actor.unwrap();
    let principal = input.command.principal;
    protected::InputBinding::checked(protected::InputScope {
        database: m.source.statement().heads[0][8..24].try_into().unwrap(),
        transaction: input.command.id,
        call: input.walk.call,
        principal: principal.try_into().unwrap(),
        application: word::profile_digest(),
        genesis: [0xa7; 32],
        rules: word::wire_profile_digest(),
        context: Sha256::digest(word_expected(case).binding()).into(),
        parent: words(m.parent),
        client: words(input.walk.client),
        controller: words(input.controllers[principal - 1]),
        source_version: m.source.version_id(),
        data_admission: Sha256::digest(data.core_expected().binding()).into(),
        snapshot: words(case.old.slots[actor].as_ref().unwrap().snapshot),
        statement: source::statement::encode_digest(m.statement),
        command: source::statement::encode_digest(m.command),
        attempt: words(input.walk.invocation),
        nonce: Sha256::digest(
            [
                word_expected(case).binding().as_slice(),
                &input.walk.call.to_le_bytes(),
            ]
            .concat(),
        )
        .into(),
    })
    .unwrap()
}
fn produce_word(case: &mut owner_cases::Case) -> Vec<u8> {
    let expected = word_expected(case);
    word::prove(&expected, word_inputs(case))
        .unwrap()
        .into_bytes()
}
fn word_inputs(case: &mut owner_cases::Case) -> word::PrivateInputs {
    let expected = word_expected(case);
    assert_eq!(expected.binding(), probe::binding(&case.metadata));
    let input = &mut case.input;
    let source = word::SourceOpening::checked(
        Zeroizing::new(
            input
                .source
                .iter()
                .flat_map(|v| u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes())
                .collect(),
        ),
        Zeroizing::new(input.source_salt.map(|v| v.as_canonical_u64())),
    )
    .unwrap();
    word::PrivateInputs::new(
        source,
        word::RegistryOpening::new(input.controllers, input.banks),
        core::mem::take(&mut input.command),
        core::mem::take(&mut input.walk),
        Zeroizing::new(input.mask),
        input.salts,
    )
}
struct Frames {
    state: Vec<u8>,
    child: Vec<u8>,
    data: Vec<u8>,
    word: Vec<u8>,
    query: Vec<u8>,
    product: Vec<u8>,
}
impl Frames {
    fn borrowed(&self) -> Evidence<'_> {
        Evidence {
            state: &self.state,
            child: &self.child,
            data: &self.data,
            word: &self.word,
            query: &self.query,
            product: &self.product,
        }
    }
}
fn damage_batch(bytes: &[u8]) -> Vec<u8> {
    let mut proof: BatchProof<Config> = postcard::from_bytes(&bytes[128..]).unwrap();
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    let payload = postcard::to_allocvec(&proof).unwrap();
    let mut out = bytes[..128].to_vec();
    out[104..108].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend(payload);
    out
}
type NativeOpening =
    <bfv_hiding_stark::Pcs as p3_commit::Pcs<Challenge, bfv_hiding_stark::Challenger>>::Proof;

fn assert_native_manifest(
    manifest: &bfv_hiding_stark::transcript::ArgumentManifest,
    base: &p3_uni_stark::OpenedValues<Challenge>,
    aux: Option<(&[Challenge], &[Challenge])>,
    opening: &NativeOpening,
) {
    let mut main = vec![base.trace_local.len()];
    if let Some(next) = &base.trace_next {
        main.push(next.len());
    }
    let mut groups = vec![
        vec![vec![base.random.as_ref().unwrap().len()]],
        vec![main],
        base.quotient_chunks.iter().map(|v| vec![v.len()]).collect(),
    ];
    if let Some(pp) = &base.preprocessed {
        let mut points = vec![pp.local.len()];
        if let Some(next) = &pp.next {
            points.push(next.len());
        }
        groups.push(vec![points]);
    }
    if let Some((local, next)) = aux {
        groups.push(vec![vec![local.len(), next.len()]]);
    }
    assert_eq!(groups.len(), opening.0.len());
    for (group, masks) in groups.iter_mut().zip(&opening.0) {
        assert_eq!(group.len(), masks.len());
        for (points, masks) in group.iter_mut().zip(masks) {
            assert_eq!(points.len(), masks.len());
            for (width, mask) in points.iter_mut().zip(masks) {
                *width += mask.len();
            }
        }
    }
    assert_eq!(groups, manifest.pcs_shape().claimed_evaluation_counts);
    assert_eq!(opening.1.input_openings.len(), manifest.commitments().len());
    for (proof, group) in opening.1.input_openings.iter().zip(manifest.commitments()) {
        for rows in &proof.opened_values {
            assert_eq!(rows.len(), group.matrices().len());
            for (row, matrix) in rows.iter().zip(group.matrices()) {
                assert_eq!(row.len(), matrix.width());
            }
        }
        for salts in &proof.opening_proof.0 {
            assert_eq!(salts.len(), group.matrices().len());
            assert!(salts.iter().all(|salt| salt.len() == 4));
        }
    }
    assert_eq!(
        opening.1.commit_phase_commits.len(),
        manifest.fri_shape().log_arities.len()
    );
    assert_eq!(
        opening.1.final_poly.len(),
        manifest.fri_shape().final_poly_len
    );
    assert_eq!(
        opening.1.commit_phase_openings.len(),
        manifest.fri_shape().log_arities.len()
    );
    for step in &opening.1.commit_phase_openings {
        assert_eq!(step.sibling_values.len(), manifest.fri_shape().num_queries);
        assert!(step.sibling_values.iter().all(|values| values.len() == 1));
        assert_eq!(step.opening_proof.0.len(), manifest.fri_shape().num_queries);
        for salts in &step.opening_proof.0 {
            assert_eq!(salts.len(), 1);
            assert_eq!(salts[0].len(), 4);
        }
    }
}
fn check_complete_native_manifests(expected: &Expected, frames: &Frames) {
    let manifests = super::transcript::inspect(expected).unwrap();
    let state_backend = crate::fixed::Backend::source_version(expected.word.source()).unwrap();
    let state: p3_uni_stark::Proof<Config> = codec::decode(
        &frames.state,
        &state_backend.shape,
        crate::wire::MAX_SEQUENCE_ELEMENTS,
        crate::wire::SOURCE_SLOTS,
    )
    .unwrap();
    assert_native_manifest(
        &manifests[0],
        &state.opened_values,
        None,
        &state.opening_proof,
    );
    drop(state);
    drop(state_backend);
    let child_backend = crate::fixed::Backend::two_lane_encoding(expected.data.source()).unwrap();
    let child: p3_uni_stark::Proof<Config> = codec::decode(
        &frames.child[wire::HEADER..],
        &child_backend.shape,
        wire::SEQUENCE,
        wire::CHILD_SLOTS,
    )
    .unwrap();
    assert_native_manifest(
        &manifests[1],
        &child.opened_values,
        None,
        &child.opening_proof,
    );
    drop(child);
    drop(child_backend);
    for (manifest, bytes) in manifests[2..]
        .iter()
        .zip([&frames.data, &frames.word, &frames.query])
    {
        let proof: BatchProof<Config> = postcard::from_bytes(&bytes[128..]).unwrap();
        let instance = &proof.opened_values.instances[0];
        assert_native_manifest(
            manifest,
            &instance.base_opened_values,
            Some((&instance.permutation_local, &instance.permutation_next)),
            &proof.opening_proof,
        );
    }
    eprintln!(
        "native_complete_five_transcript_manifests source_role3_data_word_query=true native_shapes_and_mask_openings_match=true sql=false"
    );
}
fn ring_oracle(source: &[u64], mask: &[u64]) -> Zeroizing<Vec<u64>> {
    let mut oracle = Zeroizing::new(vec![0; gold::N]);
    for (i, &x) in source.iter().enumerate().filter(|(_, v)| **v != 0) {
        for (j, &y) in mask.iter().enumerate().filter(|(_, v)| **v != 0) {
            let at = (i + j) % gold::N;
            let term = x * y % gold::T;
            oracle[at] = (oracle[at]
                + if i + j < gold::N {
                    term
                } else {
                    gold::T - term
                })
                % gold::T;
        }
    }
    oracle
}
/// A different genuine query against the SAME retained immutable DATA/key.
/// It creates fresh Word/Query proofs and public product; no cached answer is used.
fn different_retained_query(
    owner: &protected::Owner,
    data: &installed::Expected,
    retained: &installed::VerifiedDataFormation,
    data_words: &[u64],
    previous: QueryEvidence<'_>,
) {
    let began = Instant::now();
    let mut case = owner_cases::case(Kind::SkipBeforeOffset);
    case.input.mask[31] &= 0x7f; // Age255 is excluded; earlier locked/offset rows are unchanged.
    case.input.walk.call += 1;
    case.input.walk.invocation[0] += Val::ONE;
    case.metadata.blind_sql[0] += Val::ONE;
    case.input.walk.sql = case.metadata.blind_sql;
    case.rebuild();
    let statement: [Val; 96] = owner_cases::statement(&case.metadata, &case.input, &case.old)
        .try_into()
        .unwrap();
    let mut mask = Zeroizing::new(vec![0u64; gold::N]);
    for age in 0..256 {
        mask[255 - age] = u64::from((case.input.mask[age / 8] >> (age % 8)) & 1);
    }
    let original = owner
        .originate(
            protected::Mask256::new(case.input.mask),
            input_binding(&case, data),
            data.core_expected(),
        )
        .unwrap();
    let request = original.public_request().formation_request().unwrap();
    let context =
        formation::encoding_context(&request, data.core_expected(), case.metadata.statement)
            .unwrap();
    let salt = [10; 4];
    let vector = owner
        .query_commitment(&original, context.map(|v| v.as_canonical_u64()), &salt)
        .unwrap()
        .map(Val::from_u64);
    let formation = formation::expected(
        &request,
        data.core_expected(),
        case.metadata.statement,
        vector,
    )
    .unwrap();
    let prepared_ms = began.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let response = protected::Evaluator::new()
        .unwrap()
        .evaluate(original.public_request())
        .unwrap();
    let expected = Expected::checked(
        &word_expected(&case),
        data,
        &request,
        vector,
        response.output().to_vec(),
    )
    .unwrap();
    let product = response.certificate().to_vec();
    let product_ms = started.elapsed().as_secs_f64() * 1000.;
    // Public receiving starts before proof production on a separate thread.
    // This is a local component pipeline, not peer I/O or a complete SQL query.
    let ((checked, receiving_setup_ms, receive_ms, word, query), word_ms, query_ms) =
        std::thread::scope(|scope| {
            let (send, receive) = std::sync::mpsc::sync_channel::<(Vec<u8>, Vec<u8>)>(1);
            let expected = &expected;
            let product = &product;
            let receiving = scope.spawn(move || {
                let started = Instant::now();
                let receiver = Verifier::new(expected).unwrap();
                let setup_ms = started.elapsed().as_secs_f64() * 1000.;
                let (word, query) = receive.recv().unwrap();
                let started = Instant::now();
                let checked = receiver
                    .verify_retained(
                        retained,
                        QueryEvidence {
                            word: &word,
                            query: &query,
                            product,
                        },
                    )
                    .unwrap();
                let receive_ms = started.elapsed().as_secs_f64() * 1000.;
                (checked, setup_ms, receive_ms, word, query)
            });
            // Only public endpoints and proof bytes reach the receiving thread.
            // The opaque Owner and all private Word/Query inputs remain here.
            let started = Instant::now();
            let word = produce_word(&mut case);
            let word_ms = started.elapsed().as_secs_f64() * 1000.;
            let started = Instant::now();
            let query = fused::prove(
                &formation,
                owner
                    .prepare_query(
                        &original,
                        &formation,
                        Zeroizing::new(statement.map(|v| v.as_canonical_u64())),
                        Zeroizing::new(salt),
                    )
                    .unwrap(),
            )
            .unwrap()
            .into_bytes();
            let query_ms = started.elapsed().as_secs_f64() * 1000.;
            send.send((word, query)).unwrap();
            (receiving.join().unwrap(), word_ms, query_ms)
        });
    let evidence = || QueryEvidence {
        word: &word,
        query: &query,
        product: &product,
    };
    let started = Instant::now();
    let completed = owner
        .complete_checked_product(&original, checked.product())
        .unwrap();
    let actual = completed.coefficients();
    let client_ms = started.elapsed().as_secs_f64() * 1000.;
    let per_query_ms = began.elapsed().as_secs_f64() * 1000.;
    assert_eq!(actual, ring_oracle(data_words, &mask).as_slice());
    assert_eq!(actual[6 * 512 + 255], 0);
    assert_eq!(actual[7 * 512 + 255], 0);
    for (row, age) in [0u64, 1, 128].into_iter().enumerate() {
        assert_eq!(actual[2 * row * 512 + 255], 256 + age);
        assert_eq!(actual[(2 * row + 1) * 512 + 255], row as u64 + 1);
    }
    eprintln!(
        "retained_math_read different_query=true prepared_ms={prepared_ms:.3} word_prove_ms={word_ms:.3} query_fused_prove_ms={query_ms:.3} fhe_product_and_certificate_ms={product_ms:.3} receiving_setup_ms={receiving_setup_ms:.3} prepared_receive_ms={receive_ms:.3} client_ms={client_ms:.3} per_query_ms={per_query_ms:.3} query_frames_bytes={} rayon_threads={} SAME_DATA=true receiving_setup_in_budget=true local_receiver_thread=true shared_rayon_pool=true SQL=false freshness=false network=false security_assessed=false",
        word.len() + query.len() + product.len(),
        p3_maybe_rayon::prelude::current_num_threads()
    );
    // All hostile examples and their separate receiving setup are outside the measured interval.
    let receiver = Verifier::new(&expected).unwrap();
    assert!(matches!(
        receiver.verify_retained(
            retained,
            QueryEvidence {
                query: previous.query,
                ..evidence()
            }
        ),
        Err(Error::Formation(gold::Error::Binding))
    ));
    let control = word_expected(&owner_cases::case(Kind::EndCompact));
    assert!(matches!(
        Expected::checked(
            &control,
            data,
            &request,
            vector,
            expected.product.output_wire().to_vec()
        ),
        Err(Error::Binding)
    ));
    // Prior success may not cache either per-query proof's acceptance.
    let bad = damage_batch(&query);
    assert!(matches!(
        receiver.verify_retained(
            retained,
            QueryEvidence {
                query: &bad,
                ..evidence()
            }
        ),
        Err(Error::Formation(gold::Error::Verification))
    ));
    let bad = damage_batch(&word);
    assert!(matches!(
        receiver.verify_retained(
            retained,
            QueryEvidence {
                word: &bad,
                ..evidence()
            }
        ),
        Err(Error::Word(word::Error::Verification))
    ));
    let mut bad = product.clone();
    bad[8] ^= 1;
    assert!(matches!(
        receiver.verify_retained(
            retained,
            QueryEvidence {
                product: &bad,
                ..evidence()
            }
        ),
        Err(Error::Product(product::Error::Binding))
    ));
    for index in 0..3 {
        let mut missing = evidence();
        match index {
            0 => missing.word = &[],
            1 => missing.query = &[],
            _ => missing.product = &[],
        }
        assert!(matches!(
            receiver.verify_retained(retained, missing),
            Err(Error::Resource)
        ));
    }
}

#[cfg(feature = "owner-read")]
fn originating_owner_query(
    owner: &protected::Owner,
    data: &installed::Expected,
    retained: &installed::VerifiedDataFormation,
    data_words: &[u64],
    previous: &Frames,
) {
    use super::owner::{self as local, Evidence as OwnerEvidence};
    // Only immutable role-public setup and the already verified DATA version
    // survive across calls. Disclose their initialization separately.
    let started = Instant::now();
    let producer = word::Prover::new(Role::Predicate).unwrap();
    let receiver = local::Verifier::new().unwrap();
    let setup_ms = started.elapsed().as_secs_f64() * 1000.;
    for sequence in 2..4 {
        let began = Instant::now();
        let mut case = owner_cases::case(Kind::SkipBeforeOffset);
        // Age127 is absent; age255 is present. Both differ from the earlier
        // all-ones query; the second call additionally clears absent age126.
        case.input.mask[31] &= 0x7f;
        case.input.mask[15] &= if sequence == 2 { 0x7f } else { 0x3f };
        case.input.walk.call += sequence;
        case.input.walk.invocation[0] += Val::from_u64(sequence);
        case.metadata.blind_sql[0] += Val::from_u64(sequence);
        case.input.walk.sql = case.metadata.blind_sql;
        case.rebuild();
        let expected = word_expected(&case);
        let independent: [Val; 96] = owner_cases::statement(&case.metadata, &case.input, &case.old)
            .try_into()
            .unwrap();
        let mask_bytes = case.input.mask;
        let original = owner
            .originate(
                protected::Mask256::new(mask_bytes),
                input_binding(&case, data),
                data.core_expected(),
            )
            .unwrap();
        let inputs = word_inputs(&mut case);
        let opening = inputs
            .statement_opening(&expected.statement_domain())
            .unwrap();
        assert_eq!(opening.root(), expected.claims().statement);
        let statement = opening.into_words();
        assert_eq!(*statement, independent.map(|v| v.as_canonical_u64()));
        let bind_started = Instant::now();
        let input = owner.bind_statement(&original, statement).unwrap();
        let bind_ms = bind_started.elapsed().as_secs_f64() * 1000.;
        let started = Instant::now();
        let response = protected::Evaluator::new()
            .unwrap()
            .evaluate(input.public_request())
            .unwrap();
        let product_ms = started.elapsed().as_secs_f64() * 1000.;
        let started = Instant::now();
        let word = producer.produce(&expected, inputs).unwrap().into_bytes();
        let word_ms = started.elapsed().as_secs_f64() * 1000.;
        let evidence = || OwnerEvidence {
            word: &word,
            output: response.output(),
            product: response.certificate(),
        };
        let started = Instant::now();
        let checked = receiver
            .verify(&input, &expected, data, retained, evidence())
            .unwrap();
        let receive_ms = started.elapsed().as_secs_f64() * 1000.;
        let started = Instant::now();
        let completed = checked.complete(owner).unwrap();
        let client_ms = started.elapsed().as_secs_f64() * 1000.;
        let per_query_ms = began.elapsed().as_secs_f64() * 1000.;
        // The independent full-ring answer is used ONLY after all actual checks.
        let mut mask = Zeroizing::new(vec![0u64; gold::N]);
        for age in 0..256 {
            mask[255 - age] = u64::from((mask_bytes[age / 8] >> (age % 8)) & 1);
        }
        assert_eq!(
            completed.coefficients(),
            ring_oracle(data_words, &mask).as_slice()
        );
        assert_eq!(completed.coefficients()[6 * 512 + 255], 0);
        assert_eq!(completed.coefficients()[7 * 512 + 255], 0);
        eprintln!(
            "originating_owner_read sequence={sequence} role_public_setup_ms={setup_ms:.3} private_input_check_ms={bind_ms:.3} word_prove_ms={word_ms:.3} fhe_product_and_certificate_ms={product_ms:.3} fresh_receive_ms={receive_ms:.3} client_ms={client_ms:.3} local_query_ms={per_query_ms:.3} query_frames_bytes={} rayon_threads={} installed_DATA=true role_public_setup_reused=true public_Query_proof=false input_equations=true SQL=false freshness=false network=false locks=false security_assessed=false",
            word.len() + response.output().len() + response.certificate().len(),
            p3_maybe_rayon::prelude::current_num_threads()
        );

        let bad = damage_batch(&word);
        assert!(matches!(
            receiver.verify(
                &input,
                &expected,
                data,
                retained,
                OwnerEvidence {
                    word: &bad,
                    ..evidence()
                }
            ),
            Err(local::Error::Word(word::Error::Verification))
        ));
        let mut bad = response.certificate().to_vec();
        bad[8] ^= 1;
        assert!(matches!(
            receiver.verify(
                &input,
                &expected,
                data,
                retained,
                OwnerEvidence {
                    product: &bad,
                    ..evidence()
                }
            ),
            Err(local::Error::Product(product::Error::Binding))
        ));
        assert!(
            receiver
                .verify(
                    &input,
                    &expected,
                    data,
                    retained,
                    OwnerEvidence {
                        word: &previous.word,
                        ..evidence()
                    }
                )
                .is_err()
        );
        assert!(
            receiver
                .verify(
                    &input,
                    &expected,
                    data,
                    retained,
                    OwnerEvidence {
                        product: &previous.product,
                        ..evidence()
                    }
                )
                .is_err()
        );
        let mut bad_output = response.output().to_vec();
        *bad_output.last_mut().unwrap() ^= 1;
        assert!(
            receiver
                .verify(
                    &input,
                    &expected,
                    data,
                    retained,
                    OwnerEvidence {
                        output: &bad_output,
                        ..evidence()
                    }
                )
                .is_err()
        );
        let bad_request =
            data::Request::checked([0x69; 32], data.request().ciphertext().to_vec()).unwrap();
        let bad_data = installed::Expected::checked(&bad_request, data.source()).unwrap();
        assert!(matches!(
            receiver.verify(&input, &expected, &bad_data, retained, evidence()),
            Err(local::Error::Binding)
        ));
        let wrong_word = word_expected(&owner_cases::case(Kind::SkipBeforeOffset));
        assert!(matches!(
            receiver.verify(&input, &wrong_word, data, retained, evidence()),
            Err(local::Error::Binding)
        ));
        // Keep the exact same Stmt96 root and Source: the independently pinned
        // full Word context must also prevent substitution of another result.
        let mut wrong_claims = expected.claims();
        wrong_claims.next[0] += Val::ONE;
        let wrong_context = word::Expected::checked(
            expected.source(),
            Role::Predicate,
            [0xa7; 32],
            case.metadata
                .parent
                .into_iter()
                .flat_map(|v| u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            case.metadata.enrollment,
            wrong_claims,
        )
        .unwrap();
        assert_eq!(
            wrong_context.claims().statement,
            expected.claims().statement
        );
        assert!(matches!(
            receiver.verify(&input, &wrong_context, data, retained, evidence()),
            Err(local::Error::Binding)
        ));
        let control = word_expected(&owner_cases::case(Kind::EndCompact));
        assert!(matches!(
            receiver.verify(&input, &control, data, retained, evidence()),
            Err(local::Error::Binding)
        ));
        for which in 0..3 {
            let mut missing = evidence();
            match which {
                0 => missing.word = &[],
                1 => missing.output = &[],
                _ => missing.product = &[],
            }
            assert!(matches!(
                receiver.verify(&input, &expected, data, retained, missing),
                Err(local::Error::Resource)
            ));
        }
        let oversized = vec![0; 128 * 1024 + 1];
        assert!(matches!(
            receiver.verify(
                &input,
                &expected,
                data,
                retained,
                OwnerEvidence {
                    output: &oversized,
                    ..evidence()
                }
            ),
            Err(local::Error::Resource)
        ));
        // Failed evidence must never poison the role-only setup or cache success.
        let again = receiver
            .verify(&input, &expected, data, retained, evidence())
            .unwrap()
            .complete(owner)
            .unwrap();
        assert_eq!(again.coefficients(), completed.coefficients());
    }
}

#[test]
fn original_version_word_data_query_and_real_product_are_all_required_before_client_completion() {
    let began = Instant::now();
    let mut case = owner_cases::case(Kind::SkipBeforeOffset);
    let state_expected_owned = case.metadata.source.clone();
    let state_expected = &state_expected_owned;
    let claim = state_expected.statement();
    let key_commitment = source::commitment::digest(&source::commitment::key_fields(
        &claim.heads[0],
        [0x71; 32],
        [Val::ONE; 4],
    ));
    assert_eq!(key_commitment, claim.key_commitment);
    let plain = Zeroizing::new(
        case.input
            .source
            .iter()
            .flat_map(|v| u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes())
            .collect::<Vec<_>>(),
    );
    assert_eq!(plain.len(), 2348);
    let binding = |cs| {
        KeyBinding::new(
            claim.heads[0][8..24].try_into().unwrap(),
            [0x71; 16],
            1,
            [0x95; 32],
            source::statement::encode_digest(cs),
        )
        .unwrap()
    };
    let context = installed::secret_context(&binding([Val::ZERO; 4]));
    let owner =
        protected::Owner::generate([0x95; 32], context.map(|v| v.as_canonical_u64())).unwrap();
    let pinned_key = owner.key_expected().clone();
    // Explicit PUBLIC fixture wrapping key. No raw SDK key ever leaves Owner.
    let custody = protected::CustodyKey::new(Zeroizing::new([0xd1; 32]));
    let identity = protected::CustodyIdentity::checked([0xd2; 32]).unwrap();
    let sealed = owner.seal_key(&identity, &custody).unwrap();
    drop(owner);
    let owner = protected::Owner::restore_key(pinned_key, &identity, &custody, &sealed).unwrap();
    let encoding_expected = encoding::statement::Expected::source_version(
        state_expected,
        binding(owner.key_expected().root_words().map(Val::from_u64)),
    )
    .unwrap();
    let witness = Witness::source_version(&encoding_expected, plain, [2; 4], [5; 4]).unwrap();
    let mut data_words = witness.coefficients();
    let modulus = Modulus::new(gold::T).unwrap();
    modulus.scalar_mul_vec(&mut data_words, modulus.inv(gold::SCALE).unwrap());
    let original_data = owner.originate_data(data_words.clone()).unwrap();
    let data_request =
        data::Request::checked([0x61; 32], original_data.ciphertext().to_vec()).unwrap();
    let data_expected = installed::Expected::checked(&data_request, &witness.statement()).unwrap();
    let statement: [Val; 96] = owner_cases::statement(&case.metadata, &case.input, &case.old)
        .try_into()
        .unwrap();
    let mut mask_words = Zeroizing::new(vec![0u64; gold::N]);
    for age in 0..256 {
        mask_words[255 - age] = u64::from((case.input.mask[age / 8] >> (age % 8)) & 1);
    }
    let original = owner
        .originate(
            protected::Mask256::new(case.input.mask),
            input_binding(&case, &data_expected),
            data_expected.core_expected(),
        )
        .unwrap();
    let request = original.public_request().formation_request().unwrap();
    let context = formation::encoding_context(
        &request,
        data_expected.core_expected(),
        case.metadata.statement,
    )
    .unwrap();
    let salt = [9; 4];
    let vector = owner
        .query_commitment(&original, context.map(|v| v.as_canonical_u64()), &salt)
        .unwrap()
        .map(Val::from_u64);
    let query_expected = formation::expected(
        &request,
        data_expected.core_expected(),
        case.metadata.statement,
        vector,
    )
    .unwrap();

    let started = Instant::now();
    let state = source::version::prove(
        state_expected,
        &source::circuit::Witness::new([0x71; 32], [Val::ONE; 4], [Val::TWO; 4], [0, 1, 128, 255]),
    )
    .unwrap()
    .into_bytes();
    let state_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let child = encoding::prove(&encoding_expected, &witness, &state)
        .unwrap()
        .into_parts()
        .1;
    let child_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let data = installed::prove_dense_prepared(
        &data_expected,
        &data_request,
        installed::Prerequisites::checked(&state, &child).unwrap(),
        owner
            .prepare_data(
                &original_data,
                data_expected.core_expected(),
                Zeroizing::new([5; 4]),
            )
            .unwrap(),
    )
    .unwrap()
    .into_bytes();
    let data_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let word = produce_word(&mut case);
    let word_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let query = fused::prove(
        &query_expected,
        owner
            .prepare_query(
                &original,
                &query_expected,
                Zeroizing::new(statement.map(|v| v.as_canonical_u64())),
                Zeroizing::new(salt),
            )
            .unwrap(),
    )
    .unwrap();
    let query_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let response = protected::Evaluator::new()
        .unwrap()
        .evaluate(original.public_request())
        .unwrap();
    let expected = Expected::checked(
        &word_expected(&case),
        &data_expected,
        &request,
        vector,
        response.output().to_vec(),
    )
    .unwrap();
    let product = response.certificate().to_vec();
    let product_ms = started.elapsed().as_secs_f64() * 1000.;
    let frames = Frames {
        state,
        child,
        data,
        word,
        query: query.as_bytes().to_vec(),
        product,
    };
    let started = Instant::now();
    let checked =
        verify(&expected, frames.borrowed()).expect("all six genuine independent arguments");
    let receive_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let completed = owner
        .complete_checked_product(&original, checked.product())
        .unwrap();
    let actual = completed.coefficients();
    let client_ms = started.elapsed().as_secs_f64() * 1000.;
    let owner_setup_and_read_ms = began.elapsed().as_secs_f64() * 1000.;
    check_complete_native_manifests(&expected, &frames);
    // Full-ring oracle belongs only to this PUBLIC fixture, after all verification.
    assert_eq!(actual, ring_oracle(&data_words, &mask_words).as_slice());
    for (row, age) in [0u64, 1, 128, 255].into_iter().enumerate() {
        assert_eq!(actual[2 * row * 512 + 255], 256 + age);
        assert_eq!(actual[(2 * row + 1) * 512 + 255], row as u64 + 1);
    }
    eprintln!(
        "joined_math_read state_prove_ms={state_ms:.3} role3_prove_ms={child_ms:.3} data_dense_prove_ms={data_ms:.3} word_prove_ms={word_ms:.3} query_fused_prove_ms={query_ms:.3} fhe_product_and_certificate_ms={product_ms:.3} all_cold_receive_ms={receive_ms:.3} client_decrypt_ms={client_ms:.3} owner_setup_and_read_ms={owner_setup_and_read_ms:.3} frames_bytes={} SQL=false freshness=false network=false locks=false security_assessed=false",
        [
            &frames.state,
            &frames.child,
            &frames.data,
            &frames.word,
            &frames.query,
            &frames.product
        ]
        .iter()
        .map(|f| f.len())
        .sum::<usize>()
    );

    let started = Instant::now();
    let retained = installed::verify_dense(
        &data_expected,
        &data_request,
        installed::Prerequisites::checked(&frames.state, &frames.child).unwrap(),
        &frames.data,
    )
    .unwrap();
    let install_ms = started.elapsed().as_secs_f64() * 1000.;
    retained.require_expected(&data_expected).unwrap();
    let started = Instant::now();
    let again = verify_retained(&expected, &retained, frames.borrowed().query()).unwrap();
    let retained_receive_ms = started.elapsed().as_secs_f64() * 1000.;
    assert_eq!(again.output(), checked.output());
    eprintln!(
        "retained_math_receive SAME_query=true independent_install_ms={install_ms:.3} full_receive_ms={receive_ms:.3} retained_receive_ms={retained_receive_ms:.3} SQL=false freshness=false"
    );
    different_retained_query(
        &owner,
        &data_expected,
        &retained,
        &data_words,
        frames.borrowed().query(),
    );
    #[cfg(feature = "owner-read")]
    originating_owner_query(&owner, &data_expected, &retained, &data_words, &frames);

    // Same version tag and images, but a different complete C_state must not join.
    let mut foreign = owner_cases::case(Kind::SkipBeforeOffset);
    let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
        claim.heads[i]
            .iter()
            .chain(&claim.packets[i])
            .copied()
            .collect()
    });
    let heads = core::array::from_fn::<_, 2, _>(|i| {
        compact_store::Commitment::decode(&claim.heads[i], source::statement::limits()).unwrap()
    });
    let mut changed = claim.open_commitment;
    changed[0] += Val::ONE;
    foreign.metadata.source = source::version::SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        source::statement::encode_digest(claim.key_commitment),
        source::statement::encode_digest(changed),
    )
    .unwrap();
    assert_eq!(
        foreign.metadata.source.version_id(),
        state_expected.version_id()
    );
    let foreign_source = encoding::statement::Statement {
        expected: encoding::statement::Expected::source_version(
            &foreign.metadata.source,
            data_expected.source().expected.key_binding().clone(),
        )
        .unwrap(),
        encoded: data_expected.source().encoded,
    };
    let foreign_data = installed::Expected::checked(&data_request, &foreign_source).unwrap();
    assert!(matches!(
        retained.require_expected(&foreign_data),
        Err(installed::Error::Binding)
    ));
    let foreign_read = Expected::checked(
        &word_expected(&foreign),
        &foreign_data,
        &request,
        vector,
        expected.product.output_wire().to_vec(),
    )
    .unwrap();
    assert!(matches!(
        verify_retained(&foreign_read, &retained, frames.borrowed().query()),
        Err(Error::Data(installed::Error::Binding))
    ));
    // Original installation nonce and ciphertext, Cw and original Cs are retained too.
    let other_nonce =
        data::Request::checked([0x62; 32], data_request.ciphertext().to_vec()).unwrap();
    let other_ciphertext = data::Request::checked(
        data_request.nonce(),
        owner
            .originate_data(data_words.clone())
            .unwrap()
            .ciphertext()
            .to_vec(),
    )
    .unwrap();
    for different in [&other_nonce, &other_ciphertext] {
        let different = installed::Expected::checked(different, data_expected.source()).unwrap();
        assert!(matches!(
            retained.require_expected(&different),
            Err(installed::Error::Binding)
        ));
        assert!(matches!(
            installed::prove_dense_prepared(
                &different,
                different.request(),
                installed::Prerequisites::checked(&frames.state, &frames.child).unwrap(),
                owner
                    .prepare_data(
                        &original_data,
                        data_expected.core_expected(),
                        Zeroizing::new([5; 4])
                    )
                    .unwrap(),
            ),
            Err(installed::Error::Formation(gold::Error::Binding))
        ));
    }
    let mut other_cw = data_expected.source().clone();
    other_cw.encoded[0] += Val::ONE;
    let other_cw = installed::Expected::checked(&data_request, &other_cw).unwrap();
    assert!(matches!(
        retained.require_expected(&other_cw),
        Err(installed::Error::Binding)
    ));
    let mut other_cs = data_expected.core_expected().roots()[1];
    other_cs[0] += Val::ONE;
    let other_cs = encoding::statement::Statement {
        expected: encoding::statement::Expected::source_version(state_expected, binding(other_cs))
            .unwrap(),
        encoded: data_expected.source().encoded,
    };
    let other_cs = installed::Expected::checked(&data_request, &other_cs).unwrap();
    assert!(matches!(
        retained.require_expected(&other_cs),
        Err(installed::Error::Binding)
    ));
    assert!(matches!(
        Expected::checked(
            &word_expected(&foreign),
            &data_expected,
            &request,
            vector,
            expected.product.output_wire().to_vec()
        ),
        Err(Error::Binding)
    ));
    let swapped = gold::Request::checked(
        request.nonce(),
        [
            request.ciphertexts()[1].to_vec(),
            request.ciphertexts()[0].to_vec(),
        ],
    )
    .unwrap();
    assert!(matches!(
        Expected::checked(
            &word_expected(&case),
            &data_expected,
            &swapped,
            vector,
            expected.product.output_wire().to_vec()
        ),
        Err(Error::Query(formation::Error::Binding))
    ));
    // Explicit namespaces remain closed with all genuine original prerequisites.
    assert!(matches!(
        installed::verify(
            &data_expected,
            &data_request,
            installed::Prerequisites::checked(&frames.state, &frames.child).unwrap(),
            &frames.data
        ),
        Err(installed::Error::Formation(gold::Error::Encoding))
    ));

    let bad_data = damage_batch(&frames.data);
    assert!(matches!(
        installed::verify_dense(
            &data_expected,
            &data_request,
            installed::Prerequisites::checked(&frames.state, &frames.child).unwrap(),
            &bad_data
        ),
        Err(installed::Error::Formation(gold::Error::Verification))
    ));
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                data: &bad_data,
                ..frames.borrowed()
            }
        ),
        Err(Error::Data(installed::Error::Formation(
            gold::Error::Verification
        )))
    ));
    let bad_query = damage_batch(&frames.query);
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                query: &bad_query,
                ..frames.borrowed()
            }
        ),
        Err(Error::Formation(gold::Error::Verification))
    ));
    let bad_word = damage_batch(&frames.word);
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                word: &bad_word,
                ..frames.borrowed()
            }
        ),
        Err(Error::Word(word::Error::Verification))
    ));
    let backend = crate::fixed::Backend::source_version(state_expected).unwrap();
    let mut false_state: p3_uni_stark::Proof<Config> = codec::decode(
        &frames.state,
        &backend.shape,
        crate::wire::MAX_SEQUENCE_ELEMENTS,
        crate::wire::SOURCE_SLOTS,
    )
    .unwrap();
    false_state.opened_values.trace_local[0] += Challenge::ONE;
    let false_state = codec::serialize(&false_state, &backend.shape, wire::MAX_SOURCE).unwrap();
    drop(backend);
    assert!(matches!(
        installed::prove_dense_prepared(
            &data_expected,
            &data_request,
            installed::Prerequisites::checked(&false_state, &frames.child).unwrap(),
            owner
                .prepare_data(
                    &original_data,
                    data_expected.core_expected(),
                    Zeroizing::new([5; 4])
                )
                .unwrap(),
        ),
        Err(installed::Error::Prerequisite(
            wire::Error::SourceVersionProof(crate::BackendError::Verification)
        ))
    ));
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                state: &false_state,
                ..frames.borrowed()
            }
        ),
        Err(Error::Data(installed::Error::Prerequisite(
            wire::Error::SourceVersionProof(crate::BackendError::Verification)
        )))
    ));
    let backend = crate::fixed::Backend::two_lane_encoding(data_expected.source()).unwrap();
    let mut false_child: p3_uni_stark::Proof<Config> = codec::decode(
        &frames.child[wire::HEADER..],
        &backend.shape,
        wire::SEQUENCE,
        wire::CHILD_SLOTS,
    )
    .unwrap();
    false_child.opened_values.trace_local[0] += Challenge::ONE;
    let payload =
        codec::serialize(&false_child, &backend.shape, wire::MAX_CHILD - wire::HEADER).unwrap();
    let mut false_child = frames.child[..wire::HEADER].to_vec();
    false_child[144..148].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    false_child.extend(payload);
    drop(backend);
    assert!(matches!(
        installed::prove_dense_prepared(
            &data_expected,
            &data_request,
            installed::Prerequisites::checked(&frames.state, &false_child).unwrap(),
            owner
                .prepare_data(
                    &original_data,
                    data_expected.core_expected(),
                    Zeroizing::new([5; 4])
                )
                .unwrap(),
        ),
        Err(installed::Error::Prerequisite(wire::Error::Proof(
            crate::BackendError::Verification
        )))
    ));
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                child: &false_child,
                ..frames.borrowed()
            }
        ),
        Err(Error::Data(installed::Error::Prerequisite(
            wire::Error::Proof(crate::BackendError::Verification)
        )))
    ));
    let mut product_bad = frames.product.clone();
    product_bad[8] ^= 1;
    assert!(matches!(
        verify(
            &expected,
            Evidence {
                product: &product_bad,
                ..frames.borrowed()
            }
        ),
        Err(Error::Product(product::Error::Binding))
    ));
    for index in 0..6 {
        let mut evidence = frames.borrowed();
        match index {
            0 => evidence.state = &[],
            1 => evidence.child = &[],
            2 => evidence.data = &[],
            3 => evidence.word = &[],
            4 => evidence.query = &[],
            _ => evidence.product = &[],
        }
        assert!(matches!(verify(&expected, evidence), Err(Error::Resource)));
    }
    assert_ne!(profile_digest(), installed::dense_profile_digest());
}
