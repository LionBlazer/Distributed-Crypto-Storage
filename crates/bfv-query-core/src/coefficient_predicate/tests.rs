//! PUBLIC NONSECRET data. Oracles remain inside this owner boundary, never evaluation code.
use super::*;
use std::time::Instant;

fn context() -> QueryContext {
    QueryContext::new([0x71; 16], [0x72; HEAD_BYTES], [0x73; HEAD_BYTES])
}
fn rows() -> [CoefficientRow; COEFFICIENT_PREDICATE_ROWS] {
    [
        CoefficientRow { age: 0, amount: 0 },
        CoefficientRow {
            age: 127,
            amount: u16::MAX,
        },
        CoefficientRow {
            age: 128,
            amount: u16::MAX - 1,
        },
        CoefficientRow {
            age: 255,
            amount: 1,
        },
    ]
}
fn mask(ages: impl IntoIterator<Item = u8>) -> [u8; 32] {
    let mut mask = [0; 32];
    for age in ages {
        mask[usize::from(age) / 8] |= 1 << (age % 8);
    }
    mask
}
fn setup() -> (Owner, PeerEvaluator) {
    let (owner, setup) = Owner::generate(Geometry::Rows16).unwrap();
    let evaluator = PeerEvaluator::from_public_setup(&setup).unwrap();
    (owner, evaluator)
}
fn decoded(owner: &Owner, ciphertext: &[u8]) -> Vec<u64> {
    let ct = canonical_ciphertext(ciphertext, &owner.parameters).unwrap();
    let plaintext = owner.key.try_decrypt(&ct).unwrap();
    Vec::<u64>::try_decode(&plaintext, Encoding::poly()).unwrap()
}
fn expected(rows: &[CoefficientRow; 4], mask: &[u8; 32]) -> [UnverifiedCoefficientRow; 4] {
    core::array::from_fn(|i| {
        // Test oracle ONLY. The production evaluator never reads these plaintexts.
        let present = mask[usize::from(rows[i].age) / 8] & (1 << (rows[i].age % 8)) != 0;
        UnverifiedCoefficientRow {
            ordinal: i as u8,
            present,
            age: if present { rows[i].age } else { 0 },
            amount: if present { rows[i].amount } else { 0 },
        }
    })
}
fn replace_operand(wire: &[u8], operand: usize, replacement: &[u8]) -> Vec<u8> {
    let r = request_view(wire).unwrap();
    let operands = if operand == 0 {
        [replacement, r.predicate]
    } else {
        [r.original, replacement]
    };
    let mut out = common_header(REQUEST_MAGIC, &r.labels).unwrap();
    for bytes in operands {
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    }
    for bytes in operands {
        out.extend_from_slice(bytes);
    }
    out
}
fn forged_response(wire: &[u8], product: &[u8]) -> Vec<u8> {
    let r = request_view(wire).unwrap();
    let mut out = common_header(RESPONSE_MAGIC, &r.labels).unwrap();
    out.extend_from_slice(&Sha256::digest(wire));
    out.extend_from_slice(&(product.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(product);
    out
}

#[test]
fn all_four_original_ordinals_come_from_one_actual_private_fhe_product() {
    let full = Instant::now();
    let generation = Instant::now();
    let (owner, evaluator) = setup();
    let setup_ms = generation.elapsed().as_secs_f64() * 1000.;
    let original_rows = rows();
    let encryption = Instant::now();
    let original = owner
        .encrypt_original_coefficient_rows_for_experiment(&original_rows)
        .unwrap();
    let prepared = owner
        .prepare_private_coefficient_predicate_for_experiment(
            context(),
            [0x74; 32],
            &original,
            &mask([0, 128, 255]),
        )
        .unwrap();
    let encryption_ms = encryption.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let evaluated = evaluator
        .evaluate_private_coefficient_predicate_for_experiment(&prepared.request)
        .unwrap();
    let encrypted_evaluate_ms = started.elapsed().as_secs_f64() * 1000.;
    assert_eq!(evaluated.ct_ct_multiplications, 1);
    let started = Instant::now();
    let answer = owner
        .decrypt_private_coefficient_predicate_unverified_for_experiment(
            prepared.pending,
            &evaluated.output,
        )
        .unwrap();
    let completion_ms = started.elapsed().as_secs_f64() * 1000.;
    assert_eq!(answer.rows, expected(&original_rows, &mask([0, 128, 255])));
    assert_eq!(answer.rows[2].ordinal, 2); // Original order, never rank compaction.
    println!(
        "{}",
        serde_json::json!({
            "stage":"actual_private_coefficient_predicate", "rows":4,
            "ct_ct_multiplications":evaluated.ct_ct_multiplications, "rotations":0,
            "request_bytes":prepared.request.len(), "response_bytes":evaluated.output.len(),
            "owner_and_evaluator_setup_ms":setup_ms, "encryption_and_preparation_ms":encryption_ms,
            "encrypted_evaluate_ms":encrypted_evaluate_ms, "completion_ms":completion_ms,
            "through_completion_ms":full.elapsed().as_secs_f64()*1000.,
            "proof_available":false, "source_completeness_proven":false,
            "predicate_plaintext_serialized":false, "sql_grant":false
        })
    );
}

#[test]
fn empty_full_range_and_noncontiguous_masks_have_the_same_two_ciphertext_shape() {
    let (owner, evaluator) = setup();
    let originals = rows();
    let source = owner
        .encrypt_original_coefficient_rows_for_experiment(&originals)
        .unwrap();
    let mut lengths = None;
    let mut previous_query: Option<Vec<u8>> = None;
    for private in [mask([]), [255; 32], mask(127..=128), mask([0, 255])] {
        let prepared = owner
            .prepare_private_coefficient_predicate_for_experiment(
                context(),
                [0x75; 32],
                &source,
                &private,
            )
            .unwrap();
        let r = request_view(&prepared.request).unwrap();
        assert_eq!(r.original, source.as_slice());
        assert!(r.predicate.len() <= MAX_CT);
        if let Some((request_bytes, query_bytes)) = lengths {
            assert_eq!(
                (prepared.request.len(), r.predicate.len()),
                (request_bytes, query_bytes)
            );
        }
        lengths = Some((prepared.request.len(), r.predicate.len()));
        if let Some(previous) = &previous_query {
            assert_ne!(previous.as_slice(), r.predicate);
        }
        previous_query = Some(r.predicate.to_vec());
        let result = evaluator
            .evaluate_private_coefficient_predicate_for_experiment(&prepared.request)
            .unwrap();
        let answer = owner
            .decrypt_private_coefficient_predicate_unverified_for_experiment(
                prepared.pending,
                &result.output,
            )
            .unwrap();
        assert_eq!(answer.rows, expected(&originals, &private));
    }
}

#[test]
fn every_decrypted_coefficient_matches_independent_negacyclic_convolution() {
    let (owner, evaluator) = setup();
    let originals = [
        CoefficientRow {
            age: 255,
            amount: 65535,
        },
        CoefficientRow {
            age: 0,
            amount: 65535,
        },
        CoefficientRow {
            age: 255,
            amount: 65535,
        },
        CoefficientRow {
            age: 254,
            amount: 0,
        },
    ];
    let private = mask((0..=255).filter(|age| age % 3 != 1));
    let source = owner
        .encrypt_original_coefficient_rows_for_experiment(&originals)
        .unwrap();
    let prepared = owner
        .prepare_private_coefficient_predicate_for_experiment(
            context(),
            [0x76; 32],
            &source,
            &private,
        )
        .unwrap();
    let r = request_view(&prepared.request).unwrap();
    let original = decoded(&owner, r.original);
    let predicate = decoded(&owner, r.predicate);
    // Independently audit ALL source coefficients, including zero gaps and the final row.
    let mut wanted_source = vec![0u64; DEGREE];
    for (i, row) in originals.iter().enumerate() {
        for (field, value) in [1, u64::from(row.age), u64::from(row.amount)]
            .into_iter()
            .enumerate()
        {
            wanted_source[(3 * i + field) * 512 + usize::from(row.age)] = value;
        }
    }
    assert_eq!(original, wanted_source);
    for (i, coefficient) in predicate.iter().enumerate() {
        let wanted = if i < 256 {
            u64::from((private[(255 - i) / 8] >> ((255 - i) % 8)) & 1)
        } else {
            0
        };
        assert_eq!(*coefficient, wanted, "private polynomial coefficient {i}");
    }
    let mut oracle = vec![0i128; DEGREE];
    for (i, a) in original.iter().enumerate().filter(|(_, a)| **a != 0) {
        for (j, b) in predicate.iter().enumerate().filter(|(_, b)| **b != 0) {
            let exponent = i + j;
            let signed = if exponent < DEGREE { 1 } else { -1 };
            oracle[exponent % DEGREE] += signed * i128::from(*a) * i128::from(*b);
        }
    }
    let oracle: Vec<u64> = oracle
        .into_iter()
        .map(|v| v.rem_euclid(i128::from(PLAINTEXT)) as u64)
        .collect();
    let result = evaluator
        .evaluate_private_coefficient_predicate_for_experiment(&prepared.request)
        .unwrap();
    let actual = decoded(&owner, response_view(&result.output).unwrap().product);
    assert_eq!(actual.len(), 8192);
    assert_eq!(actual, oracle);
    assert!(actual[6143..].iter().all(|v| *v == 0));
    let answer = owner
        .decrypt_private_coefficient_predicate_unverified_for_experiment(
            prepared.pending,
            &result.output,
        )
        .unwrap();
    assert_eq!(answer.rows, expected(&originals, &private));
}

#[test]
fn source_encryption_has_no_query_and_private_query_encryption_is_randomized() {
    let (owner, _) = setup();
    let source = owner
        .encrypt_original_coefficient_rows_for_experiment(&rows())
        .unwrap();
    let a = owner
        .prepare_private_coefficient_predicate_for_experiment(
            context(),
            [0x77; 32],
            &source,
            &mask([127]),
        )
        .unwrap();
    let b = owner
        .prepare_private_coefficient_predicate_for_experiment(
            context(),
            [0x77; 32],
            &source,
            &mask([127]),
        )
        .unwrap();
    let ra = request_view(&a.request).unwrap();
    let rb = request_view(&b.request).unwrap();
    assert_eq!(ra.original, rb.original);
    assert_eq!(ra.original, source);
    assert_eq!(a.request[..REQUEST_HEADER], b.request[..REQUEST_HEADER]);
    assert_ne!(ra.predicate, rb.predicate);
    assert_eq!(a.pending.keyset_id, owner.keyset_id);
    assert_eq!(a.pending.context, context());
    assert_eq!(
        a.pending.request_digest,
        <[u8; 32]>::from(Sha256::digest(&a.request))
    );
    assert_ne!(a.pending.request_digest, b.pending.request_digest);
}

#[test]
fn full_query_context_keyset_and_request_digest_replays_are_rejected_at_completion() {
    let (owner, evaluator) = setup();
    let source = owner
        .encrypt_original_coefficient_rows_for_experiment(&rows())
        .unwrap();
    for at in [10, 47, 79, 95, 207, 319, 351] {
        let prepared = owner
            .prepare_private_coefficient_predicate_for_experiment(
                context(),
                [0x78; 32],
                &source,
                &mask([128]),
            )
            .unwrap();
        let mut response = evaluator
            .evaluate_private_coefficient_predicate_for_experiment(&prepared.request)
            .unwrap()
            .output;
        response[at] ^= 1;
        assert!(matches!(
            owner.decrypt_private_coefficient_predicate_unverified_for_experiment(
                prepared.pending,
                &response
            ),
            Err(Error::BindingMismatch) | Err(Error::InvalidShape)
        ));
    }
    let prepared = owner
        .prepare_private_coefficient_predicate_for_experiment(
            context(),
            [0x78; 32],
            &source,
            &mask([128]),
        )
        .unwrap();
    let other = owner
        .prepare_private_coefficient_predicate_for_experiment(
            context(),
            [0x78; 32],
            &source,
            &mask([255]),
        )
        .unwrap();
    let response = evaluator
        .evaluate_private_coefficient_predicate_for_experiment(&other.request)
        .unwrap();
    assert!(matches!(
        owner.decrypt_private_coefficient_predicate_unverified_for_experiment(
            prepared.pending,
            &response.output
        ),
        Err(Error::BindingMismatch)
    ));
}

#[test]
fn genuine_foreign_owner_roundtrip_does_not_match_original_keyset_metadata() {
    let (owner, evaluator) = setup();
    let (foreign_owner, foreign) = setup();
    let source = foreign_owner
        .encrypt_original_coefficient_rows_for_experiment(&rows())
        .unwrap();
    let prepared = foreign_owner
        .prepare_private_coefficient_predicate_for_experiment(
            context(),
            [0x79; 32],
            &source,
            &[255; 32],
        )
        .unwrap();
    let result = foreign
        .evaluate_private_coefficient_predicate_for_experiment(&prepared.request)
        .unwrap();
    assert_eq!(
        foreign_owner
            .decrypt_private_coefficient_predicate_unverified_for_experiment(
                prepared.pending,
                &result.output
            )
            .unwrap()
            .rows,
        expected(&rows(), &[255; 32])
    );
    assert!(matches!(
        evaluator.evaluate_private_coefficient_predicate_for_experiment(&prepared.request),
        Err(Error::BindingMismatch)
    ));
    assert_ne!(owner.keyset_id, foreign_owner.keyset_id);
    // Ciphertext bytes alone carry no authenticated key origin; no claim to reject
    // an arbitrary foreign same-parameter CT merely from its coefficient shape.
}

#[test]
fn borrowed_two_ciphertext_envelope_rejects_lengths_tags_and_malformed_polynomials() {
    let (owner, evaluator) = setup();
    let source = owner
        .encrypt_original_coefficient_rows_for_experiment(&rows())
        .unwrap();
    let prepared = owner
        .prepare_private_coefficient_predicate_for_experiment(
            context(),
            [0x7A; 32],
            &source,
            &[255; 32],
        )
        .unwrap();
    for at in [0, 8, 10, 11, 15] {
        let mut bad = prepared.request.clone();
        bad[at] ^= 1;
        assert!(
            evaluator
                .evaluate_private_coefficient_predicate_for_experiment(&bad)
                .is_err()
        );
    }
    for at in [COMMON_HEADER, COMMON_HEADER + 4] {
        for value in [0u32, u32::MAX] {
            let mut bad = prepared.request.clone();
            bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(matches!(
                evaluator.evaluate_private_coefficient_predicate_for_experiment(&bad),
                Err(Error::WireLimit)
            ));
        }
    }
    let mut trailing = prepared.request.clone();
    trailing.push(0);
    assert!(
        evaluator
            .evaluate_private_coefficient_predicate_for_experiment(&trailing)
            .is_err()
    );
    // Actual public evaluator calls with incomplete QueryId/data/index context.
    // Complete fixed headers can only reconstruct exact112-byte heads.
    for end in [95, 207, COMMON_HEADER - 1, REQUEST_HEADER - 1] {
        assert!(matches!(
            evaluator
                .evaluate_private_coefficient_predicate_for_experiment(&prepared.request[..end]),
            Err(Error::InvalidShape)
        ));
    }
    let mut invalid_context = context();
    invalid_context.index_head.pop();
    assert!(matches!(
        owner.prepare_private_coefficient_predicate_for_experiment(
            invalid_context,
            [0x7A; 32],
            &[],
            &[255; 32]
        ),
        Err(Error::BindingMismatch)
    ));
    assert!(matches!(
        evaluator.evaluate_private_coefficient_predicate_for_experiment(&vec![0; MAX_REQUEST + 1]),
        Err(Error::WireLimit)
    ));
    // Two tiny degree8 records are NOT a request for SDK padding/NTT expansion.
    let tiny = [10, 7, 8, 2, 16, 8, 26, 1, 0, 10, 7, 8, 2, 16, 8, 26, 1, 0];
    for operand in 0..2 {
        let bad = replace_operand(&prepared.request, operand, &tiny);
        assert!(matches!(
            evaluator.evaluate_private_coefficient_predicate_for_experiment(&bad),
            Err(Error::InvalidShape)
        ));
    }
    assert!(matches!(
        owner.prepare_private_coefficient_predicate_for_experiment(
            context(),
            [0x7A; 32],
            &tiny,
            &[255; 32]
        ),
        Err(Error::InvalidShape)
    ));
    let control = evaluator
        .evaluate_private_coefficient_predicate_for_experiment(&prepared.request)
        .unwrap();
    assert_eq!(
        owner
            .decrypt_private_coefficient_predicate_unverified_for_experiment(
                prepared.pending,
                &control.output
            )
            .unwrap()
            .rows,
        expected(&rows(), &[255; 32])
    );
}

#[test]
fn completion_rejects_response_shape_and_actual_decrypted_range_or_padding_violations() {
    let (owner, evaluator) = setup();
    let source = owner
        .encrypt_original_coefficient_rows_for_experiment(&rows())
        .unwrap();
    for case in 0..9 {
        let prepared = owner
            .prepare_private_coefficient_predicate_for_experiment(
                context(),
                [0x7B; 32],
                &source,
                &[255; 32],
            )
            .unwrap();
        let mut response = evaluator
            .evaluate_private_coefficient_predicate_for_experiment(&prepared.request)
            .unwrap()
            .output;
        match case {
            0 => response[356] = 1,
            1 => response.push(0),
            2 => response[352..356].copy_from_slice(&u32::MAX.to_le_bytes()),
            _ => {
                // Genuine encryption of intentionally malformed reply plaintext;
                // this is a hostile codec input, not simulated query execution.
                let mut coefficients = vec![0u64; DEGREE];
                match case {
                    3 => coefficients[255] = 2,
                    4 => coefficients[767] = 1, // absent presence with nonzero age
                    5 => coefficients[1279] = 65536,
                    6 => coefficients[767] = 256,
                    7 => coefficients[511] = 1,
                    _ => coefficients[LAST_PRODUCT + 1] = 1,
                }
                let ct = encrypt_poly(&owner, &coefficients).unwrap();
                response = forged_response(&prepared.request, &ct);
            }
        }
        assert!(
            owner
                .decrypt_private_coefficient_predicate_unverified_for_experiment(
                    prepared.pending,
                    &response
                )
                .is_err(),
            "reply case {case}"
        );
    }
}
