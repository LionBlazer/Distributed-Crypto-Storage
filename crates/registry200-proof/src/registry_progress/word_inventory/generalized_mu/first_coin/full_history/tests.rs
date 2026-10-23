//! Actual Challenger primitives, not a native proof or arbitrary-adversary proof.
use super::*;
use p3_challenger::{CanObserve, CanSample};
use p3_symmetric::MerkleCap;

fn observe_cap(challenger: &mut suite::Challenger, byte: u8) {
    challenger.observe(MerkleCap::<Val, [u8; 32]>::new(vec![[byte; 32]]));
}
fn sample(challenger: &mut suite::Challenger, count: usize) {
    for _ in 0..count {
        let _: Val = challenger.sample();
    }
}
fn fields(challenger: &mut suite::Challenger, values: &[Val]) {
    for value in values {
        challenger.observe(*value);
    }
}

fn public(family: usize) -> Vec<Val> {
    match family {
        0 => crate::source::hash::public_fixture_expected()
            .statement()
            .values(),
        1 => {
            let source = crate::source::hash::public_fixture_expected();
            let key = crate::two_lane_encoding::statement::KeyBinding::new(
                source.statement().heads[0][8..24].try_into().unwrap(),
                [0x73; 16],
                7,
                [0x35; 32],
                crate::source::statement::encode_digest([Val::from_u64(11); 4]),
            )
            .unwrap();
            crate::two_lane_encoding::statement::Statement {
                expected: crate::two_lane_encoding::statement::Expected::source_version(
                    &source, key,
                )
                .unwrap(),
                encoded: [Val::from_u64(13); 4],
            }
            .values()
        }
        _ => vec![Val::ZERO; PUBLIC[family]],
    }
}

/// The real sealed Challenger emits every FIELD/CAP/SAMPLE/DRAW, not a metadata
/// expansion. No native AIR/FHE/proof is made here; arbitrary opaque CAPs are
/// intentionally unverified. Word's missing fixed PP must classify as an error.
fn primitive_capture(family: usize, public: &[Val]) -> suite::audit::Trace {
    let (_, traces) = suite::audit::capture(|| {
        let mut challenger = suite::Challenger::new();
        if family < 2 {
            uni_shape(family)
                .domain_separator::<Val, Challenge>()
                .seed(&mut challenger);
        } else {
            batch_shape(family)
                .domain_separator::<Val, Challenge>()
                .seed(&mut challenger);
            fields(
                &mut challenger,
                &[
                    Val::from_usize(K[family].ilog2() as usize),
                    Val::ZERO,
                    Val::ZERO,
                    Val::ZERO,
                    Val::ZERO,
                ],
            );
        }
        observe_cap(&mut challenger, 0x41);
        fields(&mut challenger, public);
        if family >= 2 {
            observe_cap(&mut challenger, 0x42);
            sample(&mut challenger, 10);
            observe_cap(&mut challenger, 0x43);
            fields(&mut challenger, &[Val::ZERO; 5]);
        }
        sample(&mut challenger, 5);
        observe_cap(&mut challenger, 0x44);
        observe_cap(&mut challenger, 0x45);
        sample(&mut challenger, 5);
        pcs_shape(family)
            .domain_separator::<Val, Challenge>()
            .seed(&mut challenger);
        for _ in 0..OPENINGS[family] * 5 {
            challenger.observe(Val::ZERO);
        }
        sample(&mut challenger, 5);
        fri_shape(family)
            .domain_separator::<Val, Challenge>()
            .seed(&mut challenger);
        for round in 0..K[family].ilog2() as usize {
            observe_cap(&mut challenger, u8::try_from(0x50 + round).unwrap());
            sample(&mut challenger, 5);
        }
        fields(&mut challenger, &[Val::ZERO; 5]);
        sample(&mut challenger, 192);
    })
    .unwrap();
    assert_eq!(traces.len(), 1);
    traces.into_iter().next().unwrap()
}

fn raw(trace: &suite::audit::Trace, draw: &suite::audit::Draw, retry: u64) -> Vec<u8> {
    let mut raw = trace.prefix()[..draw.prefix_len()].to_vec();
    raw.push(DRAW);
    raw.extend(draw.counter().to_le_bytes());
    raw.extend(retry.to_le_bytes());
    raw
}

#[test]
fn reversed_actual_challenger_queries_restore_all_77_groups_and_1335_samples() {
    let mut driver = FullDriver::default();
    let mut accepted = 0;
    for family in 0..5 {
        let trace = primitive_capture(family, &public(family));
        // The LAST coordinate arrives before ANY explicit ancestor RAW query.
        for draw in trace.draws().iter().rev() {
            let reply = driver.sha512(&raw(&trace, draw, draw.retry()));
            assert_eq!(&reply.digest, draw.digest());
            let target = reply.history.unwrap();
            assert_eq!(target.group.family, family);
            assert_eq!(
                target.group.first_counter + target.coordinate as u64,
                draw.counter()
            );
            assert_ne!(target.eligibility, Eligibility::AfterAcceptance);
            if target.eligibility == Eligibility::Accepted {
                accepted += 1;
            }
            if family == 3 {
                assert_eq!(
                    target.group.association,
                    Err("Word-PP-differs-from-genuine-fixed-factory")
                );
            } else {
                assert_eq!(target.group.association, Ok(()));
            }
        }
    }
    assert_eq!(accepted, 1335);
    assert_eq!(driver.groups.len(), 77);
    assert_eq!(driver.words.len(), 75);
    assert_eq!(
        driver
            .words
            .keys()
            .filter(|(schema, _)| schema.role == Role::Pp)
            .count(),
        3
    );
    assert_eq!(driver.first.instances.len(), 5);
    assert!(driver.restored_draws >= 1335);
    assert!(driver.anchor_bytes < MAX_ANCHOR_BYTES);
    // This is source correspondence for an actual primitive stream, not native
    // accepted proofs or a numerical random-oracle failure-probability claim.
}

#[test]
fn reverse_retry_queries_share_the_exact_group_and_do_not_retime_words() {
    let trace = primitive_capture(4, &public(4));
    let draw = trace.draws().last().unwrap();
    let mut driver = FullDriver::default();
    let first = driver.sha512(&raw(&trace, draw, u64::MAX)).history.unwrap();
    let group = first.group;
    let words = group.words.clone();
    let draws = driver.restored_draws;
    driver.sha256(b"late unrelated public tree discovery");
    for retry in [9, 1, 0, u64::MAX, group.retries[first.coordinate]] {
        let bytes = raw(&trace, draw, retry);
        let reply = driver.sha512(&bytes);
        assert_eq!(reply.digest, <[u8; 64]>::from(Sha512::digest(&bytes)));
        let target = reply.history.unwrap();
        assert_eq!(target.retry, retry);
        assert!(Arc::ptr_eq(&group, &target.group));
        assert_eq!(
            target.eligibility,
            eligibility(retry, group.retries[first.coordinate])
        );
        assert!(
            target
                .group
                .words
                .iter()
                .zip(&words)
                .all(|(a, b)| Arc::ptr_eq(a, b))
        );
    }
    assert_eq!(driver.restored_draws, draws);
}

#[test]
fn false_sample_ancestor_is_rejected_before_later_cap_and_original_history_recovers() {
    let trace = primitive_capture(4, &public(4));
    let last = trace.draws().last().unwrap();
    let original = raw(&trace, last, last.retry());
    let mut changed = original.clone();
    // This is the actual first accepted SAMPLE's value, not a metadata offset.
    let at = trace
        .draws()
        .iter()
        .find(|draw| draw.counter() == 0)
        .unwrap()
        .prefix_len()
        + 9;
    changed[at] ^= 1;
    let mut driver = FullDriver::default();
    let rejected = driver.sha512(&changed);
    assert_eq!(rejected.digest, <[u8; 64]>::from(Sha512::digest(&changed)));
    assert_eq!(
        rejected.history.unwrap_err(),
        "noncanonical-or-false-SAMPLE-ancestor"
    );
    assert_eq!(driver.groups.len(), 1);
    assert_eq!(driver.words.len(), 2); // MAIN/PP only; AUX was never notified.
    let first = driver.words.values().cloned().collect::<Vec<_>>();
    let recovered = driver.sha512(&original).history.unwrap();
    assert_eq!(recovered.eligibility, Eligibility::Accepted);
    assert!(first.iter().all(|word| Arc::ptr_eq(
        word,
        driver.words.get(&(word.schema.clone(), word.root)).unwrap()
    )));
    assert_eq!(driver.groups.len(), 17);
}

#[test]
fn nested_seed_terminal_opening_counter_and_eof_mutations_fail_closed() {
    let trace = primitive_capture(4, &public(4));
    let last = trace.draws().last().unwrap();
    let bytes = raw(&trace, last, last.retry());
    let end_sample = |counter| {
        trace
            .draws()
            .iter()
            .find(|draw| draw.counter() == counter)
            .unwrap()
            .prefix_len()
            + 17
    };
    let pcs = end_sample(19);
    let opening = pcs + pcs_seed(4).len();
    let terminal = end_sample(9) + 41;
    for at in [pcs, terminal + 1, opening + 1] {
        let mut changed = bytes.clone();
        changed[at] ^= 0x80;
        assert!(FullDriver::default().sha512(&changed).history.is_err());
    }
    let mut noncanonical = bytes.clone();
    noncanonical[opening + 1..opening + 9].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    assert!(FullDriver::default().sha512(&noncanonical).history.is_err());
    let mut wrong_counter = bytes.clone();
    let start = wrong_counter.len() - 16;
    wrong_counter[start..start + 8].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(
        FullDriver::default()
            .sha512(&wrong_counter)
            .history
            .unwrap_err(),
        "DRAW-counter-or-EOF"
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        FullDriver::default().sha512(&trailing).history.unwrap_err(),
        "DRAW-counter-or-EOF"
    );
    assert!(
        FullDriver::default()
            .sha512(&bytes[..bytes.len() - 1])
            .history
            .is_err()
    );
    assert!(
        FullDriver::default()
            .sha512(trace.prefix())
            .history
            .is_err()
    );
}

#[test]
fn changed_public_prefix_gets_a_new_ancestor_but_shared_cap_has_one_first_snapshot() {
    let a = public(4);
    let mut b = a.clone();
    b[0] = Val::ONE;
    let traces = [primitive_capture(4, &a), primitive_capture(4, &b)];
    let mut driver = FullDriver::default();
    let mut targets = Vec::new();
    for trace in &traces {
        let draw = &trace.draws()[0];
        targets.push(
            driver
                .sha512(&raw(trace, draw, draw.retry()))
                .history
                .unwrap(),
        );
    }
    assert!(!Arc::ptr_eq(&targets[0].group, &targets[1].group));
    assert!(
        targets[0]
            .group
            .words
            .iter()
            .zip(&targets[1].group.words)
            .all(|(a, b)| Arc::ptr_eq(a, b))
    );
    assert_eq!(driver.groups.len(), 2);
    assert_eq!(driver.first.instances.len(), 2);
    assert_eq!(driver.words.len(), 2);
}

fn constant_tree(schema: &WordSchema, mutate_salt: bool) -> (Vec<Vec<u8>>, [u8; 32]) {
    let mut leaf = suite::LEAF_DOMAIN.to_vec();
    let mut value = 1u64;
    for width in &schema.widths {
        for _ in 0..width + 4 {
            leaf.extend(value.to_le_bytes());
            value += 1;
        }
    }
    if mutate_salt {
        let at = suite::LEAF_DOMAIN.len() + schema.widths[0] * 8;
        leaf[at..at + 8].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    }
    leaf.extend((schema.salted_fields() as u64).to_le_bytes());
    let mut root: [u8; 32] = Sha256::digest(&leaf).into();
    let mut queries = vec![leaf];
    for _ in 0..schema.depth {
        let mut node = suite::NODE_DOMAIN.to_vec();
        node.extend(root);
        node.extend(root);
        root = Sha256::digest(&node).into();
        queries.push(node);
    }
    (queries, root)
}

#[test]
fn full_word_row_oracle_preserves_matrix_salts_and_first_cutoff() {
    let schema = WordSchema::new(4, Role::Quotient);
    let (queries, root) = constant_tree(&schema, false);
    let mut complete = FullDriver::default();
    for query in &queries {
        complete.sha256(query);
    }
    let word = complete.word(schema.clone(), root, None).unwrap();
    assert_eq!(word.field(&complete.first.dictionary, 0, 0, 9), 10);
    assert_eq!(
        word.field(&complete.first.dictionary, (1 << schema.depth) - 1, 1, 0),
        15
    );
    assert_eq!(word.field(&complete.first.dictionary, 0, 7, 9), 108);
    let mut late = FullDriver::default();
    let missing = late.word(schema.clone(), root, None).unwrap();
    for query in queries {
        late.sha256(&query);
    }
    assert!(Arc::ptr_eq(
        &missing,
        &late.word(schema.clone(), root, None).unwrap()
    ));
    assert_eq!(missing.cutoff, 0);
    assert_eq!(missing.field(&late.first.dictionary, 0, 7, 9), 0);
    assert!(late.first.dictionary.target_hits > 0);
    let (queries, root) = constant_tree(&schema, true);
    for query in queries {
        complete.sha256(&query);
    }
    let bad = complete.word(schema, root, None).unwrap();
    assert_eq!(bad.field(&complete.first.dictionary, 0, 1, 0), 0);
}

#[test]
fn retry_classification_distinguishes_rejection_acceptance_and_unreachable_later_raw_query() {
    // A pure boundary case for first-accept arithmetic; this does not pretend to
    // exhibit an actual SHA512 rejection, whose search is intentionally absent.
    assert_eq!(eligibility(0, 2), Eligibility::Rejected);
    assert_eq!(eligibility(1, 2), Eligibility::Rejected);
    assert_eq!(eligibility(2, 2), Eligibility::Accepted);
    assert_eq!(eligibility(3, 2), Eligibility::AfterAcceptance);
    assert_eq!(eligibility(u64::MAX, 2), Eligibility::AfterAcceptance);
}

#[test]
fn resource_refusal_does_not_erase_an_existing_ancestor_or_change_raw_hash_answer() {
    let trace = primitive_capture(4, &public(4));
    let draw = &trace.draws()[0];
    let bytes = raw(&trace, draw, draw.retry());
    let mut driver = FullDriver::default();
    let original = driver.sha512(&bytes).history.unwrap().group;
    driver.anchor_bytes = MAX_ANCHOR_BYTES;
    assert!(Arc::ptr_eq(
        &original,
        &driver.sha512(&bytes).history.unwrap().group
    ));
    let last = trace.draws().last().unwrap();
    let changed = raw(&trace, last, last.retry());
    let refusal = driver.sha512(&changed);
    assert_eq!(refusal.digest, <[u8; 64]>::from(Sha512::digest(changed)));
    assert_eq!(refusal.history.unwrap_err(), "group-resource-bound");
    assert_eq!(driver.groups.len(), 1);
}

#[test]
fn aux_notification_precedes_bad_terminal_and_never_gets_a_later_cutoff() {
    let trace = primitive_capture(4, &public(4));
    let last = trace.draws().last().unwrap();
    let bytes = raw(&trace, last, last.retry());
    let terminal = trace
        .draws()
        .iter()
        .find(|draw| draw.counter() == 9)
        .unwrap()
        .prefix_len()
        + 17
        + 41;
    let mut changed = bytes.clone();
    changed[terminal + 1] = 1;
    let mut driver = FullDriver::default();
    assert_eq!(
        driver.sha512(&changed).history.unwrap_err(),
        "terminal-must-be-zero"
    );
    assert_eq!(driver.groups.len(), 1);
    assert_eq!(driver.words.len(), 3);
    let key = (WordSchema::new(4, Role::Aux), [0x43; 32]);
    let first = driver.words.get(&key).unwrap().clone();
    driver.sha256(b"later AUX tree discovery after invalid terminal");
    assert!(driver.sha512(&bytes).history.is_ok());
    assert!(Arc::ptr_eq(&first, driver.words.get(&key).unwrap()));
    assert_eq!(first.cutoff, 0);
}

#[test]
fn canonical_changed_opening_is_a_new_theta_ancestor_and_is_not_a_proof_verdict() {
    let trace = primitive_capture(4, &public(4));
    let theta = trace
        .draws()
        .iter()
        .find(|draw| draw.counter() == 20)
        .unwrap();
    let bytes = raw(&trace, theta, theta.retry());
    let opening = trace
        .draws()
        .iter()
        .find(|draw| draw.counter() == 19)
        .unwrap()
        .prefix_len()
        + 17
        + pcs_seed(4).len();
    let mut changed = bytes.clone();
    changed[opening + 1] = 1; // still canonical; opaque claim is not AIR-checked here
    let mut driver = FullDriver::default();
    let a = driver.sha512(&bytes).history.unwrap();
    let b = driver.sha512(&changed).history.unwrap();
    assert_eq!(a.group.phase, Phase::Theta);
    assert_eq!(b.group.phase, Phase::Theta);
    assert!(!Arc::ptr_eq(&a.group, &b.group));
    assert!(
        a.group
            .words
            .iter()
            .zip(&b.group.words)
            .all(|(a, b)| Arc::ptr_eq(a, b))
    );
}

#[test]
fn fixed_group_inventory_matches_actual_sdk_patterns_and_preserves_pcs_matrix_order() {
    let mut total_groups = 0;
    let mut total_samples = 0;
    for family in 0..5 {
        let stark = if family < 2 {
            inspect_separator(&uni_shape(family).domain_separator::<Val, Challenge>())
        } else {
            inspect_separator(&batch_shape(family).domain_separator::<Val, Challenge>())
        };
        let pcs = inspect_separator(&pcs_shape(family).domain_separator::<Val, Challenge>());
        let fri = inspect_separator(&fri_shape(family).domain_separator::<Val, Challenge>());
        let groups = [stark, pcs, fri]
            .into_iter()
            .flat_map(|separator| separator.challenge_group_base_draws().unwrap())
            .collect::<Vec<_>>();
        let mut expected = if family < 2 {
            vec![5, 5, 5]
        } else {
            vec![10, 5, 5, 5]
        };
        expected.extend(std::iter::repeat_n(5, K[family].ilog2() as usize));
        expected.push(192);
        assert_eq!(groups, expected);
        total_groups += groups.len();
        total_samples += groups.iter().sum::<usize>();
        let shape = pcs_shape(family);
        assert_eq!(
            shape
                .claimed_evaluation_counts
                .iter()
                .flatten()
                .flatten()
                .sum::<usize>(),
            OPENINGS[family]
        );
        assert_eq!(shape.claimed_evaluation_counts[0], vec![vec![10]]); // random first
        assert_eq!(
            shape.claimed_evaluation_counts[1],
            vec![vec![MAIN[family] + 5; 2]]
        );
        assert_eq!(
            shape.claimed_evaluation_counts[2],
            vec![vec![10]; CHUNKS[family]]
        );
    }
    assert_eq!((total_groups, total_samples), (77, 1335));
}
