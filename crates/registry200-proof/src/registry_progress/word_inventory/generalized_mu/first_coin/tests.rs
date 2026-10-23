//! Bounded source/framing tests, not native proof or a complete RBR experiment.
use super::*;
use p3_symmetric::MerkleCap;

fn cap(root: [u8; 32]) -> MerkleCap<Val, [u8; 32]> {
    MerkleCap::new(vec![root])
}

fn raw(family: usize, public: &[Val], main: [u8; 32], pp: Option<[u8; 32]>, retry: u64) -> Vec<u8> {
    let mut result = DOMAIN.to_vec();
    result.extend(seed(family));
    let field = |bytes: &mut Vec<u8>, value: Val| {
        bytes.push(FIELD);
        bytes.extend(value.as_canonical_u64().to_le_bytes());
    };
    let cap = |bytes: &mut Vec<u8>, root: [u8; 32]| {
        bytes.push(CAP);
        bytes.extend(1u64.to_le_bytes());
        bytes.extend(root);
    };
    if family >= 2 {
        for value in [
            Val::from_usize(K[family].ilog2() as usize),
            Val::ZERO,
            Val::ZERO,
            Val::ZERO,
            Val::ZERO,
        ] {
            field(&mut result, value);
        }
    }
    cap(&mut result, main);
    for value in public {
        field(&mut result, *value);
    }
    if let Some(pp) = pp {
        cap(&mut result, pp);
    }
    result.push(DRAW);
    result.extend(0u64.to_le_bytes());
    result.extend(retry.to_le_bytes());
    result
}

fn install_pp(driver: &mut Driver, matrix: &p3_matrix::dense::RowMajorMatrix<Val>) -> [u8; 32] {
    use p3_matrix::Matrix;
    let mut level = (0..matrix.height())
        .map(|row| {
            let mut raw = suite::LEAF_DOMAIN.to_vec();
            for value in &matrix.values[row * matrix.width()..(row + 1) * matrix.width()] {
                raw.extend(value.as_canonical_u64().to_le_bytes());
            }
            raw.extend([0u8; 32]); // explicit public salt4, irrelevant to PP polynomial
            raw.extend(((matrix.width() + 4) as u64).to_le_bytes());
            driver.sha256(&raw)
        })
        .collect::<Vec<_>>();
    while level.len() > 1 {
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let mut raw = suite::NODE_DOMAIN.to_vec();
                raw.extend(pair[0]);
                raw.extend(pair[1]);
                driver.sha256(&raw)
            })
            .collect();
    }
    level[0]
}

#[test]
fn all_five_sdk_first_coin_prefixes_classify_synchronously_before_hash() {
    let source = crate::source::hash::public_fixture_expected();
    let key = crate::two_lane_encoding::statement::KeyBinding::new(
        source.statement().heads[0][8..24].try_into().unwrap(),
        [0x73; 16],
        7,
        [0x35; 32],
        crate::source::statement::encode_digest([Val::from_u64(11); 4]),
    )
    .unwrap();
    let role3 = crate::two_lane_encoding::statement::Statement {
        expected: crate::two_lane_encoding::statement::Expected::source_version(&source, key)
            .unwrap(),
        encoded: [Val::from_u64(13); 4],
    };
    let public = [
        source.statement().values(),
        role3.values(),
        vec![Val::ZERO; 32],
        vec![Val::ZERO; 309],
        vec![Val::ZERO; 32],
    ];
    let mut driver = Driver::default();
    let word = super::super::word_pp().unwrap();
    let word_root = install_pp(&mut driver, &word);
    for (family, values) in public.iter().enumerate() {
        let pp = (PP[family] != 0).then_some(if family == 3 { word_root } else { [0x61; 32] });
        let bytes = raw(family, values, [0x71; 32], pp, 0);
        let before = driver.closed_before_hash;
        let reply = driver.sha512(&bytes);
        assert_eq!(reply.first_draw, Some((family, 0)));
        assert_eq!(reply.association, Some(Ok(())));
        assert_eq!(driver.closed_before_hash, before + 1);
        assert_eq!(reply.digest, <[u8; 64]>::from(Sha512::digest(&bytes)));
    }
    assert_eq!(driver.instances.len(), 5);
    // No actual AIR, FHE, proof or accepting common-data result was constructed.
}

#[test]
fn every_retry_u64_reuses_the_registered_first_word_and_classification() {
    let mut driver = Driver::default();
    let schema = Schema {
        family: 4,
        pp: true,
    };
    let mut first = None;
    for retry in [u64::MAX, 7, 1, 0, 7] {
        let bytes = raw(4, &[Val::ZERO; 32], [0x33; 32], Some([0x44; 32]), retry);
        let reply = driver.sha512(&bytes);
        assert_eq!(reply.first_draw, Some((4, retry)));
        assert_eq!(reply.association, Some(Ok(())));
        let snapshot = driver.dictionary.first.get(&(schema, [0x44; 32])).unwrap();
        if let Some(first) = &first {
            assert!(Arc::ptr_eq(first, snapshot));
        }
        first = Some(snapshot.clone());
    }
    assert_eq!(driver.instances.len(), 1);
    assert_eq!(driver.dictionary.first.len(), 2);
}

#[test]
fn main_is_notified_before_missing_public_and_later_first_prefix_queries() {
    let mut driver = Driver::default();
    let bytes = raw(4, &[Val::ZERO; 32], [0x33; 32], Some([0x44; 32]), 0);
    let main_end = DOMAIN.len() + seed(4).len() + 5 * 9 + 41;
    let partial = driver.sha512(&bytes[..main_end]);
    assert_eq!(partial.association, None);
    let schema = Schema {
        family: 4,
        pp: false,
    };
    let first = driver
        .dictionary
        .first
        .get(&(schema, [0x33; 32]))
        .unwrap()
        .clone();
    driver.sha256(b"public intervening query");
    let mut later_tail = bytes[..bytes.len() - 17].to_vec();
    later_tail.extend([3u8; 17]); // no claim that this later ancestor is canonical
    let later = driver.sha512(&later_tail);
    assert_eq!(later.association, Some(Ok(())));
    assert_eq!(later.first_draw, None);
    driver.sha512(&bytes);
    assert!(Arc::ptr_eq(
        &first,
        driver.dictionary.first.get(&(schema, [0x33; 32])).unwrap()
    ));
    assert_eq!(first.cutoff, 0);
    assert_eq!(driver.instances.len(), 1);
}

#[test]
fn a_large_malformed_tail_cannot_defer_initial_notification_or_retime_its_word() {
    let mut driver = Driver::default();
    let bytes = raw(4, &[Val::ZERO; 32], [0x33; 32], Some([0x44; 32]), 0);
    let mut large = bytes[..bytes.len() - 17].to_vec();
    large.resize(8 * 1024 * 1024 + 1, 0);
    let reply = driver.sha512(&large);
    assert_eq!(reply.association, Some(Ok(())));
    assert_eq!(reply.first_draw, None);
    let schema = Schema {
        family: 4,
        pp: true,
    };
    let first = driver
        .dictionary
        .first
        .get(&(schema, [0x44; 32]))
        .unwrap()
        .clone();
    assert_eq!(first.cutoff, 0);
    driver.sha256(b"later public dictionary growth after a long invalid tail");
    assert_eq!(driver.sha512(&bytes).association, Some(Ok(())));
    assert!(Arc::ptr_eq(
        &first,
        driver.dictionary.first.get(&(schema, [0x44; 32])).unwrap()
    ));
    assert_eq!(driver.instances.len(), 1);
}

#[test]
fn bad_word_pp_is_permanent_and_raw_hash_answers_remain_consistent() {
    let mut driver = Driver::default();
    let bytes = raw(3, &[Val::ZERO; 309], [0x11; 32], Some([0x22; 32]), 13);
    let first = driver.sha512(&bytes);
    assert_eq!(
        first.association,
        Some(Err("Word-PP-differs-from-genuine-fixed-factory"))
    );
    let schema = Schema {
        family: 3,
        pp: true,
    };
    let frozen = driver
        .dictionary
        .first
        .get(&(schema, [0x22; 32]))
        .unwrap()
        .clone();
    driver.sha256(b"irrelevant later public Expected/tree discovery");
    let replay = driver.sha512(&bytes);
    assert_eq!(replay.digest, first.digest);
    assert_eq!(replay.association, first.association);
    assert!(Arc::ptr_eq(
        &frozen,
        driver.dictionary.first.get(&(schema, [0x22; 32])).unwrap()
    ));
    assert_eq!(driver.instances.len(), 1);
}

#[test]
fn later_complete_pp_is_a_target_hit_and_cannot_replace_the_first_zero_word() {
    let schema = Schema {
        family: 4,
        pp: true,
    };
    let mut queries = Vec::new();
    let mut leaf = suite::LEAF_DOMAIN.to_vec();
    leaf.extend(7u64.to_le_bytes());
    leaf.resize(suite::LEAF_DOMAIN.len() + schema.fields() * 8, 0);
    leaf.extend((schema.fields() as u64).to_le_bytes());
    let mut root: [u8; 32] = Sha256::digest(&leaf).into();
    queries.push(leaf);
    for _ in 0..schema.depth() {
        let mut node = suite::NODE_DOMAIN.to_vec();
        node.extend(root);
        node.extend(root);
        root = Sha256::digest(&node).into();
        queries.push(node);
    }
    let mut driver = Driver::default();
    let bytes = raw(4, &[Val::ZERO; 32], [0x55; 32], Some(root), u64::MAX);
    assert_eq!(driver.sha512(&bytes).association, Some(Ok(())));
    let first = driver
        .dictionary
        .first
        .get(&(schema, root))
        .unwrap()
        .clone();
    assert_eq!(first.cutoff, 0);
    assert_eq!(first.field(0, 0), 0);
    for query in queries {
        driver.sha256(&query);
    }
    assert!(driver.dictionary.target_hits >= 1);
    assert_eq!(driver.dictionary.collisions, 0);
    assert_eq!(driver.sha512(&bytes).association, Some(Ok(())));
    assert!(Arc::ptr_eq(
        &first,
        driver.dictionary.first.get(&(schema, root)).unwrap()
    ));
    assert_eq!(first.field(0, 0), 0);
    assert_eq!(driver.instances.len(), 1);
}

#[test]
fn seed_degree_canonical_field_cap_and_draw_extent_mutations_do_not_select_another_family() {
    for family in 0..5 {
        for other in 0..5 {
            if family != other {
                assert!(!seed(family).starts_with(&seed(other)));
            }
        }
    }
    let bytes = raw(4, &[Val::ZERO; 32], [0x33; 32], Some([0x44; 32]), 0);
    let seed_end = DOMAIN.len() + seed(4).len();
    for at in [0, DOMAIN.len(), seed_end, seed_end + 5 * 9] {
        let mut mutated = bytes.clone();
        mutated[at] ^= 0x80;
        let mut driver = Driver::default();
        assert_eq!(driver.sha512(&mutated).association, None);
    }
    for count in [0u64, 2, u64::MAX] {
        let mut changed = bytes.clone();
        let start = seed_end + 5 * 9 + 1;
        changed[start..start + 8].copy_from_slice(&count.to_le_bytes());
        assert_eq!(Driver::default().sha512(&changed).association, None);
    }
    let mut noncanonical = bytes.clone();
    let value = seed_end + 5 * 9 + 41 + 1;
    noncanonical[value..value + 8].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
    let mut driver = Driver::default();
    assert_eq!(driver.sha512(&noncanonical).association, None);
    assert_eq!(driver.dictionary.first.len(), 1); // earlier MAIN notification persists
    let mut extra = bytes;
    extra.push(0);
    let reply = driver.sha512(&extra);
    assert_eq!(reply.association, Some(Ok(()))); // complete initial µ still classified
    assert_eq!(reply.first_draw, None); // extra suffix is never a canonical first DRAW
}

#[test]
fn real_challenger_draw_bytes_match_the_closed_first_parser() {
    for (family, &public_count) in PUBLIC.iter().enumerate() {
        let (_, traces) = suite::audit::capture(|| {
            let mut challenger = suite::Challenger::new();
            if family < 2 {
                let mut transcript = p3_uni_stark::StarkProverTranscript::<_, Val, Challenge>::new(
                    &mut challenger,
                    uni_shape(family),
                );
                let _ = transcript.constraint_phase(
                    cap([0x71; 32]),
                    None,
                    &vec![Val::ZERO; public_count],
                );
                transcript.abort();
            } else {
                let mut transcript =
                    p3_batch_stark::BatchProverTranscript::<_, Val, Challenge, _>::new(
                        &mut challenger,
                        batch_shape(family),
                    );
                transcript.instance_bindings(&[K[family].ilog2() as usize]);
                transcript.main_phase(cap([0x71; 32]), &[vec![Val::ZERO; public_count]]);
                transcript.preprocessed_phase(Some(cap([0x61; 32])));
                let lookups = [Vec::<p3_lookup::Lookup<Val>>::new()];
                let _ = transcript.lookup_phase(&lookups, &p3_lookup::LogUpGadget::new());
                transcript.abort();
            }
        })
        .unwrap();
        let trace = traces
            .iter()
            .find(|trace| !trace.draws().is_empty())
            .unwrap();
        let draw = &trace.draws()[0];
        let mut bytes = trace.prefix()[..draw.prefix_len()].to_vec();
        bytes.push(DRAW);
        bytes.extend(draw.counter().to_le_bytes());
        bytes.extend(draw.retry().to_le_bytes());
        let mut dictionary = Dictionary::default();
        let parsed = initial(&bytes, &mut dictionary).unwrap();
        assert_eq!(parsed.family, family);
        assert_eq!(parsed.public, vec![Val::ZERO; public_count]);
        assert_eq!(bytes[parsed.end..].len(), 17);
        assert_eq!(<[u8; 64]>::from(Sha512::digest(bytes)), *draw.digest());
    }
}
