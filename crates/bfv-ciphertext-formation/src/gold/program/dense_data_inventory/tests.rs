//! These tests validate metadata/routing only. No private relation is accepted.
use super::*;
use p3_air::BaseAir;

fn gate_words(
    hash: &mut Sha256,
    index: usize,
    ids: [u64; 4],
    coefficients: [u64; 4],
    uses: [u8; 2],
) {
    hash_word(hash, index);
    for word in ids.into_iter().chain(coefficients) {
        hash.update(word.to_le_bytes())
    }
    hash.update(uses);
}
fn original_graph_digest(plan: &plan::Plan) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"DCS/research/dense-data/unchanged81920GateSemantic/v1");
    for row in 0..RelationKind::Data.graph_rows() {
        for (slot, gate) in plan.original.graph.row(row)?.gates.into_iter().enumerate() {
            let ids = core::array::from_fn(|i| {
                let node = if i < 2 {
                    gate.inputs[i]
                } else {
                    gate.outputs[i - 2]
                };
                node.map_or(0, |n| n.id())
            });
            let coefficients = core::array::from_fn(|i| gate.linear[i / 2][i % 2]);
            gate_words(
                &mut hash,
                row * graph::SLOTS + slot,
                ids,
                coefficients,
                gate.output_uses,
            );
        }
    }
    Ok(hash.finalize().into())
}
fn dense_graph_digest(plan: &plan::Plan) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"DCS/research/dense-data/unchanged81920GateSemantic/v1");
    let mut count = 0;
    for row in 0..GRAPH_ROWS {
        let p = plan.row(row)?;
        for slot in 0..SLOTS {
            let active = p[ACTIVE + slot].as_canonical_u64();
            if active == 0 {
                assert!(p[4 * slot..4 * slot + 4].iter().all(|&x| x == Val::ZERO));
                assert!(
                    p[COEFFICIENTS + 4 * slot..COEFFICIENTS + 4 * slot + 4]
                        .iter()
                        .all(|&x| x == Val::ZERO)
                );
                assert_eq!(p[POINTWISE + slot], Val::ZERO);
                assert_eq!(p[FANOUT + slot], Val::ZERO);
                continue;
            }
            assert_eq!(active, 1);
            let ids = core::array::from_fn(|i| p[4 * slot + i].as_canonical_u64());
            let coefficients =
                core::array::from_fn(|i| p[COEFFICIENTS + 4 * slot + i].as_canonical_u64());
            let uses = [
                u8::try_from(plan::count(&p, 4 * slot + 2)?).map_err(|_| Error::Shape)?,
                u8::try_from(plan::count(&p, 4 * slot + 3)?).map_err(|_| Error::Shape)?,
            ];
            gate_words(&mut hash, count, ids, coefficients, uses);
            count += 1;
        }
    }
    if count != GATES {
        return Err(Error::Shape);
    }
    Ok(hash.finalize().into())
}

fn range_semantics(
    hash: &mut Sha256,
    row: usize,
    ids: impl Iterator<Item = u64>,
    constants: impl Iterator<Item = u64>,
    reset: u64,
    emit: u64,
    power: u64,
) {
    hash_word(hash, row);
    hash_word(hash, 2 * row);
    hash_word(hash, 2 * row + 1);
    for value in ids.chain(constants).chain([reset, emit, power]) {
        hash.update(value.to_le_bytes())
    }
}
fn range_digests(plan: &plan::Plan) -> Result<([u8; 32], [u8; 32])> {
    let mut original = Sha256::new();
    original.update(b"DCS/research/dense-data/unchanged4096RangeAndCsPack/v1");
    let mut dense = original.clone();
    for row in 0..H {
        let old = old_pp::row(&plan.original, RelationKind::Data.range_first() + row)?;
        let new = plan.row(row)?;
        range_semantics(
            &mut original,
            row,
            old[..19].iter().map(PrimeField64::as_canonical_u64),
            old[old_pp::COEFFICIENTS..old_pp::COEFFICIENTS + 4]
                .iter()
                .map(PrimeField64::as_canonical_u64),
            old[old_pp::FLAGS + old_pp::RESET].as_canonical_u64(),
            old[old_pp::FLAGS + old_pp::EMIT].as_canonical_u64(),
            old[old_pp::COEFFICIENTS + 8].as_canonical_u64(),
        );
        range_semantics(
            &mut dense,
            row,
            new[GRAPH_PORTS..PORTS]
                .iter()
                .map(PrimeField64::as_canonical_u64),
            new[RANGE_C0..RANGE_C0 + 4]
                .iter()
                .map(PrimeField64::as_canonical_u64),
            new[FLAGS + old_pp::RESET].as_canonical_u64(),
            new[FLAGS + old_pp::EMIT].as_canonical_u64(),
            new[POWER].as_canonical_u64(),
        );
    }
    Ok((original.finalize().into(), dense.finalize().into()))
}
fn hash_digests(plan: &plan::Plan) -> Result<([u8; 32], [u8; 32])> {
    let mut original = Sha256::new();
    original.update(b"DCS/research/dense-data/unchanged514Cw66CsHashPreimages/v1");
    let mut dense = original.clone();
    for block in 0..580 {
        let old = old_pp::row(&plan.original, RelationKind::Data.cw_first(0) + block)?;
        let new = plan.row(CW_FIRST + block)?;
        hash_word(&mut original, block);
        hash_word(&mut dense, block);
        for flag in [
            old_pp::HASH,
            old_pp::FIRST,
            old_pp::LAST,
            old_pp::CONTEXT,
            old_pp::SALT,
            old_pp::PAYLOAD,
            old_pp::SOURCE,
            old_pp::MASK,
            old_pp::CS,
        ] {
            original.update(old[old_pp::FLAGS + flag].as_canonical_u64().to_le_bytes());
            dense.update(new[FLAGS + flag].as_canonical_u64().to_le_bytes());
        }
        for i in 0..12 {
            original.update(
                old[old_pp::COEFFICIENTS + i]
                    .as_canonical_u64()
                    .to_le_bytes(),
            );
            dense.update(
                new[if i < 8 { CONTEXT + i } else { ROOT + i - 8 }]
                    .as_canonical_u64()
                    .to_le_bytes(),
            );
        }
        for port in 0..8 {
            original.update(old[port].as_canonical_u64().to_le_bytes());
            dense.update(new[port].as_canonical_u64().to_le_bytes());
            let old_flags =
                core::array::from_fn(|i| old[old_pp::FLAGS + i].as_canonical_u64() as i32);
            assert_eq!(
                old_pp::count(port, &old_flags, RelationKind::Data),
                plan::count(&new, port)?
            );
        }
    }
    Ok((original.finalize().into(), dense.finalize().into()))
}
fn full_pp_digest(plan: &plan::Plan) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(b"/fullPP/LE64");
    for value in [H, PP] {
        hash_word(&mut hash, value)
    }
    for row in 0..H {
        for value in plan.row(row)? {
            hash.update(value.as_canonical_u64().to_le_bytes())
        }
    }
    Ok(hash.finalize().into())
}

#[test]
fn dense_data_preserves_every_original_gate_range_and_hash_then_assesses_actual_native_metadata() {
    let expected = expected().unwrap();
    let air = air::MetadataAir::new(&expected).unwrap();
    let inventory = air.plan.inventory().unwrap();
    assert_eq!(
        (inventory.gates, inventory.hash_rows, inventory.coefficients),
        (81920, 580, 4096)
    );
    assert_eq!(inventory.positive_uses, inventory.negative_uses);
    assert_eq!(inventory.producers, 40 * 4096 + 512);
    let graph = original_graph_digest(&air.plan).unwrap();
    assert_eq!(dense_graph_digest(&air.plan).unwrap(), graph);
    let (range_before, range_after) = range_digests(&air.plan).unwrap();
    assert_eq!(range_before, range_after);
    let (hash_before, hash_after) = hash_digests(&air.plan).unwrap();
    assert_eq!(hash_before, hash_after);
    assert_eq!(
        (
            air.width(),
            air.preprocessed_width(),
            air.num_public_values()
        ),
        (512, 668, 32)
    );
    assert_eq!(air.main_next_row_columns(), (496..=508).collect::<Vec<_>>());
    assert!(air.preprocessed_next_row_columns().is_empty());
    // The metadata-only child must never materialize a complete PP matrix.
    assert!(air.preprocessed_trace().is_none());
    let pp_digest = full_pp_digest(&air.plan).unwrap();
    // Root native r27/r28 captured all rows before adding any proof backend.
    assert_eq!(
        hex(pp_digest),
        "6f4bdb87a034d70a662a9948098c5c6aefb1d69f67b0c8aedee50f3e1e465170"
    );
    let report = assessment::assess(&air).unwrap();
    report.require_resources().unwrap();
    eprintln!(
        "dense_data_inventory domain={} H={} MAIN={} PP={} PV={} graph_rows={} Cw_rows=514 Cs_rows=66 range_only_rows={} range_coefficients={} gates={} original_messages={} packed={} AUX={} chunks={} graph_semantic={} range_semantic={} hash_preimages={} dense_full_pp={} query_specific_PP=true MAIN_allocated=false full_PP_matrix=false PP_commitment=false proof=false accepted=false",
        hex(Sha256::digest(DOMAIN)),
        H,
        W,
        PP,
        PV,
        GRAPH_ROWS,
        H - RANGE_ONLY_FIRST,
        inventory.coefficients,
        inventory.gates,
        PORTS,
        report.packed_lookup_count(),
        report.aux_width(),
        report.chunks(),
        hex(graph),
        hex(range_after),
        hex(hash_after),
        hex(full_pp_digest(&air.plan).unwrap())
    );
}

#[test]
fn dense_boundary_slots_and_all_range_hash_checkpoints_are_verifier_owned() {
    let expected = expected().unwrap();
    let plan = plan::Plan::new(&expected).unwrap();
    for index in [22528, 24576, 32768, 81919] {
        let p = plan.row(index / SLOTS).unwrap();
        let slot = index % SLOTS;
        let gate = plan.gate(index).unwrap().unwrap();
        assert_eq!(p[ACTIVE + slot], Val::ONE);
        assert_eq!(
            p[POINTWISE + slot],
            Val::from_bool((24576..32768).contains(&index))
        );
        assert_eq!(
            p[FANOUT + slot],
            Val::from_bool((22528..24576).contains(&index))
        );
        for (i, &value) in gate.linear.iter().flatten().enumerate() {
            assert_eq!(p[COEFFICIENTS + 4 * slot + i], Val::from_u64(value))
        }
    }
    let last = plan.row(GRAPH_ROWS - 1).unwrap();
    assert_eq!(
        last[ACTIVE..ACTIVE + SLOTS]
            .iter()
            .filter(|&&x| x == Val::ONE)
            .count(),
        48
    );
    for slot in 48..56 {
        assert!(
            plan.gate((GRAPH_ROWS - 1) * SLOTS + slot)
                .unwrap()
                .is_none()
        );
        assert_eq!(plan::count(&last, 4 * slot).unwrap(), 0);
        assert_eq!(plan::count(&last, 4 * slot + 2).unwrap(), 0)
    }
    assert!(matches!(plan.row(H), Err(Error::Shape)));
    assert!(matches!(plan.gate(GRAPH_ROWS * SLOTS), Err(Error::Shape)));
    let mut emitted = 0;
    for row in 0..H {
        let p = plan.row(row).unwrap();
        assert_eq!(p[FLAGS + old_pp::RANGE], Val::ONE);
        assert_eq!(p[FLAGS + old_pp::RESET], Val::from_bool(row % 4 == 0));
        assert_eq!(p[FLAGS + old_pp::EMIT], Val::from_bool(row % 4 == 3));
        assert_eq!(p[POWER], Val::from_u64(1u64 << (12 * (row % 4))));
        if row % 4 == 3 {
            assert_eq!(
                p[GRAPH_PORTS + 18],
                Val::from_u64(old_pp::node(40, row / 4).unwrap())
            );
            emitted += 1
        } else {
            assert_eq!(p[GRAPH_PORTS + 18], Val::ZERO)
        }
        let hash = (CW_FIRST..RANGE_ONLY_FIRST).contains(&row);
        assert_eq!(p[FLAGS + old_pp::HASH], Val::from_bool(hash));
        if hash {
            let start = if row < CS_FIRST { CW_FIRST } else { CS_FIRST };
            let length = if row < CS_FIRST { 514 } else { 66 };
            assert_eq!(p[FLAGS + old_pp::FIRST], Val::from_bool(row == start));
            assert_eq!(
                p[FLAGS + old_pp::LAST],
                Val::from_bool(row + 1 == start + length)
            );
            assert_eq!(p[FLAGS + old_pp::CONTEXT], Val::from_bool(row == start));
            assert_eq!(p[FLAGS + old_pp::SALT], Val::from_bool(row == start + 1));
            assert_eq!(p[FLAGS + old_pp::PAYLOAD], Val::from_bool(row >= start + 2));
        }
        if row >= RANGE_ONLY_FIRST {
            assert!(p[..GRAPH_PORTS].iter().all(|&x| x == Val::ZERO));
            assert!(p[ACTIVE..].iter().all(|&x| x == Val::ZERO))
        }
    }
    assert_eq!(emitted, 512);
}
