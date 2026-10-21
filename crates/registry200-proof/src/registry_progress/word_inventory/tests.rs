//! Observable inventory refusals; NO proof/SQL/fixture-positive substitutes.
use super::plan::*;
use super::*;
use expr::Node;
fn make(predicate: bool) -> Plan {
    Plan::new(complete(&Metadata::sample(predicate)).expect("complete closed factory"))
        .expect("all nodes and streams routed")
}
#[test]
fn both_roles_cover_every_source_bank_and_continuation_field() {
    for predicate in [false, true] {
        let plan = make(predicate);
        plan.inventory().unwrap();
        let c = plan.coverage();
        for (bank, n) in [
            ("stream/source", 680),
            ("stream/enrollment", 64),
            ("stream/old", 208),
            ("stream/new", 208),
            ("stream/command", 160),
            ("stream/result", 160),
            ("stream/statement", 96),
            ("stream/old-progress", 48),
            ("stream/new-progress", 48),
            ("old/serialized", 208),
            ("new/serialized", 208),
        ] {
            assert_eq!(c.get(bank), Some(&n), "{bank}");
        }
        assert_eq!(plan.hash_blocks, 209);
        assert_eq!(plan.phases.iter().sum::<usize>(), plan.rows.len());
        assert!(plan.rows.len() <= plan.height);
        assert!(plan.height >= 512);
        eprintln!(
            "word_inventory role={} {}",
            if predicate { "predicate" } else { "control" },
            plan.summary()
        );
    }
}
#[test]
fn removing_a_real_hash_or_a_serialized_bank_consumer_is_rejected() {
    let mut plan = make(true);
    let position = plan.rows.iter().position(|r| r.phase == HASH).unwrap();
    plan.rows.remove(position);
    assert!(
        plan.inventory()
            .unwrap_err()
            .starts_with("uncovered-value:")
    );
    let mut plan = make(true);
    plan.pool.fields.remove("stream/new/189");
    assert!(
        plan.inventory()
            .unwrap_err()
            .starts_with("missing-field:new/189")
    );
    let mut plan = make(false);
    let id = plan.pool.fields["stream/old/84"];
    plan.pool.fields.insert("old/serialized/85".into(), id);
    assert_eq!(plan.inventory().unwrap_err(), "foreign-208-serialization");
}
#[test]
fn duplicate_reads_and_all_offphase_cells_have_fixed_public_routes() {
    for predicate in [false, true] {
        let plan = make(predicate);
        assert_eq!(plan.pool.reads.len(), 4);
        assert_eq!(plan.phases[MASK_READ], 4);
        assert_eq!(plan.phases[MASK_TABLE], 32);
        assert_eq!(plan.phases[POLICY_TABLE], 25);
        assert_eq!(plan.pool.predicate, predicate);
        for (row_index, row) in plan.rows.iter().enumerate() {
            let p = plan.pp_row(row_index);
            assert_eq!(p.iter().take(PHASES).filter(|v| **v == Val::ONE).count(), 1);
            for cell in row.ports.len()..PORTS {
                assert_eq!(p[PORT_META + 5 * cell], Val::ZERO);
            }
            for bit in 0..BITS {
                assert_eq!(p[RANGE_BITS + bit], Val::from_bool(row.bits[bit]));
            }
            if row.phase == MASK_READ {
                assert!(matches!(
                    plan.pool.nodes[row.ports[1].id],
                    Node::MaskRead(_)
                ));
            }
        }
        assert!(plan.pp_row(plan.height).into_iter().all(|v| v == Val::ZERO));
    }
    // Repeated use of the SAME input is two consumers, never set-deduplicated.
    let b = Builder::new(true);
    let age = b.input("test/age", expr::Ty::Bits(8));
    let a = b.mask_read(age);
    let z = b.mask_read(age);
    assert_ne!(a.id, z.id);
    let p = b.pool.borrow();
    assert_eq!(p.reads[0].age, p.reads[1].age);
}
#[test]
fn native_complete_symbolic_prescreen_reports_both_roles_without_proving() {
    for predicate in [false, true] {
        let air = air::ProgramAir {
            plan: make(predicate),
        };
        let result =
            air::symbolic_report(&air).expect("actual SDK symbolic/default-packing inspection");
        assert!(result.contains("complete=true"));
        assert!(result.contains("admitted=false"));
        assert!(result.contains("security_assessed=false"));
        eprintln!(
            "word_inventory_native role={} {}",
            if predicate { "predicate" } else { "control" },
            result
        );
    }
}

// Exhaustive semantic serialization. Rowlayout and retired construction caches
// are excluded; every live Node/annotation/assertion/range/stream/field is here.
fn full_ir_bytes(pool: &expr::Pool) -> Vec<u8> {
    use p3_field::PrimeField64;
    fn size(v: &mut Vec<u8>, n: usize) {
        v.extend(u64::try_from(n).expect("bounded IR").to_le_bytes());
    }
    fn ids(v: &mut Vec<u8>, s: &[usize]) {
        size(v, s.len());
        for n in s {
            size(v, *n);
        }
    }
    fn text(v: &mut Vec<u8>, s: &str) {
        size(v, s.len());
        v.extend(s.as_bytes());
    }
    let mut v = b"DCS/research/word208/full-semantic-IR/v1".to_vec();
    v.push(u8::from(pool.predicate));
    size(&mut v, pool.nodes.len());
    for node in &pool.nodes {
        match node {
            Node::Constant(x) => {
                v.push(0);
                v.extend(x.as_canonical_u64().to_le_bytes());
            }
            Node::Input(s, t) => {
                v.push(1);
                text(&mut v, s);
                match t {
                    expr::Ty::Gold => v.push(0),
                    expr::Ty::Bool => v.push(1),
                    expr::Ty::U32 => v.push(2),
                    expr::Ty::Bits(n) => {
                        v.push(3);
                        v.push(*n)
                    }
                    expr::Ty::Mode => v.push(4),
                }
            }
            Node::Arith(o, a, b) => {
                v.push(2);
                v.push(match o {
                    expr::Op::Add => 0,
                    expr::Op::Sub => 1,
                    expr::Op::Mul => 2,
                    expr::Op::Neg => 3,
                });
                size(&mut v, *a);
                size(&mut v, *b);
            }
            Node::Hash(a, b) => {
                v.push(3);
                size(&mut v, *a);
                size(&mut v, *b);
            }
            Node::Policy(a, b) => {
                v.push(4);
                size(&mut v, *a);
                size(&mut v, *b);
            }
            Node::PolicyFrequency(a) => {
                v.push(5);
                size(&mut v, *a);
            }
            Node::MaskBit(a, b) => {
                v.push(6);
                size(&mut v, *a);
                size(&mut v, *b);
            }
            Node::MaskFrequency(a, b) => {
                v.push(7);
                size(&mut v, *a);
                size(&mut v, *b);
            }
            Node::MaskByte(a) => {
                v.push(8);
                size(&mut v, *a);
            }
            Node::MaskRead(a) => {
                v.push(9);
                size(&mut v, *a);
            }
        }
    }
    ids(&mut v, &pool.assertions);
    size(&mut v, pool.ranges.len());
    for (i, n) in &pool.ranges {
        size(&mut v, *i);
        v.push(*n);
    }
    size(&mut v, pool.hashes.len());
    for h in &pool.hashes {
        text(&mut v, &h.label);
        ids(&mut v, &h.input);
        ids(&mut v, &h.output);
    }
    size(&mut v, pool.policies.len());
    for p in &pool.policies {
        size(&mut v, p.a);
        size(&mut v, p.b);
        ids(&mut v, &p.output);
    }
    size(&mut v, pool.mask.len());
    for m in &pool.mask {
        ids(&mut v, &m.bits);
        ids(&mut v, &m.frequencies);
        size(&mut v, m.byte);
    }
    size(&mut v, pool.reads.len());
    for r in &pool.reads {
        size(&mut v, r.age);
        size(&mut v, r.output);
    }
    size(&mut v, pool.fields.len());
    for (s, i) in &pool.fields {
        text(&mut v, s);
        size(&mut v, *i);
    }
    size(&mut v, pool.errors.len());
    for s in &pool.errors {
        text(&mut v, s);
    }
    ids(&mut v, &pool.mode_inputs);
    ids(&mut v, &pool.policy_frequencies);
    v
}
#[test]
fn packed_layout_preserves_full_ir_and_rejects_a_missing_public_range_flag() {
    use sha2::{Digest, Sha512};
    for predicate in [false, true] {
        let pool = complete(&Metadata::sample(predicate)).expect("same executed-r1 factory");
        let before = full_ir_bytes(&pool);
        let mut plan = Plan::new(pool).expect("complete packing");
        let after = full_ir_bytes(&plan.pool);
        assert_eq!(before, after, "packing mutated full semantic IR");
        let hex = Sha512::digest(&before)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        eprintln!(
            "word_inventory_ir role={} bytes={} sha512={} before_after_equal=true",
            if predicate { "predicate" } else { "control" },
            before.len(),
            hex
        );
        let (expected_len, expected_hash) = if predicate {
            (
                287395,
                "a6655a0ba1c2eb0685a27f70412080569e1433c2442221d4e7c00b560ce7467d74585ef368a48aa041d19527051ea1d0cf4669650164938d130fe2627f452388",
            )
        } else {
            (
                282032,
                "5608559f3d6a93b9e582853525d2cdda4afc3fb4438bce2b693036de0c77f776e0c2ef0f3ab2bfb1d4a2d4b4172ec212841c351ffc705642a32e00ffa624869a",
            )
        };
        assert_eq!(before.len(), expected_len, "executed-r2 full Pool bytes");
        assert_eq!(hex, expected_hash, "executed-r2 full Pool golden");
        assert_eq!(plan.phases[INPUT], 0);
        assert_eq!(plan.phases[RANGE], 0);
        assert_eq!(plan.phases[HASH], 209);
        let (mut policies, mut range_rows, mut inputs, mut inactive) = (0, 0, 0, 0);
        for (index, row) in plan.rows.iter().enumerate() {
            let p = plan.pp_row(index);
            assert_eq!(p[RANGE_ON_HASH], Val::from_bool(row.range));
            if row.range {
                range_rows += 1;
                assert_eq!(row.phase, HASH);
                assert!(row.ports.len() >= 20);
                for slot in 0..8 {
                    assert!(!row.ports[12 + slot].provider);
                }
            }
            if row.phase == HASH {
                let start = if row.range { 20 } else { 12 };
                inputs += row.ports[start..].len();
                for port in &row.ports[start..] {
                    assert!(port.provider);
                    assert!(matches!(plan.pool.nodes[port.id], Node::Input(..)));
                }
            }
            for slot in 0..POLICY_SLOTS {
                let active = slot < row.policies.len();
                assert_eq!(p[POLICY_ACTIVE + slot], Val::from_bool(active));
                if active {
                    assert_eq!(row.phase, POLICY_READ);
                    policies += 1;
                } else if row.phase == POLICY_READ {
                    inactive += 1;
                    for port in 5 * slot..5 * slot + 5 {
                        assert_eq!(p[PORT_META + 5 * port], Val::ZERO);
                    }
                }
            }
        }
        assert_eq!(range_rows, plan.pool.ranges.len().div_ceil(8));
        assert_eq!(policies, plan.pool.policies.len());
        assert_eq!(
            inputs,
            plan.pool
                .nodes
                .iter()
                .filter(|n| matches!(n, Node::Input(..)))
                .count()
        );
        assert!(inactive > 0, "partial policy row exercised");
        plan.rows
            .iter_mut()
            .find(|r| r.range)
            .expect("real range block")
            .range = false;
        assert_eq!(plan.inventory().unwrap_err(), "inactive-range-bits");
    }
}

#[test]
fn actual_r2_security_and_resource_report_precedes_preprocessing() {
    for predicate in [false, true] {
        let air = air::ProgramAir {
            plan: make(predicate),
        };
        let report = super::assessment::assess(&air)
            .expect("actual complete AIR, native packing, baseline and composed security");
        assert_eq!(
            (
                report.chunks(),
                report.packed_lookup_count(),
                report.aux_width(),
                report.openings()
            ),
            (8, 34, 175, 3012),
            "derive exact r2 shape including both native MAIN/PP rotations"
        );
        report
            .require_resources()
            .expect("checked metadata reserves fit unchanged whole-PID cap");
        // Ordinary malformed metadata only, never a cryptographic rejection claim.
        let mut bad = air::ProgramAir {
            plan: make(predicate),
        };
        bad.plan.height = 1024;
        assert!(
            super::assessment::assess(&bad).is_err(),
            "foreign height is not r2"
        );
    }
}
