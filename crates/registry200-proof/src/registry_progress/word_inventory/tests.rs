//! Observable inventory refusals; NO proof/SQL/fixture-positive substitutes.
use super::inventory_encoding::full_ir_bytes;
use super::plan::*;
use super::*;
use expr::Node;
use p3_air::BaseAir;
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

#[test]
fn packed_layout_preserves_full_ir_and_rejects_a_missing_public_range_flag() {
    use sha2::{Digest, Sha512};
    for predicate in [false, true] {
        let pool =
            complete(&Metadata::sample(predicate)).expect("new explicit typed-public factory");
        let before = full_ir_bytes(&pool);
        let mut plan = Plan::new(pool).expect("complete packing");
        super::goldens::require_plan(&plan)
            .expect("literal actual PUBLIC27 full IR and PP, no capture fallback");
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
        // Actual PUBLIC27 literals are mandatory above before any native proof.
        // No old-profile relabel or auto-accepted first-capture fallback exists.
        assert_eq!(plan.phases[PUBLIC], PUBLIC_GROUPS);
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
fn actual_dynamic_public_security_and_resource_report_precedes_preprocessing() {
    for predicate in [false, true] {
        let air = air::ProgramAir {
            plan: make(predicate),
        };
        let report = super::assessment::assess(&air)
            .expect("actual complete AIR, native packing, baseline and composed security");
        // First NEW-profile capture: native assessment derives the real packing,
        // chunks, AUX and openings. Do not relabel the old PV0/PP708 goldens.
        assert_eq!(air.num_public_values(), super::public_values::COUNT);
        assert!(report.chunks().is_power_of_two() && report.chunks() <= 8);
        assert!(report.packed_lookup_count() > 0);
        assert!(report.aux_width() > 0);
        assert!(report.openings() > WIDTH + PP_WIDTH);
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
            "foreign height is not the closed structural-PUBLIC v2 shape"
        );
    }
}
