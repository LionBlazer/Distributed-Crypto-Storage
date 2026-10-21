//! Metadata-only owning checks. These never construct a private MAIN or proof.
use super::{air::QueryMaskAir, layout::*, *};
use p3_air::BaseAir;
use p3_field::PrimeCharacteristicRing;

#[test]
fn closed_inventory_covers_full_statement_and_every_scaled_or_zero_coefficient() {
    let plan = Plan::closed().expect("complete fixed schedule");
    plan.inventory().expect("all4208 fields, all526 absorbs");
    let mut statement_fields = Vec::new();
    let mut coefficient_fields = Vec::new();
    for row in &plan.rows {
        for lane in 0..8 {
            match row.field(lane) {
                Field::Statement(index) => statement_fields.push(index),
                Field::ScaledMask { coefficient, bit } => {
                    assert_eq!(coefficient + bit, 255);
                    coefficient_fields.push(coefficient);
                }
                Field::Context(_) | Field::VectorSalt(_) | Field::Zero => {}
            }
        }
    }
    assert_eq!(statement_fields, (0..96).collect::<Vec<_>>());
    assert_eq!(coefficient_fields, (0..256).collect::<Vec<_>>());
    for coefficient in 256..4096 {
        let index = 16 + coefficient;
        let absorb = plan.rows[12 + index / 8];
        assert_eq!(absorb.field(index % 8), Field::Zero, "W{coefficient}");
    }
    assert_eq!(plan.rows[11].field(7), Field::Statement(95));
    assert_eq!(plan.rows[525].field(7), Field::Zero);
    for row in ABSORBS..HEIGHT {
        assert_eq!(plan.pp_row(row), [Val::ZERO; PP_WIDTH]);
    }
    assert_eq!(SCALE, 16389);
    assert_eq!(T, 65537);
}

#[test]
fn incomplete_or_reordered_streams_fail_closed_before_sdk_or_witness_allocation() {
    let mut plan = Plan::closed().unwrap();
    plan.rows.pop();
    assert_eq!(plan.inventory().unwrap_err(), "query-mask:closed-shape");
    let mut plan = Plan::closed().unwrap();
    plan.rows.swap(14, 45);
    assert_eq!(plan.inventory().unwrap_err(), "query-mask:foreign-route:14");
    let mut plan = Plan::closed().unwrap();
    plan.rows[11].block = 10;
    assert_eq!(plan.inventory().unwrap_err(), "query-mask:foreign-route:11");
}

#[test]
fn independent_expected_binds_both_roots_context_nonce_and_distinct_outer_role() {
    let make = |statement, vector, context, nonce| {
        Expected::checked(statement, vector, context, nonce)
            .unwrap()
            .values()
    };
    // Explicitly NONSECRET metadata claims. No opening or SQL answer is asserted.
    let statement = [Val::from_u32(7); 4];
    let vector = [Val::from_u32(11); 4];
    let context = [Val::from_u32(13); 8];
    let nonce = [0x71; 32];
    let original = make(statement, vector, context, nonce);
    for i in 0..4 {
        let mut changed = statement;
        changed[i] += Val::ONE;
        let values = make(changed, vector, context, nonce);
        assert_eq!(
            values[PUBLIC_STATEMENT + i],
            original[PUBLIC_STATEMENT + i] + Val::ONE
        );
        assert_ne!(values, original);
        let mut changed = vector;
        changed[i] += Val::ONE;
        assert_ne!(make(statement, changed, context, nonce), original);
    }
    for i in 0..8 {
        let mut changed = context;
        changed[i] += Val::ONE;
        assert_ne!(make(statement, vector, changed, nonce), original);
        let mut changed = nonce;
        changed[4 * i] ^= 1;
        assert_ne!(make(statement, vector, context, changed), original);
    }
    assert_eq!(original[PUBLIC_ROLE], Val::from_u32(QUERY_ROLE));
    assert_ne!(
        profile(),
        super::super::profile(),
        "new outer profile, original inner Stmt96"
    );
    assert!(Expected::checked(statement, vector, context, [0; 32]).is_err());
}

#[test]
fn actual_sdk_metadata_and_workspace_policy_precede_all_preprocessing_commitments() {
    let air = QueryMaskAir::closed().expect("sole closed factory");
    assert_eq!(air.width(), 649);
    assert_eq!(air.preprocessed_width(), 49);
    assert_eq!(air.num_public_values(), 33);
    assert!(air.preprocessed_next_row_columns().is_empty());
    let report = assessment::assess(&air).expect("actual complete symbolic AIR");
    report.log();
    assert_eq!(report.base, 1572);
    assert_eq!(report.extension, 0);
    assert_eq!(report.degree, 4);
    assert_eq!(report.chunks, 8);
    assert_eq!(report.openings, 1447);
    assert_eq!(report.hiding_rows, 404);
    report
        .resources
        .require_policy()
        .expect("explicit reserves, not whole-process RSS");
    let mut malformed = air;
    malformed.plan.rows.pop();
    assert!(assessment::assess(&malformed).is_err());
}
