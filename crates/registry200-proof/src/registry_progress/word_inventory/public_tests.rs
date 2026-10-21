//! First new-profile native inventory/PUBLIC binding gates, no proof acceptance.
use super::{
    Metadata, Val,
    air::ProgramAir,
    assessment, check, complete, owner,
    plan::*,
    public_values::{self, Address, Expected, Group},
    structural_setup,
    tests::full_ir_bytes,
    witness,
};
use p3_air::BaseAir;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha512};
fn pp_bytes(air: &ProgramAir) -> Vec<u8> {
    let mut v = Vec::with_capacity(air.plan.height * PP_WIDTH * 8);
    for r in 0..air.plan.height {
        for x in air.plan.pp_row(r) {
            v.extend(x.as_canonical_u64().to_le_bytes());
        }
    }
    v
}
fn fixed(m: &Metadata) -> ProgramAir {
    ProgramAir {
        plan: Plan::new(complete(m).unwrap()).unwrap(),
    }
}
#[test]
fn same_role_distinct_valid_expectations_have_identical_complete_ir_and_public_pp() {
    for role in [false, true] {
        let (a, wa) = owner::public_case_variant(role, 0);
        let (b, wb) = owner::public_case_variant(role, 1);
        let av = Expected::checked(&a).unwrap();
        let bv = Expected::checked(&b).unwrap();
        assert_ne!(av.values(), bv.values());
        assert_ne!(a.command, b.command);
        assert_ne!(a.result, b.result);
        let (aa, ta) =
            witness::prepare(&a, &wa).expect("complete honest H512 candidate or explicit overflow");
        let (ab, tb) = witness::prepare(&b, &wb).expect("second complete honest expectation");
        super::goldens::require_plan(&aa.plan).unwrap();
        super::goldens::require_plan(&ab.plan).unwrap();
        check::all(&aa, &ta, &av).unwrap();
        check::all(&ab, &tb, &bv).unwrap();
        let ai = full_ir_bytes(&aa.plan.pool);
        let bi = full_ir_bytes(&ab.plan.pool);
        assert_eq!(ai, bi, "dynamic values changed structural graph");
        let ap = pp_bytes(&aa);
        assert_eq!(ap, pp_bytes(&ab), "dynamic values changed full PP");
        assert_eq!(aa.num_public_values(), 309);
        assert_eq!(aa.plan.phases[PUBLIC], 5);
        assert_eq!(aa.plan.hash_blocks, 209);
        assert_eq!(aa.plan.stream_fields, 1672);
        // Literal actual PUBLIC27 IR/PP pins above are unconditional.
        // Independently prepared native public commitments are pinned as well.
        eprintln!(
            "word_dynamic_public_literal_guard role={} rows={} H={} MAIN={} PP={} NPV=309 full_ir_bytes={} full_ir_sha512={:x} full_pp_sha512={:x} same_role_metadata_invariant=true proof=false SQL=false",
            if role { "predicate" } else { "control" },
            aa.plan.rows.len(),
            aa.plan.height,
            WIDTH,
            PP_WIDTH,
            ai.len(),
            Sha512::digest(&ai),
            Sha512::digest(&ap)
        );
    }
}
#[test]
fn all_public_words_are_constrained_including_unused_wire_and_last_row_padding() {
    let (m, w) = owner::public_case(false);
    let expected = Expected::checked(&m).unwrap();
    let (air, mut trace) = witness::prepare(&m, &w).unwrap();
    check::all(&air, &trace, &expected).unwrap();
    for n in 0..public_values::COUNT {
        assert_eq!(Address::from_ordinal(n).ordinal(), n);
        let group = n / PORTS;
        let slot = n % PORTS;
        let row = air
            .plan
            .rows
            .iter()
            .position(|r| r.public_group == Some(group))
            .unwrap();
        assert_eq!(air.plan.rows[row].ports[slot].id, n + 1);
        assert!(air.plan.rows[row].ports[slot].provider);
    }
    let unused = Address::new(Group::BlindSql, 0).ordinal();
    assert_eq!(
        air.plan.uses[unused + 1],
        0,
        "Control ignores blinded SQL except direct PV association"
    );
    let (mut foreign, _) = owner::public_case(false);
    foreign.blind_sql[0] += Val::ONE;
    let foreign_expected = Expected::checked(&foreign).unwrap();
    assert_eq!(
        check::base(&air, &trace, &foreign_expected),
        Err(super::evaluate::Error::Base),
        "foreign independent public tuple must fail an actual ordinary constraint"
    );
    let row = air
        .plan
        .rows
        .iter()
        .position(|r| r.public_group == Some(4))
        .unwrap();
    assert_eq!(air.plan.rows[row].ports.len(), 53);
    for slot in 53..64 {
        assert_eq!(trace.0.values[row * WIDTH + 248 + slot], Val::ZERO);
        assert_eq!(air.plan.pp_row(row)[PORT_META + 5 * slot], Val::ZERO);
    }
    trace.0.values[row * WIDTH + 248 + 53] = Val::ONE;
    assert_eq!(
        check::base(&air, &trace, &expected),
        Err(super::evaluate::Error::Base)
    );
}
#[test]
fn trusted_public_preprocessing_commitment_is_role_profile_only() {
    for role in [false, true] {
        let (a, _) = owner::public_case_variant(role, 0);
        let (b, _) = owner::public_case_variant(role, 1);
        let aa = fixed(&a);
        let ab = fixed(&b);
        assert_eq!(pp_bytes(&aa), pp_bytes(&ab));
        let ar = assessment::assess(&aa).expect("actual new-profile native security prescreen");
        ar.require_resources().unwrap();
        let data = structural_setup::public_data(&aa, &ar).unwrap();
        let commitment =
            postcard::to_allocvec(&data.common.preprocessed.as_ref().unwrap().commitment).unwrap();
        drop(data);
        let br =
            assessment::assess(&ab).expect("independently derived second new-profile prescreen");
        br.require_resources().unwrap();
        let data = structural_setup::public_data(&ab, &br).unwrap();
        let other =
            postcard::to_allocvec(&data.common.preprocessed.as_ref().unwrap().commitment).unwrap();
        drop(data);
        assert_eq!(
            commitment, other,
            "identical PP must also have identical trusted native commitment"
        );
        eprintln!(
            "word_structural_public_PP role={} commitment_sha512={:x} same_role_metadata_invariant=true private_config_exposed=false proof=false",
            if role { "predicate" } else { "control" },
            Sha512::digest(&commitment)
        );
    }
}
