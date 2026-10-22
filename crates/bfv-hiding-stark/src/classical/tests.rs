//! Public nonsecret metadata examples; no prover, witness, RNG or network is used.
use super::*;

fn small_air() -> StarkSecurityParams {
    StarkSecurityParams {
        fri_log_blowup: 3,
        fri_log_final_poly_len: 0,
        fri_max_log_arity: 1,
        fri_num_queries: 192,
        fri_commit_proof_of_work_bits: 0,
        fri_query_proof_of_work_bits: 0,
        num_modulus_bits: 319,
        collision_resistance: 128,
        num_constraints: 1,
        air_max_constraint_degree: 2,
        num_quotient_chunks: 4,
        max_combo: 2,
        num_batched_functions: 20,
        grinding: GrindingSites::NONE,
    }
}

fn term<'a>(bound: &'a AlgebraicBound, label: &str) -> &'a AlgebraicTerm {
    bound
        .terms()
        .iter()
        .find(|term| term.label() == label)
        .unwrap()
}

#[test]
fn a_two_point_air_uses_paper_list_squared_and_original_lookup_messages() {
    let bound = analyze(&small_air(), 10, Some((3, 5))).unwrap();

    // For k=1024,n=8192,m=3 the paper list size is 24576/1018.
    // The four quotient chunks dominate D: 5*1024+1=5121.
    // These rational references do not use the calculator's SDK term helpers.
    let q = 2.0f64.powi(319);
    let ali_probability = 24576.0 / (1018.0 * q);
    let deep_probability = (24576.0 * 24576.0 * 5121.0) / (1018.0 * 1018.0 * q);
    let lookup_probability = 21504.0 / q; // 3 * 1024 * (5+2)
    // At m=3 the line-MCA count is 343*n^2/(3*(k-1)); it also
    // dominates the second conservative binary-fold commit contribution.
    let line_count = 343.0 * 8192.0 * 8192.0 / (3.0 * 1023.0);
    for (label, probability) in [
        ("air-composition", ali_probability),
        ("deep-ali", deep_probability),
        ("batch-combination", 19.0 * line_count / q),
        ("ldt-commit-phase", line_count / q),
        ("ldt-query-phase", (49.0f64 / 288.0).powi(96)),
        ("logup-fingerprint", lookup_probability),
    ] {
        let reported_probability = 2.0f64.powf(-term(&bound, label).bits());
        assert!(reported_probability >= probability);
        assert!(reported_probability < 4.1 * probability);
    }
    assert_eq!(term(&bound, "logup-fingerprint").bits(), 303.0);
    assert_eq!(bound.analysis_m(), 3);
    assert_eq!(bound.logup(), Some((3, 5)));
    assert!((bound.paper_list_size() - 24.141453831041257).abs() < 1e-12);
}

#[test]
fn binary_fri_shapes_charge_the_actual_biased_query_index_width() {
    for (committed_log, index_bits, bias_low, bias_high) in
        [(10, 13, 1.2e-13, 1.3e-13), (12, 15, 4.9e-13, 5.0e-13)]
    {
        let bound = analyze(&small_air(), committed_log, None).unwrap();
        assert_eq!(bound.committed_log(), committed_log);
        assert_eq!(bound.fri_shape().index_bits, index_bits);
        assert_eq!(bound.fri_shape().log_arities, vec![1; committed_log]);
        assert!(bound.query_bias_bits() >= bias_low);
        assert!(bound.query_bias_bits() <= bias_high);
        // ((7/6)/sqrt(8))^192 gives 245.300655... unrounded bits.
        // Whole-bit rounding and the explicit one-bit margin yield 244.
        assert_eq!(term(&bound, "ldt-query-phase").bits(), 244.0);
    }
}

#[test]
fn union_charges_each_probability_and_contains_no_hash_workbit_cap() {
    let bound = analyze(&small_air(), 10, None).unwrap();

    let sum: f64 = bound
        .terms()
        .iter()
        .map(|term| 2.0f64.powf(-term.bits()))
        .sum();
    let reported_probability = 2.0f64.powf(-bound.union_bits());
    assert!(reported_probability >= sum);
    assert!(reported_probability < 4.1 * sum);
    assert!(bound.union_bits() > 240.0);
    assert!(bound.union_bits() < 245.0);
    assert_eq!(bound.terms().len(), 5);
    assert!(
        bound
            .terms()
            .iter()
            .all(|term| term.label() != "commitment-collision")
    );
}

#[test]
fn doubling_constraints_cannot_improve_the_air_composition_bound() {
    let mut parameters = small_air();
    let one = analyze(&parameters, 10, None).unwrap();
    parameters.num_constraints = 2;

    let two = analyze(&parameters, 10, None).unwrap();

    assert_eq!(
        term(&one, "air-composition").bits() - 1.0,
        term(&two, "air-composition").bits()
    );
    assert_eq!(two.parameters().num_constraints, 2);
    assert_eq!(one.parameters().num_constraints, 1);
}

#[test]
fn unsupported_parameters_and_overflowing_metadata_reject() {
    let changes: &[fn(&mut StarkSecurityParams)] = &[
        |p| p.fri_log_blowup = 4,
        |p| p.fri_log_final_poly_len = 1,
        |p| p.fri_max_log_arity = 2,
        |p| p.fri_num_queries = 191,
        |p| p.fri_commit_proof_of_work_bits = 1,
        |p| p.fri_query_proof_of_work_bits = 1,
        |p| p.grinding.lookup_challenge = 1,
        |p| p.grinding.out_of_domain = 1,
        |p| p.grinding.batch_combination = 1,
        |p| p.num_modulus_bits = 320,
        |p| p.collision_resistance = 256,
        |p| p.num_constraints = 0,
        |p| p.num_constraints = usize::MAX,
        |p| p.air_max_constraint_degree = 0,
        |p| p.air_max_constraint_degree = usize::MAX,
        |p| p.num_quotient_chunks = 2,
        |p| p.num_quotient_chunks = 3,
        |p| p.num_quotient_chunks = 32,
        |p| p.num_quotient_chunks = usize::MAX,
        |p| p.max_combo = 0,
        |p| p.max_combo = usize::MAX,
        |p| p.num_batched_functions = 1,
        |p| p.num_batched_functions = usize::MAX,
    ];
    for change in changes {
        let mut parameters = small_air();
        change(&mut parameters);
        assert!(
            analyze(&parameters, 10, None).is_err(),
            "accepted {parameters:?}"
        );
    }
    for log in [0, 9, 11, 63, usize::MAX] {
        assert!(analyze(&small_air(), log, None).is_err());
    }
    for lookup in [(0, 5), (3, 0), (usize::MAX, 5), (3, usize::MAX)] {
        assert!(analyze(&small_air(), 10, Some(lookup)).is_err());
    }
}

#[test]
fn diagnostic_does_not_pretend_to_authenticate_caller_metadata() {
    let mut parameters = small_air();
    parameters.num_constraints = 17;

    let bound = analyze(&parameters, 10, None).unwrap();

    // This intentionally numeric entry point accepts a representable claimed
    // inventory. AIR-to-metadata association belongs to the trusted owning crate.
    assert_eq!(bound.parameters().num_constraints, 17);
    assert_eq!(bound.logup(), None);
    assert!(
        bound
            .terms()
            .iter()
            .all(|term| term.bits().is_finite() && term.bits() > 0.0)
    );
    assert!(bound.union_bits().is_finite());
}

#[test]
fn native_uni_stark_degree_five_hint_keeps_its_sixteen_committed_chunks() {
    let mut parameters = small_air();
    parameters.air_max_constraint_degree = 5;
    parameters.num_quotient_chunks = 16;

    let bound = analyze(&parameters, 10, None).unwrap();

    assert_eq!(bound.parameters().num_quotient_chunks, 16);
    // Seventeen degree-k segments dominate the conservative DEEP numerator.
    let reference = (24576.0f64 / 1018.0).powi(2) * 17409.0 / 2.0f64.powi(319);
    let reported = 2.0f64.powf(-term(&bound, "deep-ali").bits());
    assert!(reported >= reference && reported < 4.1 * reference);
    // The batch DATA/Word rate gate is enforced by its actual owning assessor,
    // not inferred from this low-level numeric metadata API.
}
