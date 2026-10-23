//! PUBLIC metadata-only endpoints, not ciphertexts claimed to encrypt a witness.
//! No evidence, native prover, private query execution or accepting result exists.
use super::*;
use crate::{
    Val,
    registry_progress::word::{self, Claims, Role},
    registry_progress::word_inventory::owner,
    two_lane_encoding::{self as encoding, data_formation as installed, statement::KeyBinding},
};
use bfv_ciphertext_formation::gold;
use p3_field::{PrimeCharacteristicRing, PrimeField64};

fn public_endpoint(components: usize) -> Vec<u8> {
    fn varint(mut n: usize, out: &mut Vec<u8>) {
        while n >= 128 {
            out.push((n as u8 & 127) | 128);
            n >>= 7;
        }
        out.push(n as u8);
    }
    let mut ciphertext = Vec::new();
    for _ in 0..components {
        let mut polynomial = vec![8, 2, 16];
        varint(product::N, &mut polynomial);
        polynomial.push(26);
        varint(product::N * 60 / 8, &mut polynomial);
        polynomial.resize(polynomial.len() + product::N * 60 / 8, 0);
        ciphertext.push(10);
        varint(polynomial.len(), &mut ciphertext);
        ciphertext.extend(polynomial);
    }
    ciphertext
}

fn expected() -> Expected {
    let (m, _) = owner::public_case(true);
    let word = word::Expected::checked(
        &m.source,
        Role::Predicate,
        [0xa7; 32],
        m.parent
            .into_iter()
            .flat_map(|v| u32::try_from(v.as_canonical_u64()).unwrap().to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        m.enrollment,
        Claims {
            old: m.old,
            command: m.command,
            statement: m.statement,
            next: m.next,
            result: m.result,
            blind_sql: m.blind_sql,
        },
    )
    .unwrap();
    let key = KeyBinding::new(
        m.source.statement().heads[0][8..24].try_into().unwrap(),
        [0x91; 16],
        7,
        [0x95; 32],
        [0; 32],
    )
    .unwrap();
    let child = encoding::statement::Statement {
        expected: encoding::statement::Expected::source_version(&m.source, key).unwrap(),
        encoded: [Val::ONE; 4],
    };
    let request = gold::data::Request::checked([0x93; 32], public_endpoint(2)).unwrap();
    let data = installed::Expected::checked(&request, &child).unwrap();
    let request =
        gold::Request::checked([0x94; 32], [public_endpoint(2), public_endpoint(2)]).unwrap();
    Expected::checked(&word, &data, &request, [Val::TWO; 4], public_endpoint(3)).unwrap()
}

#[test]
fn actual_closed_airs_report_five_native_arguments_and_original_lookup_counts() {
    let report = analyze(&expected(), 60).unwrap();
    let expected = [
        (Relation::SourceVersion, 10, None),
        (Relation::VersionEncoding, 10, None),
        (Relation::DataFormation, 12, Some((243, 2))),
        (Relation::PredicateWord, 10, Some((98, 5))),
        (Relation::QueryFormation, 12, Some((248, 2))),
    ];
    for (component, (relation, committed_log, lookup)) in report.components().iter().zip(expected) {
        let bound = component.bound();
        let params = bound.parameters();
        assert_eq!(component.relation(), relation);
        assert_eq!(bound.committed_log(), committed_log);
        assert_eq!(bound.logup(), lookup);
        assert_eq!(bound.analysis_m(), 3);
        assert!(params.num_constraints > 0);
        assert_eq!(
            params.num_quotient_chunks,
            if matches!(
                relation,
                Relation::SourceVersion | Relation::VersionEncoding
            ) {
                16
            } else {
                8
            }
        );
        assert!(bound.union_bits() > 235.0);
        assert_eq!(bound.terms().len(), if lookup.is_some() { 7 } else { 6 });
        eprintln!(
            "closed_classical_air relation={relation:?} committed_log={committed_log} constraints={} degree={} chunks={} openings={} original_logup={lookup:?} rbr_sum_bits={} terms={:?} proof=false sql=false",
            params.num_constraints,
            params.air_max_constraint_degree,
            params.num_quotient_chunks,
            params.num_batched_functions,
            bound.union_bits(),
            bound.terms(),
        );
    }
    assert_eq!(
        report.components()[4]
            .bound()
            .parameters()
            .num_batched_functions,
        2327
    );
    assert_eq!(report.pit_single_bits(), 306);
    print_report(&report);
}

#[test]
fn actual_sdk_patterns_group_lookup_pairs_and_complete_query_index_vectors() {
    let manifests = super::super::transcript::inspect(&expected()).unwrap();
    for (manifest, lookup, expected_groups) in manifests
        .iter()
        .zip([(false, 14), (false, 14), (true, 17), (true, 15), (true, 17)])
        .map(|(m, (lookup, groups))| (m, lookup, groups))
    {
        let stark = manifest.stark().challenge_group_base_draws().unwrap();
        assert_eq!(stark, if lookup { vec![10, 5, 5] } else { vec![5, 5] });
        let pcs = manifest.pcs().challenge_group_base_draws().unwrap();
        assert_eq!(pcs, [5]);
        let fri = manifest.fri().challenge_group_base_draws().unwrap();
        assert_eq!(fri.last(), Some(&192));
        assert!(fri[..fri.len() - 1].iter().all(|n| *n == 5));
        assert_eq!(stark.len() + pcs.len() + fri.len(), expected_groups);
    }
}

fn dkt_ceil_sqrt_ratio(numerator: u128, denominator: u128) -> u128 {
    let floor = (numerator / denominator).isqrt();
    floor + u128::from(floor * floor * denominator < numerator)
}

// DKT Section 7.2 Equation (88), using the order-zero support at m=3.
// This independently counts its monomials by closed integer sums, not SDK helpers.
// Primary: https://quangvdao.github.io/papers/authored/reed-solomon-codes-beyond-johnson.pdf
fn dkt_m3_curve_counts(k: u128, n: u128, functions: u128) -> (u128, u128, u128, u128) {
    // Bound every intermediate in this private fixed-metadata certificate.
    assert!(k.is_power_of_two() && (2..=4096).contains(&k));
    assert_eq!(n, 8 * k);
    assert!((2..=u128::from(u32::MAX)).contains(&functions));
    let degree = k - 1;
    let ell = functions - 1;
    let agreements = dkt_ceil_sqrt_ratio(49 * n * n, 288); // ceil(alpha*n).
    let x_cutoff = dkt_ceil_sqrt_ratio(49 * degree * n, 4);
    let y_degree = dkt_ceil_sqrt_ratio(49 * n, 4 * degree) - 1;
    let z_degree = (49 * ell * n).div_ceil(12 * degree) - 1;
    assert!(agreements > k && agreements <= n);
    assert!(x_cutoff <= 3 * agreements);
    assert!(y_degree >= 3);
    assert!(x_cutoff > degree * y_degree && z_degree >= ell * y_degree);

    // Count i+degree*j < x_cutoff and ell*j+h <= z_degree.
    // The preceding inequalities ensure every j-slice is untruncated.
    let slices = y_degree + 1;
    let sum_j = y_degree * slices / 2;
    let sum_j_squared = y_degree * slices * (2 * y_degree + 1) / 6;
    let variables = (z_degree + 1) * (x_cutoff * slices - degree * sum_j)
        - ell * (x_cutoff * sum_j - degree * sum_j_squared);
    // At m=3: sum_b(3-b)=6 and sum_b b*(3-b)=4.
    let equations = n * (6 * (z_degree + 1) - 4 * ell);

    // Equation (37)'s positive-part tail matters at the last positive-degree
    // FRI codes: k=2 and k=4 have y_degree > 2*degree+1.
    let psi =
        1 + (2 * degree - 1) * (2 * y_degree - 1) + 2 * y_degree.saturating_sub(2 * degree + 1);
    let denominator = agreements - degree;
    let numerator = ((2 * y_degree - 1) * z_degree + ell * (n - k) * y_degree) * denominator
        + (n - degree) * (ell * y_degree + z_degree * psi);
    (variables, equations, numerator, denominator)
}

#[test]
fn actual_five_opening_inventories_fit_the_single_partition_dkt_certificate() {
    let expected = expected();
    let report = analyze(&expected, 60).unwrap();
    let manifests = super::super::transcript::inspect(&expected).unwrap();
    assert_eq!(report.components().len(), 5);
    assert_eq!(manifests.len(), 5);
    let fixed_functions = [14502u128, 3492, 2622, 3024, 2327];

    for ((component, manifest), expected_functions) in report
        .components()
        .iter()
        .zip(&manifests)
        .zip(fixed_functions)
    {
        let bound = component.bound();
        let parameters = bound.parameters();
        let k = 1u128 << bound.committed_log();
        let n = 1u128 << manifest.lde_log();
        let functions: u128 = manifest
            .pcs_shape()
            .claimed_evaluation_counts
            .iter()
            .flatten()
            .flatten()
            .map(|&count| count as u128)
            .sum();
        assert_eq!(functions, parameters.num_batched_functions as u128);
        assert_eq!(functions, expected_functions);

        // Static pinned SDK constructor AND receiver-claim association:
        // raw MAIN/AUX and PP have N rows; hiding/zero padding doubles them.
        // R already has k=2N rows and uses inner commit without another doubling.
        // Quotient domain k*2^r split into 2^(r+1) chunks gives N rows,
        // then get_quotient_ldes doubles before the inner blowup.
        let original_height = k / 2;
        let blowup = 1u128 << parameters.fri_log_blowup;
        let chunks = parameters.num_quotient_chunks as u128;
        assert!(chunks >= 2 && chunks.is_power_of_two());
        assert_eq!(blowup, 8);
        let quotient_domain = k * (chunks / 2);
        let quotient_chunk = quotient_domain / chunks;
        assert_eq!(quotient_chunk, original_height);
        assert_eq!(
            [
                2 * original_height * blowup,
                k * blowup,
                quotient_chunk * 2 * blowup,
            ],
            [n; 3]
        );

        let (variables, equations, numerator, denominator) = dkt_m3_curve_counts(k, n, functions);

        assert!(
            variables > equations,
            "{:?}: no interpolant",
            component.relation()
        );
        // Compare Eq. (88) with ell*343*n^2/(3*(k-1)) exactly, without logs.
        assert!(3 * (k - 1) * numerator <= (functions - 1) * 343 * n * n * denominator);
        // All five closed AIRs have one input-height partition individually.
        // MatrixGeometry has no height tap: these are source-derived equations,
        // not runtime matrix-height observations or a complete native RBR proof.
        eprintln!(
            "dkt_powers_curve_partition relation={:?} k={k} n={n} functions={functions} variables={variables} equations={equations} exceptional_numerator={numerator} exceptional_denominator={denominator} source_derived_height_partitions=1 runtime_height_observation=false native_rbr=false proof=false",
            component.relation(),
        );
    }
}

#[test]
fn actual_binary_fri_schedules_cover_every_positive_degree_and_the_constant_tail() {
    // PUBLIC metadata only. These finite interpolation certificates neither run
    // native proofs nor establish the complete RBR/state-restoration correspondence.
    let expected = expected();
    let report = analyze(&expected, 60).unwrap();
    let manifests = super::super::transcript::inspect(&expected).unwrap();
    let expected_round_counts = [10usize, 10, 12, 10, 12];
    let mut positive_child_dimensions = std::collections::BTreeSet::new();
    let mut constant_tails = 0usize;
    let mut fold_cases = 0usize;

    for ((component, manifest), expected_rounds) in report
        .components()
        .iter()
        .zip(&manifests)
        .zip(expected_round_counts)
    {
        let bound = component.bound();
        let shape = manifest.fri_shape();
        let initial_k = 1u128 << bound.committed_log();
        let initial_n = 1u128 << manifest.lde_log();
        assert_eq!(shape.log_arities, vec![1; expected_rounds]);
        assert_eq!(shape.log_arities.len(), bound.committed_log());
        assert_eq!(shape.num_queries, 192);
        assert_eq!(shape.index_bits, manifest.lde_log());
        assert_eq!(shape.log_blowup, 3);
        assert_eq!(shape.max_log_arity, 1);
        assert_eq!(shape.final_poly_len, 1);
        assert_eq!(initial_n, 8 * initial_k);

        let mut parent_k = initial_k;
        let mut parent_n = initial_n;
        for (&log_arity, matrix_log) in shape.log_arities.iter().zip(manifest.fri_matrix_logs()) {
            assert_eq!(log_arity, 1);
            let child_k = parent_k / 2;
            let child_n = parent_n / 2;
            // Native FRI commits the current word as binary rows. Its matrix
            // height is the child evaluation length, not a new input PCS height.
            assert_eq!(child_n, 1u128 << matrix_log);
            assert_eq!(child_n, 8 * child_k);
            let parent_agreements = dkt_ceil_sqrt_ratio(49 * parent_n * parent_n, 288);
            let child_agreements = dkt_ceil_sqrt_ratio(49 * child_n * child_n, 288);
            assert!(2 * child_agreements >= parent_agreements);

            if child_k == 1 {
                // For E(y)+beta*O(y), every pair of distinct coefficient pairs
                // has at most one collision beta. Outside their union, any
                // constant matching >=2 positions lifts to constant E and O on
                // that same complete agreement set. This handles degree zero
                // directly; the positive-degree (k-1) denominator is unavailable.
                assert_eq!(
                    (parent_k, parent_n, child_n, child_agreements),
                    (2, 16, 8, 4)
                );
                let exceptional_pairs = child_n * (child_n - 1) / 2;
                assert_eq!(exceptional_pairs, 28);
                assert!(3 * (initial_k - 1) * exceptional_pairs <= 343 * initial_n * initial_n);
                constant_tails += 1;
            } else {
                // One binary fold is a line in its two even/odd coefficient
                // words: ell=1, hence functions=2, on this CHILD code.
                let (variables, equations, numerator, denominator) =
                    dkt_m3_curve_counts(child_k, child_n, 2);
                assert!(variables > equations);
                assert!(3 * (child_k - 1) * numerator <= 343 * child_n * child_n * denominator);
                assert!(
                    3 * (initial_k - 1) * numerator <= 343 * initial_n * initial_n * denominator
                );
                // These exact references detect omission of Psi's positive tail.
                if child_k == 2 {
                    assert_eq!(
                        (variables, equations, numerator, denominator),
                        (6475, 6272, 55887, 6)
                    );
                }
                if child_k == 4 {
                    assert_eq!(
                        (variables, equations, numerator, denominator),
                        (8976, 8320, 155798, 11)
                    );
                }
                positive_child_dimensions.insert(child_k);
            }
            fold_cases += 1;
            parent_k = child_k;
            parent_n = child_n;
        }
        assert_eq!((parent_k, parent_n), (1, 8));
    }
    assert_eq!(fold_cases, 54);
    assert_eq!(constant_tails, 5);
    assert_eq!(
        positive_child_dimensions.into_iter().collect::<Vec<_>>(),
        (1..=11).map(|log| 1u128 << log).collect::<Vec<_>>()
    );
}

fn print_report(report: &Report) {
    eprintln!(
        "closed_classical_composition log2_budget={} bcs_algebraic_bits={} bcs_collision_bits={} pit_bits={} conditional_sum_bits={} ideal_transcript_mapping_unproven=true binding_terms_excluded=true cryptographic_security_assessed=false sql_accepted=false",
        report.log2_query_budget(),
        report.bcs_algebraic_bits(),
        report.bcs_collision_bits(),
        report.pit_budget_bits(),
        report.conditional_error_bits(),
    );
}

#[test]
fn larger_adaptive_budget_charges_all_five_bcs_terms_and_the_pit_attempts() {
    let report = analyze(&expected(), 40).unwrap();
    let mut previous = f64::INFINITY;
    for b in [40, 60, 64, 120] {
        let current = compose(report.components.clone(), b).unwrap();
        // Independent probability-space expression: five full BCS collision
        // terms, five algebraic terms, and one adaptive eighteen-point PIT term.
        let q = 2.0f64.powi(b as i32);
        let algebraic: f64 = report
            .components()
            .iter()
            .map(|c| q * 2.0f64.powf(-c.bound().union_bits()))
            .sum();
        let collisions = 15.0 * (q * q + 1.0) / 2.0f64.powi(255);
        let pit = q * 2.0f64.powi(-306);
        let reported = 2.0f64.powf(-current.conditional_error_bits());
        assert!(reported >= algebraic + collisions + pit);
        assert!(reported < 4.1 * (algebraic + collisions + pit));
        assert!(current.conditional_error_bits() < previous);
        assert_eq!(current.pit_budget_bits(), 306.0 - f64::from(b));
        if b == 64 {
            assert!(
                current.conditional_error_bits() < 128.0,
                "a fixed-budget error ceiling must not be relabelled 128 workbits"
            );
        }
        previous = current.conditional_error_bits();
        print_report(&current);
    }
    assert!(matches!(
        compose(report.components.clone(), 121),
        Err(Error::Budget)
    ));
    assert!(matches!(analyze(&expected(), u32::MAX), Err(Error::Budget)));
}

#[test]
fn the_actual_product_geometry_supports_the_coarse_306_bit_pit_lemma() {
    assert_eq!(product::N, 4096);
    assert_eq!(product::POINTS, 18);
    // The smallest original Q field is the worst case, not a P intermediate.
    assert_eq!(product::QP.iter().min().copied(), Some(1_073_668_097));
    let degree = (2 * product::N - 2) as u128;
    let smallest = u128::from(*product::QP.iter().min().unwrap());
    let denominator = 1u128 << 17;
    assert!(degree * (denominator + 1) < smallest);
    assert!(degree * denominator * (denominator + 1) < 1u128 << 64);
    assert_eq!(product_single_bits().unwrap(), 306);
}

#[test]
fn fixed_five_transcript_manifest_keeps_real_salt_geometry_and_opening_order() {
    let expected = expected();
    let report = analyze(&expected, 60).unwrap();
    let manifests = super::super::transcript::inspect(&expected).unwrap();
    let widths: [&[usize]; 5] = [
        &[14, 7170, 224],
        &[14, 1665, 224],
        &[14, 521, 112, 672, 419],
        &[14, 577, 112, 718, 184],
        &[14, 425, 112, 549, 429],
    ];
    // Reviewed public seed/geometry snapshots, captured independently of proofs.
    let snapshots = [
        "406e2791ce0b1198980fda765c99e528903723aa3b8977a9ce7e2cb333fe933a",
        "378d90a66c4e82ec06b8dbe84b7b3d6538bc6aafc3a50d1393f1428ee3ff1977",
        "8536f9022089addb76a956eaefdcdf269b3cd01e4a004d6692739c840925699e",
        "9eab76dfbb11338eb63ff875189798ce1d3768d60bc96c5e3d6984db5e3d7119",
        "7884b9c9949e5ce746cc46f482928d87d1fef2b142c8b84322b3d64242e2d742",
    ];
    for (i, manifest) in manifests.iter().enumerate() {
        assert_eq!(hex(&manifest.snapshot_digest()), snapshots[i]);
        let leafs: Vec<_> = manifest
            .commitments()
            .iter()
            .map(|g| g.salted_leaf_width())
            .collect();
        assert_eq!(leafs, widths[i]);
        assert_eq!(manifest.fri_salted_leaf_width(), 14);
        assert_eq!(manifest.fri_matrix_logs().last(), Some(3));
        let count: usize = manifest
            .pcs_shape()
            .claimed_evaluation_counts
            .iter()
            .flatten()
            .flatten()
            .sum();
        assert_eq!(
            count,
            report.components()[i]
                .bound()
                .parameters()
                .num_batched_functions
        );
        assert_eq!(
            manifest.fri_shape(),
            report.components()[i].bound().fri_shape()
        );
        let name: &[u8] = if i < 2 {
            b"p3-uni-stark"
        } else {
            b"p3-batch-stark"
        };
        assert_eq!(&manifest.stark().protocol_id()[1..1 + name.len()], name);
        assert!(
            manifest
                .stark()
                .observed_fields()
                .iter()
                .all(|v| v.as_canonical_u64() < (1u64 << 56))
        );
        eprintln!(
            "closed_transcript_manifest relation={:?} snapshot_sha256={} leaf_widths={leafs:?} stark_pattern={} pcs_pattern={} fri_pattern={} lde_log={} proof=false sql=false",
            report.components()[i].relation(),
            hex(&manifest.snapshot_digest()),
            hex(manifest.stark().pattern_hash()),
            hex(manifest.pcs().pattern_hash()),
            hex(manifest.fri().pattern_hash()),
            manifest.lde_log()
        );
    }
    assert_ne!(
        manifests[0].snapshot_digest(),
        manifests[1].snapshot_digest()
    );
    assert_ne!(
        manifests[2].snapshot_digest(),
        manifests[4].snapshot_digest()
    );
    // DATA/Query share the batch message-count pattern but bind distinct widths.
    assert_eq!(
        manifests[2].stark().pattern_hash(),
        manifests[4].stark().pattern_hash()
    );
    assert_ne!(
        manifests[2].stark().instance_label(),
        manifests[4].stark().instance_label()
    );
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut text = String::new();
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}
