//! PUBLIC NONSECRET tests own the fixed engine, not any operation admission policy.
use super::*;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

struct SquareAir;
impl BaseAir<Val> for SquareAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for SquareAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let x = main.current_slice()[0];
        b.assert_eq(x * x, b.public_values()[0]);
    }
}
#[test]
fn actual_nonzero_public_value_proof_has_real_hiding_and_rejects_changed_value() {
    let air = SquareAir;
    let (parameters, report) = analyze(&air).unwrap();
    report.require_target().unwrap();
    let config = config().unwrap();
    let public = [Val::from_u8(49)];
    let trace = RowMajorMatrix::new(vec![Val::from_u8(7); TRACE_HEIGHT], 1);
    let proof = prove_with_config(&config, &air, trace, &public).unwrap();
    verify_with_assessment(&config, &air, &parameters, report, &proof, &public).unwrap();
    assert!(proof.commitments.random.is_some());
    assert!(proof.opened_values.random.is_some());
    assert!(
        verify_with_assessment(
            &config,
            &air,
            &parameters,
            report,
            &proof,
            &[Val::from_u8(48)]
        )
        .is_err()
    );
}
struct Unsupported {
    width: usize,
    public: usize,
    boolean: bool,
}
impl BaseAir<Val> for Unsupported {
    fn width(&self) -> usize {
        self.width
    }
    fn num_public_values(&self) -> usize {
        self.public
    }
    fn assumes_boolean_trace(&self) -> bool {
        self.boolean
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for Unsupported {
    fn eval(&self, _: &mut AB) {
        panic!("unsupported metadata must reject before symbolic evaluation");
    }
}
#[test]
fn unsupported_boolean_and_unrepresentable_metadata_reject_before_symbolic_allocation() {
    for air in [
        Unsupported {
            width: 1,
            public: 0,
            boolean: true,
        },
        Unsupported {
            width: usize::MAX,
            public: 0,
            boolean: false,
        },
        Unsupported {
            width: 1,
            public: usize::MAX,
            boolean: false,
        },
    ] {
        assert!(matches!(analyze(&air), Err(Error::Shape)));
    }
}
#[test]
fn fixed_suite_parameters_keep_the_existing_hiding_geometry() {
    assert_eq!(
        (TRACE_HEIGHT, PROOF_DEGREE_BITS, QUERIES, RANDOM_CODEWORDS),
        (512, 10, 192, 5)
    );
    assert_eq!(poseidon::WIDTH, 248);
    assert_eq!(
        AllocationEstimate::for_width(9932).main_lde_bytes,
        651_231_232
    );
}

/// PUBLIC NONSECRET equations for differential assessment, never proof evidence.
struct AssessmentAir {
    periods: Vec<Vec<Val>>,
    hint: Option<usize>,
    base: bool,
    extension: bool,
    evaluations: std::sync::atomic::AtomicUsize,
}
impl BaseAir<Val> for AssessmentAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn num_periodic_columns(&self) -> usize {
        self.periods.len()
    }
    fn periodic_columns(&self) -> std::borrow::Cow<'_, [Vec<Val>]> {
        std::borrow::Cow::Borrowed(&self.periods)
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![1]
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        self.hint
    }
}
impl p3_air::Air<p3_air::symbolic::SymbolicAirBuilder<Val, Challenge>> for AssessmentAir {
    fn eval(&self, b: &mut p3_air::symbolic::SymbolicAirBuilder<Val, Challenge>) {
        use p3_air::{ExtensionBuilder, symbolic::SymbolicExpressionExt};
        use p3_field::BasedVectorSpace;
        self.evaluations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let main = b.main();
        let x = main.current_slice()[0];
        let y = main.next_slice()[1];
        let periodic = b.periodic_values().iter().copied().fold(
            <p3_air::symbolic::SymbolicAirBuilder<Val, Challenge> as AirBuilder>::Expr::ONE,
            |product, column| product * column,
        );
        if self.base {
            b.assert_zero(x * x - b.public_values()[0]);
        }
        // Deliberately interleave BASE and EXT. Assessment must count/score both
        // vectors; actual proving/verification still owns the original fold order.
        if self.extension {
            let value = SymbolicExpressionExt::from(x * x * x * x * x * periodic.clone());
            let nonbase = Challenge::from_basis_coefficients_fn(|i| Val::from_usize(i + 1));
            b.assert_zero_ext(value * nonbase);
        }
        if self.base {
            b.when_first_row().assert_zero(x);
            b.when_transition().assert_zero((x * y) * periodic);
        }
        if self.extension {
            b.assert_zero_ext(SymbolicExpressionExt::from(b.is_last_row() * y));
        }
    }
}

fn complete_security_parameters(p: &p3_uni_stark::StarkSecurityParams) -> ([usize; 13], String) {
    (
        [
            p.fri_log_blowup,
            p.fri_log_final_poly_len,
            p.fri_max_log_arity,
            p.fri_num_queries,
            p.fri_commit_proof_of_work_bits,
            p.fri_query_proof_of_work_bits,
            p.num_modulus_bits,
            p.collision_resistance,
            p.num_constraints,
            p.air_max_constraint_degree,
            p.num_quotient_chunks,
            p.max_combo,
            p.num_batched_functions,
        ],
        format!("{:?}", p.grinding),
    )
}

#[test]
fn one_actual_collection_preserves_sdk_security_for_base_extension_and_periodic_constraints() {
    use p3_field::coset::TwoAdicMultiplicativeCoset;
    use p3_uni_stark::{AirLayout, OpeningShape, ProvenSecurity, StarkSecurityParams};
    // None, base-only, extension-only and mixed constraints; no hint, an
    // undersized hint, and an overestimate; differing actual periodic degrees.
    for (periods, hint, base, extension) in [
        (vec![], None, false, false),
        (vec![], None, true, false),
        (vec![], Some(5), true, false),
        (vec![2, 512], Some(2), false, true),
        (vec![1, 2, 16, 512], None, true, true),
        (vec![512], Some(7), true, true),
    ] {
        let air = AssessmentAir {
            periods: periods
                .into_iter()
                .map(|n| (0..n).map(|i| Val::from_usize(i + 1)).collect())
                .collect(),
            hint,
            base,
            extension,
            evaluations: std::sync::atomic::AtomicUsize::new(0),
        };
        let (actual, report) = analyze(&air).unwrap();
        assert_eq!(
            air.evaluations.load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // Independent unchanged SDK route evaluates the original AIR itself.
        let fri = p3_fri::FriParameters {
            log_blowup: LOG_BLOWUP,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries: QUERIES,
            batch_proof_of_work_bits: 0,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 0,
            mmcs: (),
        };
        let expected = StarkSecurityParams::from_air::<Val, Challenge, _>(
            fri.security_regime(),
            &air,
            AirLayout::from_air::<Val>(&air),
            TwoAdicMultiplicativeCoset::new(Val::ONE, TRACE_LOG_HEIGHT).unwrap(),
            MODULUS_BITS,
            SECURITY_BITS,
            2,
            OpeningShape::hiding(RANDOM_CODEWORDS),
            fri.grinding_sites(),
        );
        assert_eq!(
            complete_security_parameters(&actual),
            complete_security_parameters(&expected)
        );
        let bound = ProvenSecurity::compute_from_proof(PROOF_DEGREE_BITS, &expected);
        assert_eq!(report.unique_decoding_bits, bound.unique_decoding_bits);
        assert_eq!(report.list_decoding_bits, bound.list_decoding_bits);
        assert_eq!(
            (
                report.constraints,
                report.degree,
                report.quotient_chunks,
                report.batched_functions
            ),
            (
                expected.num_constraints,
                expected.air_max_constraint_degree,
                expected.num_quotient_chunks,
                expected.num_batched_functions
            )
        );
    }
}
