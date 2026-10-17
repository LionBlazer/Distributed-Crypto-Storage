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
