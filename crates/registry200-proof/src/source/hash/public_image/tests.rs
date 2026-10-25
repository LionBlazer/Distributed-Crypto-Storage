//! Observable arithmetic comparisons against actual owning SDK code only.
mod full_locations;
mod nonbase;
use super::*;
use p3_air::RowWindow;
use p3_commit::{PeriodicColumns, PolynomialSpace};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::HasFrobenius;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::{
    dense::RowMajorMatrixView,
    stack::{VerticalPair, ViewPair},
};
use p3_uni_stark::VerifierConstraintFolder;
use std::sync::OnceLock;

fn expected() -> &'static SourceVersionExpected {
    static EXPECTED: OnceLock<SourceVersionExpected> = OnceLock::new();
    // The owning fixture seals explicitly PUBLIC constants with a public key.
    // This requests no fixture.witness(), FHE, private trace or Source proof.
    EXPECTED.get_or_init(super::super::public_fixture_expected)
}
fn program() -> &'static SourceFoldProgram {
    static PROGRAM: OnceLock<SourceFoldProgram> = OnceLock::new();
    PROGRAM.get_or_init(|| SourceFoldProgram::from_expected(expected()).unwrap())
}
fn oracle() -> &'static NativeOracle {
    static ORACLE: OnceLock<NativeOracle> = OnceLock::new();
    ORACLE.get_or_init(|| NativeOracle::new(expected()))
}
fn alpha() -> E {
    E::from_basis_coefficients_fn(|i| F::from_usize(7 * i + 31))
}
fn pair(rows: &[Vec<E>; 2]) -> ViewPair<'_, E> {
    VerticalPair::new(
        RowMajorMatrixView::new_row(&rows[0]),
        RowMajorMatrixView::new_row(&rows[1]),
    )
}
fn at(polynomial: &[F], point: E) -> E {
    // Independent scalar Horner; the native path never calls the Ring evaluator.
    polynomial
        .iter()
        .rev()
        .fold(E::ZERO, |value, &coefficient| value * point + coefficient)
}
fn public_polynomials(degree: usize) -> Vec<Poly> {
    (0..MAIN)
        .map(|column| {
            (0..=degree)
                .map(|d| {
                    // Explicit arbitrary public arithmetic, not a witness or honest trace.
                    F::from_usize(
                        ((column + 1) * (column + d + 12) + (d + 1) * (d + 1) + 11 * (d + 3)) % 257
                            + 1,
                    )
                })
                .collect()
        })
        .collect()
}
struct NativeOracle {
    air: crate::source::air::OpeningAir,
    domain: TwoAdicMultiplicativeCoset<F>,
    public: Vec<F>,
}
impl NativeOracle {
    fn new(expected: &SourceVersionExpected) -> Self {
        Self {
            air: super::super::air(expected).unwrap(),
            domain: TwoAdicMultiplicativeCoset::new(F::ONE, 9).unwrap(),
            public: expected.statement().values(),
        }
    }
    fn periodic(&self, point: E) -> Vec<E> {
        let columns = self.air.periodic_columns();
        self.domain
            .evaluate_periodic_columns_at(PeriodicColumns::new(&columns, N).unwrap(), point)
    }
    fn fold(&self, main: &[Poly], point: E, alpha: E) -> E {
        let h = F::two_adic_generator(9);
        let rows = [point, point * h].map(|x| main.iter().map(|p| at(p, x)).collect::<Vec<_>>());
        let empty = [Vec::<E>::new(), Vec::<E>::new()];
        let periodic = self.periodic(point);
        let selectors = self.domain.selectors_at_point(point);
        // Config is only a TYPE argument. No config, RNG, proof or accepting
        // verifier is instantiated by this independent native field oracle.
        let mut folder = VerifierConstraintFolder::<bfv_hiding_stark::hash::Config> {
            main: pair(&rows),
            preprocessed: pair(&empty),
            preprocessed_window: RowWindow::from_two_rows(&[], &[]),
            periodic_values: &periodic,
            public_values: &self.public,
            is_first_row: selectors.is_first_row,
            is_last_row: selectors.is_last_row,
            is_transition: selectors.is_transition,
            alpha,
            accumulator: E::ZERO,
        };
        self.air.eval(&mut folder);
        folder.accumulator * selectors.inv_vanishing
    }
}

#[test]
fn source_periodic_polynomials_match_native_h512_and_reject_pp_style_padding() {
    let program = program();
    let oracle = oracle();
    assert_eq!(program.periodic.len(), N);
    let h = F::two_adic_generator(9);
    let inverse_n = F::from_usize(N).inverse();
    let mut sum = Vec::new();
    for (row, polynomial) in program.periodic.iter().enumerate() {
        // Independent literal one-hot interpolation, not another inverse DFT.
        let ratio = h.exp_u64(row as u64).inverse();
        assert_eq!(polynomial.len(), N);
        for (&coefficient, power) in polynomial.iter().zip(ratio.powers()) {
            assert_eq!(coefficient, inverse_n * power);
        }
        sum = ring::add(&sum, polynomial);
    }
    assert_eq!(sum, vec![F::ONE]);
    let u = E::from_basis_coefficients_fn(|i| F::from_bool(i == 1));
    for point in [E::from_u32(49), u + E::from_u32(2)] {
        let native = oracle.periodic(point);
        assert_eq!(native.len(), N);
        for (column, polynomial) in program.periodic.iter().enumerate() {
            assert_eq!(at(polynomial, point), native[column]);
        }
        let selectors = oracle.domain.selectors_at_point(point);
        assert_eq!(native[0] * F::from_usize(N), selectors.is_first_row);
        assert_eq!(
            native[N - 1] * (F::from_usize(N) * h),
            selectors.is_last_row
        );
        assert_ne!(native[0], selectors.is_first_row);
    }
    // This is deliberately WRONG periodic logic: public PP-style padding.
    let matrix = oracle.air.periodic_columns_matrix().unwrap();
    let mut padded = matrix.with_zero_cols(N);
    padded.width = N;
    let wrong = Radix2DitParallel::<F>::default()
        .idft_batch(padded)
        .to_row_major_matrix();
    let wrong_sum = (0..2 * N)
        .map(|row| {
            wrong.values[row * N..(row + 1) * N]
                .iter()
                .copied()
                .sum::<F>()
        })
        .collect::<Vec<_>>();
    let point = E::from_u32(49);
    assert_eq!(
        at(&wrong_sum, point),
        (E::ONE + point.exp_u64(N as u64)) / E::TWO
    );
    assert_ne!(at(&wrong_sum, point), E::ONE);
}

#[test]
fn complete_source_fold_matches_all_five_native_coordinates_without_witness() {
    let program = program();
    let point = E::from_u32(49);
    let domain = DisclosureDomain::checked(point, &[]).unwrap();
    assert_eq!(domain.target.degree(), 1);
    assert_eq!(domain.enlarged.degree(), 2);
    let main = public_polynomials(1);
    let input = PublicResidues::checked(&domain, main.clone()).unwrap();
    let quotient = program.fold(&domain, &input, alpha()).unwrap();
    let direct = oracle().fold(&main, point, alpha());
    let coordinates = direct.as_basis_coefficients_slice();
    for (polynomial, &coordinate) in quotient.coordinates.iter().zip(coordinates) {
        assert_eq!(polynomial.len(), usize::from(coordinate != F::ZERO));
        assert_eq!(polynomial.first().copied().unwrap_or(F::ZERO), coordinate);
    }
    assert_eq!(quotient.modulus, domain.target.modulus());
    assert_eq!(quotient.expected_public, expected().statement().values());
    assert_eq!(quotient.constraint_count, program.base.len());
    assert_eq!(quotient.cached_nodes, program.node_count);
    quotient.require_expected(expected()).unwrap();
    eprintln!(
        "source_public_image scalar_native=true coordinates=5 constraints={} cached_nodes={} source_nodes={} target_degree=1 source_degree=2 public_only=true full192=false proof=false admission=false",
        quotient.constraint_count, quotient.cached_nodes, program.node_count
    );
}

#[test]
fn source_public_residues_keep_domains_and_full_state_association() {
    let program = program();
    let domain = DisclosureDomain::checked(E::from_u32(49), &[]).unwrap();
    let main = public_polynomials(1);
    let input = PublicResidues::checked(&domain, main.clone()).unwrap();
    let quotient = program.fold(&domain, &input, alpha()).unwrap();
    let foreign = DisclosureDomain::checked(E::from_u32(9), &[]).unwrap();
    assert!(matches!(
        program.fold(&foreign, &input, alpha()),
        Err("Source-residue-domain-association")
    ));
    assert!(PublicResidues::checked(&domain, main[..MAIN - 1].to_vec()).is_err());
    let mut oversized = main.clone();
    oversized[0].push(F::ONE);
    assert!(PublicResidues::checked(&domain, oversized).is_err());
    assert!(DisclosureDomain::checked(E::ONE, &[]).is_err());
    assert!(DisclosureDomain::checked(E::from_u32(49), &[F::ZERO]).is_err());
    assert!(DisclosureDomain::checked(E::from_u32(49), &vec![F::GENERATOR; 193]).is_err());
    let environment = Environment::new(program, &domain, &input).unwrap();
    let mut refused = Evaluator {
        ring: &domain.target,
        environment: &environment,
        cache: HashMap::new(),
        limit: 0,
    };
    assert!(matches!(
        refused.base(&program.base[0]),
        Err("Source-symbolic-DAG-source-bound")
    ));

    // Reuse the SAME public images/heads. Owner::seal in a fresh fixture would
    // draw fresh OS nonces and change the version tag before this control.
    let statement = expected().statement();
    let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
        statement.heads[i]
            .iter()
            .chain(&statement.packets[i])
            .copied()
            .collect()
    });
    let heads: [_; 2] = core::array::from_fn(|i| {
        compact_store::Commitment::decode(&statement.heads[i], crate::source::statement::limits())
            .unwrap()
    });
    let mut state = statement.open_commitment;
    state[0] += F::ONE;
    let other = SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        crate::source::statement::encode_digest(statement.key_commitment),
        crate::source::statement::encode_digest(state),
    )
    .unwrap();
    assert_eq!(other.version_id(), expected().version_id());
    assert_ne!(other.statement().values(), expected().statement().values());
    assert_eq!(
        quotient.require_expected(&other),
        Err("Source-quotient-expected-association")
    );
    // The altered full public claim is valid input to its OWN arithmetic
    // program; it must not be confused with the old endpoint or a checked proof.
    let other_program = SourceFoldProgram::from_expected(&other).unwrap();
    let other_quotient = other_program.fold(&domain, &input, alpha()).unwrap();
    other_quotient.require_expected(&other).unwrap();
    assert!(other_quotient.require_expected(expected()).is_err());
    let other_native = NativeOracle::new(&other).fold(&main, E::from_u32(49), alpha());
    for (polynomial, &coordinate) in other_quotient
        .coordinates
        .iter()
        .zip(other_native.as_basis_coefficients_slice())
    {
        assert_eq!(polynomial.first().copied().unwrap_or(F::ZERO), coordinate);
    }
}
