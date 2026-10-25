//! Independent actual Role3 SDK comparisons with explicitly public arithmetic.
mod full_locations;
mod nonbase;
use super::*;
use crate::{
    source::version::SourceVersionExpected,
    two_lane_encoding::statement::{Expected, KeyBinding},
};
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

fn source() -> &'static SourceVersionExpected {
    static SOURCE: OnceLock<SourceVersionExpected> = OnceLock::new();
    // The fixture seals explicit PUBLIC constants with a public key. Owner::seal
    // may draw OS nonces. No witness(), FHE, private trace or proof is requested.
    SOURCE.get_or_init(crate::source::hash::public_fixture_expected)
}
fn key_binding(source: &SourceVersionExpected, epoch: u32) -> KeyBinding {
    KeyBinding::new(
        source.statement().heads[0][8..24].try_into().unwrap(),
        [0x91; 16],
        epoch,
        [0x95; 32],
        crate::source::statement::encode_digest([F::from_u32(3); 4]),
    )
    .unwrap()
}
fn public_statement(source: &SourceVersionExpected, epoch: u32, encoded: [F; 4]) -> Statement {
    Statement {
        expected: Expected::source_version(source, key_binding(source, epoch)).unwrap(),
        encoded,
    }
}
fn statement() -> &'static Statement {
    static STATEMENT: OnceLock<Statement> = OnceLock::new();
    // An arbitrary canonical Cw is an UNPROVED public claim, not a valid opening.
    STATEMENT.get_or_init(|| public_statement(source(), 7, [F::from_u32(17); 4]))
}
fn program() -> &'static Role3FoldProgram {
    static PROGRAM: OnceLock<Role3FoldProgram> = OnceLock::new();
    PROGRAM.get_or_init(|| Role3FoldProgram::from_statement(statement()).unwrap())
}
fn oracle() -> &'static NativeOracle {
    static ORACLE: OnceLock<NativeOracle> = OnceLock::new();
    ORACLE.get_or_init(|| NativeOracle::new(statement()))
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
                    // Arbitrary PUBLIC arithmetic, never an honest trace or valid witness.
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
    air: crate::two_lane_encoding::air::EncodingAir,
    domain: TwoAdicMultiplicativeCoset<F>,
    public: Vec<F>,
}
impl NativeOracle {
    fn new(statement: &Statement) -> Self {
        Self {
            air: super::super::air(statement).unwrap(),
            domain: TwoAdicMultiplicativeCoset::new(F::ONE, 9).unwrap(),
            public: statement.values(),
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
        // Config is only a TYPE parameter; no Config, prover or verifier is built.
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
fn role3_periodic_polynomials_match_native_h512_and_reject_pp_style_padding() {
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
fn complete_role3_fold_matches_all_five_native_coordinates_without_witness() {
    let program = program();
    let point = E::from_u32(49);
    let domain = DisclosureDomain::checked(point, &[]).unwrap();
    assert_eq!(domain.target.degree(), 1);
    assert_eq!(domain.enlarged.degree(), 2);
    let main = public_polynomials(1);
    let input = PublicResidues::checked(&domain, main.clone()).unwrap();
    let quotient = program.fold(&domain, &input, alpha()).unwrap();
    let direct = oracle().fold(&main, point, alpha());
    let coordinates: &[F] = direct.as_basis_coefficients_slice();
    for (polynomial, &coordinate) in quotient.coordinates.iter().zip(coordinates) {
        assert_eq!(polynomial.len(), usize::from(coordinate != F::ZERO));
        assert_eq!(polynomial.first().copied().unwrap_or(F::ZERO), coordinate);
    }
    assert_eq!(quotient.modulus, domain.target.modulus());
    assert_eq!(quotient.expected_public, statement().values());
    assert_eq!(quotient.constraint_count, program.base.len());
    assert_eq!(quotient.cached_nodes, program.node_count);
    quotient.require_statement(statement()).unwrap();
    eprintln!(
        "role3_public_image scalar_native=true coordinates=5 constraints={} cached_nodes={} source_nodes={} target_degree=1 source_degree=2 public_only=true full192=false proof=false admission=false",
        quotient.constraint_count, quotient.cached_nodes, program.node_count
    );
}

#[test]
fn role3_residues_keep_domains_full_cw_key_and_same_image_cstate_associations() {
    let program = program();
    let domain = DisclosureDomain::checked(E::from_u32(49), &[]).unwrap();
    let main = public_polynomials(1);
    let input = PublicResidues::checked(&domain, main.clone()).unwrap();
    let mut quotient = program.fold(&domain, &input, alpha()).unwrap();
    quotient.require_statement(statement()).unwrap();
    // A binding-only corruption must fail even when all740 public words match.
    quotient.expected_binding[0] ^= 1;
    assert!(quotient.require_statement(statement()).is_err());
    quotient.expected_binding[0] ^= 1;
    quotient.require_statement(statement()).unwrap();
    assert_eq!(
        quotient.expected_binding,
        super::super::binding(statement())
    );
    let foreign = DisclosureDomain::checked(E::from_u32(9), &[]).unwrap();
    assert!(matches!(
        program.fold(&foreign, &input, alpha()),
        Err("Role3-residue-domain-association")
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
        Err("Role3-symbolic-DAG-source-bound")
    ));

    let mut changed_cw = statement().clone();
    changed_cw.encoded[0] += F::ONE;
    assert_eq!(
        changed_cw.expected.encoding_context(),
        statement().expected.encoding_context()
    );
    let changed_epoch = public_statement(source(), 8, statement().encoded);

    // Reuse the SAME source images/heads: a new Owner::seal would consume fresh
    // OS nonces and change the version, invalidating this same-version control.
    let old = source().statement();
    let images: [Vec<u8>; 2] = core::array::from_fn(|i| {
        old.heads[i]
            .iter()
            .chain(&old.packets[i])
            .copied()
            .collect()
    });
    let heads: [_; 2] = core::array::from_fn(|i| {
        compact_store::Commitment::decode(&old.heads[i], crate::source::statement::limits())
            .unwrap()
    });
    let mut state = old.open_commitment;
    state[0] += F::ONE;
    let other_source = SourceVersionExpected::checked(
        [&images[0], &images[1]],
        [&heads[0], &heads[1]],
        crate::source::statement::encode_digest(old.key_commitment),
        crate::source::statement::encode_digest(state),
    )
    .unwrap();
    assert_eq!(other_source.version_id(), source().version_id());
    assert_eq!(other_source.statement().heads, old.heads);
    assert_eq!(other_source.statement().packets, old.packets);
    let changed_state = public_statement(&other_source, 7, statement().encoded);

    for (label, changed) in [
        ("Cw", changed_cw),
        ("key_epoch", changed_epoch),
        ("C_state", changed_state),
    ] {
        // Each altered complete claim is legitimate metadata for its OWN AIR.
        // It cannot be adopted as the original endpoint or called a valid proof.
        assert_ne!(changed.values(), statement().values(), "{label}");
        assert_ne!(
            super::super::binding(&changed),
            quotient.expected_binding,
            "{label}"
        );
        assert_eq!(
            quotient.require_statement(&changed),
            Err("Role3-quotient-expected-association")
        );
        let changed_program = Role3FoldProgram::from_statement(&changed).unwrap();
        let changed_q = changed_program.fold(&domain, &input, alpha()).unwrap();
        changed_q.require_statement(&changed).unwrap();
        assert!(changed_q.require_statement(statement()).is_err());
        assert_ne!(changed_q.coordinates, quotient.coordinates, "{label}");
        let direct = NativeOracle::new(&changed).fold(&main, E::from_u32(49), alpha());
        let coordinates: &[F] = direct.as_basis_coefficients_slice();
        for (polynomial, &coordinate) in changed_q.coordinates.iter().zip(coordinates) {
            assert_eq!(
                polynomial.first().copied().unwrap_or(F::ZERO),
                coordinate,
                "{label}"
            );
        }
        assert_eq!(changed_q.cached_nodes, changed_program.node_count);
    }
    eprintln!(
        "role3_public_image full_statement_association=true public_words=740 Cw_changed=true key_epoch_changed=true Cstate_changed_same_images_same_version=true source_nodes={} full192=false proof=false admission=false",
        program.node_count
    );
}
