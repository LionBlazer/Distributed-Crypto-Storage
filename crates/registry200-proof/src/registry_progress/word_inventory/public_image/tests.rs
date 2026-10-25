//! Actual Word Predicate AIR and native folder, explicit PUBLIC residues only.
mod full_locations;
mod native_pp;
use super::*;
use p3_air::RowWindow;
use p3_batch_stark::{
    BatchProverTranscript, BatchShape, folder::VerifierConstraintFolderWithLookups,
};
use p3_matrix::{
    dense::RowMajorMatrixView,
    stack::{VerticalPair, ViewPair},
};
use p3_symmetric::MerkleCap;
use p3_uni_stark::VerifierConstraintFolder;

fn pair(rows: &[Vec<E>; 2]) -> ViewPair<'_, E> {
    VerticalPair::new(
        RowMajorMatrixView::new_row(&rows[0]),
        RowMajorMatrixView::new_row(&rows[1]),
    )
}

struct EvaluatedRows {
    main: [Vec<E>; 2],
    pp: [Vec<E>; 2],
    aux_base: [Vec<E>; 2],
}

/// The independent oracle uses real ProgramAir + packed native LogUp and the
/// SDK concrete verifier folder. Native transcript code supplies all68 actual
/// per-context lookup values; the ring evaluator does not supply this reference.
struct NativeFolderOracle {
    air: ProgramAir,
    packed: Lookups<F>,
    original: TwoAdicMultiplicativeCoset<F>,
    public: Vec<F>,
    coins: WordCoins,
    randomness: Vec<E>,
}
impl NativeFolderOracle {
    fn new(metadata: &Metadata) -> Self {
        let air = owning_air().unwrap();
        let public = Expected::checked(metadata).unwrap().values().to_vec();
        let original = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 9).unwrap();
        let gadget = LogUpGadget::new();
        let unpacked = Lookups::<F>::from_air::<E, _>(&air);
        let log = get_log_num_quotient_chunks_for_domain::<F, E, _, _>(
            &air,
            AirLayout::from_air(&air),
            original,
            &unpacked,
            1,
            &gadget,
        );
        assert_eq!(log, 2);
        assert_eq!(unpacked.len(), 98);
        let packed = unpacked.pack_same_bus_with_degree(1usize << log, |lookup| {
            gadget.constraint_degree_with_transition(lookup, original.transition_degree_multiple())
        });
        assert_eq!(packed.len(), PACKED);
        let widest = packed
            .iter()
            .flat_map(|lookup| &lookup.elements)
            .map(Vec::len)
            .max()
            .unwrap();
        assert_eq!(widest, 5);
        let shape = BatchShape {
            trace_widths: vec![MAIN],
            public_value_counts: vec![309],
            preprocessed_widths: vec![PP],
            has_preprocessed_commitment: true,
            num_lookup_instances: 1,
            lookup_pow_bits: 0,
            has_randomization_commitment: true,
            ood_pow_bits: 0,
        };
        let mut challenger = bfv_hiding_stark::hash::Challenger::new();
        let mut native =
            BatchProverTranscript::<_, F, E, MerkleCap<F, [u8; 32]>>::new(&mut challenger, shape);
        native.instance_bindings(&[10]);
        native.main_phase(MerkleCap::new(vec![[0x31; 32]]), &[public.as_slice()]);
        native.preprocessed_phase(Some(MerkleCap::new(vec![[0x32; 32]])));
        let contexts = [&*packed];
        let (randomness, pow) = native.lookup_phase(&contexts, &gadget);
        assert_eq!(pow, Some(F::ZERO));
        assert_eq!(randomness.len(), 1);
        let randomness = randomness.into_iter().next().unwrap();
        assert_eq!(randomness.len(), 2 * PACKED);
        // First native context is assigned first-seen bus0 by the SDK itself.
        let beta = randomness[1];
        let alpha = randomness[0] - beta.exp_u64(widest as u64);
        let constraint_alpha =
            native.permutation_phase(Some(MerkleCap::new(vec![[0x33; 32]])), &[E::ZERO]);
        native.abort();
        Self {
            air,
            packed,
            original,
            public,
            coins: WordCoins {
                lookup_alpha: alpha,
                lookup_beta: beta,
                constraint_alpha,
            },
            randomness,
        }
    }

    fn fold(&self, point: E, rows: &EvaluatedRows, embedding: usize) -> E {
        let randomness = self
            .randomness
            .iter()
            .map(|value| value.repeated_frobenius(embedding))
            .collect::<Vec<_>>();
        self.fold_with_randomness(point, rows, embedding, &randomness)
    }

    fn fold_with_randomness(
        &self,
        point: E,
        rows: &EvaluatedRows,
        embedding: usize,
        randomness: &[E],
    ) -> E {
        let sigma = |value: E| value.repeated_frobenius(embedding);
        let basis = sigma(E::from_basis_coefficients_fn(|b| F::from_bool(b == 1)));
        let powers: [E; 5] = core::array::from_fn(|b| basis.exp_u64(b as u64));
        let aux: [Vec<E>; 2] = core::array::from_fn(|next| {
            rows.aux_base[next]
                .as_chunks::<5>()
                .0
                .iter()
                .map(|coordinates| {
                    coordinates
                        .iter()
                        .zip(powers)
                        .map(|(&value, power)| value * power)
                        .sum()
                })
                .collect()
        });
        let terminal = [E::ZERO];
        let selectors = self.original.selectors_at_point(point);
        let mut folder = VerifierConstraintFolderWithLookups::<bfv_hiding_stark::hash::Config> {
            inner: VerifierConstraintFolder {
                main: pair(&rows.main),
                preprocessed: pair(&rows.pp),
                preprocessed_window: RowWindow::from_two_rows(&rows.pp[0], &rows.pp[1]),
                periodic_values: &[],
                public_values: &self.public,
                is_first_row: selectors.is_first_row,
                is_last_row: selectors.is_last_row,
                is_transition: selectors.is_transition,
                alpha: sigma(self.coins.constraint_alpha),
                accumulator: E::ZERO,
            },
            permutation: pair(&aux),
            permutation_challenges: randomness,
            permutation_values: &terminal,
        };
        LogUpGadget::new().eval_air_and_lookups(&self.air, &mut folder, &self.packed);
        folder.inner.accumulator * selectors.inv_vanishing
    }
}

fn at(p: &[F], point: E) -> E {
    ring::evaluate(p, point)
}
fn rows(coefficients: &[Poly], point: E, h: F) -> [Vec<E>; 2] {
    [point, point * h].map(|x| coefficients.iter().map(|p| at(p, x)).collect())
}
fn assert_base_coordinates(actual: E, quotient: &QuotientResidues, point: F) {
    let coefficients: &[F] = actual.as_basis_coefficients_slice();
    for (b, p) in quotient.coordinates().iter().enumerate() {
        assert_eq!(at(p, E::from(point)), E::from(coefficients[b]));
    }
}

#[test]
fn actual_word_complete_public_fold_and_three_native_bus_assignments_match_the_sdk_folder() {
    let metadata = Metadata::sample(true);
    let mut program = WordFoldProgram::from_metadata(&metadata).unwrap();
    let mut oracle = NativeFolderOracle::new(&metadata);
    let point = F::from_u32(49);
    let domain = DisclosureDomain::checked(E::from(point), &[]).unwrap();
    assert_eq!((domain.target.degree(), domain.source_degree()), (1, 2));
    let main = (0..MAIN)
        .map(|i| vec![F::from_usize(i + 1), F::from_usize(2 * i + 3)])
        .collect::<Vec<_>>();
    let aux = (0..AUX_BASE)
        .map(|i| vec![F::from_usize(i + 5), F::from_usize(3 * i + 7)])
        .collect::<Vec<_>>();
    let input = PublicResidues::checked(&domain, main.clone(), aux.clone()).unwrap();
    assert_eq!(program.lookup_randomness(&oracle.coins), oracle.randomness);
    assert_eq!(program.bus_names.len(), 3);
    assert_eq!(program.max_message_width, 5);
    let mut values = EvaluatedRows {
        main: rows(&main, E::from(point), domain.h),
        pp: rows(program.public_pp_coefficients(), E::from(point), domain.h),
        aux_base: rows(&aux, E::from(point), domain.h),
    };
    let quotient = program.fold(&domain, &input, &oracle.coins).unwrap();
    assert_eq!(quotient.expected_binding(), &probe::binding(&metadata));
    assert_eq!(quotient.modulus(), domain.target_modulus());
    assert_base_coordinates(oracle.fold(E::from(point), &values, 0), &quotient, point);
    let wrong = Challenges::new(oracle.coins.lookup_alpha, oracle.coins.lookup_beta, 2, 1);
    let wrong = (0..PACKED)
        .flat_map(|_| [wrong.bus_prefix[0], oracle.coins.lookup_beta])
        .collect::<Vec<_>>();
    assert_ne!(wrong, oracle.randomness);
    assert_ne!(
        oracle.fold_with_randomness(E::from(point), &values, 0, &wrong),
        oracle.fold(E::from(point), &values, 0)
    );

    // All309 PUBLIC words are the real owner-derived inputs. Change only the
    // final independently supplied BlindSql word, preserving the structural PP.
    let mut changed = metadata.clone();
    changed.blind_sql[7] += F::ONE;
    let changed_program = WordFoldProgram::from_metadata(&changed).unwrap();
    assert_eq!(
        program.public_pp_coefficients(),
        changed_program.public_pp_coefficients()
    );
    let changed_q = changed_program
        .fold(&domain, &input, &oracle.coins)
        .unwrap();
    assert_ne!(changed_q.coordinates(), quotient.coordinates());
    oracle.public = Expected::checked(&changed).unwrap().values().to_vec();
    assert_base_coordinates(oracle.fold(E::from(point), &values, 0), &changed_q, point);
    oracle.public = Expected::checked(&metadata).unwrap().values().to_vec();

    // Negative arithmetic control is confined to this test. The factory has no
    // caller-PP override: alter the used current PUBLIC flag's constant term.
    let column = super::super::plan::PUBLIC_ACTIVE;
    let saved = program.pp_coefficients[column].clone();
    if program.pp_coefficients[column].is_empty() {
        program.pp_coefficients[column].push(F::ONE)
    } else {
        program.pp_coefficients[column][0] += F::ONE
    }
    values.pp[0][column] += E::ONE;
    values.pp[1][column] += E::ONE;
    let changed_pp_q = program.fold(&domain, &input, &oracle.coins).unwrap();
    assert_ne!(changed_pp_q.coordinates(), quotient.coordinates());
    assert_base_coordinates(
        oracle.fold(E::from(point), &values, 0),
        &changed_pp_q,
        point,
    );
    program.pp_coefficients[column] = saved;
    // Actual Word AIR reads current PP; native PCS still opens the full next PP.
    values.pp[0][column] -= E::ONE;
    values.pp[1][column] += E::from_u32(7);
    assert_base_coordinates(oracle.fold(E::from(point), &values, 0), &quotient, point);

    let mut control = metadata;
    control.predicate = false;
    assert!(matches!(
        WordFoldProgram::from_metadata(&control),
        Err("Word-public-image-requires-Predicate")
    ));
    let foreign = DisclosureDomain::checked(E::from_u32(9), &[]).unwrap();
    assert!(program.fold(&foreign, &input, &oracle.coins).is_err());
    assert!(PublicResidues::checked(&domain, main, aux[..174].to_vec()).is_err());
    assert!(DisclosureDomain::checked(E::ONE, &[]).is_err());
    assert!(DisclosureDomain::checked(E::from(point), &[F::ZERO]).is_err());
}

#[test]
fn word_target_source_maps_retain_nonbase_frobenius_and_overlapping_rotations() {
    let u = E::from_basis_coefficients_fn(|i| F::from_bool(i == 1));
    let s = F::GENERATOR;
    let h = F::two_adic_generator(9);
    let domain = DisclosureDomain::checked(u, &[s, s * h]).unwrap();
    assert_eq!((domain.target.degree(), domain.source_degree()), (7, 13));
    let p = vec![F::from_u32(5), F::from_u32(9), F::from_u32(11)];
    let shifted = ring::add(&p, &ring::mul(domain.source_modulus(), &[F::ONE, F::ONE]));
    assert_eq!(domain.project(&p, false), domain.project(&shifted, false));
    assert_eq!(domain.project(&p, true), domain.project(&shifted, true));
    let conjugate = DisclosureDomain::checked(u.repeated_frobenius(2), &[s, s * h]).unwrap();
    assert_eq!(domain.target_modulus(), conjugate.target_modulus());
    let base = DisclosureDomain::checked(E::from_u32(49), &[s, s * h]).unwrap();
    assert_eq!((base.target.degree(), base.source_degree()), (3, 5));
}
