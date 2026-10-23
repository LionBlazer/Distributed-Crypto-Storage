//! Arithmetic/source association checks only. No original witness or proof.
use super::*;
use p3_air::RowWindow;
use p3_batch_stark::folder::VerifierConstraintFolderWithLookups;
use p3_matrix::{
    dense::RowMajorMatrixView,
    stack::{VerticalPair, ViewPair},
};
use p3_uni_stark::VerifierConstraintFolder;

fn pair(rows: &[Vec<E>; 2]) -> ViewPair<'_, E> {
    VerticalPair::new(
        RowMajorMatrixView::new_row(&rows[0]),
        RowMajorMatrixView::new_row(&rows[1]),
    )
}

#[test]
fn current_query_full_air_fold_matches_native_field_folder_without_private_inputs() {
    // Existing metadata() builds only public Expected and public ciphertext
    // bytes; no Prepared, fixture private key, trace, proof or RNG is requested.
    let expected = super::super::tests::metadata();
    let program = QueryFoldProgram::from_expected(&expected).unwrap();
    // OOD-only small case:49 is outside both original H and physical7*H32768.
    // This is not a192-query coverage claim.
    let a = F::from_u32(49);
    assert_ne!((a / F::GENERATOR).exp_u64(32768), F::ONE);
    let domain = DisclosureDomain::checked(E::from(a), &[]).unwrap();
    assert_eq!(domain.target_modulus(), &[-a, F::ONE]);
    assert_eq!(domain.source_degree(), 2);
    let main: Vec<Poly> = (0..MAIN)
        .map(|i| vec![F::from_usize(i + 1), F::from_usize(2 * i + 3)])
        .collect();
    let aux: Vec<Poly> = (0..AUX_BASE)
        .map(|i| vec![F::from_usize(i + 5), F::from_usize(3 * i + 7)])
        .collect();
    let input = PublicResidues::checked(&domain, main.clone(), aux.clone()).unwrap();
    let coins = QueryCoins {
        lookup_alpha: E::from_basis_coefficients_fn(|i| F::from_usize(i + 17)),
        lookup_beta: E::from_u32(3),
        constraint_alpha: E::from_basis_coefficients_fn(|i| F::from_usize(i + 31)),
    };
    let result = program.fold(&domain, &input, &coins).unwrap();

    // Independent evaluation uses the real concrete SDK constraint FOLDER,
    // not the symbolic ring evaluator or a recreated AIR equation. Config is a
    // TYPE argument only: no configuration/private RNG is constructed here.
    let (air, _) = native::prescreen(&expected).unwrap();
    let original_domain = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 11).unwrap();
    let gadget = LogUpGadget::new();
    let unpacked = Lookups::<F>::from_air::<E, _>(&air);
    let log = get_log_num_quotient_chunks_for_domain::<F, E, _, _>(
        &air,
        AirLayout::from_air(&air),
        original_domain,
        &unpacked,
        1,
        &gadget,
    );
    let packed = unpacked.pack_same_bus_with_degree(1usize << log, |lookup| {
        gadget
            .constraint_degree_with_transition(lookup, original_domain.transition_degree_multiple())
    });
    let points = [E::from(a), E::from(a * domain.h)];
    let main_rows: [Vec<E>; 2] = core::array::from_fn(|next| {
        main.iter()
            .map(|p| ring::evaluate(p, points[next]))
            .collect()
    });
    let pp_rows: [Vec<E>; 2] = core::array::from_fn(|next| {
        program
            .public_pp_coefficients()
            .iter()
            .map(|p| ring::evaluate(p, points[next]))
            .collect()
    });
    let aux_rows: [Vec<E>; 2] = core::array::from_fn(|next| {
        aux.as_chunks::<5>()
            .0
            .iter()
            .map(|columns| {
                // All five base-coordinate evaluations are retained before the native
                // extension-column reconstruction. At this base point each is in F.
                E::from_basis_coefficients_fn(|b| {
                    <E as ExtensionField<F>>::as_base(&ring::evaluate(&columns[b], points[next]))
                        .unwrap()
                })
            })
            .collect()
    });
    let table = Challenges::new(coins.lookup_alpha, coins.lookup_beta, 2, 1);
    let randomness = (0..PACKED)
        .flat_map(|_| [table.bus_prefix[0], coins.lookup_beta])
        .collect::<Vec<_>>();
    let terminal = [E::ZERO];
    let selectors = original_domain.selectors_at_point(points[0]);
    let mut folder = VerifierConstraintFolderWithLookups::<bfv_hiding_stark::hash::Config> {
        inner: VerifierConstraintFolder {
            main: pair(&main_rows),
            preprocessed: pair(&pp_rows),
            preprocessed_window: RowWindow::from_two_rows(&pp_rows[0], &pp_rows[1]),
            periodic_values: &[],
            public_values: &program.public,
            is_first_row: selectors.is_first_row,
            is_last_row: selectors.is_last_row,
            is_transition: selectors.is_transition,
            alpha: coins.constraint_alpha,
            accumulator: E::ZERO,
        },
        permutation: pair(&aux_rows),
        permutation_challenges: &randomness,
        permutation_values: &terminal,
    };
    gadget.eval_air_and_lookups(&air, &mut folder, &packed);
    let direct_quotient = folder.inner.accumulator * selectors.inv_vanishing;
    let direct_coordinates: &[F] = direct_quotient.as_basis_coefficients_slice();
    // A=F[X]/(X-49) has basis1, so equality here checks ALL five coefficient
    // coordinates, not merely a lossy multiplication E tensor E -> E.
    for (b, coordinate) in result.coordinates().iter().enumerate() {
        assert_eq!(
            coordinate.len(),
            usize::from(direct_coordinates[b] != F::ZERO)
        );
        assert_eq!(
            coordinate.first().copied().unwrap_or(F::ZERO),
            direct_coordinates[b]
        );
    }
    assert_eq!(result.expected_binding(), &expected.binding());
    assert_eq!(result.modulus(), &[-a, F::ONE]);
    assert_eq!(
        result.constraint_count(),
        program.base.len() + program.extension.len()
    );
    assert_eq!(program.public_pp_coefficients().len(), PP);
    assert!(
        program
            .public_pp_coefficients()
            .iter()
            .all(|p| p.len() <= 4096)
    );
    // These are public arbitrary residues, not asserted to satisfy the AIR or
    // constitute any globally valid original trace/quotient/proof.
    let foreign = DisclosureDomain::checked(E::from_u32(9), &[]).unwrap();
    assert!(matches!(
        program.fold(&foreign, &input, &coins),
        Err("Query-residue-domain-association")
    ));
    assert!(PublicResidues::checked(&domain, main, aux[..419].to_vec()).is_err());
    assert!(DisclosureDomain::checked(E::ONE, &[a]).is_err());
    assert!(DisclosureDomain::checked(E::from(a), &[F::ZERO]).is_err());
}

#[test]
fn enlarged_residues_use_two_maps_into_target_and_preserve_frobenius_orbits() {
    let u = E::from_basis_coefficients_fn(|i| F::from_bool(i == 1));
    let s = F::from_u32(7);
    let domain = DisclosureDomain::checked(u, &[s, s]).unwrap();
    assert_eq!((domain.target.degree(), domain.enlarged.degree()), (6, 12));
    // An alternative representative differs by M_T. BOTH maps into A agree.
    let p = vec![F::from_u32(5), F::from_u32(9), F::from_u32(11)];
    let alternative = ring::add(&p, &ring::mul(domain.source_modulus(), &[F::ONE, F::ONE]));
    assert_eq!(
        domain.project(&p, false),
        domain.project(&alternative, false)
    );
    assert_eq!(domain.project(&p, true), domain.project(&alternative, true));
    let conjugate = DisclosureDomain::checked(u.repeated_frobenius(2), &[s]).unwrap();
    assert_eq!(domain.target.modulus(), conjugate.target.modulus());
    // X-u is nonzero in E_coeff tensor A although collapsing X=u kills it.
    let tensor = domain.target.tensor_sub(
        &domain.target.lift(&[F::ZERO, F::ONE]),
        &domain.target.constant(u),
    );
    assert_eq!(tensor[0], vec![F::ZERO, F::ONE]);
    assert_eq!(tensor[1], vec![-F::ONE]);
    assert_eq!(
        ring::evaluate(&tensor[0], u) + u * ring::evaluate(&tensor[1], u),
        E::ZERO
    );
}
