//! PUBLIC NONSECRET tables. Compare against the original dense lookup implementation.
extern crate std;
use super::*;
use crate::backend::GenericBackend;
use crate::config::DEFAULT_SLICED_ROUNDS;
use crate::fractional_gkr::materialize::LookupFractionSource;
use crate::zerocheck::AirZerocheck;
use alloc::vec;
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use rand::{SeedableRng, rngs::SmallRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

type F = BabyBear;
type EF = BinomialExtensionField<F, 4>;
type Challenger = DuplexChallenger<F, Poseidon2BabyBear<16>, 16, 8>;
fn challenger() -> Challenger {
    Challenger::new(Poseidon2BabyBear::new_from_rng_128(
        &mut SmallRng::seed_from_u64(0x10_51EA),
    ))
}
struct BoundaryLookup;
impl BaseAir<F> for BoundaryLookup {
    fn width(&self) -> usize {
        2
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
}
impl<AB: AirBuilder<F = F> + InteractionBuilder> Air<AB> for BoundaryLookup {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pp: AB::Expr = builder.preprocessed().current_slice()[0].into();
        let public: AB::Expr = builder.public_values()[0].into();
        let value = main.current_slice()[0]
            + main.next_slice()[1]
            + pp
            + public
            + builder.is_first_row()
            + builder.is_last_row();
        builder.push_local_interaction([
            (vec![value.clone()], Count::bounded(AB::Expr::ONE, 1)),
            (vec![value.clone()], Count::provided(-AB::Expr::ONE)),
        ]);
        builder.push_interaction(
            "streamed/shared",
            [value.clone()],
            Count::bounded(AB::Expr::ONE, 1),
        );
        builder.push_interaction("streamed/shared", [value], Count::provided(-AB::Expr::ONE));
    }
}
struct Scenario {
    air: BoundaryLookup,
    main: [Table<F>; 2],
    pp: [Table<F>; 2],
    values: [[F; 1]; 2],
}
impl Scenario {
    fn new(seed: u64) -> Self {
        let mut rng = SmallRng::seed_from_u64(seed);
        Self {
            air: BoundaryLookup,
            main: [Table::rand(&mut rng, 2, 6), Table::rand(&mut rng, 2, 3)],
            pp: [Table::rand(&mut rng, 1, 6), Table::rand(&mut rng, 1, 3)],
            values: [[F::ONE], [F::TWO]],
        }
    }
    fn run(&self, streamed: bool) -> (FractionGkrProof<EF>, ActiveLookupRuntime<EF>, Challenger) {
        let airs = [&self.air, &self.air];
        let heights = [6, 3];
        let main = [&self.main[0], &self.main[1]];
        let pp = [Some(&self.pp[0]), Some(&self.pp[1])];
        let values = [self.values[0].as_slice(), self.values[1].as_slice()];
        let plan = LookupPlan::build::<EF, _>(&airs, &heights)
            .unwrap()
            .unwrap();
        let mut c = challenger();
        let mut transcript =
            LookupProverTranscript::<_, F, EF>::new(&mut c, &LookupShape::new(&plan));
        let (alpha, beta) = transcript.fingerprint_challenges();
        let dense = plan.materialize_fraction(&main, &pp, &values, alpha, beta);
        let source = LookupFractionSource::new(&plan, &main, &pp, &values, alpha, beta);
        let (proof, output) = transcript.reduction(|c| {
            if streamed {
                FractionGkrProof::<EF>::prove_from_source::<F, _>(&source, c)
            } else {
                prove_fractional_gkr(
                    Fraction {
                        n: LeafNumerator::Base(&dense.n),
                        d: &dense.d,
                    },
                    c,
                )
            }
        });
        let theta = transcript.link_challenge();
        transcript.finish();
        let air_link = AirLinkClaim::new(&plan, alpha, beta, output, theta);
        let shares = if streamed {
            air_link.evaluate_streamed_instance_claims(&plan, &source, theta)
        } else {
            air_link.evaluate_instance_claims(&plan, &dense, theta)
        };
        (
            proof,
            ActiveLookupRuntime {
                claims_by_air: shares,
                air_link,
            },
            c,
        )
    }
}
#[test]
fn streamed_leaf_access_matches_every_dense_block_boundary_and_neutral_tail() {
    let s = Scenario::new(71);
    let airs = [&s.air, &s.air];
    let heights = [6, 3];
    let main = [&s.main[0], &s.main[1]];
    let pp = [Some(&s.pp[0]), Some(&s.pp[1])];
    let values = [s.values[0].as_slice(), s.values[1].as_slice()];
    let plan = LookupPlan::build::<EF, _>(&airs, &heights)
        .unwrap()
        .unwrap();
    let alpha = EF::from_basis_coefficients_fn(|i| if i == 1 { F::ONE } else { F::ZERO });
    let dense = plan.materialize_fraction(&main, &pp, &values, alpha, EF::from_u8(7));
    let mut denominators = EF::zero_vec(1 << plan.num_variables);
    dense.d.unpack_into(&mut denominators);
    let source = LookupFractionSource::new(&plan, &main, &pp, &values, alpha, EF::from_u8(7));
    for (i, (&n, &d)) in dense.n.as_slice().iter().zip(&denominators).enumerate() {
        assert_eq!(source.leaf(i), (EF::from(n), d), "leaf {i}");
    }
    assert_eq!(
        source.leaf((1 << plan.num_variables) - 1),
        (EF::ZERO, EF::ONE)
    );
    assert!(catch_unwind(AssertUnwindSafe(|| source.leaf(1 << plan.num_variables))).is_err());
    // An out-of-range request cannot leave the source's bounded row scratch borrowed/poisoned.
    assert_eq!(
        source.leaf(0),
        (EF::from(dense.n.as_slice()[0]), denominators[0])
    );
}
#[test]
fn streamed_lookup_matches_dense_proof_shares_and_all_outer_challenges() {
    let s = Scenario::new(83);
    let (dense, d, mut dc) = s.run(false);
    let (streamed, a, mut ac) = s.run(true);
    assert_eq!(
        postcard::to_allocvec(&dense).unwrap(),
        postcard::to_allocvec(&streamed).unwrap()
    );
    assert_eq!(d.air_link, a.air_link);
    assert_eq!(d.claims_by_air, a.claims_by_air);
    assert_eq!(
        dc.sample_algebra_element::<EF>(),
        ac.sample_algebra_element::<EF>()
    );
    let airs = [&s.air, &s.air];
    let mut verifier = challenger();
    let checked = verify_lookup::<F, EF, _, _>(&airs, &[6, 3], Some(&streamed), &mut verifier)
        .unwrap()
        .unwrap();
    assert_eq!(checked, a.air_link);
    let main = [&s.main[0], &s.main[1]];
    let pp = [Some(&s.pp[0]), Some(&s.pp[1])];
    let values = [s.values[0].as_slice(), s.values[1].as_slice()];
    let mut selected_c = challenger();
    let (selected, selected_state) =
        prove_lookup::<F, EF, _, _>(&airs, &main, &pp, &values, &mut selected_c);
    assert_eq!(
        postcard::to_allocvec(&selected.unwrap()).unwrap(),
        postcard::to_allocvec(&dense).unwrap()
    );
    let LookupRuntime::Active(selected_state) = selected_state else {
        panic!("active lookup expected");
    };
    assert_eq!(selected_state.air_link, d.air_link);
    assert_eq!(selected_state.claims_by_air, d.claims_by_air);
}
#[test]
fn a_genuine_streamed_foreign_lookup_cannot_close_against_other_committed_rows() {
    let foreign = Scenario::new(91);
    let original = Scenario::new(93);
    let airs = [&foreign.air, &foreign.air];
    let pp = [Some(&foreign.pp[0]), Some(&foreign.pp[1])];
    let values = [foreign.values[0].as_slice(), foreign.values[1].as_slice()];
    let sumcheck = AirZerocheck::new(&airs, 0);
    let close = |use_foreign: bool| {
        let (lookup, runtime, mut producer) = foreign.run(true);
        let main = if use_foreign {
            [&foreign.main[0], &foreign.main[1]]
        } else {
            [&original.main[0], &original.main[1]]
        };
        let attempted = catch_unwind(AssertUnwindSafe(|| {
            sumcheck.prove_with_lookup::<F, EF, GenericBackend, _>(
                &pp,
                &main,
                &values,
                LookupRuntime::Active(runtime),
                DEFAULT_SLICED_ROUNDS,
                &mut producer,
            )
        }));
        match attempted {
            Ok((proof, point)) => {
                let mut verifier = challenger();
                let link =
                    verify_lookup::<F, EF, _, _>(&airs, &[6, 3], Some(&lookup), &mut verifier)
                        .unwrap()
                        .unwrap();
                let checked = sumcheck.verify_with_lookup(
                    &proof,
                    &[6, 3],
                    &values,
                    Some(&link),
                    &mut verifier,
                );
                if use_foreign {
                    assert_eq!(checked.unwrap(), point);
                } else {
                    assert!(
                        checked.is_err(),
                        "foreign fraction openings were not linked to actual AIR rows"
                    );
                }
            }
            Err(_) => assert!(
                !use_foreign && cfg!(debug_assertions),
                "release rejection must reach the actual verifier"
            ),
        }
    };
    close(true);
    close(false);
}
#[test]
fn invalid_source_geometry_and_layout_fail_before_any_row_materialization() {
    let s = Scenario::new(107);
    let airs = [&s.air, &s.air];
    let main = [&s.main[0], &s.main[1]];
    let pp = [Some(&s.pp[0]), Some(&s.pp[1])];
    let values = [s.values[0].as_slice(), s.values[1].as_slice()];
    let mut plan = LookupPlan::build::<EF, _>(&airs, &[6, 3]).unwrap().unwrap();
    let variables = plan.num_variables;
    for invalid in [usize::BITS as usize, usize::MAX] {
        plan.num_variables = invalid;
        assert!(
            catch_unwind(AssertUnwindSafe(|| LookupFractionSource::new(
                &plan,
                &main,
                &pp,
                &values,
                EF::ONE,
                EF::TWO
            )))
            .is_err()
        );
    }
    plan.num_variables = variables;
    let bad_main = [&s.main[1], &s.main[0]];
    assert!(
        catch_unwind(AssertUnwindSafe(|| LookupFractionSource::new(
            &plan,
            &bad_main,
            &pp,
            &values,
            EF::ONE,
            EF::TWO
        )))
        .is_err()
    );
    let source = LookupFractionSource::new(&plan, &main, &pp, &values, EF::ONE, EF::TWO);
    assert_eq!(source.num_variables(), variables);
    assert_eq!(source.leaf((1 << variables) - 1), (EF::ZERO, EF::ONE));
}

struct RowCacheAir {
    main: usize,
    public: usize,
    values: usize,
    active: bool,
}
impl BaseAir<F> for RowCacheAir {
    fn width(&self) -> usize {
        self.main
    }
    fn preprocessed_width(&self) -> usize {
        self.public
    }
    fn num_public_values(&self) -> usize {
        self.values
    }
}
impl<AB: AirBuilder<F = F> + InteractionBuilder> Air<AB> for RowCacheAir {
    fn eval(&self, builder: &mut AB) {
        if !self.active {
            return;
        }
        let main = builder.main();
        let first: AB::Expr = main.current_slice()[0].into();
        let last: AB::Expr = main.current_slice()[self.main - 1].into();
        let next_first: AB::Expr = main.next_slice()[0].into();
        let next_last: AB::Expr = main.next_slice()[self.main - 1].into();
        let mut context = AB::Expr::ZERO;
        for value in builder.public_values() {
            context += Into::<AB::Expr>::into(*value);
        }
        if self.public != 0 {
            for value in builder.preprocessed().current_slice() {
                context += Into::<AB::Expr>::into(*value);
            }
        }
        let a = first + next_last + context.clone() + builder.is_first_row();
        let b = last + next_first + context + builder.is_last_row() * F::TWO;
        // Several different expressions and multiplicities reuse the same raw row.
        // Caching one evaluated fraction per AIR/row would be incorrect here.
        builder.push_local_interaction([
            (vec![a.clone()], Count::bounded(AB::Expr::ONE, 1)),
            (vec![a.clone()], Count::provided(-AB::Expr::ONE)),
            (vec![b.clone()], Count::bounded(AB::Expr::TWO, 2)),
            (vec![b.clone()], Count::provided(-AB::Expr::TWO)),
        ]);
        builder.push_interaction("row-cache/first", [a.clone(), b.clone()], 1);
        builder.push_interaction(
            "row-cache/first",
            [a.clone(), b.clone()],
            Count::provided(-AB::Expr::ONE),
        );
        builder.push_interaction("row-cache/second", [b.clone(), a.clone() + F::ONE], 2);
        builder.push_interaction(
            "row-cache/second",
            [b, a + F::ONE],
            Count::provided(-AB::Expr::TWO),
        );
    }
}

#[test]
fn per_air_raw_rows_preserve_reversed_mixed_shapes_block_expressions_and_transcripts() {
    let definitions = [
        RowCacheAir {
            main: 4,
            public: 0,
            values: 0,
            active: false,
        },
        RowCacheAir {
            main: 1,
            public: 0,
            values: 1,
            active: true,
        },
        RowCacheAir {
            main: 5,
            public: 2,
            values: 2,
            active: true,
        },
        RowCacheAir {
            main: 3,
            public: 1,
            values: 3,
            active: true,
        },
    ];
    let heights = [2, 3, 4, 6];
    let mut rng = SmallRng::seed_from_u64(0xCA_C4E);
    let main_tables = definitions
        .iter()
        .zip(heights)
        .map(|(a, h)| Table::rand(&mut rng, a.main, h))
        .collect::<Vec<_>>();
    let public_tables = definitions
        .iter()
        .zip(heights)
        .map(|(a, h)| (a.public != 0).then(|| Table::rand(&mut rng, a.public, h)))
        .collect::<Vec<_>>();
    let public_values = definitions
        .iter()
        .enumerate()
        .map(|(i, a)| {
            (0..a.values)
                .map(|j| F::from_usize(10 * i + j + 1))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let airs = definitions.iter().collect::<Vec<_>>();
    let main = main_tables.iter().collect::<Vec<_>>();
    let public = public_tables.iter().map(Option::as_ref).collect::<Vec<_>>();
    let values = public_values.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let plan = LookupPlan::build::<EF, _>(&airs, &heights)
        .unwrap()
        .unwrap();
    assert_eq!(
        plan.instances
            .iter()
            .map(|p| p.air_index)
            .collect::<Vec<_>>(),
        [3, 2, 1]
    );
    let alpha =
        EF::from_u8(13) + EF::from_basis_coefficients_fn(|i| if i == 1 { F::ONE } else { F::ZERO });
    let beta = EF::from_u8(7);
    let dense = plan.materialize_fraction(&main, &public, &values, alpha, beta);
    let source = LookupFractionSource::new(&plan, &main, &public, &values, alpha, beta);
    let len = 1usize << plan.num_variables;
    let mut denominators = EF::zero_vec(len);
    dense.d.unpack_into(&mut denominators);
    let expected = |index| (EF::from(dense.n.as_slice()[index]), denominators[index]);
    // Bit-reversal jumps between original AIR buckets, rather than relying on a
    // single sequential pass through plan order. Every leaf is compared.
    for i in 0..len {
        let index = i.reverse_bits() >> (usize::BITS as usize - plan.num_variables);
        assert_eq!(source.leaf(index), expected(index), "mixed leaf {index}");
    }
    // Hold the row constant while alternating all AIRs and every contribution.
    // Both the first row and each differently sized last row are included.
    for last in [false, true] {
        for planned in &plan.instances {
            let height = 1usize << planned.num_variables;
            let row = if last { height - 1 } else { 0 };
            let mut at = planned.base_offset;
            for lookup in planned.lookups.iter() {
                for _ in &lookup.elements {
                    assert_eq!(source.leaf(at + row), expected(at + row));
                    at += height;
                }
            }
        }
    }
    let final_instance = plan.instances.last().unwrap();
    let used = final_instance.base_offset
        + (1usize << final_instance.num_variables)
            * final_instance
                .lookups
                .iter()
                .map(|l| l.elements.len())
                .sum::<usize>();
    assert!(used < len);
    for index in used..len {
        assert_eq!(source.leaf(index), (EF::ZERO, EF::ONE));
    }
    assert_eq!(source.leaf(0), expected(0));

    let run = |streamed| {
        let mut c = challenger();
        let mut transcript =
            LookupProverTranscript::<_, F, EF>::new(&mut c, &LookupShape::new(&plan));
        let (alpha, beta) = transcript.fingerprint_challenges();
        let dense = plan.materialize_fraction(&main, &public, &values, alpha, beta);
        let source = LookupFractionSource::new(&plan, &main, &public, &values, alpha, beta);
        let (proof, output) = transcript.reduction(|c| {
            if streamed {
                FractionGkrProof::<EF>::prove_from_source::<F, _>(&source, c)
            } else {
                prove_fractional_gkr(
                    Fraction {
                        n: LeafNumerator::Base(&dense.n),
                        d: &dense.d,
                    },
                    c,
                )
            }
        });
        let theta = transcript.link_challenge();
        transcript.finish();
        let link = AirLinkClaim::new(&plan, alpha, beta, output, theta);
        let shares = if streamed {
            link.evaluate_streamed_instance_claims(&plan, &source, theta)
        } else {
            link.evaluate_instance_claims(&plan, &dense, theta)
        };
        (proof, link, shares, c)
    };
    let (dense_proof, dense_link, dense_shares, mut dc) = run(false);
    let (streamed_proof, streamed_link, streamed_shares, mut sc) = run(true);
    assert_eq!(
        postcard::to_allocvec(&dense_proof).unwrap(),
        postcard::to_allocvec(&streamed_proof).unwrap()
    );
    assert_eq!(dense_link, streamed_link);
    assert_eq!(dense_shares, streamed_shares);
    let next = dc.sample_algebra_element::<EF>();
    assert_eq!(sc.sample_algebra_element::<EF>(), next);
    let mut verifier = challenger();
    let checked =
        verify_lookup::<F, EF, _, _>(&airs, &heights, Some(&streamed_proof), &mut verifier)
            .unwrap()
            .unwrap();
    assert_eq!(checked, streamed_link);
    assert_eq!(verifier.sample_algebra_element::<EF>(), next);
    let mut selected = challenger();
    let (selected_proof, selected_state) =
        prove_lookup::<F, EF, _, _>(&airs, &main, &public, &values, &mut selected);
    assert_eq!(
        postcard::to_allocvec(&selected_proof.unwrap()).unwrap(),
        postcard::to_allocvec(&dense_proof).unwrap()
    );
    let LookupRuntime::Active(selected_state) = selected_state else {
        panic!("active mixed lookup expected");
    };
    assert_eq!(selected_state.air_link, dense_link);
    assert_eq!(selected_state.claims_by_air, dense_shares);
    assert_eq!(selected.sample_algebra_element::<EF>(), next);
}
