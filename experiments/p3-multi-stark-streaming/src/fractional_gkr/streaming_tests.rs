//! PUBLIC NONSECRET small witnesses; dense upstream prover is the independent reference.
extern crate std;
use super::*;
use core::cell::Cell;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_binary_field::{BinaryChallenger, BinaryField32, BinaryField128};
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger64};
use p3_field::BasedVectorSpace;
use p3_field::extension::BinomialExtensionField;
use p3_goldilocks::Goldilocks;
use p3_keccak::Keccak256Hash;
use rand::{SeedableRng, rngs::SmallRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

type F = BabyBear;
type EF = BinomialExtensionField<F, 4>;
type Challenger = DuplexChallenger<F, Poseidon2BabyBear<16>, 16, 8>;
fn challenger() -> Challenger {
    Challenger::new(Poseidon2BabyBear::new_from_rng_128(
        &mut SmallRng::seed_from_u64(0x51_7EA0),
    ))
}
struct Tables<'a, F: Field, EF: ExtensionField<F>>(LeafFraction<'a, F, EF>);
fn extension_at<F: Field, EF: ExtensionField<F>>(p: &PolyMaybePacked<F, EF>, index: usize) -> EF {
    match p {
        PolyMaybePacked::Scalar(p) => p.as_slice()[index],
        PolyMaybePacked::Packed(p) => EF::ExtensionPacking::to_ext_iter(core::iter::once(
            p.as_slice()[index / F::Packing::WIDTH],
        ))
        .nth(index % F::Packing::WIDTH)
        .unwrap(),
    }
}
impl<F: Field, EF: ExtensionField<F>> FractionSource<EF> for Tables<'_, F, EF> {
    fn num_variables(&self) -> usize {
        self.0.n.num_variables()
    }
    fn leaf(&self, index: usize) -> (EF, EF) {
        let n = match self.0.n {
            LeafNumerator::Base(p) => EF::from(p.as_slice()[index]),
            LeafNumerator::Ext(p) => extension_at(p, index),
        };
        (n, extension_at(self.0.d, index))
    }
}
fn agreement<F, EF, C>(fraction: LeafFraction<'_, F, EF>, original: C)
where
    F: TranscriptField,
    EF: ExtensionField<F> + serde::Serialize,
    C: FieldChallenger<F> + Clone,
{
    // Direct rational sums, independent of the production reduction implementation:
    // every proper prefix-reduced subtree is nonzero; cancellation occurs only at the root.
    let source = Tables(fraction);
    let len = 1usize << source.num_variables();
    let sum: EF = (0..len)
        .map(|i| {
            let (n, d) = source.leaf(i);
            n * d.inverse()
        })
        .sum();
    assert_eq!(sum, EF::ZERO);
    for remaining in 1..=source.num_variables() {
        let stride = 1usize << remaining;
        for index in 0..stride {
            let partial: EF = (index..len)
                .step_by(stride)
                .map(|i| {
                    let (n, d) = source.leaf(i);
                    n * d.inverse()
                })
                .sum();
            assert_ne!(
                partial,
                EF::ZERO,
                "fixture cancels before its complete root"
            );
        }
    }
    let mut dense = original.clone();
    let (expected, expected_output) = prove_fractional_gkr(fraction, &mut dense);
    let mut streamed = original.clone();
    let (actual, output) =
        FractionGkrProof::<EF>::prove_from_source::<F, _>(&Tables(fraction), &mut streamed);
    assert_eq!(
        postcard::to_allocvec(&actual).unwrap(),
        postcard::to_allocvec(&expected).unwrap()
    );
    assert_eq!(output, expected_output);
    let next: EF = dense.sample_algebra_element();
    assert_eq!(streamed.sample_algebra_element::<EF>(), next);
    let mut verifier = original;
    assert_eq!(
        crate::fractional_gkr::verify_fractional_gkr::<F, EF, _>(
            &actual,
            fraction.n.num_variables(),
            &mut verifier
        )
        .unwrap(),
        output
    );
    assert_eq!(verifier.sample_algebra_element::<EF>(), next);
}
fn balanced(variables: usize) -> (Poly<F>, Poly<EF>) {
    let half = (1usize << variables) / 2;
    let mut n = Vec::new();
    let mut d = Vec::new();
    let unit =
        EF::from_u8(17) + EF::from_basis_coefficients_fn(|i| if i == 1 { F::ONE } else { F::ZERO });
    for i in 0..half {
        let value = F::from_usize(i + 1);
        let denominator = unit * EF::from(value);
        // Matched +/- pairs are interleaved, not placed across the first split.
        n.extend([value, -value]);
        d.extend([denominator, denominator]);
    }
    (Poly::new(n), Poly::new(d))
}
#[test]
fn streamed_base_leaves_match_dense_bytes_openings_and_challenges_including_tiny_and_packed() {
    for variables in 1..=10 {
        let (n, d) = balanced(variables);
        let scalar = PolyMaybePacked::Scalar(d.clone());
        agreement(
            Fraction {
                n: LeafNumerator::Base(&n),
                d: &scalar,
            },
            challenger(),
        );
        if variables >= log2_strict_usize(<F as Field>::Packing::WIDTH) {
            let packed = PolyMaybePacked::<F, EF>::Packed(d.pack::<F, EF>());
            agreement(
                Fraction {
                    n: LeafNumerator::Base(&n),
                    d: &packed,
                },
                challenger(),
            );
        }
    }
}
#[test]
fn streamed_extension_leaves_match_dense_scalar_and_packed_transcripts() {
    for variables in 1..=9 {
        let (n, d) = balanced(variables);
        let nonbase = EF::from_basis_coefficients_fn(|i| if i == 1 { F::ONE } else { F::ZERO });
        let n = Poly::new(
            n.as_slice()
                .iter()
                .copied()
                .map(|v| EF::from(v) * nonbase)
                .collect::<Vec<_>>(),
        );
        let ns = PolyMaybePacked::Scalar(n.clone());
        let ds = PolyMaybePacked::Scalar(d.clone());
        agreement(
            Fraction {
                n: LeafNumerator::Ext(&ns),
                d: &ds,
            },
            challenger(),
        );
        if variables >= log2_strict_usize(<F as Field>::Packing::WIDTH) {
            let np = PolyMaybePacked::<F, EF>::Packed(n.pack::<F, EF>());
            let dp = PolyMaybePacked::<F, EF>::Packed(d.pack::<F, EF>());
            agreement(
                Fraction {
                    n: LeafNumerator::Ext(&np),
                    d: &dp,
                },
                challenger(),
            );
        }
    }
}
#[test]
fn streamed_binary_interpolation_uses_field_nodes_and_preserves_the_dense_transcript() {
    type B = BinaryField32;
    type E = BinaryField128;
    type C = BinaryChallenger<B, HashChallenger<u8, Keccak256Hash, 32>>;
    for variables in 1..=7 {
        let mut rng = SmallRng::seed_from_u64(0xB1_51 + variables as u64);
        let half = (1usize << variables) / 2;
        let n = Poly::<B>::rand(&mut rng, variables);
        let d = Poly::<E>::rand(&mut rng, variables);
        let mut ns = Vec::new();
        let mut ds = Vec::new();
        for i in 0..half {
            let value = if n.as_slice()[i] == B::ZERO {
                B::ONE
            } else {
                n.as_slice()[i]
            };
            let denominator = if d.as_slice()[i] == E::ZERO {
                E::ONE
            } else {
                d.as_slice()[i]
            };
            ns.extend([value, -value]);
            ds.extend([denominator, denominator]);
        }
        let n = Poly::new(ns);
        let d = PolyMaybePacked::Scalar(Poly::new(ds));
        let c = C::from_hasher(b"streamed-fraction-binary-parity".to_vec(), Keccak256Hash);
        agreement(
            Fraction {
                n: LeafNumerator::Base(&n),
                d: &d,
            },
            c,
        );
    }
}

#[test]
fn streamed_goldilocks_ef5_matches_dense_nonzero_intermediate_trees_and_byte_challenger() {
    type G = Goldilocks;
    type E = BinomialExtensionField<G, 5>;
    type C = SerializingChallenger64<G, HashChallenger<u8, Keccak256Hash, 32>>;
    let fresh = || {
        C::from_hasher(
            b"streamed-goldilocks-EF5-byte-parity".to_vec(),
            Keccak256Hash,
        )
    };
    for variables in 1..=9 {
        let nonbase = E::from_basis_coefficients_fn(|i| if i == 1 { G::ONE } else { G::ZERO });
        let mut ns = Vec::new();
        let mut ds = Vec::new();
        for i in 0..(1usize << (variables - 1)) {
            let value = G::from_usize(i + 1);
            let denominator = (E::from_u8(17) + nonbase) * E::from(value);
            ns.extend([value, -value]);
            ds.extend([denominator, denominator]);
        }
        let n = Poly::new(ns);
        let d = Poly::new(ds);
        let scalar = PolyMaybePacked::Scalar(d.clone());
        agreement(
            Fraction {
                n: LeafNumerator::Base(&n),
                d: &scalar,
            },
            fresh(),
        );
        let e = Poly::new(
            n.as_slice()
                .iter()
                .copied()
                .map(|v| E::from(v) * nonbase)
                .collect::<Vec<_>>(),
        );
        let es = PolyMaybePacked::Scalar(e.clone());
        agreement(
            Fraction {
                n: LeafNumerator::Ext(&es),
                d: &scalar,
            },
            fresh(),
        );
        if variables >= log2_strict_usize(<G as Field>::Packing::WIDTH) {
            let dp = PolyMaybePacked::<G, E>::Packed(d.pack::<G, E>());
            let ep = PolyMaybePacked::<G, E>::Packed(e.pack::<G, E>());
            agreement(
                Fraction {
                    n: LeafNumerator::Base(&n),
                    d: &dp,
                },
                fresh(),
            );
            agreement(
                Fraction {
                    n: LeafNumerator::Ext(&ep),
                    d: &dp,
                },
                fresh(),
            );
        }
    }
}

#[test]
fn streamed_proof_rejects_last_claim_damage_with_the_original_verifier() {
    let (n, d) = balanced(6);
    let d = PolyMaybePacked::Scalar(d);
    let source = Tables(Fraction {
        n: LeafNumerator::Base(&n),
        d: &d,
    });
    let (mut proof, _) =
        FractionGkrProof::<EF>::prove_from_source::<F, _>(&source, &mut challenger());
    proof.layers.last_mut().unwrap().claims.d1 += EF::ONE;
    assert!(
        crate::fractional_gkr::verify_fractional_gkr::<F, EF, _>(&proof, 6, &mut challenger())
            .is_err()
    );
}
#[test]
fn unrepresentable_stream_shape_rejects_before_reading_witness_or_changing_transcript() {
    struct Invalid {
        variables: usize,
        reads: Cell<usize>,
    }
    impl FractionSource<EF> for Invalid {
        fn num_variables(&self) -> usize {
            self.variables
        }
        fn leaf(&self, _: usize) -> (EF, EF) {
            self.reads.set(self.reads.get() + 1);
            (EF::ZERO, EF::ONE)
        }
    }
    for variables in [0, usize::BITS as usize, usize::MAX] {
        let source = Invalid {
            variables,
            reads: Cell::new(0),
        };
        let mut c = challenger();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                FractionGkrProof::<EF>::prove_from_source::<F, _>(&source, &mut c)
            }))
            .is_err()
        );
        assert_eq!(source.reads.get(), 0);
        assert_eq!(
            c.sample_algebra_element::<EF>(),
            challenger().sample_algebra_element::<EF>()
        );
    }
}
