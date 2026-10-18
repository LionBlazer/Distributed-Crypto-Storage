//! Prover-only recomputation of lookup fractions. No transcript or verifier policy lives here.
use super::*;
use core::alloc::Layout;

use crate::lookup::FractionSource;

/// Checked address/allocation shape, not a promise about available process RAM.
fn checked_len<EF>(variables: usize) -> usize {
    assert!(
        variables > 0,
        "fraction GKR requires at least one input variable"
    );
    let shift = u32::try_from(variables).expect("fraction GKR variable count exceeds u32");
    let len = 1usize
        .checked_shl(shift)
        .expect("fraction GKR table size overflow");
    // No allocation below is larger than one quarter of the logical input in EF elements.
    Layout::array::<EF>((len / 4).max(1)).expect("fraction GKR layer allocation overflow");
    len
}

fn add<EF: Field>((n0, d0): (EF, EF), (n1, d1): (EF, EF)) -> (EF, EF) {
    (d1 * n0 + d0 * n1, d0 * d1)
}

/// Prefix-bit pairing is exactly the original split-half reduction, not adjacent rows.
fn reduced<EF: Field>(source: &impl FractionSource<EF>, depth: usize, index: usize) -> (EF, EF) {
    if depth == 0 {
        source.leaf(index)
    } else {
        let stride = 1usize << (source.num_variables() - depth);
        add(
            reduced(source, depth - 1, index),
            reduced(source, depth - 1, index + stride),
        )
    }
}

/// Build only the current four split arrays. Packed storage is written directly;
/// there is no dense leaf table, scalar layer clone, or all-layer cache.
fn split_from_fn<F: Field, EF: ExtensionField<F>>(
    half: usize,
    value: impl Fn(usize) -> (EF, EF),
) -> SplitFractionMaybePacked<F, EF> {
    let width = F::Packing::WIDTH;
    if half >= width {
        let pair = |start| {
            let mut n = Vec::with_capacity(half / width);
            let mut d = Vec::with_capacity(half / width);
            let mut ns = EF::zero_vec(width);
            let mut ds = EF::zero_vec(width);
            for at in (0..half).step_by(width) {
                for lane in 0..width {
                    (ns[lane], ds[lane]) = value(start + at + lane);
                }
                n.push(EF::ExtensionPacking::from_ext_slice(&ns));
                d.push(EF::ExtensionPacking::from_ext_slice(&ds));
            }
            (Poly::new(n), Poly::new(d))
        };
        let (n0, d0) = pair(0);
        let (n1, d1) = pair(half);
        let mut fraction = SplitFractionMaybePacked::Packed(SplitFraction { n0, d0, n1, d1 });
        fraction.transition();
        fraction
    } else {
        let pair = |start| {
            let (n, d): (Vec<_>, Vec<_>) = (0..half).map(|i| value(start + i)).unzip();
            (Poly::new(n), Poly::new(d))
        };
        let (n0, d0) = pair(0);
        let (n1, d1) = pair(half);
        SplitFractionMaybePacked::Scalar(SplitFraction { n0, d0, n1, d1 })
    }
}

/// First leaf-layer round without retaining its input. This equality vector is
/// dropped before the four folded extension arrays are allocated.
fn leaf_round<EF: Field>(
    source: &impl FractionSource<EF>,
    point: &Point<EF>,
    lambda: EF,
) -> [EF; 2] {
    let quarter = 1usize << (source.num_variables() - 2);
    let eq = Poly::new_from_point(&point.as_slice()[1..], EF::ONE);
    let node = EF::interpolation_node(2);
    let mut out = [EF::ZERO; 2];
    for i in 0..quarter {
        let (n00, d00) = source.leaf(i);
        let (n01, d01) = source.leaf(i + quarter);
        let (n10, d10) = source.leaf(i + 2 * quarter);
        let (n11, d11) = source.leaf(i + 3 * quarter);
        let gate = |n0, n1, d0, d1| d1 * n0 + d0 * n1 + lambda * d0 * d1;
        out[0] += eq.as_slice()[i] * gate(n00, n10, d00, d10);
        out[1] += eq.as_slice()[i]
            * gate(
                n00 + node * (n01 - n00),
                n10 + node * (n11 - n10),
                d00 + node * (d01 - d00),
                d10 + node * (d11 - d10),
            );
    }
    out
}

/// Same proof, challenge order and dense reference kernels; only witness storage changes.
impl<EF: Field> FractionGkrProof<EF> {
    pub(crate) fn prove_from_source<F, Challenger>(
        source: &impl FractionSource<EF>,
        challenger: &mut Challenger,
    ) -> (Self, FractionGkrOutput<EF>)
    where
        F: TranscriptField,
        EF: ExtensionField<F>,
        Challenger: FieldChallenger<F>,
    {
        let num_variables = source.num_variables();
        let len = checked_len::<EF>(num_variables);
        let (n0, d0) = reduced(source, num_variables - 1, 0);
        let (n1, d1) = reduced(source, num_variables - 1, 1);
        let root_claims = SplitFraction { n0, d0, n1, d1 };
        let root_denominator = d0 * d1;
        assert_eq!(
            d1 * n0 + d0 * n1,
            EF::ZERO,
            "fraction GKR input fractions must sum to zero"
        );
        assert_ne!(
            root_denominator,
            EF::ZERO,
            "fraction GKR root denominator must be nonzero"
        );
        let mut transcript = FractionGkrProverTranscript::<Challenger, F, EF>::new(
            challenger,
            FractionGkrShape { num_variables },
            root_denominator,
        );
        let interpolator = RoundPolyInterpolator::new(2);
        let mut layer_proofs = Vec::with_capacity(num_variables);
        let lambda = transcript.begin_layer();
        debug_assert_eq!(lambda * root_denominator, root_claims.gate(lambda));
        let branch = transcript.end_layer(&root_claims);
        let mut numerator = n0 + branch * (n1 - n0);
        let mut denominator = d0 + branch * (d1 - d0);
        let mut point = Point::new(vec![branch]);
        layer_proofs.push(FractionGkrLayerProof {
            round_polys: Vec::new(),
            claims: root_claims,
        });

        // Rebuild precisely the layer required by the next proof bracket. A consumed
        // layer's owned arrays are dropped by into_claims before the next one is built.
        for variables in 2..num_variables {
            let half = 1usize << (variables - 1);
            let depth = num_variables - variables;
            let fraction = split_from_fn::<F, EF>(half, |i| reduced(source, depth, i));
            let lambda = transcript.begin_layer();
            let mut normalized_sum = numerator + lambda * denominator;
            let mut layer = Layer::new(fraction, &point);
            let mut round_polys = Vec::with_capacity(point.num_variables());
            let mut round_point = Vec::with_capacity(point.num_variables());
            for round in 0..point.num_variables() {
                let coordinate = point[round];
                let quadratic_evals = layer.round_polys(lambda);
                let (round_poly, q_sum) = restore_equality_factor(
                    quadratic_evals,
                    normalized_sum,
                    coordinate,
                    layer.eq_prefix,
                    &interpolator,
                );
                let challenge = transcript.round(&round_poly);
                round_polys.push(round_poly);
                round_point.push(challenge);
                normalized_sum = interpolator.eval(&quadratic_evals, q_sum, challenge);
                layer.fold(coordinate, challenge);
            }
            let claims = layer.into_claims();
            debug_assert_eq!(normalized_sum, claims.gate(lambda));
            let branch = transcript.end_layer(&claims);
            numerator = claims.n0 + branch * (claims.n1 - claims.n0);
            denominator = claims.d0 + branch * (claims.d1 - claims.d0);
            round_point.insert(0, branch);
            point = Point::new(round_point);
            layer_proofs.push(FractionGkrLayerProof {
                round_polys,
                claims,
            });
        }

        // A one-variable input has already closed at the root; there is no leaf sumcheck.
        if num_variables > 1 {
            let lambda = transcript.begin_layer();
            let mut normalized_sum = numerator + lambda * denominator;
            let mut round_polys = Vec::with_capacity(point.num_variables());
            let mut round_point = Vec::with_capacity(point.num_variables());
            let coordinate = point[0];
            let quadratic_evals = leaf_round(source, &point, lambda);
            let (round_poly, q_sum) = restore_equality_factor(
                quadratic_evals,
                normalized_sum,
                coordinate,
                EF::ONE,
                &interpolator,
            );
            let challenge = transcript.round(&round_poly);
            round_polys.push(round_poly);
            round_point.push(challenge);
            normalized_sum = interpolator.eval(&quadratic_evals, q_sum, challenge);
            let quarter = len / 4;
            let fraction = split_from_fn::<F, EF>(quarter, |i| {
                let base = if i < quarter { i } else { i + quarter };
                let (n0, d0) = source.leaf(base);
                let (n1, d1) = source.leaf(base + quarter);
                (n0 + challenge * (n1 - n0), d0 + challenge * (d1 - d0))
            });
            let claims = if point.num_variables() == 1 {
                // The streamed first round already leaves four constants. Layer::new
                // requires an unfixed coordinate, so close this tiny case directly.
                let constants = fraction.unpack();
                SplitFraction {
                    n0: constants.n0.as_constant().unwrap(),
                    d0: constants.d0.as_constant().unwrap(),
                    n1: constants.n1.as_constant().unwrap(),
                    d1: constants.d1.as_constant().unwrap(),
                }
            } else {
                let suffix = point.get_subpoint_over_range(1..);
                let mut layer = Layer::new(fraction, &suffix);
                layer.eq_prefix =
                    (EF::ONE - coordinate) + challenge * (coordinate.double() - EF::ONE);
                for round in 1..point.num_variables() {
                    let coordinate = point[round];
                    let quadratic_evals = layer.round_polys(lambda);
                    let (round_poly, q_sum) = restore_equality_factor(
                        quadratic_evals,
                        normalized_sum,
                        coordinate,
                        layer.eq_prefix,
                        &interpolator,
                    );
                    let challenge = transcript.round(&round_poly);
                    round_polys.push(round_poly);
                    round_point.push(challenge);
                    normalized_sum = interpolator.eval(&quadratic_evals, q_sum, challenge);
                    layer.fold(coordinate, challenge);
                }
                layer.into_claims()
            };
            debug_assert_eq!(normalized_sum, claims.gate(lambda));
            let branch = transcript.end_layer(&claims);
            numerator = claims.n0 + branch * (claims.n1 - claims.n0);
            denominator = claims.d0 + branch * (claims.d1 - claims.d0);
            round_point.insert(0, branch);
            point = Point::new(round_point);
            layer_proofs.push(FractionGkrLayerProof {
                round_polys,
                claims,
            });
        }
        transcript.finish();
        (
            FractionGkrProof {
                root_denominator,
                layers: layer_proofs,
            },
            FractionGkrOutput {
                point,
                numerator,
                denominator,
            },
        )
    }
}

#[cfg(test)]
#[path = "streaming_tests.rs"]
mod tests;
