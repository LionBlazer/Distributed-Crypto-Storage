//! Prover-private AIR-link shares regenerated from the same lookup leaves.
use super::*;
/// Internal commitment-bound prover input, never verifier authority or a receipt.
pub(crate) trait FractionSource<EF: Field> {
    fn num_variables(&self) -> usize;
    fn leaf(&self, index: usize) -> (EF, EF);
}

impl<EF: Field> AirLinkClaim<EF> {
    pub(super) fn evaluate_streamed_instance_claims<F: Field>(
        &self,
        plan: &LookupPlan<F>,
        source: &impl FractionSource<EF>,
        theta: EF,
    ) -> BTreeMap<usize, EF>
    where
        EF: ExtensionField<F>,
    {
        let mut claims = BTreeMap::new();
        for planned in &plan.instances {
            let suffix = self.point.get_subpoint_over_range(
                plan.num_variables - planned.num_variables..plan.num_variables,
            );
            // Two square-root-sized factors, never the full equality tensor.
            let split = suffix.num_variables() / 2;
            let prefix = Poly::new_from_point(&suffix.as_slice()[..split], EF::ONE);
            let tail = Poly::new_from_point(&suffix.as_slice()[split..], EF::ONE);
            let tail_variables = suffix.num_variables() - split;
            let height = 1usize << planned.num_variables;
            let mut start = planned.base_offset;
            let mut claim = EF::ZERO;
            for &weight in self.links_by_air[&planned.air_index]
                .lookups
                .iter()
                .flat_map(|lookup| &lookup.block_weights)
            {
                let mut block_claim = EF::ZERO;
                for row in 0..height {
                    let eq = prefix.as_slice()[row >> tail_variables]
                        * tail.as_slice()[row & (tail.num_evals() - 1)];
                    let (n, d) = source.leaf(start + row);
                    block_claim += eq * (n + theta * (d - EF::ONE));
                }
                claim += weight * block_claim;
                start += height;
            }
            assert!(claims.insert(planned.air_index, claim).is_none());
        }
        claims
    }
}

#[cfg(test)]
#[path = "streaming_tests.rs"]
mod tests;
