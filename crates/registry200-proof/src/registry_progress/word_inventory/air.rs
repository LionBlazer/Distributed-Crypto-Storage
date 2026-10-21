//! Complete Poseidon2 + typed global LogUp AIR with ordinary PUBLIC constraints.
//! Native mathematical proofs create no receiving or SQL authority here.
use super::plan::*;
use crate::Val;
#[cfg(test)]
use bfv_hiding_stark::Challenge;
use bfv_hiding_stark::poseidon;
#[cfg(test)]
use p3_air::symbolic::AirLayout;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
#[cfg(test)]
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_lookup::{Count, InteractionBuilder};
#[cfg(test)]
use p3_lookup::{LogUpGadget, Lookups};
use p3_matrix::dense::RowMajorMatrix;
const WIRE: &str = "DCS/research/word208/v1/ssa";
const POLICY: &str = "DCS/research/word208/v1/policy25";
const MASK: &str = "DCS/research/word208/v1/mask256";
#[derive(Clone)]
pub(super) struct ProgramAir {
    pub plan: Plan,
}
impl BaseAir<Val> for ProgramAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        super::public_values::COUNT
    }
    fn preprocessed_width(&self) -> usize {
        PP_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        let mut p = Vec::with_capacity(self.plan.height * PP_WIDTH);
        for r in 0..self.plan.height {
            p.extend(self.plan.pp_row(r));
        }
        Some(RowMajorMatrix::new(p, PP_WIDTH))
    }
}
impl<AB: InteractionBuilder<F = Val>> Air<AB> for ProgramAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let row = main.current_slice();
        let pre = b.preprocessed().clone();
        let p = pre.current_slice();
        let f: [AB::Expr; PHASES] = core::array::from_fn(|i| p[i].into());
        let v: [AB::Expr; PORTS] = core::array::from_fn(|i| row[248 + i].into());
        let bits: [AB::Expr; BITS] = core::array::from_fn(|i| row[248 + PORTS + i].into());
        let public: [AB::Expr; super::public_values::COUNT] =
            core::array::from_fn(|j| b.public_values()[j].into());
        for j in 0..super::public_values::COUNT {
            // Ordinary constraints bind even an otherwise unused public word.
            // Selectors are immutable PP flags, never prover/private routing.
            b.assert_zero(
                p[PUBLIC_ACTIVE + j / PORTS] * (v[j % PORTS].clone() - public[j].clone()),
            );
        }
        for (i, value) in v.iter().enumerate() {
            let at = PORT_META + 5 * i;
            let active: AB::Expr = p[at].into();
            let constant: AB::Expr = p[at + 1].into();
            b.assert_zero((AB::Expr::ONE - active) * value.clone());
            b.assert_zero(constant * (value.clone() - p[at + 2]));
            b.push_interaction(
                WIRE,
                [p[at + 3].into(), value.clone()],
                Count::bounded(p[at + 4].into(), self.plan.max_fanout),
            );
        }
        for i in 0..BITS {
            let active: AB::Expr = p[RANGE_BITS + i].into();
            b.assert_zero((AB::Expr::ONE - active.clone()) * bits[i].clone());
            b.assert_zero(active * bits[i].clone() * (bits[i].clone() - AB::Expr::ONE));
        }
        for slot in 0..GATES {
            let i = 3 * slot;
            let k = OPS + 4 * slot;
            let a = v[i].clone();
            let c = v[i + 1].clone();
            let y = v[i + 2].clone();
            b.assert_zero(p[k] * (y.clone() - a.clone() - c.clone()));
            b.assert_zero(p[k + 1] * (y.clone() - a.clone() + c.clone()));
            b.assert_zero(p[k + 2] * (y.clone() - a.clone() * c));
            b.assert_zero(p[k + 3] * (y + a));
        }
        for x in &v {
            b.assert_zero(f[ASSERT].clone() * x.clone());
        }
        for k in 0..8 {
            let x: AB::Expr = (0..32)
                .map(|j| bits[32 * k + j].clone() * Val::from_u64(1u64 << j))
                .sum();
            b.assert_zero(p[RANGE_ON_HASH] * (v[12 + k].clone() - x));
        }
        let h = f[HASH].clone();
        for &cell in row.iter().take(248) {
            b.assert_zero((AB::Expr::ONE - h.clone()) * cell);
        }
        for i in 0..12 {
            b.assert_zero(h.clone() * (row[i] - v[i].clone()));
        }
        let outputs = poseidon::evaluate(&mut b.when(h), &row[..248]);
        for (i, y) in outputs.into_iter().enumerate() {
            b.push_interaction(
                WIRE,
                [p[HASH_OUTPUT + 2 * i].into(), y],
                Count::bounded(p[HASH_OUTPUT + 2 * i + 1].into(), self.plan.max_fanout),
            );
        }
        // Each slot is enabled ONLY by immutable verifier-owned PP metadata.
        // A final short row has zero count and zero generic ports for every
        // unused tuple; no private routing bit or frequency selector is added.
        for slot in 0..POLICY_SLOTS {
            let active: AB::Expr = p[POLICY_ACTIVE + slot].into();
            b.push_interaction(
                POLICY,
                v[5 * slot..5 * slot + 5].iter().cloned(),
                Count::bounded(-active, 1),
            );
        }
        let table: [AB::Expr; 5] = core::array::from_fn(|i| p[POLICY_VALUES + i].into());
        b.push_interaction(
            POLICY,
            table,
            Count::bounded(
                f[POLICY_TABLE].clone() * v[0].clone(),
                self.plan.policy_queries as u32,
            ),
        );
        // Exact mask frequencies (0..4), bit/byte relation, and all four duplicate
        // physical-age queries. Control still constrains the zero-count mask payload.
        let mt = f[MASK_TABLE].clone();
        for j in 0..8 {
            b.assert_zero(mt.clone() * v[j].clone() * (v[j].clone() - AB::Expr::ONE));
            let n = bits[3 * j].clone()
                + bits[3 * j + 1].clone() * Val::from_u8(2)
                + bits[3 * j + 2].clone() * Val::from_u8(4);
            b.assert_zero(mt.clone() * (v[8 + j].clone() - n));
            b.assert_zero(
                mt.clone()
                    * bits[3 * j + 2].clone()
                    * (bits[3 * j].clone() + bits[3 * j + 1].clone()),
            );
            b.push_interaction(
                MASK,
                [p[MASK_INDEX] + Val::from_usize(j), v[j].clone()],
                Count::bounded(mt.clone() * v[8 + j].clone(), 4),
            );
        }
        let byte: AB::Expr = (0..8)
            .map(|j| v[j].clone() * Val::from_u64(1u64 << j))
            .sum();
        b.assert_zero(mt * (v[16].clone() - byte));
        let read = f[MASK_READ].clone();
        b.assert_zero(read.clone() * v[1].clone() * (v[1].clone() - AB::Expr::ONE));
        if !self.plan.pool.predicate {
            b.assert_zero(read.clone() * v[1].clone());
        }
        b.push_interaction(
            MASK,
            [v[0].clone(), v[1].clone()],
            Count::bounded(
                if self.plan.pool.predicate {
                    -read
                } else {
                    AB::Expr::ZERO
                },
                1,
            ),
        );
    }
}
/// Actual SDK automatic LogUp packing and ordered BASE/EXT count/degree. This
/// allocates symbolic DAGs only, never PP/Main/LDE/PCS/proofs. H may exceed512
/// solely to report the COMPLETE overflowed candidate; it is NOT an admitted H.
#[cfg(test)]
pub(super) fn symbolic_report(air: &ProgramAir) -> Result<String, String> {
    use p3_batch_stark::symbolic::{
        get_log_num_quotient_chunks_for_domain, get_max_constraint_degree, get_symbolic_constraints,
    };
    use p3_commit::PolynomialSpace;
    air.plan.inventory()?;
    let h = air.plan.height;
    let log = h.trailing_zeros() as usize;
    if 1usize.checked_shl(log as u32) != Some(h) {
        return Err("nonbinary-height".into());
    }
    let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, log).ok_or("domain")?;
    let layout = AirLayout::from_air(air);
    let gadget = LogUpGadget::new();
    let original = Lookups::<Val>::from_air::<Challenge, ProgramAir>(air);
    p3_lookup::check_bus_widths(core::slice::from_ref(&original)).map_err(|_| "bus-width")?;
    p3_lookup::check_multiplicity_height_bound(core::slice::from_ref(&original), &[h])
        .map_err(|_| "multiplicity-height")?;
    let sizing = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        air, layout, domain, &original, 1, &gadget,
    );
    let chunks = 1usize
        .checked_shl(sizing as u32)
        .ok_or("quotient-overflow")?;
    let packed = original.clone().pack_same_bus_with_degree(chunks, |q| {
        gadget.constraint_degree_with_transition(q, domain.transition_degree_multiple())
    });
    p3_lookup::check_bus_widths(core::slice::from_ref(&packed)).map_err(|_| "packed-bus-width")?;
    p3_lookup::check_multiplicity_height_bound(core::slice::from_ref(&packed), &[h])
        .map_err(|_| "packed-multiplicity")?;
    let after = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        air, layout, domain, &packed, 1, &gadget,
    );
    if sizing != after || packed.total_count_weight() != original.total_count_weight() {
        return Err("native-packing".into());
    }
    let (base, ext) =
        get_symbolic_constraints::<Val, Challenge, _, _>(air, layout, &packed, &gadget);
    let degree =
        get_max_constraint_degree::<Val, Challenge, _, _>(air, layout, h, &packed, &gadget);
    let committed = chunks.checked_mul(2).ok_or("zk-chunks")?;
    let aux = (packed.len() + 1).checked_mul(5).ok_or("aux-width")?;
    // Security/resource admission deliberately absent: any row overflow is FINAL
    // for this concrete layout. A fitted shape still needs the full actual report,
    // resource ledger and native hostile proving gates before any future backend.
    Ok(format!(
        "{} BASE={} EXT={} actual_degree={} original_messages={} default_packed={} committed_chunks={} rate_chunks=8 AUX={} EF=5 queries=192 random_codewords=5 salt_elements=4 security_assessed=false resources_assessed=false admitted=false stop={}",
        air.plan.summary(),
        base.len(),
        ext.len(),
        degree,
        original.len(),
        packed.len(),
        committed,
        aux,
        if air.plan.admissible_rows() {
            "native-security-resource-unassessed"
        } else {
            "complete-H512-overflow"
        }
    ))
}
