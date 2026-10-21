//! Native full-ProgramAir shape, security and allocation prescreen only.
//! No trace, proof, trusted preprocessing or mathematical capability is created.

use bfv_hiding_stark::{
    Challenge, Challenger, EXTENSION_DEGREE, LOG_BLOWUP, MODULUS_BITS, Pcs, QUERIES,
    RANDOM_CODEWORDS, SALT_ELEMENTS, SECURITY_BITS, Val,
};
use p3_air::BaseAir;
use p3_air::symbolic::AirLayout;
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks_for_domain, get_max_constraint_degree,
    get_symbolic_constraints,
};
use p3_commit::{PolynomialSpace, UnivariateStarkPcs};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, TwoAdicField};
use p3_lookup::{Kind, LogUpGadget, Lookups};
use p3_security::fri::FriRegime;
use p3_security::grinding::GrindingSites;
use p3_security::logup::{LogUpAir, security_term};
use p3_security::report::RegimeReport;
use p3_security::shape::{InstanceShape, StarkAirParams};
use p3_security::stark::proven_security_report;
use p3_uni_stark::{OpeningShape, ProvenSecurity, StarkSecurityParams};

use super::air::ProgramAir;
use super::{BUS, DEGREE_BITS, HEIGHT, LOG_HEIGHT, PORTS, PP_WIDTH, WIDTH};
use super::{Error, Result};

const RESOURCE_LIMIT_BYTES: usize = 1792 * 1024 * 1024;
const MESSAGE_WIDTH: usize = 2;
const MAX_PORT_COUNT: u32 = 4;
const DIGEST_WORDS: usize = 4;

/// Actual immutable-AIR metadata, never a submitted report or verification result.
/// Resource acceptance is deliberately separate so a rejected shape can be logged
/// without building its PP or private MAIN. Future proving must call that gate.
pub(in crate::gold) struct Assessment {
    chunks: usize,
    packed: usize,
    aux_width: usize,
    resources: Resources,
}

impl Assessment {
    pub(in crate::gold) fn chunks(&self) -> usize {
        self.chunks
    }
    pub(in crate::gold) fn aux_width(&self) -> usize {
        self.aux_width
    }
    pub(in crate::gold) fn packed_lookup_count(&self) -> usize {
        self.packed
    }

    /// Apply before calling preprocessed_trace, native setup or private MAIN.
    /// This conservative shape prescreen does not replace a held-PID RSS limit.
    pub(in crate::gold) fn require_resources(&self) -> Result<()> {
        if self.resources.estimated_workspace_bytes > RESOURCE_LIMIT_BYTES {
            return Err(Error::Resource);
        }
        Ok(())
    }
}

/// Assess the actual closed AIR before PP commitment or any private trace.
/// This never calls preprocessed_trace or accepts CommonData from another party.
/// Native setup must subsequently use the SAME AIR, fixed configuration and
/// automatic packing; this inspector is not a generic proving/verification API.
pub(in crate::gold) fn assess(air: &ProgramAir) -> Result<Assessment> {
    // This walks only the genuine public plan and all fixed row/port metadata.
    // It proves no private relation, but checks actual fanout, balance and counts.
    air.inventory()?;
    let shape = Shape::derive(air)?;
    let dimension = <Challenge as BasedVectorSpace<Val>>::DIMENSION;
    let modulus_bits = usize::try_from(Challenge::order().bits())
        .map_err(|_| Error::Security)?
        .checked_sub(1)
        .ok_or(Error::Security)?;
    let zk = usize::from(<Pcs as UnivariateStarkPcs<Challenge, Challenger>>::ZK);
    if zk != 1
        || dimension != EXTENSION_DEGREE
        || dimension != 5
        || modulus_bits != MODULUS_BITS
        || RANDOM_CODEWORDS != 5
        || SALT_ELEMENTS != 4
        || LOG_BLOWUP != 3
        || QUERIES != 192
        || SECURITY_BITS != 128
        || DEGREE_BITS != add(LOG_HEIGHT, zk)?
        || add(DEGREE_BITS, LOG_BLOWUP)? > Val::TWO_ADICITY
    {
        return Err(Error::Security);
    }
    // Native AUX is opened at both points unconditionally. MAIN and PP follow
    // their actual next-row traits; the complete width is opened at either point.
    let max_points = 2usize;
    let hiding_budget = mul(add(mul(dimension, max_points)?, QUERIES)?, 2)?;
    if dimension > RANDOM_CODEWORDS || hiding_budget > shape.height {
        return Err(Error::Security);
    }
    let domain =
        TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_HEIGHT).ok_or(Error::Shape)?;
    if domain.size() != shape.height {
        return Err(Error::Shape);
    }
    let layout = AirLayout::from_air(air);
    let gadget = LogUpGadget::new();
    let original = Lookups::<Val>::from_air::<Challenge, ProgramAir>(air);
    let messages = Messages::derive(&original)?;
    p3_lookup::check_bus_widths(core::slice::from_ref(&original)).map_err(|_| Error::Shape)?;
    p3_lookup::check_multiplicity_height_bound(core::slice::from_ref(&original), &[shape.height])
        .map_err(|_| Error::Security)?;

    // EXACT SDK ProverData::from_airs_and_degrees default algorithm. No packing
    // override is allowed. The domain is original H, not its ZK doubled degree.
    let unpacked_log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        air, layout, domain, &original, zk, &gadget,
    );
    let free_budget = add(pow2(unpacked_log)?, 1)?
        .checked_sub(zk)
        .ok_or(Error::Resource)?;
    let packed = original
        .clone()
        .pack_same_bus_with_degree(free_budget, |lookup| {
            gadget.constraint_degree_with_transition(lookup, domain.transition_degree_multiple())
        });
    if packed.is_empty()
        || packed.len() > original.len()
        || packed.total_count_weight() != original.total_count_weight()
    {
        return Err(Error::Shape);
    }
    let packed_messages = Messages::packed(&packed)?;
    if packed_messages != messages.count {
        return Err(Error::Shape);
    }
    p3_lookup::check_bus_widths(core::slice::from_ref(&packed)).map_err(|_| Error::Shape)?;
    p3_lookup::check_multiplicity_height_bound(core::slice::from_ref(&packed), &[shape.height])
        .map_err(|_| Error::Security)?;
    let packed_log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        air, layout, domain, &packed, zk, &gadget,
    );
    if packed_log != unpacked_log {
        return Err(Error::Shape);
    }
    let uncommitted_chunks = pow2(packed_log)?;
    let chunks = pow2(add(packed_log, zk)?)?;
    let rate_chunks = pow2(LOG_BLOWUP)?;
    // SDK's default packing equality is only debug asserted. Both this equality
    // and the ACTUAL ZK-doubled committed-chunk/rate test are mandatory in release.
    if chunks < 2 || chunks > rate_chunks {
        eprintln!(
            "gold_formation_security_rejected sizing_chunks={} committed_chunks={} rate_chunks={}",
            uncommitted_chunks, chunks, rate_chunks
        );
        return Err(Error::Security);
    }

    // These native helpers include REAL LogUp constraints in both BASE and EXT,
    // allocate the correct permutation/challenge/terminal symbolic widths, and
    // use the actual two-adic domain weighted degree. Base-only counting is wrong.
    let (base, extension) =
        get_symbolic_constraints::<Val, Challenge, _, _>(air, layout, &packed, &gadget);
    let base_constraints = base.len();
    let extension_constraints = extension.len();
    let constraints = add(base_constraints, extension_constraints)?;
    let native_layout =
        get_constraint_layout::<Val, Challenge, _, _>(air, layout, &packed, &gadget);
    if constraints == 0
        || native_layout.total_constraints() != constraints
        || air
            .num_constraints()
            .is_some_and(|hint| hint != base_constraints)
    {
        return Err(Error::Shape);
    }
    let degree = get_max_constraint_degree::<Val, Challenge, _, _>(
        air,
        layout,
        domain.size(),
        &packed,
        &gadget,
    )
    .max(air.max_constraint_degree().unwrap_or(0));
    if degree == 0 || degree > rate_chunks {
        return Err(Error::Security);
    }
    drop(base);
    drop(extension);
    let aux_width = mul(add(packed.len(), 1)?, dimension)?;
    let openings = p3_batch_stark::num_batched_openings(
        shape.main_width,
        !shape.main_next.is_empty(),
        shape.pp_width,
        !shape.pp_next.is_empty(),
        chunks,
        packed.len(),
        dimension,
        OpeningShape::hiding(RANDOM_CODEWORDS),
    );
    let max_combo =
        if !packed.is_empty() || !shape.main_next.is_empty() || !shape.pp_next.is_empty() {
            2
        } else {
            1
        };
    // All parameters below are the pinned actual bfv_hiding_stark::config:
    // Gold/EF5, native hiding FRI, binary folds/final degree1 and zero grinding.
    let fri = FriRegime {
        log_blowup: LOG_BLOWUP,
        num_queries: QUERIES,
        log_final_poly_len: 0,
        max_log_arity: 1,
        commit_pow_bits: 0,
        query_pow_bits: 0,
    };
    let grinding = GrindingSites::NONE;
    let air_shape = StarkAirParams {
        num_constraints: constraints,
        max_constraint_degree: degree,
        num_quotient_chunks: chunks,
        max_combo,
    };
    let instance = InstanceShape {
        log_trace_length: DEGREE_BITS,
        modulus_bits,
        collision_resistance: SECURITY_BITS,
        num_batched_functions: openings,
    };
    let params = StarkSecurityParams::new(
        fri,
        modulus_bits,
        SECURITY_BITS,
        constraints,
        degree,
        max_combo,
        openings,
        chunks,
    )
    .with_grinding(grinding);
    let baseline = ProvenSecurity::compute_from_proof(DEGREE_BITS, &params);
    // ORIGINAL uncompressed denominator count, never the smaller packed count.
    // Use the doubled committed height conservatively for this lookup extra.
    let logup = security_term(
        &LogUpAir {
            num_interactions: messages.count,
            max_message_width: messages.width,
        },
        &instance,
        &grinding,
    )
    .ok_or(Error::Security)?;
    let report = proven_security_report(&fri, &air_shape, &instance, &[logup], &grinding);
    if baseline.unique_decoding_bits < SECURITY_BITS
        || baseline.list_decoding_bits < SECURITY_BITS
        || !meets_floor(&report.udr)
        || !report.ldr.as_ref().is_some_and(meets_floor)
    {
        eprintln!(
            "gold_formation_security_rejected udr_bits={:.12} ldr_bits={:.12} logup_bits={:.12}",
            report.udr.security_bits(),
            report.ldr.as_ref().map_or(0.0, RegimeReport::security_bits),
            logup.bits.bits()
        );
        return Err(Error::Security);
    }
    let resources = Resources::derive(&shape, aux_width, chunks, dimension)?;
    #[cfg(test)]
    eprintln!(
        "core_gold_assessment relation={} base={} extension={} degree={} chunks={} original={} packed={} aux={} openings={} workspace_bytes={} unique_bits={} list_bits={} udr_bits={:.12} ldr_bits={:.12} logup_bits={:.12}",
        if air.kind() == super::super::relation::RelationKind::Data {
            "data"
        } else {
            "pair"
        },
        base_constraints,
        extension_constraints,
        degree,
        chunks,
        messages.count,
        packed.len(),
        aux_width,
        openings,
        resources.estimated_workspace_bytes,
        baseline.unique_decoding_bits,
        baseline.list_decoding_bits,
        report.udr.security_bits(),
        report.ldr.as_ref().map_or(0.0, RegimeReport::security_bits),
        logup.bits.bits()
    );
    Ok(Assessment {
        chunks,
        packed: packed.len(),
        aux_width,
        resources,
    })
}

fn meets_floor(regime: &RegimeReport) -> bool {
    let bits = regime.security_bits();
    bits.is_finite()
        && bits >= SECURITY_BITS as f64
        && !regime.terms().is_empty()
        && regime.terms().iter().all(|term| {
            let bits = term.bits.bits();
            bits.is_finite() && bits >= SECURITY_BITS as f64
        })
}

struct Shape {
    height: usize,
    main_width: usize,
    pp_width: usize,
    main_next: Vec<usize>,
    pp_next: Vec<usize>,
}
impl Shape {
    fn derive(air: &ProgramAir) -> Result<Self> {
        let main_width = air.width();
        let pp_width = air.preprocessed_width();
        let public_values = air.num_public_values();
        let main_next = air.main_next_row_columns();
        let pp_next = air.preprocessed_next_row_columns();
        // Closed-profile consistency checks; report inputs are still actual traits.
        // No call here materializes the large fixed preprocessing matrix.
        if main_width != WIDTH
            || pp_width != PP_WIDTH
            || public_values != air.kind().public_values()
            || HEIGHT != pow2(LOG_HEIGHT)?
            || main_width == 0
            || pp_width == 0
            || air.num_periodic_columns() != 0
            || !air.periodic_columns().is_empty()
            || !air.public_boundary_io().is_empty()
            || air.assumes_boolean_trace()
            || !valid_columns(&main_next, main_width)
            || !valid_columns(&pp_next, pp_width)
        {
            return Err(Error::Shape);
        }
        Ok(Self {
            height: HEIGHT,
            main_width,
            pp_width,
            main_next,
            pp_next,
        })
    }
}
fn valid_columns(columns: &[usize], width: usize) -> bool {
    columns.iter().all(|&i| i < width) && columns.windows(2).all(|p| p[0] < p[1])
}

struct Messages {
    count: usize,
    width: usize,
}
impl Messages {
    fn derive(original: &Lookups<Val>) -> Result<Self> {
        if original.is_empty() || original.len() != PORTS {
            return Err(Error::Shape);
        }
        let mut count = 0usize;
        let mut width = 0usize;
        for (i, lookup) in original.iter().enumerate() {
            if lookup.kind != Kind::Global(BUS.to_owned())
                || lookup.column != i
                || lookup.flags.is_some()
                || lookup.elements.len() != 1
                || lookup.multiplicities.len() != 1
                || lookup.count_weight == 0
                || lookup.count_weight > MAX_PORT_COUNT
            {
                return Err(Error::Shape);
            }
            for tuple in &lookup.elements {
                if tuple.len() != MESSAGE_WIDTH {
                    return Err(Error::Shape);
                }
                count = add(count, 1)?;
                width = width.max(tuple.len());
            }
        }
        Ok(Self { count, width })
    }
    fn packed(packed: &Lookups<Val>) -> Result<usize> {
        let mut count = 0usize;
        for (i, lookup) in packed.iter().enumerate() {
            if lookup.kind != Kind::Global(BUS.to_owned())
                || lookup.column != i
                || lookup.flags.is_some()
                || lookup.elements.len() != lookup.multiplicities.len()
                || lookup.elements.is_empty()
            {
                return Err(Error::Shape);
            }
            for tuple in &lookup.elements {
                if tuple.len() != MESSAGE_WIDTH {
                    return Err(Error::Shape);
                }
                count = add(count, 1)?;
            }
        }
        Ok(count)
    }
}

/// Checked stage-specific native-workspace budget, not a proven RSS bound.
/// The fixed1792MiB external whole-PID cap and every original raw, mask, salt,
/// tree and FRI reserve remain. PP is committed before MAIN, then AUX, quotient
/// and randomization. Conservatively reserve two copies of the current LDE;
/// owned conversions may move storage, and borrowed conversions may copy it.
/// An extra largest MAIN never overlaps all later committed banks.
/// Opening retains borrowed LDEs plus separately charged EF workspace below.
struct Resources {
    estimated_workspace_bytes: usize,
}
impl Resources {
    fn derive(s: &Shape, aux_width: usize, chunks: usize, dimension: usize) -> Result<Self> {
        let bytes = core::mem::size_of::<Val>();
        let ext_height = pow2(DEGREE_BITS)?;
        let lde_height = mul(ext_height, pow2(LOG_BLOWUP)?)?;
        let main = add(s.main_width, RANDOM_CODEWORDS)?;
        let aux = add(aux_width, RANDOM_CODEWORDS)?;
        let chunk = add(dimension, RANDOM_CODEWORDS)?;
        let quotient = mul(chunks, chunk)?;
        let total_width = [main, aux, s.pp_width, quotient, chunk]
            .into_iter()
            .try_fold(0usize, add)?;
        let raw_main_bytes = mul(mul(s.height, s.main_width)?, bytes)?;
        let raw_pp_bytes = mul(mul(s.height, s.pp_width)?, bytes)?;
        let raw_aux_bytes = mul(mul(s.height, aux_width)?, bytes)?;
        let masked_bank_bytes = mul(mul(ext_height, total_width)?, bytes)?;
        let matrices = add(chunks, 4)?;
        let salt_bytes = mul(mul(mul(matrices, lde_height)?, SALT_ELEMENTS)?, bytes)?;
        let tree_upper_bytes = mul(mul(mul(matrices, lde_height)?, 2 * DIGEST_WORDS)?, bytes)?;
        let fri_workspace_bytes = mul(
            mul(
                mul(2, lde_height)?,
                add(add(mul(2, dimension)?, SALT_ELEMENTS)?, 2 * DIGEST_WORDS)?,
            )?,
            bytes,
        )?;
        let bank_bytes = |width| mul(mul(lde_height, width)?, bytes);
        let stages = LdeStages::derive(
            bank_bytes(s.pp_width)?,
            bank_bytes(main)?,
            bank_bytes(aux)?,
            bank_bytes(quotient)?,
            bank_bytes(chunk)?,
        )?;
        // At most two unique points: zeta and zeta*g. Native opening borrows
        // all matrices. Its largest buffers are two denominator vectors, one
        // temporary input/result during sequential batch inversion, adjusted
        // weights of at most2*(H_LDE/8), one compressed and one reduced EF vector,
        // plus a base coset and small powers/opened/query data. Eight full EF
        // vectors conservatively cover their overlapping lifetimes. FRI's
        // retained folded vectors/salts/trees remain charged SEPARATELY above.
        let opening_workspace_bytes = mul(mul(mul(8, dimension)?, lde_height)?, bytes)?;
        let estimated_workspace_bytes = [
            raw_main_bytes,
            raw_pp_bytes,
            raw_aux_bytes,
            masked_bank_bytes,
            salt_bytes,
            tree_upper_bytes,
            fri_workspace_bytes,
            stages.peak(),
            opening_workspace_bytes,
        ]
        .into_iter()
        .try_fold(0usize, add)?;
        Ok(Self {
            estimated_workspace_bytes,
        })
    }
}

/// LDE ownership envelope for the pinned sequential one-AIR native prover.
/// Quotient conservatively duplicates its WHOLE bank, although native chunks
/// are transformed/copied one at a time. Every earlier committed bank stays live.
struct LdeStages {
    phases: [usize; 6],
}
impl LdeStages {
    fn derive(pp: usize, main: usize, aux: usize, quotient: usize, random: usize) -> Result<Self> {
        let pp_stage = mul(2, pp)?;
        let main_stage = add(pp, mul(2, main)?)?;
        let before_aux = add(pp, main)?;
        let aux_stage = add(before_aux, mul(2, aux)?)?;
        let before_quotient = add(before_aux, aux)?;
        let quotient_stage = add(before_quotient, mul(2, quotient)?)?;
        let before_random = add(before_quotient, quotient)?;
        let random_stage = add(before_random, mul(2, random)?)?;
        let opening = add(before_random, random)?;
        Ok(Self {
            phases: [
                pp_stage,
                main_stage,
                aux_stage,
                quotient_stage,
                random_stage,
                opening,
            ],
        })
    }
    fn peak(&self) -> usize {
        // All fixed phases are present; the array is never empty.
        *self
            .phases
            .iter()
            .max()
            .expect("six native ownership phases")
    }
}

fn pow2(exponent: usize) -> Result<usize> {
    1usize
        .checked_shl(u32::try_from(exponent).map_err(|_| Error::Resource)?)
        .ok_or(Error::Resource)
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Resource)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(Error::Resource)
}

#[cfg(test)]
mod stage_tests {
    use super::*;

    #[test]
    fn main_copy_does_not_overlap_future_aux_and_quotient_banks() {
        let stages = LdeStages::derive(272, 517, 225, 80, 10).unwrap();
        assert_eq!(stages.phases[1], 1306);
        assert_eq!(stages.phases[5], 1104);
        assert_eq!(stages.peak(), stages.phases[1]);
        assert!(stages.peak() < stages.phases[5] + 517);
    }

    #[test]
    fn a_later_quotient_copy_can_be_the_peak() {
        let stages = LdeStages::derive(2, 3, 5, 100, 7).unwrap();
        assert_eq!(stages.phases[3], 210);
        assert_eq!(stages.peak(), stages.phases[3]);
        assert_eq!(stages.phases[5], 117);
    }

    #[test]
    fn every_phase_addition_and_doubling_is_checked() {
        for banks in [
            [usize::MAX, 0, 0, 0, 0],
            [0, usize::MAX, 0, 0, 0],
            [0, 0, usize::MAX, 0, 0],
            [0, 0, 0, usize::MAX, 0],
            [0, 0, 0, 0, usize::MAX],
            [usize::MAX / 2, usize::MAX / 2, usize::MAX / 2, 0, 0],
        ] {
            assert!(matches!(
                LdeStages::derive(banks[0], banks[1], banks[2], banks[3], banks[4]),
                Err(Error::Resource)
            ));
        }
    }
}
