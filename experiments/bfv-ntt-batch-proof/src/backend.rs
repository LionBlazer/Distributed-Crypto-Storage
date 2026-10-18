//! Actual SDK assessment for sequential two-instance units of one atomic statement.
use crate::{Error, Expected};
use bfv_multilinear_stark::{AirSpec, Domains, assess, config_for};
pub use bfv_multilinear_stark::{Challenge, POLICY_BITS, Val, sha512 as digest};
pub(crate) use bfv_multilinear_stark::{Config, Proof};
use bfv_ntt_circuit::{
    DEGREE,
    multistark::{PreparedBatch, prepare_batch},
    parameters,
};
use p3_air::{BaseAir, symbolic::AirLayout};
use p3_lookup::InteractionSymbolicBuilder;
use p3_multi_stark::{ProvingKey, VerifierInstance, VerifierInstances, VerifyingKey, setup};
use serde::Serialize;
use sha2::{Digest, Sha512};

pub const MAX_MERKLE_DEPTH: usize = 26;
pub const MAX_TOTAL_QUERY_PHASES: usize = 10;
pub const COMPONENT_SERIALIZED_BOUND: usize = 2_649_168;
pub const COMPONENT_DECODE_SLOTS_BOUND: usize = 1_675_589;

pub(crate) fn domains() -> Domains {
    Domains::new(
        b"DCS/NTT-BATCH/v2/LEAF/",
        b"DCS/NTT-BATCH/v2/NODE/",
        b"DCS/NTT-BATCH/v2/FS/",
        b"DCS/NTT-BATCH/v2/statement/",
    )
    .unwrap()
}
pub fn profile(expected: &Expected) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/NTT-BATCH-PROOF/v2/profile/full-SHA512/streaming-lookups/");
    h.update(b"BFVNTB02/frame320/uniform-complete2/outer2,4,8/fixed-array1,2,4/shared-decode-budget/full-outer-request-output/component-ordinal-range/min-actual-bits-minus-log2-count/atomic-no-partial-result/no-Aux/no-prover-VK");
    h.update(bfv_multilinear_stark::PROTOCOL_DESCRIPTOR);
    h.update(bfv_ntt_circuit::multistark::MACHINE_DESCRIPTOR);
    h.update(bfv_ntt_circuit::multistark::BATCH_DESCRIPTOR);
    h.update((expected.requests().len() as u64).to_le_bytes());
    for r in expected.requests() {
        h.update([r.direction() as u8, r.basis().index()]);
        for v in [
            r.basis().modulus(),
            parameters(r.basis()).primitive_root(),
            parameters(r.basis()).inverse_size(),
        ] {
            h.update(v.to_le_bytes());
        }
        for weights in [
            parameters(r.basis()).forward_twiddles(),
            parameters(r.basis()).inverse_twiddles(),
        ] {
            for &v in weights {
                h.update(v.to_le_bytes());
            }
        }
    }
    for n in [
        crate::MAX_FRAME_BYTES,
        crate::MAX_SEQUENCE_ELEMENTS,
        crate::MAX_DECODE_ELEMENTS,
        crate::MAX_COMPONENT_PROOF_BYTES,
        COMPONENT_SERIALIZED_BOUND,
        COMPONENT_DECODE_SLOTS_BOUND,
        MAX_MERKLE_DEPTH,
        MAX_TOTAL_QUERY_PHASES,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
}
pub(crate) fn component_profile(expected: &Expected, ordinal: usize) -> Result<[u8; 64], Error> {
    let range = expected.component_range(ordinal)?;
    let mut h = Sha512::new();
    h.update(b"DCS/NTT-BATCH/v2/component/full-outer-profile-and-position/");
    h.update(profile(expected));
    for n in [expected.component_count(), ordinal, range.start, range.end] {
        h.update((n as u64).to_le_bytes());
    }
    Ok(h.finalize().into())
}
pub(crate) fn challenger(
    config: &Config,
    expected: &Expected,
    ordinal: usize,
) -> Result<bfv_multilinear_stark::Challenger, Error> {
    Ok(config.challenger(
        component_profile(expected, ordinal)?,
        &expected.request_wire(),
        &expected.output_wire(),
    ))
}

#[derive(Clone, Debug, Serialize)]
pub struct Schedule {
    pub variables: usize,
    pub folding: Vec<usize>,
    pub queries: Vec<usize>,
    pub rates: Vec<usize>,
    pub initial_claims: usize,
    pub final_variables: usize,
}
impl From<bfv_multilinear_stark::PcsSchedule> for Schedule {
    fn from(s: bfv_multilinear_stark::PcsSchedule) -> Self {
        Self {
            variables: s.variables,
            folding: s.folding,
            queries: s.queries,
            rates: s.rates,
            initial_claims: s.initial_claims,
            final_variables: s.final_variables,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct AirReport {
    pub instance: Option<usize>,
    pub height: usize,
    pub main_width: usize,
    pub preprocessed_width: usize,
    pub constraints: usize,
    pub degree: usize,
    pub interactions: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct Term {
    pub label: &'static str,
    pub component: Option<&'static str>,
    pub bits: f64,
}
#[derive(Clone, Debug, Serialize)]
pub struct ResourceBound {
    pub serialized_bytes: usize,
    pub decode_slots: usize,
    pub canonical_frontier_digests: usize,
    pub loose_frontier_digests: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct ComponentReport {
    pub ordinal: usize,
    pub first_instance: usize,
    pub end_instance: usize,
    pub batch: usize,
    pub air_count: usize,
    pub coefficients_per_instance: usize,
    pub main_cells: usize,
    pub preprocessed_cells: usize,
    pub lookup_contributions: usize,
    pub lookup_count_weight: usize,
    pub lookup_padded: usize,
    pub main_trace_bytes: usize,
    pub public_preprocessing_bytes: usize,
    pub outer_rounds: usize,
    pub lookup_rounds: usize,
    pub required_security_bits: usize,
    pub whole_security_bits: f64,
    pub unassessed_components: Vec<&'static str>,
    pub terms: Vec<Term>,
    pub tables: Vec<AirReport>,
    pub main_pcs: Schedule,
    pub preprocessed_pcs: Schedule,
    pub bounds: ResourceBound,
}
#[derive(Clone, Debug, Serialize)]
pub struct SecurityReport {
    pub stage: &'static str,
    pub batch: usize,
    pub component_count: usize,
    pub instances_per_component: usize,
    pub coefficients_per_instance: usize,
    pub required_security_bits: usize,
    pub whole_security_bits: f64,
    pub composition: &'static str,
    pub union_loss_bits: usize,
    pub unassessed_components: Vec<&'static str>,
    pub serialized_bound: usize,
    pub decode_slots_bound: usize,
    pub components: Vec<ComponentReport>,
}

/// Binary cap-zero frontier for at most q distinct leaves at depth d.
/// At each level a maximal frontier occupies min(q, 2^(d-level)) nodes.
/// Repeated STIR queries only reduce the number of distinct authenticated leaves.
pub(crate) fn frontier_bound(q: usize, d: usize) -> Result<usize, Error> {
    if q == 0 || d == 0 || d > MAX_MERKLE_DEPTH || q > (1usize << (d - 1)) {
        return Err(Error::Security);
    }
    let mut bound = 2usize;
    for level in 1..d {
        bound = bound
            .checked_add(q.min(1usize << (d - level)))
            .ok_or(Error::ResourceLimit)?;
    }
    bound.checked_sub(q).ok_or(Error::Security)
}
pub(crate) fn query_depth(s: &Schedule, phase: usize) -> Result<usize, Error> {
    if phase >= s.folding.len() {
        return Err(Error::Security);
    }
    let prior = s.folding[..phase].iter().sum::<usize>();
    let rate = if phase == 0 {
        1
    } else {
        *s.rates.get(phase - 1).ok_or(Error::Security)?
    };
    s.variables
        .checked_sub(prior)
        .and_then(|n| n.checked_add(rate))
        .and_then(|n| n.checked_sub(s.folding[phase]))
        .filter(|&d| d > 0 && d <= MAX_MERKLE_DEPTH)
        .ok_or(Error::Security)
}
fn schedule_bounds(s: &Schedule, variables: usize, max_queries: &[usize]) -> Result<(), Error> {
    if s.variables != variables
        || s.folding.len() != max_queries.len()
        || s.queries.len() != max_queries.len()
        || s.rates.len() + 1 != max_queries.len()
        || s.folding.iter().any(|&f| f != 4)
        || s.rates.iter().enumerate().any(|(i, &r)| r != 4 + 3 * i)
        || s.queries
            .iter()
            .zip(max_queries)
            .any(|(&q, &max)| q == 0 || q > max)
        || s.final_variables != variables - 4 * max_queries.len()
    {
        return Err(Error::Security);
    }
    Ok(())
}
fn resource_bound(
    tables: &[AirReport],
    main: &Schedule,
    public: &Schedule,
    outer_rounds: usize,
    lookup_rounds: usize,
) -> Result<ResourceBound, Error> {
    // Acceptance ceilings for schedules DERIVED by config_for. An SDK change
    // fails rather than silently assuming the old byte or decoder bound.
    schedule_bounds(main, 23, &[386, 176, 162, 161, 161])?;
    schedule_bounds(public, 22, &[386, 176, 162, 161])?;
    if tables.len() > 34
        || outer_rounds != 23
        || lookup_rounds != 23
        || main.initial_claims != tables.iter().map(|t| t.main_width).sum::<usize>()
        || public.initial_claims != tables.iter().map(|t| t.preprocessed_width).sum::<usize>()
        || main.initial_claims > 990
        || public.initial_claims > 330
    {
        return Err(Error::Security);
    }
    let mut bytes = 0usize;
    let mut slots = 0usize;
    let mut canonical = 0usize;
    let mut loose = 0usize;
    let phases = main.queries.len() + public.queries.len();
    let queries = main.queries.iter().chain(&public.queries).sum::<usize>();
    for schedule in [main, public] {
        for (i, &q) in schedule.queries.iter().enumerate() {
            let d = query_depth(schedule, i)?;
            let siblings = frontier_bound(q, d)?;
            let width = 1usize << schedule.folding[i];
            if q * MAX_MERKLE_DEPTH > crate::MAX_SEQUENCE_ELEMENTS {
                return Err(Error::Security);
            }
            canonical += siblings;
            loose += q * MAX_MERKLE_DEPTH;
            // Gold binary serde is8 bytes/9 nested slots. EF5 is40 bytes;
            // 50 slots includes its struct/array/Gold parent containers.
            bytes += q * width * if i == 0 { 8 } else { 40 };
            slots += q * (1 + width * if i == 0 { 9 } else { 50 });
        }
    }
    // GKR root/layers, outer sumcheck, both WHIR sumchecks/final polynomials,
    // and every current-only column evaluation, all in the actual plan.
    let ef = 1
        + 4 * lookup_rounds
        + 3 * lookup_rounds * (lookup_rounds - 1) / 2
        + 1
        + 3 * outer_rounds
        + 2 * (main.variables + public.variables)
        + (1usize << main.final_variables)
        + (1usize << public.final_variables)
        + main.initial_claims
        + public.initial_claims;
    let caps = 1 + (main.queries.len() - 1) + (public.queries.len() - 1);
    let pow_scalars = phases; // all intermediate/final WHIR witnesses must be ZERO
    // Every remaining length/tag/struct slot: <=2 per query,16 per AIR,
    // 16 per GKR layer,8 per outer round,32 per PCS phase, plus512 fixed.
    // Ten bytes per such item bounds each Postcard usize/enum/option marker;
    // struct fields themselves add no serialized delimiters.
    let metadata =
        512 + 2 * queries + 16 * tables.len() + 16 * lookup_rounds + 8 * outer_rounds + 32 * phases;
    bytes += canonical * 80 + ef * 40 + caps * 80 + pow_scalars * 8 + metadata * 10;
    // One outer fixed-array slot per proof is charged here, exactly once.
    slots += loose * 9 + ef * 50 + caps * 11 + pow_scalars * 9 + metadata + 1;
    if bytes > COMPONENT_SERIALIZED_BOUND || slots > COMPONENT_DECODE_SLOTS_BOUND {
        return Err(Error::ResourceLimit);
    }
    Ok(ResourceBound {
        serialized_bytes: bytes,
        decode_slots: slots,
        canonical_frontier_digests: canonical,
        loose_frontier_digests: loose,
    })
}

pub(crate) struct Backend {
    pub machine: PreparedBatch,
    pub config: Config,
    pub prover: ProvingKey<Config>,
    pub verifier: VerifyingKey<Config>,
    pub report: ComponentReport,
}
impl Backend {
    pub fn new(expected: &Expected, ordinal: usize) -> Result<Self, Error> {
        let range = expected.component_range(ordinal)?;
        // Keep original GLOBAL labels. Only this pair's trusted private data
        // buses are local0/1; full outer bytes and position seed the transcript.
        let machine = prepare_batch(
            &expected.requests()[range.clone()],
            &expected.outputs()[range.clone()],
        )
        .map_err(|_| Error::Statement)?;
        let mut tables = Vec::new();
        let mut interactions = 0usize;
        let mut weight = 0usize;
        for (air, table) in machine.airs().iter().zip(machine.shape().tables()) {
            if !air.is_prepared()
                || air.num_public_values() != 0
                || !air.main_next_row_columns().is_empty()
                || !air.preprocessed_next_row_columns().is_empty()
            {
                return Err(Error::Preparation);
            }
            let symbolic = InteractionSymbolicBuilder::<Val, Challenge>::from_air(
                air,
                AirLayout::from_air::<Val>(air),
            );
            let cs = symbolic.base_constraints();
            let degree = cs.iter().map(|e| e.poly_degree(2, &[])).max().unwrap_or(0);
            let atoms = symbolic.global_interactions();
            if cs.is_empty()
                || degree > 2
                || atoms.len() != table.table().lookup_contributions_per_row()
            {
                return Err(Error::Security);
            }
            interactions += air.height() * atoms.len();
            weight += air.height() * atoms.iter().map(|a| a.count_weight as usize).sum::<usize>();
            tables.push(AirReport {
                instance: table.instance().map(|i| range.start + i),
                height: air.height(),
                main_width: air.width(),
                preprocessed_width: air.preprocessed_width(),
                constraints: cs.len(),
                degree,
                interactions: atoms.len(),
            });
        }
        let shape = machine.shape();
        if interactions != shape.total_lookup_contributions()
            || weight != shape.total_lookup_count_weight()
        {
            return Err(Error::Security);
        }
        let specs = machine
            .airs()
            .iter()
            .map(|a| AirSpec::new(a, a.height().ilog2() as usize))
            .collect::<Vec<_>>();
        let (config, plan) = config_for(&specs, domains()).map_err(|_| Error::Security)?;
        let public = plan.preprocessed_pcs.ok_or(Error::Security)?;
        if plan.main_cells != shape.total_main_cells()
            || plan.preprocessed_cells != shape.total_preprocessed_cells()
            || plan.main_pcs.variables + 1 > MAX_MERKLE_DEPTH
            || public.variables + 1 > MAX_MERKLE_DEPTH
            || plan.main_pcs.queries.len() + public.queries.len() > MAX_TOTAL_QUERY_PHASES
        {
            return Err(Error::Security);
        }
        let lookup_padded = interactions
            .checked_next_power_of_two()
            .ok_or(Error::Security)?;
        let lookup_rounds = lookup_padded.ilog2() as usize;
        let outer_rounds = lookup_rounds.max(
            tables
                .iter()
                .map(|t| t.height.ilog2() as usize)
                .max()
                .ok_or(Error::Security)?,
        );
        let main_pcs: Schedule = plan.main_pcs.into();
        let preprocessed_pcs: Schedule = public.into();
        let bounds = resource_bound(
            &tables,
            &main_pcs,
            &preprocessed_pcs,
            outer_rounds,
            lookup_rounds,
        )?;
        let refs = machine.airs().iter().collect::<Vec<_>>();
        let (prover, verifier) =
            setup(&config, &refs, &mut challenger(&config, expected, ordinal)?)
                .map_err(|_| Error::Preparation)?;
        let instances = VerifierInstances::new(
            machine
                .airs()
                .iter()
                .map(|a| VerifierInstance::new(a, &verifier, a.height().ilog2() as usize, &[]))
                .collect(),
        );
        let actual = assess(&config, &instances).map_err(|_| Error::Security)?;
        actual
            .require_security(POLICY_BITS)
            .map_err(|_| Error::Security)?;
        let bits = actual.security_bits().ok_or(Error::Security)?;
        if !bits.is_finite() || !actual.unassessed_components().is_empty() {
            return Err(Error::Security);
        }
        let report = ComponentReport {
            ordinal,
            first_instance: range.start,
            end_instance: range.end,
            batch: 2,
            air_count: tables.len(),
            coefficients_per_instance: DEGREE,
            main_cells: plan.main_cells,
            preprocessed_cells: plan.preprocessed_cells,
            lookup_contributions: interactions,
            lookup_count_weight: weight,
            lookup_padded,
            main_trace_bytes: plan.main_cells * 8,
            public_preprocessing_bytes: plan.preprocessed_cells * 8,
            outer_rounds,
            lookup_rounds,
            required_security_bits: POLICY_BITS,
            whole_security_bits: bits,
            unassessed_components: actual.unassessed_components().to_vec(),
            terms: actual
                .terms()
                .iter()
                .map(|t| Term {
                    label: t.label,
                    component: t.component,
                    bits: t.bits.bits(),
                })
                .collect(),
            tables,
            main_pcs,
            preprocessed_pcs,
            bounds,
        };
        Ok(Self {
            machine,
            config,
            prover,
            verifier,
            report,
        })
    }
}
pub(crate) fn summarize(
    expected: &Expected,
    components: Vec<ComponentReport>,
) -> Result<SecurityReport, Error> {
    let count = expected.component_count();
    if components.len() != count || !matches!(count, 1 | 2 | 4) {
        return Err(Error::Security);
    }
    let mut minimum = f64::INFINITY;
    let mut bytes = crate::proof::HEADER;
    let mut slots = 0usize;
    for (ordinal, r) in components.iter().enumerate() {
        let range = expected.component_range(ordinal)?;
        if r.ordinal != ordinal
            || r.first_instance != range.start
            || r.end_instance != range.end
            || r.batch != 2
            || !r.whole_security_bits.is_finite()
            || r.whole_security_bits < POLICY_BITS as f64
            || !r.unassessed_components.is_empty()
        {
            return Err(Error::Security);
        }
        minimum = minimum.min(r.whole_security_bits);
        bytes = bytes
            .checked_add(r.bounds.serialized_bytes)
            .ok_or(Error::ResourceLimit)?;
        slots = slots
            .checked_add(r.bounds.decode_slots)
            .ok_or(Error::ResourceLimit)?;
    }
    let loss = count.ilog2() as usize;
    let bits = minimum - loss as f64;
    if bits < POLICY_BITS as f64
        || bytes > crate::MAX_FRAME_BYTES
        || slots > crate::MAX_DECODE_ELEMENTS
    {
        return Err(Error::Security);
    }
    Ok(SecurityReport {
        stage: "security_batched_ntt",
        batch: expected.requests().len(),
        component_count: count,
        instances_per_component: 2,
        coefficients_per_instance: DEGREE,
        required_security_bits: POLICY_BITS,
        whole_security_bits: bits,
        composition: "conservative min(actual component SDK bits)-log2(component count)",
        union_loss_bits: loss,
        unassessed_components: Vec::new(),
        serialized_bound: bytes,
        decode_slots_bound: slots,
        components,
    })
}
/// Zero IO with real ordered PP/VK/security; no NTT/Aux/main witness is generated.
pub fn analyze(
    context: crate::Context,
    specs: &[bfv_ntt_circuit::multistark::BatchSpec],
) -> Result<SecurityReport, Error> {
    let expected = crate::fixture::zero_statement(context, specs)?;
    let mut components = Vec::with_capacity(expected.component_count());
    for ordinal in 0..expected.component_count() {
        let backend = Backend::new(&expected, ordinal)?;
        components.push(backend.report.clone());
        drop(backend);
    }
    summarize(&expected, components)
}
