//! Actual sequential phase assessments over the shared serial SHA512/WHIR backend.
use crate::{
    COMPONENTS, Context, Error, Expected,
    machine::{self, Machine},
    statement,
};
use bfv_multilinear_stark::{AirSpec, Domains, assess, config_for};
pub use bfv_multilinear_stark::{Challenge, POLICY_BITS, Val, sha512 as digest};
pub(crate) use bfv_multilinear_stark::{Config, Proof};
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
        b"DCS/ARITHMETIC-BATCH/v2/LEAF/",
        b"DCS/ARITHMETIC-BATCH/v2/NODE/",
        b"DCS/ARITHMETIC-BATCH/v2/FS/",
        b"DCS/ARITHMETIC-BATCH/v2/statement/",
    )
    .expect("fixed prefix-free domains")
}
pub fn profile_digest(context: Context) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/ARITHMETIC-BATCH-PROOF/v2/profile/SHA512-full64/streaming-lookups/");
    h.update(bfv_multilinear_stark::PROTOCOL_DESCRIPTOR);
    h.update(b"fixed17=Extend0,Extend1,Extend2,Extend3,TensorQ0,Q1,Q2,Q3,Q4,P0,P1,P2,P3,P4,Down0,Down1,Down2;atomic3=[0,4),[4,14),[14,17);PV0;current-only;exact8192;noAuxWire;notDAG;notZK;frame320/BFVABP02;fixedProofArray3/oneSharedDecode;fullCanonicalOuterRequestOutputEveryFS;ordinalRange;minActualBitsMinus2;noPartialResult;noProverVK;globalRequestBindingsV1Unchanged");
    h.update(b"MAINvars23/23/22;PPvars21/22/21;lookupvars23/23/22;outerDegree2/3/2;fold4;rate4,7,10,13;queryCeil386,176,162,161,161;exactClaims650/165,544/282,492/186;cap0CanonicalPrunedFrontier;looseDecodeDepth26");
    for ordinal in 0..COMPONENTS {
        let namespace = statement::namespace(context, ordinal);
        for index in statement::component_range(ordinal).expect("fixed phase") {
            match statement::role(index).expect("fixed role") {
                (2, basis) => h.update(bfv_tensor_circuit::multistark::profile_digest(
                    bfv_tensor_circuit::Basis::new(basis).expect("fixed basis"),
                    namespace,
                )),
                (tag, _) => h.update(bfv_scale_circuit::multistark::profile_digest(
                    if tag == 1 {
                        bfv_scale_circuit::Role::Extend5To10
                    } else {
                        bfv_scale_circuit::Role::Scale10To5
                    },
                    namespace,
                )),
            }
        }
        for &range in machine::ranges(ordinal).expect("fixed supports") {
            h.update((range.bits() as u64).to_le_bytes());
            h.update((range.height() as u64).to_le_bytes());
            h.update(limb_range_air::bus(namespace, range).as_bytes());
        }
    }
    for n in [
        crate::MAX_FRAME_BYTES,
        crate::MAX_SEQUENCE_ELEMENTS,
        crate::MAX_DECODE_ELEMENTS,
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
    let range = statement::component_range(ordinal)?;
    let mut h = Sha512::new();
    h.update(b"DCS/ARITHMETIC-BATCH/v2/phase/full-outer-profile-and-position/");
    h.update(profile_digest(expected.context()));
    for n in [COMPONENTS, ordinal, range.start, range.end] {
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
    pub height: usize,
    pub main_width: usize,
    pub preprocessed_width: usize,
    pub constraints: usize,
    pub degree: usize,
    pub interactions: usize,
    pub count_weight: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct Term {
    pub label: &'static str,
    pub component: Option<&'static str>,
    pub bits: f64,
}
#[derive(Clone, Debug, Serialize)]
pub struct ComponentReport {
    pub ordinal: usize,
    pub first_relation: usize,
    pub end_relation: usize,
    pub stage: &'static str,
    pub relations: usize,
    pub air_count: usize,
    pub coefficients_per_relation: usize,
    pub main_cells: usize,
    pub preprocessed_cells: usize,
    pub lookup_contributions: usize,
    pub lookup_count_weight: usize,
    pub lookup_padded: usize,
    pub main_trace_bytes: usize,
    pub public_preprocessing_bytes: usize,
    pub outer_rounds: usize,
    pub outer_degree: usize,
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
pub struct ResourceBound {
    pub serialized_bytes: usize,
    pub decode_slots: usize,
    pub canonical_frontier_digests: usize,
    pub loose_frontier_digests: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct SecurityReport {
    pub stage: &'static str,
    pub relations: usize,
    pub component_count: usize,
    pub coefficients_per_relation: usize,
    pub required_security_bits: usize,
    pub whole_security_bits: f64,
    pub composition: &'static str,
    pub union_loss_bits: usize,
    pub unassessed_components: Vec<&'static str>,
    pub serialized_bound: usize,
    pub decode_slots_bound: usize,
    pub components: Vec<ComponentReport>,
}
pub(crate) struct Backend {
    pub machine: Machine,
    pub config: Config,
    pub prover: ProvingKey<Config>,
    pub verifier: VerifyingKey<Config>,
    pub report: ComponentReport,
}
impl Backend {
    pub fn new(expected: &Expected, ordinal: usize) -> Result<Self, Error> {
        let range = statement::component_range(ordinal)?;
        let supports = machine::ranges(ordinal)?;
        let machine = Machine::new(expected, ordinal)?;
        let mut tables = Vec::with_capacity(machine.airs.len());
        let mut atoms = 0usize;
        let mut weight = 0usize;
        let mut combined_degree = 0usize;
        for (index, air) in machine.airs.iter().enumerate() {
            if !air.prepared()
                || air.num_public_values() != 0
                || !air.main_next_row_columns().is_empty()
                || !air.preprocessed_next_row_columns().is_empty()
            {
                return Err(Error::Preparation);
            }
            let s = InteractionSymbolicBuilder::<Val, Challenge>::from_air(
                air,
                AirLayout::from_air::<Val>(air),
            );
            let cs = s.base_constraints();
            let degree = cs.iter().map(|c| c.poly_degree(2, &[])).max().unwrap_or(0);
            let interactions = s.global_interactions();
            let row_weight = interactions
                .iter()
                .map(|i| i.count_weight as usize)
                .sum::<usize>();
            let link_degree = interactions
                .iter()
                .flat_map(|i| i.fields.iter().chain(core::iter::once(&i.count)))
                .map(|e| e.poly_degree(2, &[]))
                .max()
                .unwrap_or(0);
            combined_degree = combined_degree.max(degree).max(link_degree);
            let wanted = if index < range.len() {
                match ordinal {
                    0 => (8192, 160, 40, 63, 1, 160, 160),
                    1 => (8192, 54, 28, 24, 2, 54, 54),
                    _ => (8192, 160, 60, 63, 1, 160, 160),
                }
            } else {
                let r = supports[index - range.len()];
                (r.height(), 2, 1, 1, 1, 1, 0)
            };
            if (
                air.height(),
                air.width(),
                air.preprocessed_width(),
                cs.len(),
                degree,
                interactions.len(),
                row_weight,
            ) != wanted
            {
                return Err(Error::Security);
            }
            atoms += air.height() * interactions.len();
            weight += air.height() * row_weight;
            tables.push(AirReport {
                height: air.height(),
                main_width: air.width(),
                preprocessed_width: air.preprocessed_width(),
                constraints: cs.len(),
                degree,
                interactions: interactions.len(),
                count_weight: row_weight,
            });
        }
        if tables.len() != range.len() + supports.len() {
            return Err(Error::Security);
        }
        let specs = machine
            .airs
            .iter()
            .map(|a| AirSpec::new(a, a.height().ilog2() as usize))
            .collect::<Vec<_>>();
        let (config, plan) = config_for(&specs, domains()).map_err(|_| Error::Security)?;
        let public = plan.preprocessed_pcs.ok_or(Error::Security)?;
        let wanted_geometry = match ordinal {
            0 => (5_473_312, 1_425_936, 5_358_096),
            1 => (4_555_776, 2_359_808, 4_489_728),
            _ => (4_178_976, 1_597_968, 4_055_568),
        };
        if (plan.main_cells, plan.preprocessed_cells, atoms) != wanted_geometry
            || plan.main_pcs.variables + 1 > MAX_MERKLE_DEPTH
            || public.variables + 1 > MAX_MERKLE_DEPTH
            || plan.main_pcs.queries.len() + public.queries.len() > MAX_TOTAL_QUERY_PHASES
            || plan.main_cells
                != tables
                    .iter()
                    .map(|t| t.height * t.main_width)
                    .sum::<usize>()
            || plan.preprocessed_cells
                != tables
                    .iter()
                    .map(|t| t.height * t.preprocessed_width)
                    .sum::<usize>()
        {
            return Err(Error::Security);
        }
        let lookup_padded = atoms.checked_next_power_of_two().ok_or(Error::Security)?;
        let lookup_rounds = lookup_padded.ilog2() as usize;
        let outer_rounds = lookup_rounds.max(
            tables
                .iter()
                .map(|t| t.height.ilog2() as usize)
                .max()
                .ok_or(Error::Security)?,
        );
        // The SDK adds the zerocheck equality weight to the maximum ordinary
        // constraint OR lookup field/count degree. Scalers are2; tensors are3.
        let outer_degree = combined_degree + 1;
        let wanted_outer_degree = if ordinal == 1 { 3 } else { 2 };
        if outer_degree != wanted_outer_degree {
            return Err(Error::Security);
        }
        let main_pcs: Schedule = plan.main_pcs.into();
        let preprocessed_pcs: Schedule = public.into();
        let bounds = resource_bound(
            ordinal,
            &tables,
            &main_pcs,
            &preprocessed_pcs,
            outer_rounds,
            outer_degree,
            lookup_rounds,
        )?;
        let refs = machine.airs.iter().collect::<Vec<_>>();
        let (prover, verifier) =
            setup(&config, &refs, &mut challenger(&config, expected, ordinal)?)
                .map_err(|_| Error::Preparation)?;
        let instances = VerifierInstances::new(
            machine
                .airs
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
            stage: "security_arithmetic_component",
            ordinal,
            first_relation: range.start,
            end_relation: range.end,
            relations: range.len(),
            air_count: tables.len(),
            coefficients_per_relation: 8192,
            main_cells: plan.main_cells,
            preprocessed_cells: plan.preprocessed_cells,
            lookup_contributions: atoms,
            lookup_count_weight: weight,
            lookup_padded,
            main_trace_bytes: plan.main_cells * 8,
            public_preprocessing_bytes: plan.preprocessed_cells * 8,
            outer_rounds,
            outer_degree,
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
/// Real verifier preprocessing and actual SDK assessment; no Aux or main trace.
pub fn analyze(expected: &Expected) -> Result<SecurityReport, Error> {
    let mut reports = Vec::with_capacity(COMPONENTS);
    for ordinal in 0..COMPONENTS {
        let backend = Backend::new(expected, ordinal)?;
        reports.push(backend.report.clone());
    }
    summarize(reports)
}

/// Binary cap-zero frontier for q queried leaves at depth d. Repeated queries
/// reduce the distinct leaf set; they cannot increase this upper bound.
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
    ordinal: usize,
    tables: &[AirReport],
    main: &Schedule,
    public: &Schedule,
    outer: usize,
    outer_degree: usize,
    lookup: usize,
) -> Result<ResourceBound, Error> {
    // These are acceptance ceilings for schedules RETURNED by config_for, not
    // purported query measurements. A future SDK/layout change must fail here.
    let (main_vars, public_vars, rounds) = match ordinal {
        0 => (23, 21, 23),
        1 => (23, 22, 23),
        2 => (22, 21, 22),
        _ => return Err(Error::Statement),
    };
    let main_ceiling: &[usize] = if main_vars == 23 {
        &[386, 176, 162, 161, 161]
    } else {
        &[386, 176, 162, 161]
    };
    schedule_bounds(main, main_vars, main_ceiling)?;
    schedule_bounds(public, public_vars, &[386, 176, 162, 161])?;
    let wanted_outer_degree = if ordinal == 1 { 3 } else { 2 };
    if outer != rounds
        || lookup != rounds
        || outer_degree != wanted_outer_degree
        || tables.len() > 12
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
            let siblings = frontier_bound(q, query_depth(schedule, i)?)?;
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
    let ef = 1
        + 4 * lookup
        + 3 * lookup * (lookup - 1) / 2
        + 1
        + outer_degree * outer
        + 2 * (main.variables + public.variables)
        + (1usize << main.final_variables)
        + (1usize << public.final_variables)
        + main.initial_claims
        + public.initial_claims;
    let caps = 1 + (main.queries.len() - 1) + (public.queries.len() - 1);
    // Remaining tags/lengths:2 per query,16 per AIR/GKR layer,8 per outer
    // round,32 per PCS phase,512 fixed. Ten bytes covers each Postcard marker.
    let metadata = 512 + 2 * queries + 16 * tables.len() + 16 * lookup + 8 * outer + 32 * phases;
    bytes += canonical * 80 + ef * 40 + caps * 80 + phases * 8 + metadata * 10;
    // Loose frontiers intentionally budget malformed-but-bounded containers;
    // accepted proofs must also pass the tighter canonical frontier check.
    // The outer fixed-array slot is charged once per component here.
    slots += loose * 9 + ef * 50 + caps * 11 + phases * 9 + metadata + 1;
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
pub(crate) fn summarize(components: Vec<ComponentReport>) -> Result<SecurityReport, Error> {
    if components.len() != COMPONENTS {
        return Err(Error::Security);
    }
    let mut minimum = f64::INFINITY;
    let mut bytes = crate::proof::HEADER;
    let mut slots = 0usize;
    for (ordinal, r) in components.iter().enumerate() {
        let range = statement::component_range(ordinal)?;
        if r.ordinal != ordinal
            || r.first_relation != range.start
            || r.end_relation != range.end
            || r.relations != range.len()
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
    // ceil(log2(3))=2. ilog2(3)=1 would undercharge this three-proof union.
    let bits = minimum - 2.;
    if bits < POLICY_BITS as f64
        || bytes > crate::MAX_FRAME_BYTES
        || slots > crate::MAX_DECODE_ELEMENTS
    {
        return Err(Error::Security);
    }
    Ok(SecurityReport {
        stage: "security_arithmetic_batch",
        relations: 17,
        component_count: COMPONENTS,
        coefficients_per_relation: 8192,
        required_security_bits: POLICY_BITS,
        whole_security_bits: bits,
        composition: "conservative min(actual component SDK bits)-ceil(log2(3))",
        union_loss_bits: 2,
        unassessed_components: Vec::new(),
        serialized_bound: bytes,
        decode_slots_bound: slots,
        components,
    })
}
