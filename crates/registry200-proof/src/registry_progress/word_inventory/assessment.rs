//! Closed r2 native security/resource metadata only. No PP, MAIN or proof is built.
//! All reports remain nonaccepting; the future witness/owner boundary is separate.
use super::{
    air::ProgramAir,
    plan::{PORTS, PP_WIDTH, WIDTH},
};
use bfv_hiding_stark::{
    Challenge, Challenger, EXTENSION_DEGREE, LOG_BLOWUP, MODULUS_BITS, Pcs, QUERIES,
    RANDOM_CODEWORDS, SALT_ELEMENTS, SECURITY_BITS, Val,
};
use p3_air::{BaseAir, symbolic::AirLayout};
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks_for_domain, get_max_constraint_degree,
    get_symbolic_constraints,
};
use p3_commit::{PolynomialSpace, UnivariateStarkPcs};
use p3_field::{
    BasedVectorSpace, Field, PrimeCharacteristicRing, TwoAdicField,
    coset::TwoAdicMultiplicativeCoset,
};
use p3_lookup::{Kind, LogUpGadget, Lookups};
use p3_security::{
    fri::FriRegime,
    grinding::GrindingSites,
    logup::{LogUpAir, security_term},
    report::{RegimeReport, SecurityReport},
    shape::{InstanceShape, StarkAirParams},
    stark::proven_security_report,
};
use p3_uni_stark::{OpeningShape, ProvenSecurity, StarkSecurityParams};

type Result<T> = core::result::Result<T, String>;
const HEIGHT: usize = 512;
const LOG_HEIGHT: usize = 9;
const RESOURCE_LIMIT_BYTES: usize = 1792 * 1024 * 1024;
const BUS_WIRE: &str = "DCS/research/word208/v1/ssa";
const BUS_POLICY: &str = "DCS/research/word208/v1/policy25";
const BUS_MASK: &str = "DCS/research/word208/v1/mask256";

/// Derived numeric metadata, not a checked state, mathematical proof or grant.
pub(super) struct Assessment {
    role: &'static str,
    base: usize,
    extension: usize,
    degree: usize,
    original: usize,
    widest: usize,
    weight: u64,
    weighted_height: u64,
    packed: usize,
    chunks: usize,
    aux: usize,
    openings: usize,
    hiding_rows: usize,
    baseline: ProvenSecurity,
    baseline_report: SecurityReport,
    report: SecurityReport,
    logup_bits: f64,
    resources: Resources,
}
impl Assessment {
    pub(super) fn chunks(&self) -> usize {
        self.chunks
    }
    pub(super) fn aux_width(&self) -> usize {
        self.aux
    }
    pub(super) fn packed_lookup_count(&self) -> usize {
        self.packed
    }
    pub(super) fn openings(&self) -> usize {
        self.openings
    }

    /// Apply before any PP commitment or private trace. Still not an RSS theorem.
    pub(super) fn require_resources(&self) -> Result<()> {
        if self.resources.total > RESOURCE_LIMIT_BYTES {
            return Err("word-assessment:resource-limit".into());
        }
        Ok(())
    }
    fn require_security(&self) -> Result<()> {
        if self.baseline.unique_decoding_bits < SECURITY_BITS
            || self.baseline.list_decoding_bits < SECURITY_BITS
            || !meets_floor(&self.baseline_report.udr)
            || !self.baseline_report.ldr.as_ref().is_some_and(meets_floor)
            || !meets_floor(&self.report.udr)
            || !self.report.ldr.as_ref().is_some_and(meets_floor)
            || !self.logup_bits.is_finite()
            || self.logup_bits < SECURITY_BITS as f64
        {
            return Err("word-assessment:security-floor".into());
        }
        Ok(())
    }
    fn log(&self) {
        eprintln!(
            "word_assessment role={} H={} MAIN={} PP={} main_next={} pp_next={} BASE={} EXT={} degree={} original={} widest={} count_weight={} weighted_height={} packed={} chunks={} AUX={} openings={} hiding_rows={} baseline_udr={} baseline_ldr={} udr_bits={:.12} ldr_bits={:.12} logup_bits={:.12} workspace_bytes={} external_cap={} admitted=false proof=false owner_budget_unproven=true",
            self.role,
            HEIGHT,
            WIDTH,
            PP_WIDTH,
            WIDTH,
            PP_WIDTH,
            self.base,
            self.extension,
            self.degree,
            self.original,
            self.widest,
            self.weight,
            self.weighted_height,
            self.packed,
            self.chunks,
            self.aux,
            self.openings,
            self.hiding_rows,
            self.baseline.unique_decoding_bits,
            self.baseline.list_decoding_bits,
            self.report.udr.security_bits(),
            self.report
                .ldr
                .as_ref()
                .map_or(0.0, RegimeReport::security_bits),
            self.logup_bits,
            self.resources.total,
            RESOURCE_LIMIT_BYTES
        );
        for (name, regime) in [
            ("baseline-udr", Some(&self.baseline_report.udr)),
            ("baseline-ldr", self.baseline_report.ldr.as_ref()),
            ("composed-udr", Some(&self.report.udr)),
            ("composed-ldr", self.report.ldr.as_ref()),
        ] {
            if let Some(regime) = regime {
                for term in regime.terms() {
                    eprintln!(
                        "word_assessment_term role={} regime={} term={} bits={:.12}",
                        self.role,
                        name,
                        term.label,
                        term.bits.bits()
                    );
                }
            }
        }
        for &(label, bytes) in &self.resources.charges {
            eprintln!(
                "word_assessment_resource role={} category={} bytes={}",
                self.role, label, bytes
            );
        }
        eprintln!(
            "word_assessment_lde_stages role={} bytes={:?}",
            self.role, self.resources.stages
        );
    }
}

/// Uses the SAME immutable AIR and native default algorithm. No caller counts,
// custom report, configuration, PP or CommonData can replace those inputs.
pub(super) fn assess(air: &ProgramAir) -> Result<Assessment> {
    air.plan.inventory()?;
    if air.plan.rows.len() > HEIGHT
        || air.plan.height != HEIGHT
        || WIDTH != 568
        || PP_WIDTH != 708
        || air.width() != WIDTH
        || air.preprocessed_width() != PP_WIDTH
        || air.num_public_values() != 0
        || air.num_periodic_columns() != 0
        || !air.periodic_columns().is_empty()
        || !air.public_boundary_io().is_empty()
        || air.assumes_boolean_trace()
        || air.main_next_row_columns() != (0..WIDTH).collect::<Vec<_>>()
        || air.preprocessed_next_row_columns() != (0..PP_WIDTH).collect::<Vec<_>>()
    {
        return Err("word-assessment:closed-shape".into());
    }
    let dimension = <Challenge as BasedVectorSpace<Val>>::DIMENSION;
    let bits = usize::try_from(Challenge::order().bits())
        .map_err(|_| "field-bits")?
        .checked_sub(1)
        .ok_or("field-bits")?;
    let zk = usize::from(<Pcs as UnivariateStarkPcs<Challenge, Challenger>>::ZK);
    let committed_log = add(LOG_HEIGHT, zk)?;
    if zk != 1
        || dimension != EXTENSION_DEGREE
        || dimension != 5
        || bits != MODULUS_BITS
        || bits != 319
        || LOG_BLOWUP != 3
        || QUERIES != 192
        || RANDOM_CODEWORDS != 5
        || SALT_ELEMENTS != 4
        || SECURITY_BITS != 128
        || add(committed_log, LOG_BLOWUP)? > Val::TWO_ADICITY
    {
        return Err("word-assessment:configuration".into());
    }
    let hiding_rows = mul(add(QUERIES, mul(dimension, 2)?)?, 2)?;
    if RANDOM_CODEWORDS < dimension || hiding_rows > HEIGHT {
        return Err("word-assessment:hiding-budget".into());
    }
    let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_HEIGHT).ok_or("domain")?;
    if domain.size() != HEIGHT {
        return Err("word-assessment:domain".into());
    }
    let layout = AirLayout::from_air(air);
    let gadget = LogUpGadget::new();
    let original = Lookups::<Val>::from_air::<Challenge, ProgramAir>(air);
    let messages = Messages::original(air, &original)?;
    p3_lookup::check_bus_widths(core::slice::from_ref(&original)).map_err(|_| "bus-width")?;
    p3_lookup::check_multiplicity_height_bound(core::slice::from_ref(&original), &[HEIGHT])
        .map_err(|_| "multiplicity-height")?;
    // Native ProverData's default free-degree budget, with real ZK adjustment.
    let before = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        air, layout, domain, &original, zk, &gadget,
    );
    let free = add(pow2(before)?, 1)?
        .checked_sub(zk)
        .ok_or("packing-budget")?;
    let packed = original.clone().pack_same_bus_with_degree(free, |lookup| {
        gadget.constraint_degree_with_transition(lookup, domain.transition_degree_multiple())
    });
    if packed.is_empty()
        || packed.len() > original.len()
        || packed.total_count_weight() != original.total_count_weight()
        || Messages::packed(&packed)? != messages.count
    {
        return Err("word-assessment:packing".into());
    }
    p3_lookup::check_bus_widths(core::slice::from_ref(&packed)).map_err(|_| "packed-bus-width")?;
    p3_lookup::check_multiplicity_height_bound(core::slice::from_ref(&packed), &[HEIGHT])
        .map_err(|_| "packed-multiplicity-height")?;
    let after = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        air, layout, domain, &packed, zk, &gadget,
    );
    if before != after {
        return Err("word-assessment:packing-degree".into());
    }
    let chunks = pow2(add(after, zk)?)?;
    if chunks < 2 || chunks > pow2(LOG_BLOWUP)? {
        return Err(format!("word-assessment:quotient-rate chunks={chunks}"));
    }
    let (base, ext) =
        get_symbolic_constraints::<Val, Challenge, _, _>(air, layout, &packed, &gadget);
    let n_base = base.len();
    let n_ext = ext.len();
    let constraints = add(n_base, n_ext)?;
    if constraints == 0
        || get_constraint_layout::<Val, Challenge, _, _>(air, layout, &packed, &gadget)
            .total_constraints()
            != constraints
        || air.num_constraints().is_some_and(|n| n != n_base)
    {
        return Err("word-assessment:constraints".into());
    }
    let degree =
        get_max_constraint_degree::<Val, Challenge, _, _>(air, layout, HEIGHT, &packed, &gadget)
            .max(air.max_constraint_degree().unwrap_or(0));
    if degree == 0 || degree > pow2(LOG_BLOWUP)? {
        return Err("word-assessment:degree".into());
    }
    drop(base);
    drop(ext);
    let aux = mul(add(packed.len(), 1)?, dimension)?;
    let openings = p3_batch_stark::num_batched_openings(
        air.width(),
        !air.main_next_row_columns().is_empty(),
        air.preprocessed_width(),
        !air.preprocessed_next_row_columns().is_empty(),
        chunks,
        packed.len(),
        dimension,
        OpeningShape::hiding(RANDOM_CODEWORDS),
    );
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
        max_combo: 2,
    };
    let instance = InstanceShape {
        log_trace_length: committed_log,
        modulus_bits: bits,
        collision_resistance: SECURITY_BITS,
        num_batched_functions: openings,
    };
    let params = StarkSecurityParams::new(
        fri,
        bits,
        SECURITY_BITS,
        constraints,
        degree,
        2,
        openings,
        chunks,
    )
    .with_grinding(grinding);
    let baseline = ProvenSecurity::compute_from_proof(committed_log, &params);
    // ORIGINAL denominator factors, not packed fractions; conservative doubled H.
    let extra = security_term(
        &LogUpAir {
            num_interactions: messages.count,
            max_message_width: messages.width,
        },
        &instance,
        &grinding,
    )
    .ok_or("logup-extra")?;
    let baseline_report = proven_security_report(&fri, &air_shape, &instance, &[], &grinding);
    let report = proven_security_report(&fri, &air_shape, &instance, &[extra], &grinding);
    let resources = Resources::derive(air, aux, chunks, dimension, committed_log)?;
    let assessment = Assessment {
        role: if air.plan.pool.predicate {
            "predicate"
        } else {
            "control"
        },
        base: n_base,
        extension: n_ext,
        degree,
        original: messages.count,
        widest: messages.width,
        weight: messages.weight,
        weighted_height: messages.weighted_height,
        packed: packed.len(),
        chunks,
        aux,
        openings,
        hiding_rows,
        baseline,
        baseline_report,
        report,
        logup_bits: extra.bits.bits(),
        resources,
    };
    // Complete numeric report precedes any security/resource refusal.
    assessment.log();
    assessment.require_security()?;
    Ok(assessment)
}
fn meets_floor(regime: &RegimeReport) -> bool {
    regime.security_bits().is_finite()
        && regime.security_bits() >= SECURITY_BITS as f64
        && !regime.terms().is_empty()
        && regime.terms().iter().all(|term| {
            let bits = term.bits.bits();
            bits.is_finite() && bits >= SECURITY_BITS as f64
        })
}
struct Messages {
    count: usize,
    width: usize,
    weight: u64,
    weighted_height: u64,
}
impl Messages {
    fn original(air: &ProgramAir, lookups: &Lookups<Val>) -> Result<Self> {
        if lookups.len() != 98 || PORTS != 64 {
            return Err("original98".into());
        }
        let mut sizes = [0usize; 3];
        let mut weight = 0u64;
        let mut width = 0;
        for (column, lookup) in lookups.iter().enumerate() {
            let (index, tuple_width, expected_weight) = match &lookup.kind {
                Kind::Global(bus) if bus == BUS_WIRE => (0, 2, air.plan.max_fanout),
                Kind::Global(bus) if bus == BUS_POLICY => (
                    1,
                    5,
                    if sizes[1] < 12 {
                        1
                    } else {
                        u32::try_from(air.plan.policy_queries).map_err(|_| "policy-weight")?
                    },
                ),
                Kind::Global(bus) if bus == BUS_MASK => (2, 2, if sizes[2] < 8 { 4 } else { 1 }),
                _ => return Err("foreign-bus".into()),
            };
            if lookup.column != column
                || lookup.flags.is_some()
                || lookup.elements.len() != 1
                || lookup.multiplicities.len() != 1
                || lookup.elements[0].len() != tuple_width
                || lookup.count_weight != expected_weight
                || expected_weight == 0
            {
                return Err("original-message".into());
            }
            sizes[index] = add(sizes[index], 1)?;
            width = width.max(tuple_width);
            weight = weight
                .checked_add(u64::from(expected_weight))
                .ok_or("weight-overflow")?;
        }
        if sizes != [76, 13, 9] {
            return Err("bus-inventory".into());
        }
        let weighted_height = weight
            .checked_mul(HEIGHT as u64)
            .ok_or("height-weight-overflow")?;
        Ok(Self {
            count: lookups.len(),
            width,
            weight,
            weighted_height,
        })
    }
    fn packed(lookups: &Lookups<Val>) -> Result<usize> {
        let mut count = 0usize;
        for (column, lookup) in lookups.iter().enumerate() {
            let width = match &lookup.kind {
                Kind::Global(bus) if bus == BUS_WIRE || bus == BUS_MASK => 2,
                Kind::Global(bus) if bus == BUS_POLICY => 5,
                _ => return Err("packed-foreign-bus".into()),
            };
            if lookup.column != column
                || lookup.flags.is_some()
                || lookup.elements.is_empty()
                || lookup.elements.len() != lookup.multiplicities.len()
                || lookup.elements.iter().any(|tuple| tuple.len() != width)
            {
                return Err("packed-message".into());
            }
            count = add(count, lookup.elements.len())?;
        }
        Ok(count)
    }
}

/// Named charges are explicit policy reserves, not measurements or an allocator theorem.
/// Future recipes/owner code MUST bound its own allocations; the held-PID cap remains.
struct Resources {
    total: usize,
    charges: Vec<(&'static str, usize)>,
    stages: [usize; 6],
}
impl Resources {
    fn derive(
        air: &ProgramAir,
        aux_width: usize,
        chunks: usize,
        d: usize,
        log: usize,
    ) -> Result<Self> {
        let ext = pow2(log)?;
        let lde = mul(ext, pow2(LOG_BLOWUP)?)?;
        let bytes = core::mem::size_of::<Val>();
        let main = add(WIDTH, RANDOM_CODEWORDS)?;
        let aux = add(aux_width, RANDOM_CODEWORDS)?;
        let chunk = add(d, RANDOM_CODEWORDS)?;
        let quotient = mul(chunks, chunk)?;
        let total_width = [PP_WIDTH, main, aux, quotient, chunk]
            .into_iter()
            .try_fold(0, add)?;
        let bank = |w| mul(mul(lde, w)?, bytes);
        let pp_b = bank(PP_WIDTH)?;
        let main_b = bank(main)?;
        let aux_b = bank(aux)?;
        let q_b = bank(quotient)?;
        let r_b = bank(chunk)?;
        let before_aux = add(pp_b, main_b)?;
        let before_q = add(before_aux, aux_b)?;
        let before_r = add(before_q, q_b)?;
        let stages = [
            mul(2, pp_b)?,
            add(pp_b, mul(2, main_b)?)?,
            add(before_aux, mul(2, aux_b)?)?,
            add(before_q, mul(2, q_b)?)?,
            add(before_r, mul(2, r_b)?)?,
            add(before_r, r_b)?,
        ];
        let raw = mul(mul(HEIGHT, add(add(WIDTH, PP_WIDTH)?, aux_width)?)?, bytes)?;
        let matrices = add(chunks, 4)?;
        let ir = ir_reserve(air)?;
        let charges = vec![
            ("raw_main_pp_aux", raw),
            ("masked_banks", mul(mul(ext, total_width)?, bytes)?),
            (
                "salts_all_matrices",
                mul(mul(mul(matrices, lde)?, SALT_ELEMENTS)?, bytes)?,
            ),
            (
                "merkle_per_matrix_upper",
                mul(mul(mul(matrices, lde)?, 8)?, bytes)?,
            ),
            (
                "fri_vectors_salts_trees",
                mul(
                    mul(mul(2, lde)?, add(add(mul(2, d)?, SALT_ELEMENTS)?, 8)?)?,
                    bytes,
                )?,
            ),
            (
                "lde_stage_peak",
                *stages.iter().max().ok_or("empty-stages")?,
            ),
            (
                "opening_eight_ef_vectors",
                mul(mul(mul(8, d)?, lde)?, bytes)?,
            ),
            ("fixed_ir_plan_and_retired_caches_reserve", ir),
            // Concrete future sidecar ceilings, NOT currently allocated recipes.
            (
                "planned_recipe_max_256_bytes_per_node",
                mul(air.plan.pool.nodes.len(), 256)?,
            ),
            (
                "planned_two_ssa_values",
                mul(mul(air.plan.pool.nodes.len(), 2)?, bytes)?,
            ),
            ("symbolic_dag_and_native_runtime_reserve", 128 * 1024 * 1024),
            ("codec_decode_reencode_frames_reserve", 128 * 1024 * 1024),
            (
                "owner_prerequisites_threads_allocator_reserve",
                256 * 1024 * 1024,
            ),
        ];
        let total = charges.iter().try_fold(0usize, |n, (_, v)| add(n, *v))?;
        Ok(Self {
            total,
            charges,
            stages,
        })
    }
}
fn ir_reserve(air: &ProgramAir) -> Result<usize> {
    use super::expr::Node;
    let p = &air.plan.pool;
    // Four retired private BTree caches have at most one entry per node each.
    // 512B/entry is a deliberate excess reserve, not std allocator instrumentation.
    let mut bytes = mul(p.nodes.len(), 4 * 512)?;
    bytes = add(
        bytes,
        mul(p.nodes.capacity(), core::mem::size_of::<Node>())?,
    )?;
    for node in &p.nodes {
        if let Node::Input(label, _) = node {
            bytes = add(bytes, mul(label.capacity(), 2)?)?;
        }
    }
    for h in &p.hashes {
        bytes = add(bytes, h.label.capacity())?;
    }
    bytes = add(
        bytes,
        mul(
            p.hashes.capacity(),
            core::mem::size_of::<super::expr::Hash>(),
        )?,
    )?;
    bytes = add(
        bytes,
        mul(
            p.policies.capacity(),
            core::mem::size_of::<super::expr::Policy>(),
        )?,
    )?;
    bytes = add(
        bytes,
        mul(
            p.mask.capacity(),
            core::mem::size_of::<super::expr::MaskByte>(),
        )?,
    )?;
    bytes = add(
        bytes,
        mul(
            p.reads.capacity(),
            core::mem::size_of::<super::expr::MaskRead>(),
        )?,
    )?;
    bytes = add(
        bytes,
        mul(p.assertions.capacity(), core::mem::size_of::<usize>())?,
    )?;
    bytes = add(
        bytes,
        mul(
            add(p.mode_inputs.capacity(), p.policy_frequencies.capacity())?,
            core::mem::size_of::<usize>(),
        )?,
    )?;
    bytes = add(bytes, mul(add(p.ranges.len(), p.fields.len())?, 512)?)?;
    for label in p.fields.keys() {
        bytes = add(bytes, label.capacity())?;
    }
    bytes = add(
        bytes,
        mul(
            air.plan.rows.capacity(),
            core::mem::size_of::<super::plan::Row>(),
        )?,
    )?;
    bytes = add(
        bytes,
        mul(air.plan.uses.capacity(), core::mem::size_of::<u32>())?,
    )?;
    for row in &air.plan.rows {
        bytes = add(
            bytes,
            mul(
                row.ports.capacity(),
                core::mem::size_of::<super::plan::Port>(),
            )?,
        )?;
        bytes = add(
            bytes,
            mul(row.ops.capacity(), core::mem::size_of::<super::expr::Op>())?,
        )?;
        bytes = add(
            bytes,
            mul(row.policies.capacity(), core::mem::size_of::<usize>())?,
        )?;
        bytes = add(
            bytes,
            mul(row.labels.capacity(), core::mem::size_of::<String>())?,
        )?;
        for label in &row.labels {
            bytes = add(bytes, label.capacity())?;
        }
    }
    Ok(bytes)
}
fn pow2(n: usize) -> Result<usize> {
    1usize
        .checked_shl(u32::try_from(n).map_err(|_| "shift")?)
        .ok_or("shift-overflow".into())
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("add-overflow".into())
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or("mul-overflow".into())
}
