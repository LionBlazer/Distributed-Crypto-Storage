//! Actual SDK symbolic geometry and explicit workspace-policy charges only.
//! No PP commitment, private MAIN, proof, security admission or timing is produced.
use super::{PUBLIC_COUNT, air::QueryMaskAir, layout::*};
use bfv_hiding_stark::{
    Challenge, Challenger, EXTENSION_DEGREE, LOG_BLOWUP, MODULUS_BITS, Pcs, QUERIES,
    RANDOM_CODEWORDS, SALT_ELEMENTS, SECURITY_BITS, Val,
};
use p3_air::{BaseAir, symbolic::AirLayout};
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks_for_domain, get_max_constraint_degree,
    get_symbolic_constraints,
};
use p3_commit::UnivariateStarkPcs;
use p3_field::{
    BasedVectorSpace, Field, PrimeCharacteristicRing, TwoAdicField,
    coset::TwoAdicMultiplicativeCoset,
};
use p3_lookup::{LogUpGadget, Lookups};
use p3_uni_stark::OpeningShape;

type Result<T> = core::result::Result<T, String>;
const RESOURCE_LIMIT: usize = 1792 * 1024 * 1024;

pub(super) struct Report {
    pub base: usize,
    pub extension: usize,
    pub degree: usize,
    pub chunks: usize,
    pub openings: usize,
    pub hiding_rows: usize,
    pub resources: Resources,
}
impl Report {
    pub(super) fn log(&self) {
        eprintln!(
            "query_mask_inventory complete=true fields=4208 statement_fields=96 vector_fields=4112 p2_absorbs=526 low_coefficients=256 high_zero_coefficients=3840 H={} MAIN={} PP={} PUBLIC={} main_next={} pp_next=0 BASE={} EXT={} degree={} lookup_messages=0 AUX=0 committed_chunks={} openings={} hiding_rows={} workspace_policy_bytes={} workspace_limit={} security_assessed=false proof=false admitted=false owner_bridge=false query_ct_bridge=false full_query_500ms=false",
            HEIGHT,
            WIDTH,
            PP_WIDTH,
            PUBLIC_COUNT,
            WIDTH,
            self.base,
            self.extension,
            self.degree,
            self.chunks,
            self.openings,
            self.hiding_rows,
            self.resources.total,
            RESOURCE_LIMIT,
        );
        for &(label, bytes) in &self.resources.charges {
            eprintln!("query_mask_inventory_resource label={label} bytes={bytes}");
        }
    }
}

pub(super) fn assess(air: &QueryMaskAir) -> Result<Report> {
    air.plan.inventory()?;
    if air.width() != WIDTH
        || air.preprocessed_width() != PP_WIDTH
        || air.num_public_values() != PUBLIC_COUNT
        || air.main_next_row_columns() != (0..WIDTH).collect::<Vec<_>>()
        || !air.preprocessed_next_row_columns().is_empty()
        || air.num_periodic_columns() != 0
        || !air.periodic_columns().is_empty()
        || !air.public_boundary_io().is_empty()
        || air.assumes_boolean_trace()
    {
        return Err("query-mask:assessment-shape".into());
    }
    let dimension = <Challenge as BasedVectorSpace<Val>>::DIMENSION;
    let bits = usize::try_from(Challenge::order().bits())
        .map_err(|_| "field-bits")?
        .checked_sub(1)
        .ok_or("field-bits")?;
    let zk = usize::from(<Pcs as UnivariateStarkPcs<Challenge, Challenger>>::ZK);
    let committed_log = add(LOG_HEIGHT, zk)?;
    if HEIGHT != pow2(LOG_HEIGHT)?
        || zk != 1
        || dimension != 5
        || dimension != EXTENSION_DEGREE
        || bits != 319
        || bits != MODULUS_BITS
        || LOG_BLOWUP != 3
        || QUERIES != 192
        || RANDOM_CODEWORDS != 5
        || SALT_ELEMENTS != 4
        || SECURITY_BITS != 128
        || add(committed_log, LOG_BLOWUP)? > Val::TWO_ADICITY
    {
        return Err("query-mask:assessment-suite".into());
    }
    // Conservative maximum two opening points per column; PP uses only local.
    let hiding_rows = mul(add(QUERIES, mul(dimension, 2)?)?, 2)?;
    if RANDOM_CODEWORDS < dimension || hiding_rows > HEIGHT {
        return Err("query-mask:hiding-budget".into());
    }
    let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_HEIGHT).ok_or("domain")?;
    if domain.size() != HEIGHT {
        return Err("query-mask:domain".into());
    }
    let layout = AirLayout::from_air(air);
    let gadget = LogUpGadget::new();
    let lookups = Lookups::<Val>::from_air::<Challenge, QueryMaskAir>(air);
    if !lookups.is_empty() {
        return Err("query-mask:unexpected-lookup".into());
    }
    let quotient_log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        air, layout, domain, &lookups, zk, &gadget,
    );
    let chunks = pow2(add(quotient_log, zk)?)?;
    if chunks > pow2(LOG_BLOWUP)? {
        return Err("query-mask:quotient-rate".into());
    }
    let (base, extension) =
        get_symbolic_constraints::<Val, Challenge, _, _>(air, layout, &lookups, &gadget);
    let degree =
        get_max_constraint_degree::<Val, Challenge, _, _>(air, layout, HEIGHT, &lookups, &gadget)
            .max(air.max_constraint_degree().unwrap_or(0));
    let constraints = add(base.len(), extension.len())?;
    if base.is_empty()
        || !extension.is_empty()
        || degree == 0
        || degree > pow2(LOG_BLOWUP)?
        || get_constraint_layout::<Val, Challenge, _, _>(air, layout, &lookups, &gadget)
            .total_constraints()
            != constraints
    {
        return Err("query-mask:actual-constraints".into());
    }
    let openings = p3_batch_stark::num_batched_openings(
        WIDTH,
        true,
        PP_WIDTH,
        false,
        chunks,
        0,
        dimension,
        OpeningShape::hiding(RANDOM_CODEWORDS),
    );
    let resources = Resources::derive(chunks, dimension, committed_log)?;
    Ok(Report {
        base: base.len(),
        extension: extension.len(),
        degree,
        chunks,
        openings,
        hiding_rows,
        resources,
    })
}

/// Named conservative policy reserves, not measured RSS or an allocator theorem.
/// There is no owner/witness yet; those allocations require their own review.
pub(super) struct Resources {
    pub total: usize,
    charges: Vec<(&'static str, usize)>,
}
impl Resources {
    fn derive(chunks: usize, dimension: usize, committed_log: usize) -> Result<Self> {
        let ext = pow2(committed_log)?;
        let lde = mul(ext, pow2(LOG_BLOWUP)?)?;
        let bytes = core::mem::size_of::<Val>();
        let matrix = |rows, width| mul(mul(rows, width)?, bytes);
        let main_width = add(WIDTH, RANDOM_CODEWORDS)?;
        let chunk_width = add(dimension, RANDOM_CODEWORDS)?;
        let widths = [PP_WIDTH, main_width, mul(chunks, chunk_width)?, chunk_width];
        let total_width = widths.into_iter().try_fold(0, add)?;
        let mut before = 0;
        let mut stage_peak = 0;
        for width in widths {
            let bank = matrix(lde, width)?;
            stage_peak = stage_peak.max(add(before, mul(2, bank)?)?);
            before = add(before, bank)?;
        }
        let matrices = add(chunks, 3)?; // PP, MAIN, quotient chunks, random.
        let charges = vec![
            ("raw_main_and_pp", matrix(HEIGHT, add(WIDTH, PP_WIDTH)?)?),
            ("masked_banks", matrix(ext, total_width)?),
            ("lde_stage_peak", stage_peak),
            (
                "salts_all_matrices",
                matrix(mul(matrices, lde)?, SALT_ELEMENTS)?,
            ),
            ("merkle_per_matrix_upper", matrix(mul(matrices, lde)?, 8)?),
            (
                "fri_vectors_salts_trees",
                matrix(
                    mul(2, lde)?,
                    add(add(mul(2, dimension)?, SALT_ELEMENTS)?, 8)?,
                )?,
            ),
            ("opening_eight_ef_vectors", matrix(mul(8, lde)?, dimension)?),
            (
                "independent_public_receiver_setup",
                [
                    matrix(HEIGHT, PP_WIDTH)?,
                    matrix(ext, PP_WIDTH)?,
                    matrix(lde, add(add(PP_WIDTH, SALT_ELEMENTS)?, 8)?)?,
                ]
                .into_iter()
                .try_fold(0, add)?,
            ),
            (
                "symbolic_dags_and_runtime_policy_reserve",
                128 * 1024 * 1024,
            ),
            (
                "codec_policy_reserve_no_codec_implemented",
                128 * 1024 * 1024,
            ),
            (
                "owner_threads_allocator_policy_reserve_no_owner_implemented",
                256 * 1024 * 1024,
            ),
        ];
        let total = charges.iter().try_fold(0, |n, (_, bytes)| add(n, *bytes))?;
        Ok(Self { total, charges })
    }
    pub(super) fn require_policy(&self) -> Result<()> {
        if self.total > RESOURCE_LIMIT {
            return Err("query-mask:workspace-policy".into());
        }
        Ok(())
    }
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
