//! Closed native-batch shape and soundness preflight; no proof authority is produced.

use bfv_hiding_stark::{
    Challenge, Config, EXTENSION_DEGREE, LOG_BLOWUP, MODULUS_BITS, QUERIES, RANDOM_CODEWORDS,
    SALT_ELEMENTS, SECURITY_BITS, Val,
};
use p3_air::BaseAir;
use p3_air::symbolic::{AirLayout, BaseLeaf, SymbolicExpression};
use p3_batch_stark::CommonData;
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks_for_domain, get_max_constraint_degree,
    get_symbolic_constraints,
};
use p3_commit::PolynomialSpace;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_lookup::{Kind, LogUpGadget, Lookups};
use p3_security::fri::FriRegime;
use p3_security::grinding::GrindingSites;
use p3_security::logup::{LogUpAir, security_term};
use p3_security::report::{RegimeReport, SecurityReport};
use p3_security::shape::{InstanceShape, StarkAirParams};
use p3_security::stark::proven_security_report;
use p3_uni_stark::{OpeningShape, ProvenSecurity, StarkSecurityParams};

use super::air::{DEGREE_BITS, FixedAir, HEIGHT, LOG_HEIGHT, PP_WIDTH, PUBLIC_VALUES, WIDTH};
use super::{Error, Result};

const BUS: &str = "dcs/hiding-logup-wire/v1/node-value";
const ORIGINAL_TUPLES: usize = 4;
const MESSAGE_WIDTH: usize = 2;
const RESOURCE_LIMIT_BYTES: usize = 1792 * 1024 * 1024;

/// Metadata derived only from this experiment's actual AIR and trusted public setup.
/// This is neither a verified proof nor a caller-supplied security report.
pub(super) struct Assessment {
    constraints: usize,
    degree: usize,
    chunks: usize,
    packed: usize,
    aux_width: usize,
    openings: usize,
    weighted_height: u64,
    logup_bits: f64,
    report: SecurityReport,
    resources: Resources,
}

impl Assessment {
    pub(super) fn chunks(&self) -> usize {
        self.chunks
    }

    /// Base-field width of the committed native extension-field permutation trace.
    pub(super) fn aux_width(&self) -> usize {
        self.aux_width
    }

    pub(super) fn packed_lookup_count(&self) -> usize {
        self.packed
    }

    /// Public numeric diagnostics only; never logs MAIN, AUX or private openings.
    pub(super) fn log(&self) {
        eprintln!(
            "hiding_logup_assessment constraints={} degree={} quotient_chunks={} packed_lookups={} original_tuples={} message_width={} aux_base_width={} batched_openings={} weighted_height={} logup_bits={:.6} udr_bits={:.6} ldr_bits={:.6} raw_trace_bytes={} masked_trace_bytes={} lde_bytes={} tree_bytes={} fri_workspace_bytes={} estimated_workspace_bytes={}",
            self.constraints,
            self.degree,
            self.chunks,
            self.packed,
            ORIGINAL_TUPLES,
            MESSAGE_WIDTH,
            self.aux_width,
            self.openings,
            self.weighted_height,
            self.logup_bits,
            self.report.udr.security_bits(),
            self.report
                .ldr
                .as_ref()
                .map_or(0.0, RegimeReport::security_bits),
            self.resources.raw_trace_bytes,
            self.resources.masked_trace_bytes,
            self.resources.lde_bytes,
            self.resources.tree_bytes,
            self.resources.fri_workspace_bytes,
            self.resources.estimated_workspace_bytes,
        );
    }
}

/// Run after the sealed public-only setup helper and before allocating private MAIN.
/// The setup helper must derive PP/its commitment itself; submitted CommonData is forbidden.
pub(super) fn assess(air: &FixedAir, common: &CommonData<Config>) -> Result<Assessment> {
    require_fixed_shape(air, common)?;
    let dimension = <Challenge as BasedVectorSpace<Val>>::DIMENSION;
    let modulus_bits = usize::try_from(Challenge::order().bits())
        .map_err(|_| Error::Security)?
        .checked_sub(1)
        .ok_or(Error::Security)?;
    if dimension != EXTENSION_DEGREE
        || dimension != 5
        || modulus_bits != MODULUS_BITS
        || RANDOM_CODEWORDS != 5
        || SALT_ELEMENTS != 4
        || LOG_BLOWUP != 3
        || QUERIES != 192
        || SECURITY_BITS != 128
    {
        return Err(Error::Security);
    }
    // Exact native HidingFriPcs budget for the largest opening schedule (AUX):
    // two points, EF5, Q192 => 2*(5*2+192)=404 masked degrees <= H512.
    let hiding_budget = mul(add(mul(dimension, 2)?, QUERIES)?, 2)?;
    if hiding_budget > HEIGHT {
        return Err(Error::Security);
    }
    // HidingFriPcs uses the shift-one subgroup of the ORIGINAL trace height
    // for quotient sizing; security below uses its doubled committed degree.
    let domain =
        TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_HEIGHT).ok_or(Error::Shape)?;
    let layout = AirLayout::from_air(air);
    let gadget = LogUpGadget::new();
    let original = Lookups::<Val>::from_air::<Challenge, FixedAir>(air);
    require_original_messages(&original)?;
    let unpacked_log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        air, layout, domain, &original, 1, &gadget,
    );
    let free_budget = pow2(unpacked_log)?; // 2^log + 1 - is_zk; is_zk is exactly one.
    let expected = original
        .clone()
        .pack_same_bus_with_degree(free_budget, |lookup| {
            gadget.constraint_degree_with_transition(lookup, domain.transition_degree_multiple())
        });
    let actual = &common.lookups[0];
    if !same_lookups(&expected, actual) {
        return Err(Error::Shape);
    }
    p3_lookup::check_bus_widths(&common.lookups).map_err(|_| Error::Shape)?;
    p3_lookup::check_multiplicity_height_bound(&common.lookups, &[HEIGHT])
        .map_err(|_| Error::Security)?;
    let weighted_height = actual
        .total_count_weight()
        .checked_mul(u64::try_from(HEIGHT).map_err(|_| Error::Resource)?)
        .ok_or(Error::Resource)?;
    // All four magnitudes are one and are selected by the trusted 0/1 PP columns.
    if weighted_height != (ORIGINAL_TUPLES * HEIGHT) as u64 {
        return Err(Error::Shape);
    }
    let packed_log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
        air, layout, domain, actual, 1, &gadget,
    );
    if packed_log != unpacked_log {
        return Err(Error::Shape);
    }
    let chunks = pow2(packed_log.checked_add(1).ok_or(Error::Resource)?)?;
    // SDK default packing uses a debug-only equality check. Enforce the actual
    // committed quotient/rate bound in release, including ZK doubling.
    if chunks < 2 || chunks > pow2(LOG_BLOWUP)? {
        return Err(Error::Security);
    }
    let (base, extension) =
        get_symbolic_constraints::<Val, Challenge, _, _>(air, layout, actual, &gadget);
    let constraints = base
        .len()
        .checked_add(extension.len())
        .ok_or(Error::Resource)?;
    let native_layout = get_constraint_layout::<Val, Challenge, _, _>(air, layout, actual, &gadget);
    if constraints == 0 || native_layout.total_constraints() != constraints {
        return Err(Error::Shape);
    }
    let degree = get_max_constraint_degree::<Val, Challenge, _, _>(
        air,
        layout,
        domain.size(),
        actual,
        &gadget,
    )
    .max(air.max_constraint_degree().unwrap_or(0));
    if degree == 0 || degree > pow2(LOG_BLOWUP)? {
        return Err(Error::Security);
    }
    let aux_width = mul(
        actual.len().checked_add(1).ok_or(Error::Resource)?,
        dimension,
    )?;
    // Native batch always opens AUX at zeta AND zeta*g, even though this
    // closed AIR reads neither MAIN nor PP at the next row. Random columns
    // are appended to MAIN/AUX/every quotient chunk/randomizing codeword.
    let openings = p3_batch_stark::num_batched_openings(
        WIDTH,
        false,
        PP_WIDTH,
        false,
        chunks,
        actual.len(),
        dimension,
        OpeningShape::hiding(RANDOM_CODEWORDS),
    );
    let resources = Resources::derive(aux_width, chunks)?;
    // This mirror is fixed to the unchanged bfv_hiding_stark::config():
    // final degree one, binary folding, zero grinding at EVERY site.
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
        log_trace_length: DEGREE_BITS,
        modulus_bits,
        collision_resistance: SECURITY_BITS,
        num_batched_functions: openings,
    };
    // The uni convenience adapter does not accept extra terms. Keep it as an
    // independent baseline cross-check, NEVER as the full lookup assessment.
    let baseline_params = StarkSecurityParams::new(
        fri,
        modulus_bits,
        SECURITY_BITS,
        constraints,
        degree,
        2,
        openings,
        chunks,
    )
    .with_grinding(grinding);
    let baseline = ProvenSecurity::compute_from_proof(DEGREE_BITS, &baseline_params);
    // Use the larger committed height for this extra as a conservative bound;
    // native interactions actually range over the original H512 rows.
    let logup = security_term(
        &LogUpAir {
            num_interactions: original.iter().map(|lookup| lookup.elements.len()).sum(),
            max_message_width: original
                .iter()
                .flat_map(|lookup| &lookup.elements)
                .map(Vec::len)
                .max()
                .ok_or(Error::Shape)?,
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
            "hiding_logup_security_rejected udr_bits={:.12} ldr_bits={:.12} logup_bits={:.12}",
            report.udr.security_bits(),
            report.ldr.as_ref().map_or(0.0, RegimeReport::security_bits),
            logup.bits.bits(),
        );
        return Err(Error::Security);
    }
    Ok(Assessment {
        constraints,
        degree,
        chunks,
        packed: actual.len(),
        aux_width,
        openings,
        weighted_height,
        logup_bits: logup.bits.bits(),
        report,
        resources,
    })
}

fn meets_floor(regime: &RegimeReport) -> bool {
    !regime.terms().is_empty()
        && regime.terms().iter().all(|term| {
            let bits = term.bits.bits();
            bits.is_finite() && bits >= SECURITY_BITS as f64
        })
}

fn require_fixed_shape(air: &FixedAir, common: &CommonData<Config>) -> Result<()> {
    if HEIGHT != 512
        || LOG_HEIGHT != 9
        || DEGREE_BITS != 10
        || air.width() != WIDTH
        || WIDTH != 19
        || air.preprocessed_width() != PP_WIDTH
        || PP_WIDTH != 3
        || air.num_public_values() != PUBLIC_VALUES
        || PUBLIC_VALUES != 17
        || air.num_periodic_columns() != 0
        || !air.periodic_columns().is_empty()
        || !air.main_next_row_columns().is_empty()
        || !air.preprocessed_next_row_columns().is_empty()
        || !air.public_boundary_io().is_empty()
        || air.assumes_boolean_trace()
        || common.lookups.len() != 1
    {
        return Err(Error::Shape);
    }
    let pp = common.preprocessed.as_ref().ok_or(Error::Shape)?;
    if pp.instances.len() != 1 || pp.matrix_to_instance.as_slice() != [0] {
        return Err(Error::Shape);
    }
    let meta = pp.instances[0].as_ref().ok_or(Error::Shape)?;
    if meta.matrix_index != 0 || meta.width != PP_WIDTH || meta.degree_bits != DEGREE_BITS {
        return Err(Error::Shape);
    }
    Ok(())
}

fn require_original_messages(original: &Lookups<Val>) -> Result<()> {
    if original.len() != ORIGINAL_TUPLES
        || original.iter().enumerate().any(|(i, lookup)| {
            lookup.kind != Kind::Global(BUS.to_owned())
                || lookup.column != i
                || lookup.flags.is_some()
                || lookup.elements.len() != 1
                || lookup.elements[0].len() != MESSAGE_WIDTH
                || lookup.multiplicities.len() != 1
                || lookup.count_weight != 1
        })
    {
        return Err(Error::Shape);
    }
    Ok(())
}

fn same_lookups(expected: &Lookups<Val>, actual: &Lookups<Val>) -> bool {
    expected.len() == actual.len()
        && expected.iter().zip(actual.iter()).all(|(a, b)| {
            a.kind == b.kind
                && a.column == b.column
                && a.count_weight == b.count_weight
                && a.flags.is_none()
                && b.flags.is_none()
                && a.elements.len() == b.elements.len()
                && a.elements
                    .iter()
                    .zip(&b.elements)
                    .all(|(a, b)| same_expressions(a, b))
                && same_expressions(&a.multiplicities, &b.multiplicities)
        })
}

fn same_expressions(a: &[SymbolicExpression<Val>], b: &[SymbolicExpression<Val>]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same_expression(a, b))
}

fn same_expression(a: &SymbolicExpression<Val>, b: &SymbolicExpression<Val>) -> bool {
    use p3_air::symbolic::SymbolicExpr::{Add, Leaf, Mul, Neg, Sub};
    match (a, b) {
        (Leaf(a), Leaf(b)) => match (a, b) {
            (BaseLeaf::Variable(a), BaseLeaf::Variable(b)) => {
                a.entry == b.entry && a.index == b.index
            }
            (BaseLeaf::Constant(a), BaseLeaf::Constant(b)) => a == b,
            (BaseLeaf::IsFirstRow, BaseLeaf::IsFirstRow)
            | (BaseLeaf::IsLastRow, BaseLeaf::IsLastRow)
            | (BaseLeaf::IsTransition, BaseLeaf::IsTransition) => true,
            _ => false,
        },
        (
            Add {
                x: ax,
                y: ay,
                degree_multiple: ad,
            },
            Add {
                x: bx,
                y: by,
                degree_multiple: bd,
            },
        )
        | (
            Sub {
                x: ax,
                y: ay,
                degree_multiple: ad,
            },
            Sub {
                x: bx,
                y: by,
                degree_multiple: bd,
            },
        )
        | (
            Mul {
                x: ax,
                y: ay,
                degree_multiple: ad,
            },
            Mul {
                x: bx,
                y: by,
                degree_multiple: bd,
            },
        ) => ad == bd && same_expression(ax, bx) && same_expression(ay, by),
        (
            Neg {
                x: a,
                degree_multiple: ad,
            },
            Neg {
                x: b,
                degree_multiple: bd,
            },
        ) => ad == bd && same_expression(a, b),
        _ => false,
    }
}

/// Shape-based prescreen, not an allocator or a promise about whole-process RAM.
/// Trees are over-counted per matrix (native MMCS shares one tree per bank).
/// A four-bank workspace reserve covers overlapping transforms/copies; the
/// external held-PID cap is still mandatory for any native run.
struct Resources {
    raw_trace_bytes: usize,
    masked_trace_bytes: usize,
    lde_bytes: usize,
    tree_bytes: usize,
    fri_workspace_bytes: usize,
    estimated_workspace_bytes: usize,
}

impl Resources {
    fn derive(aux_width: usize, chunks: usize) -> Result<Self> {
        let bytes = core::mem::size_of::<Val>();
        let ext_height = pow2(DEGREE_BITS)?;
        let lde_height = mul(ext_height, pow2(LOG_BLOWUP)?)?;
        let main = WIDTH.checked_add(RANDOM_CODEWORDS).ok_or(Error::Resource)?;
        let aux = aux_width
            .checked_add(RANDOM_CODEWORDS)
            .ok_or(Error::Resource)?;
        let chunk = EXTENSION_DEGREE
            .checked_add(RANDOM_CODEWORDS)
            .ok_or(Error::Resource)?;
        let total_width = [main, aux, PP_WIDTH, mul(chunks, chunk)?, chunk]
            .into_iter()
            .try_fold(0usize, add)?;
        let raw_trace_bytes = mul(mul(HEIGHT, add(WIDTH, aux_width)?)?, bytes)?;
        let masked_trace_bytes = mul(mul(ext_height, total_width)?, bytes)?;
        let lde_bytes = mul(mul(lde_height, total_width)?, bytes)?;
        let matrix_count = chunks.checked_add(4).ok_or(Error::Resource)?;
        let salts = mul(mul(mul(matrix_count, lde_height)?, SALT_ELEMENTS)?, bytes)?;
        let digests = mul(mul(mul(matrix_count, lde_height)?, 2 * 4)?, bytes)?;
        let tree_bytes = add(salts, digests)?;
        // Binary FRI's geometric row sum is below twice the initial LDE.
        // Count two extension values, four salts and two 4-word digests per row.
        let fri_workspace_bytes = mul(
            mul(2 * lde_height, 2 * EXTENSION_DEGREE + SALT_ELEMENTS + 8)?,
            bytes,
        )?;
        let estimated_workspace_bytes = add(
            raw_trace_bytes,
            add(
                mul(4, add(add(masked_trace_bytes, lde_bytes)?, tree_bytes)?)?,
                fri_workspace_bytes,
            )?,
        )?;
        if estimated_workspace_bytes > RESOURCE_LIMIT_BYTES {
            return Err(Error::Resource);
        }
        Ok(Self {
            raw_trace_bytes,
            masked_trace_bytes,
            lde_bytes,
            tree_bytes,
            fri_workspace_bytes,
            estimated_workspace_bytes,
        })
    }
}

fn pow2(exponent: usize) -> Result<usize> {
    1usize
        .checked_shl(u32::try_from(exponent).map_err(|_| Error::Resource)?)
        .ok_or(Error::Resource)
}

fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(Error::Resource)
}

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Resource)
}
