//! Conditional algebraic diagnostics for trusted metadata of the fixed native suite.
//!
//! This does not associate metadata with an AIR, verify a proof, establish hiding,
//! or authorize an operation. See [`analyze`] and the crate's `CLASSICAL.md`.

use crate::{Challenge, Error, LOG_BLOWUP, MODULUS_BITS, QUERIES, SECURITY_BITS, Val};
use p3_field::PrimeField64;
use p3_fri::{FriFoldingStrategy, FriParameters, FriShape, TwoAdicFriFolding};
use p3_security::{ErrorBits, GrindingSites, SecurityAssumption};
use p3_security::{fri, logup, proximity, shape::InstanceShape};
use p3_uni_stark::StarkSecurityParams;
use std::marker::PhantomData;

const ANALYSIS_M: usize = 3;
const MAX_EXACT_INTEGER: u128 = 1 << 53;

/// One conservative algebraic error contribution, in minus-log2 probability bits.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AlgebraicTerm {
    label: &'static str,
    bits: f64,
}
impl AlgebraicTerm {
    pub fn label(&self) -> &'static str {
        self.label
    }
    pub fn bits(&self) -> f64 {
        self.bits
    }
}

/// Metadata-only conditional bound; this is not a proof or an admission capability.
#[derive(Debug, Clone)]
pub struct AlgebraicBound {
    parameters: StarkSecurityParams,
    committed_log: usize,
    fri_shape: FriShape,
    logup: Option<(usize, usize)>,
    paper_list_size: f64,
    query_bias_bits: f64,
    terms: Vec<AlgebraicTerm>,
    union_bits: f64,
}
impl AlgebraicBound {
    pub fn parameters(&self) -> &StarkSecurityParams {
        &self.parameters
    }
    pub fn committed_log(&self) -> usize {
        self.committed_log
    }
    pub fn fri_shape(&self) -> &FriShape {
        &self.fri_shape
    }
    /// Original interactions per row and widest original payload, before packing.
    pub fn logup(&self) -> Option<(usize, usize)> {
        self.logup
    }
    pub fn analysis_m(&self) -> usize {
        ANALYSIS_M
    }
    pub fn paper_list_size(&self) -> f64 {
        self.paper_list_size
    }
    /// Upper bound on the query-sampling loss before conservative bit rounding.
    pub fn query_bias_bits(&self) -> f64 {
        self.query_bias_bits
    }
    pub fn terms(&self) -> &[AlgebraicTerm] {
        &self.terms
    }
    /// Sum of reported algebraic RBR contributions, without hash terms.
    ///
    /// This conservatively bounds their worst round. It does not sum over FRI
    /// folds or claim the failure probability of a complete interactive execution.
    pub fn union_bits(&self) -> f64 {
        self.union_bits
    }
}

/// Analyze caller-associated immutable metadata at fixed analysis multiplicity three.
///
/// The trusted caller must derive all fields from the same complete AIR, original
/// lookup inventory and actual hiding proof configuration. In particular, this
/// function cannot detect omitted constraints, openings or lookups. `None` asserts
/// that the AIR has no lookup argument. Height is the doubled committed height,
/// not the original trace height. Only the existing 1024/4096 committed heights
/// and unchanged Goldilocks/EF5, blowup-eight, 192-query, unground suite are supported.
///
/// Terms omit commitment collision workbits, Fiat-Shamir query budgets, external
/// binding hashes, primitive assumptions and zero-knowledge error. No proof,
/// configuration, RNG, preprocessing or operation policy is created or changed.
pub fn analyze(
    parameters: &StarkSecurityParams,
    committed_log: usize,
    original_logup: Option<(usize, usize)>,
) -> Result<AlgebraicBound, Error> {
    validate(parameters, committed_log, original_logup)?;
    let k = 1usize << committed_log;
    let lde_log = committed_log + LOG_BLOWUP;
    let n = 1usize << lde_log;
    let rho = 1.0 / ((1usize << LOG_BLOWUP) as f64);
    let alpha = proximity::alpha_ldr_m(LOG_BLOWUP, ANALYSIS_M);
    // These are strict paper and SDK proximity preconditions, checked before APIs
    // whose degeneracy convention would otherwise return a misleading zero-bit term.
    // For m=3, alpha^2 > (k+max_combo)/n is exactly
    // 49*k > 36*(k+max_combo), hence 13*k > 36*max_combo.
    let proximity_left = k.checked_mul(13).ok_or(Error::Shape)?;
    let proximity_right = parameters.max_combo.checked_mul(36).ok_or(Error::Shape)?;
    if 2 * ANALYSIS_M >= k || proximity_left <= proximity_right {
        return Err(Error::SecurityProfile);
    }
    let list_denominator = rho - 2.0 * ANALYSIS_M as f64 / n as f64;
    if !list_denominator.is_finite() || list_denominator <= 0.0 {
        return Err(Error::SecurityProfile);
    }
    let paper_list_size = ANALYSIS_M as f64 / list_denominator;
    let instance = InstanceShape {
        log_trace_length: committed_log,
        modulus_bits: MODULUS_BITS,
        collision_resistance: SECURITY_BITS,
        num_batched_functions: parameters.num_batched_functions,
    };
    let regime = fri::FriRegime {
        log_blowup: LOG_BLOWUP,
        num_queries: QUERIES,
        log_final_poly_len: 0,
        max_log_arity: 1,
        commit_pow_bits: 0,
        query_pow_bits: 0,
    };
    let fri_parameters = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: (),
    };
    let folding = TwoAdicFriFolding::<(), ()>(PhantomData);
    let extra_bits =
        <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<Val, Challenge>>::extra_query_index_bits(
            &folding,
        );
    let index_bits = lde_log.checked_add(extra_bits).ok_or(Error::Shape)?;
    let fri_shape = FriShape::new(&fri_parameters, &[lde_log], index_bits);
    let query_bias_bits = sampling_bias_bits(fri_shape.index_bits)?;

    // Use the larger two-point expansion even for current-row-only AIRs. Each
    // committed quotient chunk has degree below k, so (c+1)k+1 also bounds
    // the paper's k+(f-1)ell+(k^+-1), with ell <= k and k^+ <= k+2.
    let expanded = k.checked_add(2).ok_or(Error::Shape)?;
    let air_factor = parameters
        .air_max_constraint_degree
        .checked_mul(expanded - 1)
        .and_then(|v| v.checked_add(k - 1))
        .ok_or(Error::Shape)?;
    let chunk_factor = parameters
        .num_quotient_chunks
        .checked_add(1)
        .and_then(|v| v.checked_mul(k))
        .and_then(|v| v.checked_add(1))
        .ok_or(Error::Shape)?;
    let deep_factor = air_factor.max(chunk_factor);
    // q >= 2^319, |D union H| <= n+k. ln_1p retains the denominator
    // correction even when subtracting n+k directly from 2^319 rounds away.
    let excluded_domain_size = n.checked_add(k).ok_or(Error::Shape)?;
    let excluded_fraction = excluded_domain_size as f64 * 2.0f64.powi(-(MODULUS_BITS as i32));
    let denominator_bits =
        MODULUS_BITS as f64 + (-excluded_fraction).ln_1p() / std::f64::consts::LN_2;
    let mut terms = Vec::with_capacity(7);
    push_term(
        &mut terms,
        "air-composition",
        MODULUS_BITS as f64 - paper_list_size.log2() - (parameters.num_constraints as f64).log2(),
    )?;
    push_term(
        &mut terms,
        "deep-ali",
        denominator_bits - 2.0 * paper_list_size.log2() - (deep_factor as f64).log2(),
    )?;
    // The paper's excluded-domain denominator is conditional on an OOD point
    // outside D union H. Native sampling uses the whole extension field; in
    // particular, rejecting a pole at a queried row is not global exclusion of D.
    push_term(
        &mut terms,
        "ood-domain-hit",
        MODULUS_BITS as f64 - (excluded_domain_size as f64).log2(),
    )?;
    push_term(
        &mut terms,
        "batch-combination",
        SecurityAssumption::prox_gaps_error_jb_at_m(
            committed_log,
            LOG_BLOWUP,
            MODULUS_BITS,
            parameters.num_batched_functions,
            ANALYSIS_M,
        ),
    )?;
    push_term(
        &mut terms,
        "ldt-commit-phase",
        fri::commit_phase_error_ldr_m(&regime, &instance, ANALYSIS_M)
            .ok_or(Error::SecurityProfile)?
            .bits(),
    )?;
    push_term(
        &mut terms,
        "ldt-query-phase",
        fri::query_phase_error(alpha, QUERIES, 0).bits() - query_bias_bits,
    )?;
    if let Some((num_interactions, max_message_width)) = original_logup {
        // MAIN is committed before the fingerprint, but list decoding permits
        // several joint MAIN candidates. Later AUX must project into that list.
        push_term(
            &mut terms,
            "logup-fingerprint",
            logup::fingerprint_error(
                &logup::LogUpAir {
                    num_interactions,
                    max_message_width,
                },
                &instance,
            )
            .bits()
                - paper_list_size.log2(),
        )?;
    }
    let errors: Vec<_> = terms
        .iter()
        .map(|term| ErrorBits::from_log2(term.bits))
        .collect();
    let union_bits = conservative_bits(ErrorBits::sum(&errors).bits())?;
    Ok(AlgebraicBound {
        parameters: parameters.clone(),
        committed_log,
        fri_shape,
        logup: original_logup,
        paper_list_size,
        query_bias_bits,
        terms,
        union_bits,
    })
}

fn validate(
    p: &StarkSecurityParams,
    committed_log: usize,
    lookup: Option<(usize, usize)>,
) -> Result<(), Error> {
    if !matches!(committed_log, 10 | 12)
        || p.fri_log_blowup != LOG_BLOWUP
        || p.fri_log_final_poly_len != 0
        || p.fri_max_log_arity != 1
        || p.fri_num_queries != QUERIES
        || p.fri_commit_proof_of_work_bits != 0
        || p.fri_query_proof_of_work_bits != 0
        || p.num_modulus_bits != MODULUS_BITS
        || p.collision_resistance != SECURITY_BITS
        || p.grinding != GrindingSites::NONE
    {
        return Err(Error::SecurityProfile);
    }
    let minimum_chunks = p
        .air_max_constraint_degree
        .checked_add(1)
        .and_then(|degree| (degree.max(2) - 1).checked_next_power_of_two())
        .and_then(|chunks| chunks.checked_mul(2))
        .ok_or(Error::Shape)?;
    if p.num_constraints == 0
        || p.num_constraints as u128 > MAX_EXACT_INTEGER
        || !(1..=8).contains(&p.air_max_constraint_degree)
        || !(1..=2).contains(&p.max_combo)
        || p.num_batched_functions < 2
        || p.num_batched_functions as u128 > MAX_EXACT_INTEGER
        || !p.num_quotient_chunks.is_power_of_two()
        || p.num_quotient_chunks < minimum_chunks
        || p.num_quotient_chunks > 16
    {
        return Err(Error::Shape);
    }
    if let Some((count, width)) = lookup {
        let original_messages = (count as u128)
            .checked_mul(1u128 << committed_log)
            .ok_or(Error::Shape)?;
        if count == 0
            || width == 0
            || width as u128 > MAX_EXACT_INTEGER
            || original_messages > MAX_EXACT_INTEGER
        {
            return Err(Error::Shape);
        }
    }
    Ok(())
}

fn sampling_bias_bits(index_bits: usize) -> Result<f64, Error> {
    let buckets = 1u128
        .checked_shl(u32::try_from(index_bits).map_err(|_| Error::Shape)?)
        .ok_or(Error::Shape)?;
    let p = Val::ORDER_U64 as u128;
    if buckets >= p {
        return Err(Error::Shape);
    }
    let largest_bucket = p.div_ceil(buckets);
    let excess = buckets
        .checked_mul(largest_bucket)
        .and_then(|v| v.checked_sub(p))
        .ok_or(Error::Shape)?;
    // p-1 is exactly representable in f64 for Goldilocks and gives an upper
    // bound on excess/p, without a rounded-up denominator understating bias.
    Ok(QUERIES as f64 * (excess as f64 / (p - 1) as f64).ln_1p() / std::f64::consts::LN_2)
}

fn push_term(terms: &mut Vec<AlgebraicTerm>, label: &'static str, bits: f64) -> Result<(), Error> {
    terms.push(AlgebraicTerm {
        label,
        bits: conservative_bits(bits)?,
    });
    Ok(())
}

fn conservative_bits(bits: f64) -> Result<f64, Error> {
    if !bits.is_finite() || bits < 2.0 {
        return Err(Error::SecurityProfile);
    }
    // Whole bits plus one bit of slack avoid claiming precision from floating
    // logarithms, SDK formula evaluation or sub-ulp denominator corrections.
    Ok(bits.floor() - 1.0)
}

#[cfg(test)]
mod tests;
