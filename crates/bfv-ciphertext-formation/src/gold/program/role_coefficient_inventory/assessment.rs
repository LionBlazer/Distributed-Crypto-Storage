//! Actual two-instance SDK symbolic/default-packing assessment. No PP/MAIN/proof.
use super::air::MetadataAir;
use super::*;
use bfv_hiding_stark::{
    Challenge, Challenger, EXTENSION_DEGREE, LOG_BLOWUP, MODULUS_BITS, Pcs, QUERIES,
    RANDOM_CODEWORDS, SALT_ELEMENTS, SECURITY_BITS,
};
use p3_air::{BaseAir, symbolic::AirLayout};
use p3_batch_stark::symbolic::{
    get_constraint_layout, get_log_num_quotient_chunks_for_domain, get_max_constraint_degree,
    get_symbolic_constraints,
};
use p3_commit::{PolynomialSpace, UnivariateStarkPcs};
use p3_field::{BasedVectorSpace, Field, TwoAdicField, coset::TwoAdicMultiplicativeCoset};
use p3_lookup::{Kind, LogUpGadget, Lookups};
use p3_security::{
    fri::FriRegime,
    grinding::GrindingSites,
    logup::{LogUpAir, security_term},
    report::RegimeReport,
    shape::{InstanceShape, StarkAirParams},
    stark::proven_security_report,
};
use p3_uni_stark::{OpeningShape, ProvenSecurity, StarkSecurityParams};

const LIMIT: usize = 1792 * 1024 * 1024;
pub(super) struct Instance {
    pub(super) base: usize,
    pub(super) extension: usize,
    pub(super) degree: usize,
    pub(super) chunks: usize,
    pub(super) original: usize,
    pub(super) packed: usize,
    pub(super) aux: usize,
    pub(super) openings: usize,
    main: usize,
    pp: usize,
}
pub(super) struct Assessment {
    pub(super) instances: [Instance; 2],
    pub(super) total_openings: usize,
    pub(super) workspace: usize,
    pub(super) deep_envelope_chunks: usize,
}
impl Assessment {
    /// No validated heterogeneous security theorem is minted by this inspector.
    /// A future private prover MUST refuse until this separate obligation is reviewed.
    pub(super) fn require_proof_security(&self) -> Result<()> {
        Err(Error::Security)
    }

    pub(super) fn require_resources(&self) -> Result<()> {
        if self.workspace > LIMIT {
            return Err(Error::Resource);
        }
        Ok(())
    }
}
pub(super) fn assess(airs: &[MetadataAir; 2]) -> Result<Assessment> {
    if !matches!(
        airs,
        [MetadataAir::Data(_), MetadataAir::PublicCoefficientHash]
    ) {
        return Err(Error::Shape);
    }
    plan::inventory(airs[0].plan()?)?;
    let dim = <Challenge as BasedVectorSpace<Val>>::DIMENSION;
    let modulus_bits = (Challenge::order().bits() as usize)
        .checked_sub(1)
        .ok_or(Error::Security)?;
    let zk = usize::from(<Pcs as UnivariateStarkPcs<Challenge, Challenger>>::ZK);
    if zk != 1
        || dim != 5
        || dim != EXTENSION_DEGREE
        || modulus_bits != MODULUS_BITS
        || RANDOM_CODEWORDS != 5
        || SALT_ELEMENTS != 4
        || LOG_BLOWUP != 3
        || QUERIES != 192
        || SECURITY_BITS != 128
        || LOG_H + zk + LOG_BLOWUP > Val::TWO_ADICITY
        || 2 * (QUERIES + 2 * dim) > H
    {
        return Err(Error::Security);
    }
    let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_H).ok_or(Error::Shape)?;
    let originals: Vec<_> = airs
        .iter()
        .map(Lookups::<Val>::from_air::<Challenge, MetadataAir>)
        .collect();
    p3_lookup::check_bus_widths(&originals).map_err(|_| Error::Shape)?;
    p3_lookup::check_multiplicity_height_bound(&originals, &[H, H]).map_err(|_| Error::Security)?;
    let gadget = LogUpGadget::new();
    let mut instances = Vec::with_capacity(2);
    let mut total_constraints = 0usize;
    let mut total_openings = 0usize;
    let mut max_degree = 0usize;
    let mut deep_envelope = 0usize;
    let mut total_messages = 0usize;
    for (index, (air, original)) in airs.iter().zip(&originals).enumerate() {
        let (width, pp_width, pv, ports, max_count) = if index == 0 {
            (W, PP, PV, PORTS, 4)
        } else {
            (HASH_W, HASH_PP, HASH_PV, HASH_PORTS, 1)
        };
        if air.width() != width
            || air.preprocessed_width() != pp_width
            || air.num_public_values() != pv
            || air.num_periodic_columns() != 0
            || !air.periodic_columns().is_empty()
            || !air.public_boundary_io().is_empty()
            || air.assumes_boolean_trace()
            || air.preprocessed_trace().is_some()
            || !air.preprocessed_next_row_columns().is_empty()
            || original.len() != ports
        {
            return Err(Error::Shape);
        }
        let want_next: Vec<_> = if index == 0 {
            (496..=508).collect()
        } else {
            (248..260).collect()
        };
        if air.main_next_row_columns() != want_next {
            return Err(Error::Shape);
        }
        for (column, lookup) in original.iter().enumerate() {
            if lookup.kind != Kind::Global(BUS.to_owned())
                || lookup.column != column
                || lookup.flags.is_some()
                || lookup.elements.len() != 1
                || lookup.multiplicities.len() != 1
                || lookup.count_weight != max_count
                || lookup.elements[0].len() != 2
            {
                return Err(Error::Shape);
            }
        }
        let layout = AirLayout::from_air(air);
        let unpacked = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
            air, layout, domain, original, zk, &gadget,
        );
        let budget = add(pow2(unpacked)?, 1)?
            .checked_sub(zk)
            .ok_or(Error::Resource)?;
        let packed = original
            .clone()
            .pack_same_bus_with_degree(budget, |lookup| {
                gadget
                    .constraint_degree_with_transition(lookup, domain.transition_degree_multiple())
            });
        let packed_log = get_log_num_quotient_chunks_for_domain::<Val, Challenge, _, _>(
            air, layout, domain, &packed, zk, &gadget,
        );
        if packed_log != unpacked
            || packed.is_empty()
            || packed.total_count_weight() != original.total_count_weight()
        {
            return Err(Error::Shape);
        }
        let mut packed_messages = 0;
        for (column, lookup) in packed.iter().enumerate() {
            if lookup.kind != Kind::Global(BUS.to_owned())
                || lookup.column != column
                || lookup.flags.is_some()
                || lookup.elements.len() != lookup.multiplicities.len()
                || lookup.elements.is_empty()
                || lookup.elements.iter().any(|t| t.len() != 2)
            {
                return Err(Error::Shape);
            }
            packed_messages = add(packed_messages, lookup.elements.len())?;
        }
        if packed_messages != ports {
            return Err(Error::Shape);
        }
        let chunks = pow2(add(packed_log, zk)?)?;
        if chunks > pow2(LOG_BLOWUP)? {
            return Err(Error::Security);
        }
        let (base, extension) =
            get_symbolic_constraints::<Val, Challenge, _, _>(air, layout, &packed, &gadget);
        let constraints = add(base.len(), extension.len())?;
        if get_constraint_layout::<Val, Challenge, _, _>(air, layout, &packed, &gadget)
            .total_constraints()
            != constraints
            || air.num_constraints().is_some_and(|n| n != base.len())
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
        if degree == 0 || degree > pow2(LOG_BLOWUP)? {
            return Err(Error::Security);
        }
        let aux = mul(add(packed.len(), 1)?, dim)?;
        let openings = p3_batch_stark::num_batched_openings(
            width,
            true,
            pp_width,
            false,
            chunks,
            packed.len(),
            dim,
            OpeningShape::hiding(RANDOM_CODEWORDS),
        );
        total_constraints = add(total_constraints, constraints)?;
        total_openings = add(total_openings, openings)?;
        total_messages = add(total_messages, ports)?;
        max_degree = max_degree.max(degree);
        // UNASSESSED analytical candidate, NOT a native security derivation.
        // Proposed conservative union envelope for both per-instance DEEP factors:
        // factor_i <= (degree_i+chunks_i+max_combo_i+1)*k, k>=2.
        // The single SDK report's (envelope_chunks+1)*k dominates their sum.
        // This is NOT a native quotient shape or a packing override.
        deep_envelope = add(deep_envelope, add(add(degree, chunks)?, 3)?)?;
        eprintln!(
            "role_coeff_instance index={} H={} MAIN={} PP={} PV={} base={} extension={} degree={} committed_chunks={} original={} packed={} AUX={} openings={} defaultpack=true",
            index,
            H,
            width,
            pp_width,
            pv,
            base.len(),
            extension.len(),
            degree,
            chunks,
            ports,
            packed.len(),
            aux,
            openings
        );
        instances.push(Instance {
            base: base.len(),
            extension: extension.len(),
            degree,
            chunks,
            original: ports,
            packed: packed.len(),
            aux,
            openings,
            main: width,
            pp: pp_width,
        });
    }
    if total_messages != PORTS + HASH_PORTS {
        return Err(Error::Shape);
    }
    let instances: [Instance; 2] = instances.try_into().map_err(|_| Error::Shape)?;
    let deep_envelope_chunks = deep_envelope
        .checked_next_power_of_two()
        .ok_or(Error::Resource)?;
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
        num_constraints: total_constraints,
        max_constraint_degree: max_degree,
        num_quotient_chunks: deep_envelope_chunks,
        max_combo: 2,
    };
    let shape = InstanceShape {
        log_trace_length: LOG_H + zk,
        modulus_bits,
        collision_resistance: SECURITY_BITS,
        num_batched_functions: total_openings,
    };
    let params = StarkSecurityParams::new(
        fri,
        modulus_bits,
        SECURITY_BITS,
        total_constraints,
        max_degree,
        2,
        total_openings,
        deep_envelope_chunks,
    )
    .with_grinding(grinding);
    let baseline = ProvenSecurity::compute_from_proof(LOG_H + zk, &params);
    // Both AIRs share one alpha,beta namespace. Use ALL original denominators,
    // not packed count or an invented independent per-AIR amplification.
    let logup = security_term(
        &LogUpAir {
            num_interactions: total_messages,
            max_message_width: 2,
        },
        &shape,
        &grinding,
    )
    .ok_or(Error::Security)?;
    let report = proven_security_report(&fri, &air_shape, &shape, &[logup], &grinding);
    for (label, regime) in [
        ("UDR", &report.udr),
        ("LDR", report.ldr.as_ref().ok_or(Error::Security)?),
    ] {
        eprintln!(
            "role_coeff_analytical_candidate_UNASSESSED regime={} bits={:.12}",
            label,
            regime.security_bits()
        );
        for term in regime.terms() {
            eprintln!(
                "role_coeff_analytical_candidate_term_UNASSESSED regime={} label={} bits={:.12}",
                label,
                term.label,
                term.bits.bits()
            );
        }
        if !floor(regime) {
            return Err(Error::Security);
        }
    }
    if baseline.unique_decoding_bits < SECURITY_BITS || baseline.list_decoding_bits < SECURITY_BITS
    {
        return Err(Error::Security);
    }
    let workspace = resources(&instances, dim)?;
    eprintln!(
        "role_coeff_batch openings={} constraints={} original_messages={} deep_envelope_chunks={} workspace_bytes={} limit_bytes={} PUBLIC_fullPP=false MAIN=false proof=false aggregate_security_UNASSESSED=true security_assessed=false admission=false",
        total_openings, total_constraints, total_messages, deep_envelope_chunks, workspace, LIMIT
    );
    Ok(Assessment {
        instances,
        total_openings,
        workspace,
        deep_envelope_chunks,
    })
}
fn floor(regime: &RegimeReport) -> bool {
    let v = regime.security_bits();
    v.is_finite()
        && v >= SECURITY_BITS as f64
        && !regime.terms().is_empty()
        && regime
            .terms()
            .iter()
            .all(|t| t.bits.bits().is_finite() && t.bits.bits() >= SECURITY_BITS as f64)
}

/// Native batch live-bank envelope: both per-instance matrices are charged in
/// EVERY bank, including both randomization matrices and every quotient chunk.
/// No largest single AIR is substituted for their simultaneous ownership.
fn resources(instances: &[Instance; 2], dim: usize) -> Result<usize> {
    let bytes = core::mem::size_of::<Val>();
    let ext = pow2(LOG_H + 1)?;
    let lde = mul(ext, pow2(LOG_BLOWUP)?)?;
    let mut main = 0;
    let mut pp = 0;
    let mut aux = 0;
    let mut quotient = 0;
    let mut random = 0;
    let mut matrices = 0;
    let mut raw_main = 0;
    let mut raw_aux = 0;
    for i in instances {
        main = add(main, add(i.main, RANDOM_CODEWORDS)?)?;
        pp = add(pp, i.pp)?;
        aux = add(aux, add(i.aux, RANDOM_CODEWORDS)?)?;
        quotient = add(quotient, mul(i.chunks, add(dim, RANDOM_CODEWORDS)?)?)?;
        random = add(random, add(dim, RANDOM_CODEWORDS)?)?;
        matrices = add(matrices, add(i.chunks, 4)?)?;
        raw_main = add(raw_main, i.main)?;
        raw_aux = add(raw_aux, i.aux)?;
    }
    let cellbytes = |height, width| mul(mul(height, width)?, bytes);
    let banks = [pp, main, aux, quotient, random]
        .map(|w| cellbytes(lde, w))
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let mut earlier = 0;
    let mut peak = 0;
    for &bank in &banks {
        peak = peak.max(add(earlier, mul(2, bank)?)?);
        earlier = add(earlier, bank)?;
    }
    let total_width = [pp, main, aux, quotient, random]
        .into_iter()
        .try_fold(0, add)?;
    let terms = [
        cellbytes(H, raw_main)?,
        cellbytes(H, pp)?,
        cellbytes(H, raw_aux)?,
        cellbytes(ext, total_width)?,
        mul(mul(mul(matrices, lde)?, SALT_ELEMENTS)?, bytes)?,
        mul(mul(mul(matrices, lde)?, 8)?, bytes)?,
        mul(mul(mul(2, lde)?, 2 * dim + SALT_ELEMENTS + 8)?, bytes)?,
        peak,
        // Sixteen full EF vectors, conservatively twice the one-instance opening
        // reserve. Native opening still borrows ALL retained LDE banks.
        mul(mul(mul(16, dim)?, lde)?, bytes)?,
        // Same guarded equation/wire banks as original private writer, pending
        // exact next-stage writer liveness, not permission to exceed this budget.
        16 * 1024 * 1024,
        // Public coefficient FFT/roots/expected/canonical CTS and static schedules,
        // native symbolics/report/allocator/proof-codec/runtime reserve.
        64 * 1024 * 1024,
    ];
    for (index, charge) in terms.iter().enumerate() {
        eprintln!(
            "role_coeff_resource_charge index={} bytes={}",
            index, charge
        );
    }
    terms.into_iter().try_fold(0, add)
}
fn pow2(e: usize) -> Result<usize> {
    1usize
        .checked_shl(u32::try_from(e).map_err(|_| Error::Resource)?)
        .ok_or(Error::Resource)
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Resource)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(Error::Resource)
}
