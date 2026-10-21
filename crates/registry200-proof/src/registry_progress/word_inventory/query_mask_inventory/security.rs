//! Conditional native STARK floor for this exact no-LogUp mathematical AIR.
//! No key/FHE/encoding admission, private commitment, proof or runtime grant.
use super::{air::QueryMaskAir, assessment, layout::*};
use bfv_hiding_stark::{
    Challenge, LOG_BLOWUP, MODULUS_BITS, QUERIES, RANDOM_CODEWORDS, SECURITY_BITS, Val,
};
use p3_air::symbolic::AirLayout;
use p3_field::{PrimeCharacteristicRing, coset::TwoAdicMultiplicativeCoset};
use p3_security::{
    fri::FriRegime,
    grinding::GrindingSites,
    report::{
        ALI_LABEL, BATCH_LABEL, COLLISION_LABEL, DEEP_LABEL, LDT_LABEL, RegimeReport,
        SecurityReport,
    },
    shape::{InstanceShape, StarkAirParams},
    stark::proven_security_report,
};
use p3_uni_stark::{OpeningShape, ProvenSecurity, StarkSecurityParams};

type Result<T> = core::result::Result<T, String>;

/// Private numeric metadata only. A passed gate has no accepting capability.
pub(super) struct Gate {
    pub metadata: assessment::Report,
    baseline: ProvenSecurity,
    full: SecurityReport,
}
impl Gate {
    fn log(&self) {
        let ldr = self.full.ldr.as_ref();
        eprintln!(
            "query_mask_security H={} committed_log={} BASE={} EXT={} degree={} chunks={} openings={} baseline_udr={} baseline_ldr={} full_udr={:.12} full_ldr={:.12} udr_terms={} ldr_terms={} extra_terms=0 baseline_equals_composed=true LogUp=false conditional_STARK_only=true key_security=false admission=false full_query_500ms=false",
            HEIGHT,
            LOG_HEIGHT + 1,
            self.metadata.base,
            self.metadata.extension,
            self.metadata.degree,
            self.metadata.chunks,
            self.metadata.openings,
            self.baseline.unique_decoding_bits,
            self.baseline.list_decoding_bits,
            self.full.udr.security_bits(),
            ldr.map_or(0.0, RegimeReport::security_bits),
            self.full.udr.terms().len(),
            ldr.map_or(0, |r| r.terms().len()),
        );
        for (name, regime) in [
            ("baseline-and-composed-udr", Some(&self.full.udr)),
            ("baseline-and-composed-ldr", ldr),
        ] {
            if let Some(regime) = regime {
                for term in regime.terms() {
                    eprintln!(
                        "query_mask_security_term regime={} term={} component={} bits={:.12}",
                        name,
                        term.label,
                        term.component.unwrap_or("none"),
                        term.bits.bits(),
                    );
                }
            }
        }
    }

    pub(super) fn require_floor(&self) -> Result<()> {
        let ldr = self.full.ldr.as_ref().ok_or("query-mask:security-no-ldr")?;
        for regime in [&self.full.udr, ldr] {
            // Enumerate EVERY term actually returned by the pinned SDK. No
            // caller-provided term count, filter, LogUp charge or fabricated extra.
            if regime.terms().is_empty()
                || !at_floor(regime.security_bits())
                || regime
                    .terms()
                    .iter()
                    .any(|term| !at_floor(term.bits.bits()))
            {
                return Err("query-mask:security-term-floor".into());
            }
            for label in [ALI_LABEL, DEEP_LABEL, LDT_LABEL, COLLISION_LABEL] {
                if !regime.terms().iter().any(|term| term.label == label) {
                    return Err("query-mask:security-missing-native-term".into());
                }
            }
            if self.metadata.openings > 1
                && !regime.terms().iter().any(|term| term.label == BATCH_LABEL)
            {
                return Err("query-mask:security-missing-batch-term".into());
            }
        }
        if self.baseline.unique_decoding_bits < SECURITY_BITS
            || self.baseline.list_decoding_bits < SECURITY_BITS
            || self.baseline.unique_decoding_bits != self.full.udr.security_bits() as usize
            || self.baseline.list_decoding_bits != ldr.security_bits() as usize
            || !at_floor(self.full.security_bits())
        {
            return Err("query-mask:security-native-baseline".into());
        }
        self.metadata.resources.require_policy()
    }
}

fn at_floor(bits: f64) -> bool {
    bits.is_finite() && bits >= SECURITY_BITS as f64
}

pub(super) fn assess(air: &QueryMaskAir) -> Result<Gate> {
    // Independent role-only setup performs this before any PP/private commitment.
    // The helper is the existing r33 snapshot body, narrowly extracted unchanged.
    super::snapshot::require_closed(air);
    let metadata = assessment::assess(air)?;
    // Actual Root r32 metadata, not a relabel of the Word/lookup shape.
    if metadata.base != 1572
        || metadata.extension != 0
        || metadata.degree != 4
        || metadata.chunks != 8
        || metadata.openings != 1447
        || metadata.hiding_rows != 404
    {
        return Err("query-mask:security-geometry".into());
    }
    let fri = FriRegime {
        log_blowup: LOG_BLOWUP,
        num_queries: QUERIES,
        log_final_poly_len: 0,
        max_log_arity: 1,
        commit_pow_bits: 0,
        query_pow_bits: 0,
    };
    let grinding = GrindingSites::NONE;
    let domain = TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, LOG_HEIGHT)
        .ok_or("query-mask:security-domain")?;
    // Safe here because this actual AIR has zero lookup/permutation columns;
    // assessment::assess already rejects any newly introduced lookup.
    let parameters = StarkSecurityParams::from_air::<Val, Challenge, _>(
        fri,
        air,
        AirLayout::from_air(air),
        domain,
        MODULUS_BITS,
        SECURITY_BITS,
        2,
        OpeningShape::hiding(RANDOM_CODEWORDS),
        grinding,
    );
    if parameters.num_constraints != metadata.base
        || parameters.air_max_constraint_degree != metadata.degree
        || parameters.num_quotient_chunks != metadata.chunks
        || parameters.num_batched_functions != metadata.openings
        || parameters.max_combo != 2
    {
        return Err("query-mask:security-native-shape".into());
    }
    let committed_log = LOG_HEIGHT.checked_add(1).ok_or("committed-log")?;
    let baseline = ProvenSecurity::compute_from_proof(committed_log, &parameters);
    let shape = StarkAirParams {
        num_constraints: parameters.num_constraints,
        max_constraint_degree: parameters.air_max_constraint_degree,
        num_quotient_chunks: parameters.num_quotient_chunks,
        max_combo: parameters.max_combo,
    };
    let instance = InstanceShape {
        log_trace_length: committed_log,
        modulus_bits: parameters.num_modulus_bits,
        collision_resistance: parameters.collision_resistance,
        num_batched_functions: parameters.num_batched_functions,
    };
    // The native baseline itself calls this same function with extras=[].
    // Therefore baseline and composed labels coincide for this no-LogUp AIR;
    // do not invent a second protocol or count duplicated labels as coverage.
    let full = proven_security_report(&fri, &shape, &instance, &[], &grinding);
    let gate = Gate {
        metadata,
        baseline,
        full,
    };
    gate.log(); // Record every real term BEFORE any refusal.
    gate.require_floor()?;
    Ok(gate)
}

#[test]
fn actual_no_lookup_native_baseline_and_every_composed_term_meet_the_floor() {
    let air = QueryMaskAir::closed().expect("original closed QueryMaskEncoding AIR");
    let gate = assess(&air).expect("actual native baseline plus every UDR/LDR term");
    gate.require_floor()
        .expect("conditional STARK floor, no admission");
}

#[test]
fn missing_ldr_and_a_downgraded_native_summary_are_rejected() {
    let air = QueryMaskAir::closed().unwrap();
    let mut gate = assess(&air).unwrap();
    let ldr = gate.full.ldr.take();
    assert_eq!(
        gate.require_floor().unwrap_err(),
        "query-mask:security-no-ldr"
    );
    gate.full.ldr = ldr;
    gate.baseline.unique_decoding_bits = SECURITY_BITS - 1;
    assert_eq!(
        gate.require_floor().unwrap_err(),
        "query-mask:security-native-baseline"
    );
}
