//! One actual closed full-AIR native proof. Evidence is not Source/key/SQL authority.
use super::program::{Assessment, ProgramAir};
use super::{Error, Expected, Prepared, Result, program, setup, wire};
use bfv_hiding_stark::Config;
use p3_batch_stark::{
    BatchProof, CommonData, ProverData, StarkInstance, prove_batch, verify_batch,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
#[cfg(test)]
use std::time::Instant;

pub const MAX_EVIDENCE_BYTES: usize = wire::MAX_FRAME_BYTES;

/// Canonical bounded producer bytes, deliberately UNVERIFIED. This contains no
/// success verdict: only the independent receiving verify() may mint a result.
pub struct UnverifiedFormationEvidence {
    expected: Expected,
    bytes: Vec<u8>,
}
impl UnverifiedFormationEvidence {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Move-only mathematical Formation result from actual cold native verification.
/// Contains only its complete PUBLIC expectation, no private key/trace, SDK proof,
/// configuration, cache lease, installed-key, Source, freshness or SQL grant.
///
/// Its actual private field cannot be forged by a consumer:
/// ```compile_fail
/// use bfv_ciphertext_formation::gold::{Expected, VerifiedFormation};
/// fn forge(expected: Expected) -> VerifiedFormation { VerifiedFormation { expected } }
/// ```
/// The mathematical result is not cloneable:
/// ```compile_fail
/// use bfv_ciphertext_formation::gold::VerifiedFormation;
/// fn duplicate(result: &VerifiedFormation) -> VerifiedFormation { result.clone() }
/// ```
pub struct VerifiedFormation {
    expected: Expected,
}
impl VerifiedFormation {
    pub fn expected(&self) -> &Expected {
        &self.expected
    }
}

fn prescreen(expected: &Expected) -> Result<(ProgramAir, Assessment)> {
    let air = ProgramAir::new(expected.clone())?;
    let assessment = program::assess(&air)?;
    assessment.require_resources()?;
    wire::require_assessment(&assessment)?;
    Ok((air, assessment))
}
fn private_config() -> Result<Config> {
    // This is the actual fresh OS-seeded configuration. PUBLIC setup never
    // returns a config or RNG, and no seeded PP config reaches these commits.
    bfv_hiding_stark::config().map_err(|_| Error::Backend)
}

/// Genuinely prove the complete relation and encode bounded UNVERIFIED bytes.
/// No expensive self-verification is hidden in this producer. Receiving verify
/// remains mandatory. Prescreening precedes both public PP and private MAIN.
pub fn prove(expected: &Expected, prepared: Prepared) -> Result<UnverifiedFormationEvidence> {
    catch_unwind(AssertUnwindSafe(|| {
        prepared.require_expected(expected)?;
        let (air, assessment) = prescreen(expected)?;
        #[cfg(test)]
        let began = phase_start("public_pp_setup");
        let data = setup::public_data(&air, expected, &assessment)?;
        #[cfg(test)]
        phase_end("public_pp_setup", began);
        #[cfg(test)]
        let began = phase_start("private_full_trace");
        let trace = prepared.trace(expected)?;
        #[cfg(test)]
        phase_end("private_full_trace", began);
        let proof = prove_trace(expected, &air, &trace.0, &data)?;
        drop(trace); // Guarded MAIN clears on this path and on every unwinding/error path.
        drop(data);
        drop(air);
        #[cfg(test)]
        let began = phase_start("canonical_encode");
        let bytes = wire::encode(expected, &proof, &assessment)?;
        #[cfg(test)]
        phase_end("canonical_encode", began);
        Ok(UnverifiedFormationEvidence {
            expected: expected.clone(),
            bytes,
        })
    }))
    .map_err(|_| Error::Proving)?
}
fn prove_trace(
    expected: &Expected,
    air: &ProgramAir,
    trace: &p3_matrix::dense::RowMajorMatrix<bfv_hiding_stark::Val>,
    data: &ProverData<Config>,
) -> Result<BatchProof<Config>> {
    let config = private_config()?;
    let instances = [StarkInstance {
        air,
        trace,
        public_values: expected.values().to_vec(),
    }];
    #[cfg(test)]
    let began = phase_start("prove_batch");
    let result = catch_unwind(AssertUnwindSafe(|| prove_batch(&config, &instances, data)))
        .map_err(|_| Error::Proving)?
        .map_err(|_| Error::Proving);
    #[cfg(test)]
    phase_end("prove_batch", began);
    result
}

/// Full receiving path: independently retained Expected, canonical bounded frame,
/// same actual analytical/resource gates, rederived PUBLIC PP/CommonData, fresh
/// actual native verify_batch. No verdict is restored from serialized metadata.
pub fn verify(expected: &Expected, frame: &[u8]) -> Result<VerifiedFormation> {
    let payload = wire::payload(expected, frame)?; // BEFORE any heavy setup or decoding.
    catch_unwind(AssertUnwindSafe(|| {
        let (air, assessment) = prescreen(expected)?;
        let proof = wire::decode(payload, &assessment)?;
        #[cfg(test)]
        let began = phase_start("cold_public_pp_setup");
        let data = setup::public_data(&air, expected, &assessment)?;
        #[cfg(test)]
        phase_end("cold_public_pp_setup", began);
        let common = data.common;
        drop(data.prover_only); // No public PP LDEs retained by the receiving verifier.
        verify_native(expected, &air, &proof, &common)?;
        // SDK proof/config/CommonData/AIR all die before this mathematical result returns.
        Ok(VerifiedFormation {
            expected: expected.clone(),
        })
    }))
    .map_err(|_| Error::Backend)?
}
fn verify_native(
    expected: &Expected,
    air: &ProgramAir,
    proof: &BatchProof<Config>,
    common: &CommonData<Config>,
) -> Result<()> {
    let config = private_config()?;
    #[cfg(test)]
    let began = phase_start("cold_verify_batch");
    let result = catch_unwind(AssertUnwindSafe(|| {
        verify_batch(
            &config,
            core::slice::from_ref(air),
            proof,
            &[expected.values().to_vec()],
            common,
        )
    }))
    .map_err(|_| Error::Backend)?
    .map_err(|_| Error::Verification);
    #[cfg(test)]
    phase_end("cold_verify_batch", began);
    result
}

#[cfg(test)]
fn phase_start(phase: &'static str) -> Instant {
    eprintln!("core_gold_native phase={phase} state=start");
    Instant::now()
}
#[cfg(test)]
fn phase_end(phase: &'static str, began: Instant) {
    eprintln!(
        "core_gold_native phase={phase} state=end elapsed_ms={:.3}",
        began.elapsed().as_secs_f64() * 1000.
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bfv_hiding_stark::{Challenge, Val};
    use p3_batch_stark::BatchVerificationError;
    use p3_field::PrimeCharacteristicRing;
    use p3_lookup::LookupError;
    use p3_uni_stark::VerificationError;

    #[test]
    fn false_first_graph_wire_preserves_local_equations_but_real_native_lookup_rejects() {
        let (expected, prepared) = super::super::tests::fixture();
        let (air, assessment) = prescreen(&expected).unwrap();
        let coefficients = air.first_gate_coefficients();
        assert_eq!(coefficients[0], Val::ONE);
        assert_eq!(coefficients[2], Val::ONE);
        let data = setup::public_data(&air, &expected, &assessment).unwrap();
        let mut trace = prepared.trace(&expected).unwrap();
        // Change ONLY the first gate's input0 and both outputs. Its two local
        // equations still hold; EVERY other row, all four final AS products,
        // range banks, Cw and packed-Cs hash inputs remain exactly unchanged.
        trace.0.values[0] += Val::ONE;
        trace.0.values[2] += Val::ONE;
        trace.0.values[3] += Val::ONE;
        assert_eq!(
            trace.0.values[2],
            coefficients[0] * trace.0.values[0] + coefficients[1] * trace.0.values[1]
        );
        assert_eq!(
            trace.0.values[3],
            coefficients[2] * trace.0.values[0] + coefficients[3] * trace.0.values[1]
        );
        let attempted = prove_trace(&expected, &air, &trace.0, &data);
        if cfg!(debug_assertions) {
            // Debug native bus replay may reject early; RELEASE below is the
            // required real proof+verification oracle. No Shape/resource passes.
            assert!(matches!(attempted, Err(Error::Proving)));
            return;
        }
        let mut proof = attempted.expect("release must produce the actual unbalanced argument");
        drop(trace);
        assert_ne!(
            proof.lookup_terminals[0].as_ref().unwrap().0,
            Challenge::ZERO
        );
        let config = private_config().unwrap();
        let error = verify_batch(
            &config,
            core::slice::from_ref(&air),
            &proof,
            &[expected.values().to_vec()],
            &data.common,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BatchVerificationError::Lookup(LookupError::TerminalSumNonZero)
        ));
        // Decoder terminal0 is necessary, never sufficient: repairing only that
        // public numeral keeps native topology valid but not the cryptographic argument.
        proof.lookup_terminals[0].as_mut().unwrap().0 = Challenge::ZERO;
        wire::check(&proof, &assessment).unwrap();
        let error = verify_batch(
            &private_config().unwrap(),
            core::slice::from_ref(&air),
            &proof,
            &[expected.values().to_vec()],
            &data.common,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BatchVerificationError::Verification(
                VerificationError::InvalidOpeningArgument(_)
                    | VerificationError::OodEvaluationMismatch { .. }
            )
        ));
    }
}
