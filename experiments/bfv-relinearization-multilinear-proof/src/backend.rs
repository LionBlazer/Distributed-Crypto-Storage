//! Operation-specific envelope/profile/report and independent public preprocessing.
use crate::Error;
use bfv_multilinear_stark::{AirSpec, Domains, assess, config_for};
pub use bfv_multilinear_stark::{Challenge, POLICY_BITS, Val, sha512 as digest};
pub(crate) use bfv_multilinear_stark::{Config, Proof};
use bfv_relinearization_circuit::plonky3::{ArithmeticAir, prepare};
use bfv_relinearization_circuit::{
    Aux, DEGREE, EMBEDDING_QUOTIENT_BOUNDS, MODULI, Output, Request, Role,
};
use p3_air::{BaseAir, symbolic::AirLayout};
use p3_lookup::InteractionSymbolicBuilder;
use p3_multi_stark::{ProvingKey, VerifierInstance, VerifierInstances, VerifyingKey, setup};
use serde::Serialize;
use sha2::{Digest, Sha512};
pub const LOG_HEIGHT: usize = 13;
pub const MAX_MERKLE_DEPTH: usize = 22;
pub fn role_name(role: Role) -> &'static str {
    match role {
        Role::Embed => "embed",
        Role::AccumulateAndAdd => "accumulate",
    }
}
pub(crate) fn domains() -> Domains {
    Domains::new(
        b"DCS/RELIN-MULTILINEAR/v1/MERKLE-LEAF/LE64/",
        b"DCS/RELIN-MULTILINEAR/v1/MERKLE-NODE/LE64/",
        b"DCS/RELIN-MULTILINEAR/v1/FIAT-SHAMIR/BYTES/",
        b"DCS/RELIN-MULTILINEAR/v1/STATEMENT/",
    )
    .expect("fixed domains are nonempty and prefix-free")
}
/// Complete fixed semantics/configuration, beyond the legacy SHA256 role digest.
pub fn profile_digest(role: Role) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/RELIN-MULTILINEAR-PROOF/v1/PROFILE/");
    h.update(bfv_multilinear_stark::PROTOCOL_DESCRIPTOR);
    for domain in [
        domains().leaf(),
        domains().node(),
        domains().transcript(),
        domains().statement(),
    ] {
        h.update((domain.len() as u64).to_le_bytes());
        h.update(domain);
    }
    h.update([role as u8]);
    for modulus in MODULI {
        h.update(modulus.to_le_bytes());
    }
    for row in EMBEDDING_QUOTIENT_BOUNDS {
        h.update(row);
    }
    h.update(b"N8192/Q5/level0-0/logbase0;Embed5PB-to25PB-source-i-target-j:r=E+qj*t,t<=2;Accumulate85NTT-to10NTT-target-j:block17=O0,O1,D0..4,K00..04,K10..14;out2j+c;orig+sum5D*K=out+q*k;k<5q;limbs3x16/sixdigits/fivecarry25-bias2^24/zero-endpoints;canonical-input-output-and-aux-before-field;publicAux-not-private-main;main1-zero/PV32-legacy-consistency;full-seed=tag+profile64+SHA512(tag+lenRequest+fullRequest+lenAux+fullAux)+SHA512(fullOutput);opaque-context32-not-key-authority;no-NTT-provenance;no-completeRelin;no-SQL");
    h.update(bfv_relinearization_circuit::profile_digest(role));
    for n in [
        DEGREE,
        LOG_HEIGHT,
        role.input_coefficients(),
        role.output_coefficients(),
        role.preprocessed_width(),
        role.aux_bytes(),
        32,
        1,
        19,
        22,
        144,
        160,
        256,
        4,
        6,
        512,
        MAX_MERKLE_DEPTH,
        crate::MAX_PROOF_BYTES,
        crate::MAX_PROOF_SEQUENCE_ELEMENTS,
        crate::MAX_PROOF_DECODE_ELEMENTS,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
}
/// Unambiguous complete canonical Request+Aux bytes, not only their old digest fields.
pub(crate) fn envelope(input: &Request, aux: &Aux) -> Vec<u8> {
    let request = input.encode();
    let aux = aux.encode();
    let mut bytes = b"DCS/RELIN-MULTILINEAR/v1/REQUEST-AND-PUBLIC-AUX/".to_vec();
    bytes.extend((request.len() as u64).to_le_bytes());
    bytes.extend(request);
    bytes.extend((aux.len() as u64).to_le_bytes());
    bytes.extend(aux);
    bytes
}
#[derive(Clone, Debug, Serialize)]
pub struct PcsSchedule {
    pub variables: usize,
    pub folding: Vec<usize>,
    pub queries: Vec<usize>,
    pub rates: Vec<usize>,
    pub initial_claims: usize,
    pub final_variables: usize,
}
impl From<bfv_multilinear_stark::PcsSchedule> for PcsSchedule {
    fn from(p: bfv_multilinear_stark::PcsSchedule) -> Self {
        Self {
            variables: p.variables,
            folding: p.folding,
            queries: p.queries,
            rates: p.rates,
            initial_claims: p.initial_claims,
            final_variables: p.final_variables,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Term {
    pub label: &'static str,
    pub component: Option<&'static str>,
    pub bits: f64,
}
#[derive(Clone, Debug, Serialize)]
pub struct SecurityReport {
    pub stage: &'static str,
    pub role: &'static str,
    pub trace_height: usize,
    pub main_width: usize,
    pub preprocessed_width: usize,
    pub public_values: usize,
    pub constraints: usize,
    pub constraint_degree: usize,
    pub main_trace_bytes: usize,
    pub public_preprocessing_bytes: usize,
    pub public_auxiliary_bytes: usize,
    pub extension_degree: usize,
    pub collision_bits: usize,
    pub required_security_bits: usize,
    pub whole_security_bits: f64,
    pub unassessed_components: Vec<&'static str>,
    pub terms: Vec<Term>,
    pub main_pcs: PcsSchedule,
    pub preprocessed_pcs: PcsSchedule,
}
pub(crate) struct Backend {
    pub air: ArithmeticAir,
    pub values: Vec<Val>,
    pub config: Config,
    pub prover: ProvingKey<Config>,
    pub verifier: VerifyingKey<Config>,
    pub report: SecurityReport,
}
impl Backend {
    pub fn new(input: &Request, output: &Output, aux: &Aux) -> Result<Self, Error> {
        let (air, values) = prepare(input, output, aux)
            .map_err(|_| Error::Statement)?
            .into_parts();
        if !air.is_prepared()
            || air.role() != input.role()
            || air.width() != 1
            || air.num_public_values() != 32
            || values.len() != 32
            || air.preprocessed_width() != input.role().preprocessed_width()
        {
            return Err(Error::Preprocessing);
        }
        let symbolic = InteractionSymbolicBuilder::<Val, Challenge>::from_air(
            &air,
            AirLayout::from_air::<Val>(&air),
        );
        let cs = symbolic.base_constraints();
        let degree = cs.iter().map(|c| c.poly_degree(2, &[])).max().unwrap_or(0);
        if cs.is_empty()
            || degree
                > match input.role() {
                    Role::Embed => 1,
                    Role::AccumulateAndAdd => 2,
                }
            || !symbolic.global_interactions().is_empty()
        {
            return Err(Error::SecurityProfile);
        }
        let (config, plan) = config_for(&[AirSpec::new(&air, LOG_HEIGHT)], domains())
            .map_err(|_| Error::SecurityProfile)?;
        let public = plan.preprocessed_pcs.ok_or(Error::SecurityProfile)?;
        if plan.main_pcs.variables != 13
            || plan.main_pcs.initial_claims != 1
            || public.variables
                != match input.role() {
                    Role::Embed => 19,
                    Role::AccumulateAndAdd => 22,
                }
            || public.initial_claims != input.role().preprocessed_width()
        {
            return Err(Error::SecurityProfile);
        }
        if plan.main_pcs.folding != [4, 4]
            || plan.main_pcs.queries.len() != 2
            || plan.main_pcs.final_variables != 5
            || public.folding != [4, 4, 4, 4]
            || public.queries.len() != 4
            || public.final_variables
                != match input.role() {
                    Role::Embed => 3,
                    Role::AccumulateAndAdd => 6,
                }
        {
            return Err(Error::SecurityProfile);
        }
        let wire = envelope(input, aux);
        let out = output.encode();
        let profile = profile_digest(input.role());
        let (prover, verifier) = setup(
            &config,
            &[&air],
            &mut config.challenger(profile, &wire, &out),
        )
        .map_err(|_| Error::Preprocessing)?;
        let instances = VerifierInstances::new(vec![VerifierInstance::new(
            &air, &verifier, LOG_HEIGHT, &values,
        )]);
        let actual = assess(&config, &instances).map_err(|_| Error::SecurityProfile)?;
        let bits = actual.security_bits().ok_or(Error::SecurityProfile)?;
        let report = SecurityReport {
            stage: "security_multilinear_public_relinearization_arithmetic",
            role: role_name(input.role()),
            trace_height: DEGREE,
            main_width: 1,
            preprocessed_width: air.preprocessed_width(),
            public_values: values.len(),
            constraints: cs.len(),
            constraint_degree: degree,
            main_trace_bytes: DEGREE * 8,
            public_preprocessing_bytes: DEGREE * air.preprocessed_width() * 8,
            public_auxiliary_bytes: input.role().aux_bytes(),
            extension_degree: 5,
            collision_bits: bfv_multilinear_stark::COLLISION_BITS,
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
            main_pcs: plan.main_pcs.into(),
            preprocessed_pcs: public.into(),
        };
        Ok(Self {
            air,
            values,
            config,
            prover,
            verifier,
            report,
        })
    }
}
/// Builds real job-specific public setup/security report, without arithmetic evaluation or a main trace.
pub fn analyze(role: Role) -> Result<SecurityReport, Error> {
    let (input, output, aux) = crate::fixture::zero_statement(role)?;
    Ok(Backend::new(&input, &output, &aux)?.report)
}
