//! NTT-owned statement policy and reports over the shared serial SHA512/WHIR backend.
use crate::Error;
use bfv_multilinear_stark::{AirSpec, Domains, assess, config_for};
pub use bfv_multilinear_stark::{
    COLLISION_BITS, Challenge, FOLDING, MAX_FINAL_VARIABLES, MAX_QUERIES, MAX_QUERY_PHASES,
    PHASE_BITS, POLICY_BITS, Val, sha512 as digest,
};
pub(crate) use bfv_multilinear_stark::{Config, Proof};
use bfv_ntt_circuit::multistark::{PreparedMachine, prepare_public};
use bfv_ntt_circuit::{Basis, DEGREE, Direction, Output, Request, parameters};
use p3_air::{BaseAir, symbolic::AirLayout};
use p3_lookup::InteractionSymbolicBuilder;
use p3_multi_stark::{ProvingKey, VerifierInstance, VerifierInstances, VerifyingKey, setup};
use serde::Serialize;
use sha2::{Digest, Sha512};

pub const MAX_MERKLE_DEPTH: usize = 22;

/// The application domains are unchanged protocol inputs, owned by this consumer.
pub(crate) fn domains() -> Domains {
    Domains::new(
        b"DCS/NTT-WITNESS/v1/MERKLE-LEAF/LE64/",
        b"DCS/NTT-WITNESS/v1/MERKLE-NODE/LE64/",
        b"DCS/NTT-WITNESS/v1/FIAT-SHAMIR/BYTES/",
        b"DCS/NTT-WITNESS-PROOF/v1/statement/",
    )
    .expect("the fixed NTT domains are nonempty and prefix-free")
}

pub fn direction_name(d: Direction) -> &'static str {
    match d {
        Direction::Forward => "forward",
        Direction::Inverse => "inverse",
    }
}
pub(crate) fn tag(d: Direction) -> u8 {
    d as u8
}
/// Complete fixed machine/backend policy. Old circuit SHA256 profiles are unchanged.
pub fn profile_digest(d: Direction, b: Basis) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"DCS/NTT-WITNESS-PROOF/v1/profile/SHA512/full-output/");
    h.update(b"Plonky3-0.8.0/a21e3ed42905040ad49c519e402f018381c12d0c/Goldilocks/EF5/WHIR/UniqueDecoding/PrefixProver/LogUp/shared-job-specific-VK/no-hiding/");
    h.update([tag(d), b.index()]);
    for n in [
        DEGREE as u64,
        b.modulus(),
        parameters(b).primitive_root(),
        parameters(b).inverse_size(),
    ] {
        h.update(n.to_le_bytes());
    }
    for ws in [
        parameters(b).forward_twiddles(),
        parameters(b).inverse_twiddles(),
    ] {
        for &v in ws {
            h.update(v.to_le_bytes());
        }
    }
    h.update(bfv_ntt_circuit::multistark::MACHINE_DESCRIPTOR);
    h.update(b"native-SDK-order;Stage35=x4,y4,z4,delta4,U5,carrylo7,carryhi7;PP11=j,ix,iy,a4,b4;IO1/PP9=j,input4,output4;Range2/PP1;heights65536,16384,512,16-repeat4;R16x17/R14x2/R9x7/R2x1;d0=d8=2^24;Uoffset2^64;8radix16digits;canonical-z+delta=q-1;route-all4limbs;provider-2/norm-1/final-1;PV0;leaf/node/FS-distinct-domains;all8-u64-digestwords;seed=tag+profile64+SHA512(completeRequest)+SHA512(completeOutput)");
    for n in [
        POLICY_BITS,
        PHASE_BITS,
        COLLISION_BITS,
        FOLDING,
        1,
        0,
        22,
        21,
        MAX_QUERY_PHASES,
        MAX_QUERIES,
        MAX_MERKLE_DEPTH,
        MAX_FINAL_VARIABLES,
        crate::MAX_PROOF_BYTES,
        crate::MAX_PROOF_SEQUENCE_ELEMENTS,
        crate::MAX_PROOF_DECODE_ELEMENTS,
    ] {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
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
    fn from(schedule: bfv_multilinear_stark::PcsSchedule) -> Self {
        Self {
            variables: schedule.variables,
            folding: schedule.folding,
            queries: schedule.queries,
            rates: schedule.rates,
            initial_claims: schedule.initial_claims,
            final_variables: schedule.final_variables,
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
pub struct AirReport {
    pub height: usize,
    pub main_width: usize,
    pub preprocessed_width: usize,
    pub constraints: usize,
    pub constraint_degree: usize,
    pub lookup_contributions: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct SecurityReport {
    pub stage: &'static str,
    pub direction: &'static str,
    pub basis_index: u8,
    pub modulus: u64,
    pub trace_height: usize,
    pub stages: usize,
    pub air_count: usize,
    pub main_cells: usize,
    pub preprocessed_cells: usize,
    pub lookup_contributions: usize,
    pub lookup_count_weight: usize,
    pub lookup_padded: usize,
    pub main_trace_bytes: usize,
    pub public_preprocessing_bytes: usize,
    pub extension_degree: usize,
    pub collision_bits: usize,
    pub required_security_bits: usize,
    pub whole_security_bits: f64,
    pub unassessed_components: Vec<&'static str>,
    pub terms: Vec<Term>,
    pub tables: Vec<AirReport>,
    pub main_pcs: PcsSchedule,
    pub preprocessed_pcs: PcsSchedule,
}
pub(crate) struct Backend {
    pub machine: PreparedMachine,
    pub config: Config,
    pub prover: ProvingKey<Config>,
    pub verifier: VerifyingKey<Config>,
    pub report: SecurityReport,
}
impl Backend {
    pub fn new(input: &Request, output: &Output) -> Result<Self, Error> {
        let machine = prepare_public(input, output).map_err(|_| Error::Statement)?;
        if machine.airs().iter().any(|a| {
            !a.is_prepared()
                || a.num_public_values() != 0
                || !a.main_next_row_columns().is_empty()
                || !a.preprocessed_next_row_columns().is_empty()
        }) {
            return Err(Error::Preprocessing);
        }
        let tables: Vec<_> = machine
            .airs()
            .iter()
            .map(|a| {
                let symbolic = InteractionSymbolicBuilder::<Val, Challenge>::from_air(
                    a,
                    AirLayout::from_air::<Val>(a),
                );
                let cs = symbolic.base_constraints();
                AirReport {
                    height: a.height(),
                    main_width: a.width(),
                    preprocessed_width: a.preprocessed_width(),
                    constraints: cs.len(),
                    constraint_degree: cs.iter().map(|c| c.poly_degree(2, &[])).max().unwrap_or(0),
                    lookup_contributions: symbolic.global_interactions().len(),
                }
            })
            .collect();
        let main_cells = tables
            .iter()
            .map(|a| a.height * a.main_width)
            .sum::<usize>();
        let preprocessed_cells = tables
            .iter()
            .map(|a| a.height * a.preprocessed_width)
            .sum::<usize>();
        let lookup_contributions = tables
            .iter()
            .map(|a| a.height * a.lookup_contributions)
            .sum::<usize>();
        let lookup_count_weight = machine
            .airs()
            .iter()
            .map(|a| {
                let s = InteractionSymbolicBuilder::<Val, Challenge>::from_air(
                    a,
                    AirLayout::from_air::<Val>(a),
                );
                a.height()
                    * s.global_interactions()
                        .iter()
                        .map(|i| i.count_weight as usize)
                        .sum::<usize>()
            })
            .sum::<usize>();
        let inverse = input.direction() == Direction::Inverse;
        let expected = if inverse {
            (4187168, 1417744, 3531280, 3555328)
        } else {
            (3900448, 1327632, 3293712, 3317760)
        };
        if (
            main_cells,
            preprocessed_cells,
            lookup_contributions,
            lookup_count_weight,
        ) != expected
            || tables.len() != input.direction().stages() + 5
            || tables
                .iter()
                .any(|a| a.constraint_degree > 2 || a.constraints == 0)
        {
            return Err(Error::SecurityProfile);
        }
        let main_variables = main_cells.next_power_of_two().ilog2() as usize;
        let public_variables = preprocessed_cells.next_power_of_two().ilog2() as usize;
        if (main_variables, public_variables) != (22, 21) {
            return Err(Error::SecurityProfile);
        }
        let specs: Vec<_> = machine
            .airs()
            .iter()
            .map(|a| AirSpec::new(a, a.height().ilog2() as usize))
            .collect();
        let (config, plan) = config_for(&specs, domains()).map_err(|_| Error::SecurityProfile)?;
        let public_plan = plan.preprocessed_pcs.ok_or(Error::SecurityProfile)?;
        if plan.main_cells != main_cells
            || plan.preprocessed_cells != preprocessed_cells
            || plan.main_pcs.variables != main_variables
            || public_plan.variables != public_variables
            || plan.main_pcs.initial_claims != tables.iter().map(|a| a.main_width).sum::<usize>()
            || public_plan.initial_claims
                != tables.iter().map(|a| a.preprocessed_width).sum::<usize>()
        {
            return Err(Error::SecurityProfile);
        }
        let main_pcs = plan.main_pcs.into();
        let preprocessed_pcs = public_plan.into();
        let airs = machine.airs().iter().collect::<Vec<_>>();
        let (prover, verifier) = setup(
            &config,
            &airs,
            &mut config.challenger(
                profile_digest(input.direction(), input.basis()),
                &input.encode(),
                &output.encode(),
            ),
        )
        .map_err(|_| Error::Preprocessing)?;
        let instances = VerifierInstances::new(
            machine
                .airs()
                .iter()
                .map(|a| VerifierInstance::new(a, &verifier, a.height().ilog2() as usize, &[]))
                .collect(),
        );
        let actual = assess(&config, &instances).map_err(|_| Error::SecurityProfile)?;
        actual
            .require_security(POLICY_BITS)
            .map_err(|_| Error::SecurityProfile)?;
        let bits = actual.security_bits().ok_or(Error::SecurityProfile)?;
        if !bits.is_finite() || !actual.unassessed_components().is_empty() {
            return Err(Error::SecurityProfile);
        }
        let report = SecurityReport {
            stage: "security_witness_ntt",
            direction: direction_name(input.direction()),
            basis_index: input.basis().index(),
            modulus: input.basis().modulus(),
            trace_height: DEGREE,
            stages: input.direction().stages(),
            air_count: tables.len(),
            main_cells,
            preprocessed_cells,
            lookup_contributions,
            lookup_count_weight,
            lookup_padded: lookup_contributions.next_power_of_two(),
            main_trace_bytes: main_cells * 8,
            public_preprocessing_bytes: preprocessed_cells * 8,
            extension_degree: 5,
            collision_bits: COLLISION_BITS,
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
/// No main trace or NTT evaluation. This DOES allocate and commit verifier-built
/// fixed/public tables, since the published security-report API needs a real VK.
pub fn analyze(direction: Direction, basis: Basis) -> Result<SecurityReport, Error> {
    let (input, output) = crate::fixture::zero_statement(direction, basis)?;
    Ok(Backend::new(&input, &output)?.report)
}
