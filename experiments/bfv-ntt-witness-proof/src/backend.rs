//! Consumer-owned SHA512/WHIR policy and complete SDK statement security report.
use crate::{Error, hashes};
use bfv_ntt_circuit::multistark::{PreparedMachine, prepare_public};
use bfv_ntt_circuit::{Basis, DEGREE, Direction, Output, Request, parameters};
use p3_air::{BaseAir, symbolic::AirLayout};
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::extension::BinomialExtensionField;
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionSymbolicBuilder;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multi_stark::config::{MultiStarkConfig, ProverData};
use p3_multi_stark::{
    MultiStarkProof, ProvingKey, VerifierInstance, VerifierInstances, VerifyingKey,
    security_report, setup,
};
use p3_sumcheck::layout::{Layout, PrefixProver, Table, Witness};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};
use serde::Serialize;
use sha2::{Digest, Sha512};

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 5>;
pub(crate) type Challenger =
    SerializingChallenger64<Val, HashChallenger<u8, hashes::Transcript, 64>>;
pub(crate) type Mmcs = MerkleTreeMmcs<
    Val,
    u64,
    SerializingHasher<hashes::Leaf>,
    CompressionFunctionFromHasher<hashes::Node, 2, 8>,
    2,
    8,
>;
type L = PrefixProver<Val, Challenge>;
type Pcs = WhirProver<Challenge, Val, Radix2DFTSmallBatch<Val>, Mmcs, Challenger, L>;
pub(crate) type Proof = MultiStarkProof<Config>;
pub const POLICY_BITS: usize = 144;
pub const PHASE_BITS: usize = 160;
pub const COLLISION_BITS: usize = 256;
pub const FOLDING: usize = 4;
pub const MAX_QUERY_PHASES: usize = 6;
pub const MAX_QUERIES: usize = 512;
pub const MAX_MERKLE_DEPTH: usize = 22;
pub const MAX_FINAL_VARIABLES: usize = 6;

pub(crate) struct Config {
    main: Pcs,
    public: Pcs,
}
impl MultiStarkConfig for Config {
    type Val = Val;
    type Challenge = Challenge;
    type Challenger = Challenger;
    type Pcs = Pcs;
    fn pcs(&self) -> &Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Pcs {
        &self.public
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(COLLISION_BITS)
    }
    fn min_num_variables(&self) -> usize {
        FOLDING
    }
    fn build_witness(&self, tables: Vec<Table<Val>>) -> Witness<Val> {
        L::new_witness(tables, FOLDING)
    }
    fn committed_table<'a>(&self, data: &'a ProverData<Self>, index: usize) -> &'a Table<Val> {
        data.table(index)
    }
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
fn pcs(variables: usize, claims: usize) -> Result<(Pcs, PcsSchedule), Error> {
    let params = ProtocolParameters {
        starting_log_inv_rate: 1,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(FOLDING),
        soundness_type: SecurityAssumption::UniqueDecoding,
        security_level: PHASE_BITS,
        pow_bits: 0,
    };
    let cfg = WhirConfig::<Challenge, Val, Challenger>::new_with_initial_claims(
        variables, params, claims,
    )
    .map_err(|_| Error::SecurityProfile)?;
    let mut queries: Vec<_> = cfg
        .round_parameters()
        .iter()
        .map(|r| r.num_queries)
        .collect();
    queries.push(cfg.terminal().num_queries);
    if cfg.max_pow_bits() != 0
        || cfg.commitment_ood_samples() != 0
        || cfg
            .round_parameters()
            .iter()
            .any(|r| r.ood_samples != 0 || r.folding_factor > FOLDING)
        || queries.len() > MAX_QUERY_PHASES
        || queries.iter().any(|&q| q == 0 || q > MAX_QUERIES)
        || cfg.final_sumcheck_rounds() > MAX_FINAL_VARIABLES
    {
        return Err(Error::SecurityProfile);
    }
    let report = PcsSchedule {
        variables,
        folding: cfg.folding_schedule().to_vec(),
        queries,
        rates: cfg
            .round_parameters()
            .iter()
            .map(|r| r.log_inv_rate)
            .collect(),
        initial_claims: claims,
        final_variables: cfg.final_sumcheck_rounds(),
    };
    let mmcs = Mmcs::new(
        SerializingHasher::new(hashes::Leaf),
        CompressionFunctionFromHasher::new(hashes::Node),
        0,
    );
    Ok((Pcs::new(cfg, Radix2DFTSmallBatch::default(), mmcs), report))
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
pub fn digest(bytes: &[u8]) -> [u8; 64] {
    Sha512::digest(bytes).into()
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
pub(crate) fn challenger(input: &Request, output: &Output) -> Challenger {
    let mut seed = b"DCS/NTT-WITNESS-PROOF/v1/statement/".to_vec();
    seed.extend(profile_digest(input.direction(), input.basis()));
    // Hash complete canonical wire bytes, never merely the old SHA256 header digests.
    seed.extend(digest(&input.encode()));
    seed.extend(digest(&output.encode()));
    SerializingChallenger64::new(HashChallenger::new(seed, hashes::Transcript))
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
        let (main, main_pcs) = pcs(main_variables, tables.iter().map(|a| a.main_width).sum())?;
        let (public, preprocessed_pcs) = pcs(
            public_variables,
            tables.iter().map(|a| a.preprocessed_width).sum(),
        )?;
        let config = Config { main, public };
        let airs = machine.airs().iter().collect::<Vec<_>>();
        let (prover, verifier) = setup(&config, &airs, &mut challenger(input, output))
            .map_err(|_| Error::Preprocessing)?;
        let instances = VerifierInstances::new(
            machine
                .airs()
                .iter()
                .map(|a| VerifierInstance::new(a, &verifier, a.height().ilog2() as usize, &[]))
                .collect(),
        );
        let actual = security_report(&config, &instances).map_err(|_| Error::SecurityProfile)?;
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
