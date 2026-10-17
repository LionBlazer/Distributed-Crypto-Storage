//! Fixed serial protocol and checked current-only committed table geometry.
use crate::{Domains, Error, Sha512Leaf, Sha512Node, Sha512Transcript, sha512};
use p3_air::{
    Air, BaseAir,
    symbolic::{
        AirLayout, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression, SymbolicVariable,
    },
};
use p3_bus::BusSymbolicBuilder;
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::extension::BinomialExtensionField;
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionSymbolicBuilder;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multi_stark::MultiStarkProof;
use p3_multi_stark::config::{MultiStarkConfig, ProverData};
use p3_sumcheck::layout::{Layout, PrefixProver, Table, Witness};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 5>;
pub type Challenger = SerializingChallenger64<Val, HashChallenger<u8, Sha512Transcript, 64>>;
type Mmcs = MerkleTreeMmcs<
    Val,
    u64,
    SerializingHasher<Sha512Leaf>,
    CompressionFunctionFromHasher<Sha512Node, 2, 8>,
    2,
    8,
>;
type L = PrefixProver<Val, Challenge>;
pub type Pcs = WhirProver<Challenge, Val, Radix2DFTSmallBatch<Val>, Mmcs, Challenger, L>;
pub type Proof = MultiStarkProof<Config>;
pub const POLICY_BITS: usize = 144;
pub const PHASE_BITS: usize = 160;
pub const COLLISION_BITS: usize = 256;
pub const FOLDING: usize = 4;
pub const MAX_QUERY_PHASES: usize = 6;
pub const MAX_QUERIES: usize = 512;
pub const MAX_FINAL_VARIABLES: usize = 6;
/// Fixed protocol identity, not an operation profile or an acceptance token.
pub const PROTOCOL_DESCRIPTOR: &[u8] = b"DCS/BFV-MULTILINEAR-STARK/v1/Plonky3-0.8.0/a21e3ed42905040ad49c519e402f018381c12d0c/Goldilocks/EF5/SHA512-full64/LE64-digest8/Merkle-binary-cap0/PrefixProver/WHIR-UniqueDecoding/start-rate1/derived-rates/fold4/phase160/whole144/collision256/PoW0/OOD0/no-hiding/current-only/global-LogUp/no-indexed-no-binary-no-periodic-no-boundary-no-boolean/seed=statement+profile64+SHA512(fullRequest)+SHA512(fullOutput)";

/// The AIR and its height are trusted verifier inputs, never decoded proof counts.
pub struct AirSpec<'a, A> {
    pub(crate) air: &'a A,
    pub(crate) log_height: usize,
}
impl<'a, A> AirSpec<'a, A> {
    pub const fn new(air: &'a A, log_height: usize) -> Self {
        Self { air, log_height }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableShape {
    pub log_height: usize,
    pub main_width: usize,
    pub preprocessed_width: usize,
    pub public_values: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcsSchedule {
    pub variables: usize,
    pub folding: Vec<usize>,
    pub queries: Vec<usize>,
    pub rates: Vec<usize>,
    pub initial_claims: usize,
    pub final_variables: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolPlan {
    pub tables: Vec<TableShape>,
    pub main_cells: usize,
    pub preprocessed_cells: usize,
    pub main_pcs: PcsSchedule,
    pub preprocessed_pcs: Option<PcsSchedule>,
}

pub struct Config {
    main: Pcs,
    public: Option<Pcs>,
    domains: Domains,
    plan: ProtocolPlan,
}
impl Config {
    pub fn plan(&self) -> &ProtocolPlan {
        &self.plan
    }
    pub const fn domains(&self) -> Domains {
        self.domains
    }
    /// The caller validates and encodes the COMPLETE operation envelope. This helper
    /// hashes all supplied canonical wire bytes, including bytes after legacy digests.
    /// The fixed concatenation exactly preserves the existing NTT transcript.
    pub fn challenger(
        &self,
        profile: [u8; 64],
        request_wire: &[u8],
        output_wire: &[u8],
    ) -> Challenger {
        let mut seed = self.domains.statement().to_vec();
        seed.extend(profile);
        seed.extend(sha512(request_wire));
        seed.extend(sha512(output_wire));
        SerializingChallenger64::new(HashChallenger::new(
            seed,
            Sha512Transcript(self.domains.transcript()),
        ))
    }
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
        self.public
            .as_ref()
            .expect("preprocessed PCS requires the matching config_for table shapes")
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

// Complete metadata pass before any symbolic builder allocates AIR-width vectors.
pub(crate) fn dimensions<A: BaseAir<Val>>(
    specs: &[AirSpec<'_, A>],
) -> Result<(Vec<TableShape>, usize, usize), Error> {
    if specs.is_empty() {
        return Err(Error::InvalidShape);
    }
    let mut tables = Vec::with_capacity(specs.len());
    let mut main_cells = 0usize;
    let mut public_cells = 0usize;
    for spec in specs {
        let air = spec.air;
        if spec.log_height < FOLDING || spec.log_height >= usize::BITS as usize || air.width() == 0
        {
            return Err(Error::InvalidShape);
        }
        // The SDK allocates two symbolic rows and one public-value vector. Check
        // their actual element layout before constructing either symbolic builder.
        for count in [
            air.width().checked_mul(2),
            air.preprocessed_width().checked_mul(2),
            Some(air.num_public_values()),
        ] {
            let count = count.ok_or(Error::InvalidShape)?;
            std::alloc::Layout::array::<SymbolicVariable<Val>>(count)
                .map_err(|_| Error::InvalidShape)?;
        }
        let rows = 1usize
            .checked_shl(spec.log_height as u32)
            .ok_or(Error::InvalidShape)?;
        for (width, cells) in [
            (air.width(), &mut main_cells),
            (air.preprocessed_width(), &mut public_cells),
        ] {
            *cells = rows
                .checked_mul(width)
                .and_then(|n| cells.checked_add(n))
                .ok_or(Error::InvalidShape)?;
        }
        tables.push(TableShape {
            log_height: spec.log_height,
            main_width: air.width(),
            preprocessed_width: air.preprocessed_width(),
            public_values: air.num_public_values(),
        });
    }
    if main_cells.checked_next_power_of_two().is_none()
        || public_cells.checked_next_power_of_two().is_none()
    {
        return Err(Error::InvalidShape);
    }
    Ok((tables, main_cells, public_cells))
}
fn current_expression(e: &SymbolicExpression<Val>, shape: &TableShape) -> bool {
    match e {
        SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => match v.entry {
            BaseEntry::Main { offset: 0 } => v.index < shape.main_width,
            BaseEntry::Preprocessed { offset: 0 } => v.index < shape.preprocessed_width,
            BaseEntry::Public => v.index < shape.public_values,
            _ => false,
        },
        SymbolicExpr::Leaf(_) => true,
        SymbolicExpr::Add { x, y, .. }
        | SymbolicExpr::Sub { x, y, .. }
        | SymbolicExpr::Mul { x, y, .. } => {
            current_expression(x, shape) && current_expression(y, shape)
        }
        SymbolicExpr::Neg { x, .. } => current_expression(x, shape),
    }
}
pub(crate) fn validate_airs<A>(specs: &[AirSpec<'_, A>], shapes: &[TableShape]) -> Result<(), Error>
where
    A: BaseAir<Val>
        + Air<InteractionSymbolicBuilder<Val, Challenge>>
        + Air<BusSymbolicBuilder<Val, Challenge>>,
{
    for (spec, shape) in specs.iter().zip(shapes) {
        let air = spec.air;
        if air.assumes_boolean_trace()
            || !air.public_boundary_io().is_empty()
            || !air.main_next_row_columns().is_empty()
            || !air.preprocessed_next_row_columns().is_empty()
            || air.num_periodic_columns() != 0
            || !air.periodic_columns().is_empty()
        {
            return Err(Error::UnsupportedAir);
        }
        let s = InteractionSymbolicBuilder::<Val, Challenge>::from_air(
            air,
            AirLayout::from_air::<Val>(air),
        );
        let b =
            BusSymbolicBuilder::<Val, Challenge>::from_air(air, AirLayout::from_air::<Val>(air));
        if !s.local_interactions().is_empty()
            || !s.exclusive_interactions().is_empty()
            || !s.indexed_reads().is_empty()
            || !s.indexed_tables().is_empty()
            || !s.extension_constraints().is_empty()
            || !b.interactions().is_empty()
            || !b.extension_constraints().is_empty()
        {
            return Err(Error::UnsupportedAir);
        }
        let cs = s.base_constraints();
        if cs
            .iter()
            .chain(b.base_constraints().iter())
            .any(|e| !current_expression(e, shape))
            || s.global_interactions().iter().any(|i| {
                !current_expression(&i.count, shape)
                    || i.fields.iter().any(|e| !current_expression(e, shape))
            })
        {
            return Err(Error::UnsupportedAir);
        }
        if cs.is_empty() && s.global_interactions().is_empty() {
            return Err(Error::InvalidShape);
        }
    }
    Ok(())
}

fn pcs(variables: usize, claims: usize, domains: Domains) -> Result<(Pcs, PcsSchedule), Error> {
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
    .map_err(|_| Error::Schedule)?;
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
        return Err(Error::Schedule);
    }
    let schedule = PcsSchedule {
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
        SerializingHasher::new(Sha512Leaf(domains.leaf())),
        CompressionFunctionFromHasher::new(Sha512Node(domains.node())),
        0,
    );
    Ok((
        Pcs::new(cfg, Radix2DFTSmallBatch::default(), mmcs),
        schedule,
    ))
}

/// Construct the fixed protocol from actual ordered current-only AIR dimensions.
/// This performs symbolic validation, not preparation, setup, witness generation or
/// proof verification. Symbolic evaluator preconditions remain the trusted AIR's contract.
pub fn config_for<A>(
    specs: &[AirSpec<'_, A>],
    domains: Domains,
) -> Result<(Config, ProtocolPlan), Error>
where
    A: BaseAir<Val>
        + Air<InteractionSymbolicBuilder<Val, Challenge>>
        + Air<BusSymbolicBuilder<Val, Challenge>>,
{
    let (tables, main_cells, preprocessed_cells) = dimensions(specs)?;
    let main_claims = tables
        .iter()
        .try_fold(0usize, |n, t| n.checked_add(t.main_width))
        .ok_or(Error::InvalidShape)?;
    let public_claims = tables
        .iter()
        .try_fold(0usize, |n, t| n.checked_add(t.preprocessed_width))
        .ok_or(Error::InvalidShape)?;
    let (main, main_pcs) = pcs(
        main_cells.next_power_of_two().ilog2() as usize,
        main_claims,
        domains,
    )?;
    let (public, preprocessed_pcs) = if preprocessed_cells == 0 {
        (None, None)
    } else {
        let (p, s) = pcs(
            preprocessed_cells.next_power_of_two().ilog2() as usize,
            public_claims,
            domains,
        )?;
        (Some(p), Some(s))
    };
    validate_airs(specs, &tables)?;
    let plan = ProtocolPlan {
        tables,
        main_cells,
        preprocessed_cells,
        main_pcs,
        preprocessed_pcs,
    };
    Ok((
        Config {
            main,
            public,
            domains,
            plan: plan.clone(),
        },
        plan,
    ))
}
