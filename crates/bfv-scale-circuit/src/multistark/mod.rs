//! Compact coefficient AIR with no auxiliary values in public preprocessing/PV.
#[cfg(test)]
mod tests;
use crate::{Aux, CARRIES, DEGREE, Error, Output, Request, Result, Role, codec};
use limb_range_air::{Histogram, RangeAir};
pub use limb_range_air::{Namespace, Range};
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use sha2::{Digest, Sha256};

pub const MAIN_WIDTH: usize = 160;
const EXTEND_RANGES: [Range; 5] = [Range::R16, Range::R15, Range::R14, Range::R9, Range::R2];
const SCALE_RANGES: [Range; 6] = [
    Range::R16,
    Range::R15,
    Range::R14,
    Range::R13,
    Range::R9,
    Range::R2,
];
fn ranges(role: Role) -> &'static [Range] {
    if role == Role::Extend5To10 {
        &EXTEND_RANGES
    } else {
        &SCALE_RANGES
    }
}
/// Every MAIN column has exactly one explicit range query.
pub fn column_range(role: Role, column: usize) -> Option<Range> {
    Some(match column {
        0..=10 => Range::R16,
        11 => {
            if role == Role::Extend5To10 {
                Range::R15
            } else {
                Range::R13
            }
        }
        12..=13 => Range::R16,
        14 => Range::R14,
        15..=21 => Range::R16,
        22 => Range::R15,
        23..=47 => {
            if (column - 23) % 5 == 4 {
                Range::R2
            } else {
                Range::R16
            }
        }
        48..=103 => Range::R16,
        104..=159 => Range::R9,
        _ => return None,
    })
}
pub fn profile_digest(role: Role, namespace: Namespace) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/BFV-SCALE-MAIN-LIMBS/v1");
    h.update(crate::profile_digest(role));
    h.update(namespace.as_bytes());
    h.update(b"H8192;MAIN160=v4,rv8,Wb3,re8,U25,carryLow56,carryHigh56;PP=input4n,computedOutput20;PV0;63exactResiduals;allEndpointCarries;R16/R15/R14/R13/R9/R2;noAuxWire;notZK;consumerFullRequestOutputTranscriptRequired");
    for range in ranges(role) {
        h.update((range.bits() as u64).to_le_bytes());
        h.update((range.height() as u64).to_le_bytes());
    }
    h.finalize().into()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableKind {
    Arithmetic,
    Range(Range),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableShape {
    kind: TableKind,
    height: usize,
    main: usize,
    public: usize,
    contributions: usize,
    weight: usize,
}
impl TableShape {
    pub fn kind(&self) -> TableKind {
        self.kind
    }
    pub fn height(&self) -> usize {
        self.height
    }
    pub fn main_width(&self) -> usize {
        self.main
    }
    pub fn preprocessed_width(&self) -> usize {
        self.public
    }
    pub fn lookup_contributions_per_row(&self) -> usize {
        self.contributions
    }
    pub fn lookup_count_weight_per_row(&self) -> usize {
        self.weight
    }
}
#[derive(Clone)]
pub struct ArithmeticAir {
    role: Role,
    namespace: Namespace,
    public: Option<RowMajorMatrix<Val>>,
}
/// The arithmetic payload is sealed; ranges use shared fixed-support constructors.
/// Shape is analysis-only; trusted public preparation fixes role/constants/ranges
/// and ALL input/output rows before any verifier setup.
#[derive(Clone)]
pub enum ProgramAir {
    Arithmetic(ArithmeticAir),
    Range(RangeAir),
}
impl ProgramAir {
    pub fn table_kind(&self) -> TableKind {
        match self {
            Self::Arithmetic(_) => TableKind::Arithmetic,
            Self::Range(r) => TableKind::Range(r.range()),
        }
    }
    pub fn is_prepared(&self) -> bool {
        match self {
            Self::Arithmetic(a) => a.public.is_some(),
            Self::Range(r) => r.is_prepared(),
        }
    }
    pub fn table_shape(&self) -> TableShape {
        match self {
            Self::Arithmetic(a) => TableShape {
                kind: TableKind::Arithmetic,
                height: DEGREE,
                main: MAIN_WIDTH,
                public: 4 * a.role.input_moduli().len() + 20,
                contributions: MAIN_WIDTH,
                weight: MAIN_WIDTH,
            },
            Self::Range(r) => TableShape {
                kind: TableKind::Range(r.range()),
                height: r.height(),
                main: 2,
                public: 1,
                contributions: 1,
                weight: 0,
            },
        }
    }
    pub fn height(&self) -> usize {
        self.table_shape().height
    }
}
impl BaseAir<Val> for ProgramAir {
    fn width(&self) -> usize {
        self.table_shape().main
    }
    fn preprocessed_width(&self) -> usize {
        self.table_shape().public
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        match self {
            Self::Arithmetic(a) => a.public.clone(),
            Self::Range(r) => r.preprocessed_trace(),
        }
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn num_constraints(&self) -> Option<usize> {
        Some(if matches!(self, Self::Arithmetic(_)) {
            63
        } else {
            1
        })
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(1)
    }
}
impl<AB: InteractionBuilder<F = Val>> Air<AB> for ProgramAir {
    fn eval(&self, b: &mut AB) {
        match self {
            Self::Range(r) => r.eval(b),
            Self::Arithmetic(a) => {
                let m = b.main();
                let main: Vec<AB::Expr> = (0..MAIN_WIDTH)
                    .map(|i| m.current(i).unwrap().into())
                    .collect();
                let p = b.preprocessed();
                let mut equation: Vec<AB::Expr> = (0..self.preprocessed_width())
                    .map(|i| p.current(i).unwrap().into())
                    .collect();
                equation.extend_from_slice(&main[..48]);
                for i in 0..CARRIES {
                    equation.push(
                        main[48 + i].clone() + main[104 + i].clone() * Val::from_u32(1 << 16),
                    );
                }
                crate::air_equation::enforce(b, a.role, &equation);
                for (column, value) in main.into_iter().enumerate() {
                    limb_range_air::query(
                        b,
                        a.namespace,
                        column_range(a.role, column).expect("fixed MAIN column"),
                        value,
                    );
                }
            }
        }
    }
}
#[derive(Clone)]
pub struct MachineShape {
    role: Role,
    namespace: Namespace,
    airs: Vec<ProgramAir>,
    tables: Vec<TableShape>,
}
impl MachineShape {
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn namespace(&self) -> Namespace {
        self.namespace
    }
    pub fn airs(&self) -> &[ProgramAir] {
        &self.airs
    }
    pub fn tables(&self) -> &[TableShape] {
        &self.tables
    }
    pub fn total_main_cells(&self) -> usize {
        self.tables.iter().map(|t| t.height * t.main).sum()
    }
    pub fn total_preprocessed_cells(&self) -> usize {
        self.tables.iter().map(|t| t.height * t.public).sum()
    }
    pub fn total_lookup_contributions(&self) -> usize {
        self.tables.iter().map(|t| t.height * t.contributions).sum()
    }
    pub fn total_lookup_count_weight(&self) -> usize {
        self.tables.iter().map(|t| t.height * t.weight).sum()
    }
}
/// Metadata only; does not clone coefficient vectors or allocate support tables.
pub fn shape(role: Role, namespace: Namespace) -> MachineShape {
    let mut airs = vec![ProgramAir::Arithmetic(ArithmeticAir {
        role,
        namespace,
        public: None,
    })];
    airs.extend(
        ranges(role)
            .iter()
            .map(|&r| ProgramAir::Range(RangeAir::shape(namespace, r))),
    );
    let tables = airs.iter().map(ProgramAir::table_shape).collect();
    MachineShape {
        role,
        namespace,
        airs,
        tables,
    }
}
pub struct PreparedMachine {
    request: Request,
    output: Output,
    shape: MachineShape,
    airs: Vec<ProgramAir>,
}
impl PreparedMachine {
    pub fn role(&self) -> Role {
        self.request.role()
    }
    pub fn namespace(&self) -> Namespace {
        self.shape.namespace
    }
    pub fn shape(&self) -> &MachineShape {
        &self.shape
    }
    pub fn airs(&self) -> &[ProgramAir] {
        &self.airs
    }
    pub fn arithmetic_air(&self) -> &ProgramAir {
        &self.airs[0]
    }
    /// Prover-only sealed certificate conversion. AIR range queries do not trust
    /// this range validation; a verifier never receives this Aux.
    pub fn witness(&self, aux: &Aux) -> Result<MachineWitness> {
        codec::check_binding(&self.request, &self.output, aux)?;
        let mut histogram = Histogram::new(ranges(self.role())).map_err(range_error)?;
        let mut values = Vec::with_capacity(DEGREE * MAIN_WIDTH);
        for a in &aux.rows {
            let mut row = [0u64; MAIN_WIDTH];
            put(&mut row[..4], a.v as u128);
            put(&mut row[4..12], a.remainder_v);
            put(&mut row[12..15], a.biased_w as u128);
            put(&mut row[15..23], a.remainder_e);
            for (i, &v) in a.biased_quotients.iter().enumerate() {
                put(&mut row[23 + 5 * i..28 + 5 * i], v);
            }
            for (i, &v) in a.carries.iter().enumerate() {
                row[48 + i] = u64::from(v & 65535);
                row[104 + i] = u64::from(v >> 16);
            }
            for (column, &value) in row.iter().enumerate() {
                histogram
                    .add(
                        column_range(self.role(), column).expect("fixed MAIN column"),
                        value,
                    )
                    .map_err(range_error)?;
            }
            values.extend(row.into_iter().map(Val::from_u64));
        }
        Ok(MachineWitness {
            main: RowMajorMatrix::new(values, MAIN_WIDTH),
            histogram,
        })
    }
}
pub struct MachineWitness {
    main: RowMajorMatrix<Val>,
    histogram: Histogram,
}
impl MachineWitness {
    /// For a batch, merge these histograms and include exactly one provider per
    /// (namespace,range). Never concatenate standalone providers under one bus.
    pub fn into_parts(self) -> (RowMajorMatrix<Val>, Histogram) {
        (self.main, self.histogram)
    }
    pub fn into_traces(self) -> Result<Vec<RowMajorMatrix<Val>>> {
        let mut traces = vec![self.main];
        for range in self.histogram.ranges() {
            traces.push(self.histogram.trace(range).map_err(range_error)?);
        }
        Ok(traces)
    }
}
fn range_error(e: limb_range_air::Error) -> Error {
    match e {
        limb_range_air::Error::MultiplicityOverflow => Error::Arithmetic,
        limb_range_air::Error::OutOfRange => Error::AuxiliaryRange,
        _ => Error::Shape,
    }
}
fn put(out: &mut [u64], value: u128) {
    for (i, v) in out.iter_mut().enumerate() {
        *v = ((value >> (16 * i)) & 65535) as u64;
    }
}
/// Verifier public preparation: exact codec identity, canonical residues, copy5
/// and limb splitting ONLY. No v/W/quotient/remainder/scaler evaluation.
pub fn prepare_public(
    request: &Request,
    output: &Output,
    namespace: Namespace,
) -> Result<PreparedMachine> {
    codec::check_output_binding(request, output)?;
    let shape = shape(request.role(), namespace);
    let width = shape.tables[0].public;
    let offset = if request.role() == Role::Extend5To10 {
        5 * DEGREE
    } else {
        0
    };
    let mut public = Vec::with_capacity(DEGREE * width);
    for row in 0..DEGREE {
        for i in 0..request.role().input_moduli().len() {
            append(&mut public, request.input()[i * DEGREE + row]);
        }
        for i in 0..5 {
            append(
                &mut public,
                output.coefficients()[offset + i * DEGREE + row],
            );
        }
    }
    let mut airs = vec![ProgramAir::Arithmetic(ArithmeticAir {
        role: request.role(),
        namespace,
        public: Some(RowMajorMatrix::new(public, width)),
    })];
    airs.extend(
        ranges(request.role())
            .iter()
            .map(|&r| ProgramAir::Range(RangeAir::prepare(namespace, r))),
    );
    Ok(PreparedMachine {
        request: request.clone(),
        output: output.clone(),
        shape,
        airs,
    })
}
fn append(out: &mut Vec<Val>, value: u64) {
    for i in 0..4 {
        out.push(Val::from_u16(((value >> (16 * i)) & 65535) as u16));
    }
}
