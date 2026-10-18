//! Full tensor limb equations with compact range-constrained MAIN certificates.
#[cfg(test)]
mod tests;
use crate::{Aux, Basis, CARRIES, DEGREE, Error, Output, Request, Result, codec};
use limb_range_air::{Histogram, RangeAir};
pub use limb_range_air::{Namespace, Range};
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use sha2::{Digest, Sha256};

pub const MAIN_WIDTH: usize = 54;
pub const PUBLIC_WIDTH: usize = 28;
const RANGES: [Range; 2] = [Range::R16, Range::R9];
pub fn column_range(column: usize) -> Option<Range> {
    match column {
        0..=32 => Some(Range::R16),
        33..=53 => Some(Range::R9),
        _ => None,
    }
}
pub fn profile_digest(basis: Basis, namespace: Namespace) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/BFV-TENSOR-MAIN-LIMBS/v1");
    h.update(crate::profile_digest(basis));
    h.update(namespace.as_bytes());
    h.update(b"H8192;MAIN54=quotient12,carryLow21,carryHigh21;PP28=input16,output12;PV0;24exactResiduals;eightDigits;allEndpointCarries;quotientUnsigned64FullProductImpliesOriginalBounds;R16/R9;noAuxWire;notZK;consumerFullRequestOutputTranscriptRequired");
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
    basis: Basis,
    namespace: Namespace,
    public: Option<RowMajorMatrix<Val>>,
}
/// The arithmetic payload is sealed; range payloads use the shared fixed-support
/// constructors. Trusted preparation fixes a basis and complete canonical public
/// vectors. A program is never proof authority.
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
            Self::Arithmetic(_) => TableShape {
                kind: TableKind::Arithmetic,
                height: DEGREE,
                main: MAIN_WIDTH,
                public: PUBLIC_WIDTH,
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
            24
        } else {
            1
        })
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(if matches!(self, Self::Arithmetic(_)) {
            2
        } else {
            1
        })
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
                let mut equation: Vec<AB::Expr> = (0..PUBLIC_WIDTH)
                    .map(|i| p.current(i).unwrap().into())
                    .collect();
                equation.extend_from_slice(&main[..12]);
                for i in 0..3 * CARRIES {
                    equation
                        .push(main[12 + i].clone() + main[33 + i].clone() * Val::from_u32(1 << 16));
                }
                crate::air_equation::enforce(b, a.basis, &equation);
                for (column, value) in main.into_iter().enumerate() {
                    limb_range_air::query(
                        b,
                        a.namespace,
                        column_range(column).expect("fixed MAIN column"),
                        value,
                    );
                }
            }
        }
    }
}
#[derive(Clone)]
pub struct MachineShape {
    basis: Basis,
    namespace: Namespace,
    airs: Vec<ProgramAir>,
    tables: Vec<TableShape>,
}
impl MachineShape {
    pub fn basis(&self) -> Basis {
        self.basis
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
/// Metadata only; no coefficients or fixed support matrices are allocated.
pub fn shape(basis: Basis, namespace: Namespace) -> MachineShape {
    let mut airs = vec![ProgramAir::Arithmetic(ArithmeticAir {
        basis,
        namespace,
        public: None,
    })];
    airs.extend(
        RANGES
            .iter()
            .map(|&r| ProgramAir::Range(RangeAir::shape(namespace, r))),
    );
    let tables = airs.iter().map(ProgramAir::table_shape).collect();
    MachineShape {
        basis,
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
    pub fn basis(&self) -> Basis {
        self.request.basis()
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
    /// Prover-only sealed conversion; verifier soundness still requires the
    /// emitted range LogUp and all local equations, not this host validation.
    pub fn witness(&self, aux: &Aux) -> Result<MachineWitness> {
        codec::check_binding(&self.request, &self.output, aux)?;
        let mut histogram = Histogram::new(&RANGES).map_err(range_error)?;
        let mut values = Vec::with_capacity(DEGREE * MAIN_WIDTH);
        for a in &aux.rows {
            let mut row = [0u64; MAIN_WIDTH];
            for (component, &q) in a.quotients.iter().enumerate() {
                put(&mut row[4 * component..4 * component + 4], q);
            }
            for (component, chain) in a.carries.iter().enumerate() {
                for (i, &carry) in chain.iter().enumerate() {
                    row[12 + 7 * component + i] = u64::from(carry & 65535);
                    row[33 + 7 * component + i] = u64::from(carry >> 16);
                }
            }
            for (column, &value) in row.iter().enumerate() {
                histogram
                    .add(column_range(column).expect("fixed MAIN column"), value)
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
    pub fn into_parts(self) -> (RowMajorMatrix<Val>, Histogram) {
        (self.main, self.histogram)
    }
    /// Standalone tables only. Batch consumers merge histograms and include each
    /// shared(namespace,range) provider once, rather than concatenate providers.
    pub fn into_traces(self) -> Result<Vec<RowMajorMatrix<Val>>> {
        let mut out = vec![self.main];
        for range in self.histogram.ranges() {
            out.push(self.histogram.trace(range).map_err(range_error)?);
        }
        Ok(out)
    }
}
fn range_error(e: limb_range_air::Error) -> Error {
    match e {
        limb_range_air::Error::MultiplicityOverflow => Error::Arithmetic,
        limb_range_air::Error::OutOfRange => Error::AuxiliaryRange,
        _ => Error::Shape,
    }
}
fn put(out: &mut [u64], value: u64) {
    for (i, v) in out.iter_mut().enumerate() {
        *v = (value >> (16 * i)) & 65535;
    }
}
/// Canonical public codec/hash/limb splitting only; no tensor multiplication,
/// division, quotient or auxiliary evaluation. PV0 requires the consumer's full
/// trusted Request/Output/namespace/profile transcript before real verification.
pub fn prepare_public(
    request: &Request,
    output: &Output,
    namespace: Namespace,
) -> Result<PreparedMachine> {
    codec::check_output_binding(request, output)?;
    let shape = shape(request.basis(), namespace);
    let mut public = Vec::with_capacity(DEGREE * PUBLIC_WIDTH);
    for row in 0..DEGREE {
        for i in 0..4 {
            append(&mut public, request.input()[i * DEGREE + row]);
        }
        for i in 0..3 {
            append(&mut public, output.coefficients()[i * DEGREE + row]);
        }
    }
    let mut airs = vec![ProgramAir::Arithmetic(ArithmeticAir {
        basis: request.basis(),
        namespace,
        public: Some(RowMajorMatrix::new(public, PUBLIC_WIDTH)),
    })];
    airs.extend(
        RANGES
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
