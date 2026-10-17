//! Main-witness semantic AIRs. Consumers own the actual multi-STARK proof and transcript.
mod air;
#[cfg(test)]
mod tests;
mod witness;

use crate::{Aux, Basis, DEGREE, Direction, Output, Request, Result, codec, parameters::lane};
pub use air::{InputOutputAir, ProgramAir, RangeAir, StageAir};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_matrix::dense::RowMajorMatrix;

/// Fixed relation/layout descriptor, not a proof profile or acceptance capability.
pub const MACHINE_DESCRIPTOR: &[u8] = b"DCS/BFV-NTT-MAIN-WITNESS/v1/full8192/old-native-positiveweights/stage35/PP11/IO1PP9/R16R14R9R2/copy-index-all4limbs/8digits-end0/zdelta62/U66/carry16+9/range17,2,7,1/PV0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeKind {
    R16,
    R14,
    R9,
    R2,
}
impl RangeKind {
    pub const fn height(self) -> usize {
        match self {
            Self::R16 => 65536,
            Self::R14 => 16384,
            Self::R9 => 512,
            Self::R2 => 16,
        }
    }
    pub const fn domain_size(self) -> usize {
        match self {
            Self::R16 => 65536,
            Self::R14 => 16384,
            Self::R9 => 512,
            Self::R2 => 4,
        }
    }
    pub(super) const fn index(self) -> usize {
        match self {
            Self::R16 => 0,
            Self::R14 => 1,
            Self::R9 => 2,
            Self::R2 => 3,
        }
    }
    pub(super) const fn bus(self) -> &'static str {
        match self {
            Self::R16 => "dcs/bfv-ntt-witness/range/16",
            Self::R14 => "dcs/bfv-ntt-witness/range/14",
            Self::R9 => "dcs/bfv-ntt-witness/range/9",
            Self::R2 => "dcs/bfv-ntt-witness/range/2",
        }
    }
}
pub(super) const RANGES: [RangeKind; 4] =
    [RangeKind::R16, RangeKind::R14, RangeKind::R9, RangeKind::R2];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableKind {
    Stage(usize),
    Io,
    Range(RangeKind),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableShape {
    kind: TableKind,
    height: usize,
    main: usize,
    public: usize,
    interactions: usize,
    count_weight: usize,
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
        self.interactions
    }
    pub fn lookup_count_weight_per_row(&self) -> usize {
        self.count_weight
    }
}
/// Complete ordered metadata only; contains no trace or public preprocessing matrix.
#[derive(Clone)]
pub struct MachineShape {
    direction: Direction,
    basis: Basis,
    tables: Vec<TableShape>,
    airs: Vec<ProgramAir>,
}
impl MachineShape {
    pub fn direction(&self) -> Direction {
        self.direction
    }
    pub fn basis(&self) -> Basis {
        self.basis
    }
    pub fn tables(&self) -> &[TableShape] {
        &self.tables
    }
    pub fn airs(&self) -> &[ProgramAir] {
        &self.airs
    }
    pub fn total_main_cells(&self) -> usize {
        self.tables.iter().map(|t| t.height * t.main).sum()
    }
    pub fn total_preprocessed_cells(&self) -> usize {
        self.tables.iter().map(|t| t.height * t.public).sum()
    }
    pub fn total_lookup_contributions(&self) -> usize {
        self.tables.iter().map(|t| t.height * t.interactions).sum()
    }
    pub fn total_lookup_count_weight(&self) -> usize {
        self.tables.iter().map(|t| t.height * t.count_weight).sum()
    }
}
pub fn shape(direction: Direction, basis: Basis) -> MachineShape {
    let mut airs = Vec::with_capacity(direction.stages() + 5);
    for stage in 0..direction.stages() {
        airs.push(ProgramAir::stage(direction, basis, stage));
    }
    airs.push(ProgramAir::io(direction));
    for range in RANGES {
        airs.push(ProgramAir::range(range));
    }
    let tables = airs.iter().map(ProgramAir::table_shape).collect();
    MachineShape {
        direction,
        basis,
        tables,
        airs,
    }
}
/// Independently prepared verifier statement; no auxiliary/NTT evaluation is involved.
pub struct PreparedMachine {
    request: Request,
    output: Output,
    shape: MachineShape,
    airs: Vec<ProgramAir>,
}
impl PreparedMachine {
    pub fn direction(&self) -> Direction {
        self.request.direction()
    }
    pub fn basis(&self) -> Basis {
        self.request.basis()
    }
    pub fn shape(&self) -> &MachineShape {
        &self.shape
    }
    pub fn airs(&self) -> &[ProgramAir] {
        &self.airs
    }
    /// Prover-only layout conversion from an old canonical Aux, not proof verification.
    pub fn witness(&self, aux: &Aux) -> Result<Vec<RowMajorMatrix<Val>>> {
        witness::build(self, aux)
    }
}
fn limbs(out: &mut Vec<Val>, value: u64) {
    out.extend(crate::math::digits(value as u128, 4).map(Val::from_u16));
}
pub fn prepare_public(request: &Request, output: &Output) -> Result<PreparedMachine> {
    codec::check_output_binding(request, output)?;
    let shape = shape(request.direction(), request.basis());
    let mut airs = shape.airs.clone();
    for air in &mut airs {
        let meta = air.table_shape();
        let mut values = Vec::with_capacity(meta.height * meta.public);
        match air.table_kind() {
            TableKind::Stage(stage) => {
                for j in 0..DEGREE {
                    let l = lane(request.direction(), request.basis(), stage, j);
                    values.extend([
                        Val::from_usize(j),
                        Val::from_usize(l.x),
                        Val::from_usize(l.y),
                    ]);
                    limbs(&mut values, l.a);
                    limbs(&mut values, l.b);
                }
            }
            TableKind::Io => {
                for j in 0..DEGREE {
                    values.push(Val::from_usize(j));
                    limbs(&mut values, request.input()[j]);
                    limbs(&mut values, output.coefficients()[j]);
                }
            }
            TableKind::Range(range) => {
                for j in 0..range.height() {
                    values.push(Val::from_usize(j % range.domain_size()));
                }
            }
        }
        air.set_public(RowMajorMatrix::new(values, meta.public));
    }
    Ok(PreparedMachine {
        request: request.clone(),
        output: output.clone(),
        shape,
        airs,
    })
}
