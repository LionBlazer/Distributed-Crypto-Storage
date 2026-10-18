//! Fixed semantic tables and complete global copy/range interactions.
use super::{RangeKind, TableKind, TableShape};
use crate::{Basis, DEGREE, Direction};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks as Val;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

fn data_bus(index: usize) -> String {
    format!("dcs/bfv-ntt-witness/data/{index}")
}
#[derive(Clone)]
pub struct StageAir {
    direction: Direction,
    basis: Basis,
    index: usize,
    input_bus: String,
    output_bus: String,
    public: Option<RowMajorMatrix<Val>>,
}
impl StageAir {
    fn normalization(&self) -> bool {
        self.direction == Direction::Inverse && self.index == 13
    }
    fn output_count(&self) -> usize {
        if self.index + 1 == self.direction.stages()
            || (self.direction == Direction::Inverse && self.index == 12)
        {
            1
        } else {
            2
        }
    }
}
#[derive(Clone)]
pub struct InputOutputAir {
    stages: usize,
    input_bus: String,
    output_bus: String,
    public: Option<RowMajorMatrix<Val>>,
}
#[derive(Clone)]
pub struct RangeAir {
    range: RangeKind,
    public: Option<RowMajorMatrix<Val>>,
}
/// Payload fields/constructors are private; only a complete fixed machine mints tables.
#[derive(Clone)]
pub enum ProgramAir {
    Stage(StageAir),
    Io(InputOutputAir),
    Range(RangeAir),
}
impl ProgramAir {
    pub(super) fn stage(direction: Direction, basis: Basis, index: usize) -> Self {
        debug_assert!(index < direction.stages());
        Self::Stage(StageAir {
            direction,
            basis,
            index,
            input_bus: data_bus(index),
            output_bus: data_bus(index + 1),
            public: None,
        })
    }
    pub(super) fn io(direction: Direction) -> Self {
        Self::Io(InputOutputAir {
            stages: direction.stages(),
            input_bus: data_bus(0),
            output_bus: data_bus(direction.stages()),
            public: None,
        })
    }
    pub(super) fn range(range: RangeKind) -> Self {
        Self::Range(RangeAir {
            range,
            public: None,
        })
    }
    // Only the sealed complete batch constructor can select an instance namespace.
    pub(super) fn in_batch(mut self, instance: usize) -> Self {
        let bus = |stage| format!("dcs/bfv-ntt-witness/batch/{instance}/data/{stage}");
        match &mut self {
            Self::Stage(s) => {
                s.input_bus = bus(s.index);
                s.output_bus = bus(s.index + 1);
            }
            Self::Io(i) => {
                i.input_bus = bus(0);
                i.output_bus = bus(i.stages);
            }
            Self::Range(_) => {}
        }
        self
    }
    pub fn table_kind(&self) -> TableKind {
        match self {
            Self::Stage(s) => TableKind::Stage(s.index),
            Self::Io(_) => TableKind::Io,
            Self::Range(r) => TableKind::Range(r.range),
        }
    }
    pub fn height(&self) -> usize {
        match self {
            Self::Range(r) => r.range.height(),
            _ => DEGREE,
        }
    }
    pub fn is_prepared(&self) -> bool {
        self.public().is_some()
    }
    fn public(&self) -> &Option<RowMajorMatrix<Val>> {
        match self {
            Self::Stage(s) => &s.public,
            Self::Io(i) => &i.public,
            Self::Range(r) => &r.public,
        }
    }
    pub(super) fn set_public(&mut self, matrix: RowMajorMatrix<Val>) {
        match self {
            Self::Stage(s) => s.public = Some(matrix),
            Self::Io(i) => i.public = Some(matrix),
            Self::Range(r) => r.public = Some(matrix),
        }
    }
    pub fn table_shape(&self) -> TableShape {
        let (main, public, interactions, count_weight) = match self {
            Self::Stage(s) => (
                35,
                11,
                if s.normalization() { 29 } else { 30 },
                27 + (if s.normalization() { 1 } else { 2 }) + s.output_count(),
            ),
            Self::Io(_) => (1, 9, 2, 3),
            Self::Range(_) => (2, 1, 1, 0),
        };
        TableShape {
            kind: self.table_kind(),
            height: self.height(),
            main,
            public,
            interactions,
            count_weight,
        }
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
        self.public().clone()
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
        Some(match self {
            Self::Stage(s) => {
                if s.normalization() {
                    13
                } else {
                    9
                }
            }
            _ => 1,
        })
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(if matches!(self, Self::Stage(_)) { 2 } else { 1 })
    }
}
fn key<E: Clone>(index: E, limbs: &[E]) -> Vec<E> {
    core::iter::once(index)
        .chain(limbs.iter().cloned())
        .collect()
}
fn integer<AB: AirBuilder<F = Val>>(limbs: &[AB::Expr]) -> AB::Expr {
    limbs
        .iter()
        .enumerate()
        .fold(AB::Expr::ZERO, |value, (i, limb)| {
            value + limb.clone() * Val::from_u64(1u64 << (16 * i))
        })
}
pub(super) const R16_COLUMNS: [usize; 17] = [
    8, 9, 10, 12, 13, 14, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27,
];
pub(super) const R14_COLUMNS: [usize; 2] = [11, 15];
pub(super) const R9_COLUMNS: [usize; 7] = [28, 29, 30, 31, 32, 33, 34];
pub(super) const R2_COLUMNS: [usize; 1] = [20];
impl<AB: InteractionBuilder<F = Val>> Air<AB> for ProgramAir {
    fn eval(&self, builder: &mut AB) {
        let main: Vec<AB::Expr> = {
            let m = builder.main();
            (0..self.width())
                .map(|i| m.current(i).unwrap().into())
                .collect()
        };
        let public: Vec<AB::Expr> = {
            let p = builder.preprocessed();
            (0..self.preprocessed_width())
                .map(|i| p.current(i).unwrap().into())
                .collect()
        };
        match self {
            Self::Stage(s) => {
                // Same private kernel and same32 expression ordering as the old PP AIR.
                let mut equation: Vec<AB::Expr> = Vec::with_capacity(32);
                equation.extend_from_slice(&main[..12]);
                equation.extend_from_slice(&public[3..11]);
                equation.extend_from_slice(&main[16..21]);
                for i in 0..7 {
                    equation
                        .push(main[21 + i].clone() + main[28 + i].clone() * Val::from_u64(1 << 16));
                }
                let modulus_digits = crate::air_equation::modulus_digits::<AB>(s.basis);
                crate::air_equation::enforce(builder, &modulus_digits, &equation);
                // Both operands are<2^62 via the range buses, so this sum<2^63<Gold.
                builder.assert_zero(
                    integer::<AB>(&main[8..12]) + integer::<AB>(&main[12..16])
                        - Val::from_u64(s.basis.modulus() - 1),
                );
                if s.normalization() {
                    for y in &main[4..8] {
                        builder.assert_zero(y.clone());
                    }
                }
                builder.push_interaction(&s.input_bus, key(public[1].clone(), &main[..4]), 1);
                if !s.normalization() {
                    builder.push_interaction(&s.input_bus, key(public[2].clone(), &main[4..8]), 1);
                }
                builder.push_interaction(
                    &s.output_bus,
                    key(public[0].clone(), &main[8..12]),
                    -(s.output_count() as i32),
                );
                for (range, columns) in [
                    (RangeKind::R16, &R16_COLUMNS[..]),
                    (RangeKind::R14, &R14_COLUMNS[..]),
                    (RangeKind::R9, &R9_COLUMNS[..]),
                    (RangeKind::R2, &R2_COLUMNS[..]),
                ] {
                    for &column in columns {
                        builder.push_interaction(range.bus(), [main[column].clone()], 1);
                    }
                }
            }
            Self::Io(i) => {
                builder.assert_zero(main[0].clone());
                builder.push_interaction(&i.input_bus, key(public[0].clone(), &public[1..5]), -2);
                builder.push_interaction(&i.output_bus, key(public[0].clone(), &public[5..9]), 1);
            }
            Self::Range(r) => {
                builder.assert_zero(main[0].clone() - public[0].clone());
                // The provided table frequency is deliberately excluded from query weights.
                builder.push_interaction(
                    r.range.bus(),
                    [main[0].clone()],
                    Count::provided(-main[1].clone()),
                );
            }
        }
    }
}
