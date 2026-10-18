//! Union construction delegates every arithmetic equation to its owning Core AIR.
use crate::{Error, Expected, RelationOutput, RelationRequest, statement};
pub(crate) use bfv_multilinear_stark::Val;
use bfv_scale_circuit::multistark as scale;
use bfv_tensor_circuit::multistark as tensor;
use limb_range_air::{Histogram, Range, RangeAir};
use p3_air::{Air, BaseAir};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
pub(crate) const RANGES: [Range; 6] = [
    Range::R2,
    Range::R9,
    Range::R13,
    Range::R14,
    Range::R15,
    Range::R16,
];
const EXTEND_RANGES: [Range; 5] = [Range::R2, Range::R9, Range::R14, Range::R15, Range::R16];
const TENSOR_RANGES: [Range; 2] = [Range::R9, Range::R16];
pub(crate) fn ranges(ordinal: usize) -> Result<&'static [Range], Error> {
    match ordinal {
        0 => Ok(&EXTEND_RANGES),
        1 => Ok(&TENSOR_RANGES),
        2 => Ok(&RANGES),
        _ => Err(Error::Statement),
    }
}
#[derive(Clone)]
pub(crate) enum ProgramAir {
    Scale(scale::ProgramAir),
    Tensor(tensor::ProgramAir),
    Range(RangeAir),
}
impl ProgramAir {
    pub fn height(&self) -> usize {
        match self {
            Self::Scale(a) => a.height(),
            Self::Tensor(a) => a.height(),
            Self::Range(a) => a.height(),
        }
    }
    pub fn prepared(&self) -> bool {
        match self {
            Self::Scale(a) => a.is_prepared(),
            Self::Tensor(a) => a.is_prepared(),
            Self::Range(a) => a.is_prepared(),
        }
    }
}
impl BaseAir<Val> for ProgramAir {
    fn width(&self) -> usize {
        match self {
            Self::Scale(a) => a.width(),
            Self::Tensor(a) => a.width(),
            Self::Range(a) => a.width(),
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Scale(a) => a.preprocessed_width(),
            Self::Tensor(a) => a.preprocessed_width(),
            Self::Range(a) => a.preprocessed_width(),
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        match self {
            Self::Scale(a) => a.preprocessed_trace(),
            Self::Tensor(a) => a.preprocessed_trace(),
            Self::Range(a) => a.preprocessed_trace(),
        }
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_constraints(&self) -> Option<usize> {
        match self {
            Self::Scale(a) => a.num_constraints(),
            Self::Tensor(a) => a.num_constraints(),
            Self::Range(a) => a.num_constraints(),
        }
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Scale(a) => a.max_constraint_degree(),
            Self::Tensor(a) => a.max_constraint_degree(),
            Self::Range(a) => a.max_constraint_degree(),
        }
    }
}
impl<AB: InteractionBuilder<F = Val>> Air<AB> for ProgramAir {
    fn eval(&self, b: &mut AB) {
        match self {
            Self::Scale(a) => a.eval(b),
            Self::Tensor(a) => a.eval(b),
            Self::Range(a) => a.eval(b),
        }
    }
}
enum Prepared {
    Scale(scale::PreparedMachine),
    Tensor(tensor::PreparedMachine),
}
pub(crate) enum Aux {
    Scale(bfv_scale_circuit::Aux),
    Tensor(bfv_tensor_circuit::Aux),
}
pub(crate) struct Machine {
    pub airs: Vec<ProgramAir>,
    prepared: Vec<Prepared>,
    ranges: &'static [Range],
}
impl Machine {
    pub fn new(expected: &Expected, ordinal: usize) -> Result<Self, Error> {
        let range = statement::component_range(ordinal)?;
        let ranges = ranges(ordinal)?;
        let namespace = statement::namespace(expected.context(), ordinal);
        let mut prepared = Vec::with_capacity(range.len());
        let mut airs = Vec::with_capacity(range.len() + ranges.len());
        for (r, o) in expected.requests()[range.clone()]
            .iter()
            .zip(&expected.outputs()[range])
        {
            match (r, o) {
                (RelationRequest::Scale(r), RelationOutput::Scale(o)) => {
                    let p = scale::prepare_public(r, o, namespace).map_err(|_| Error::Statement)?;
                    airs.push(ProgramAir::Scale(p.arithmetic_air().clone()));
                    prepared.push(Prepared::Scale(p));
                }
                (RelationRequest::Tensor(r), RelationOutput::Tensor(o)) => {
                    let p =
                        tensor::prepare_public(r, o, namespace).map_err(|_| Error::Statement)?;
                    airs.push(ProgramAir::Tensor(p.arithmetic_air().clone()));
                    prepared.push(Prepared::Tensor(p));
                }
                _ => return Err(Error::Statement),
            }
        }
        airs.extend(
            ranges
                .iter()
                .map(|&r| ProgramAir::Range(RangeAir::prepare(namespace, r))),
        );
        Ok(Self {
            airs,
            prepared,
            ranges,
        })
    }
    pub fn witness(&self, aux: &[Aux]) -> Result<Vec<RowMajorMatrix<Val>>, Error> {
        if aux.len() != self.prepared.len() {
            return Err(Error::Statement);
        }
        let mut histogram = Histogram::new(self.ranges).map_err(|_| Error::Statement)?;
        let mut traces = Vec::with_capacity(self.airs.len());
        for (p, a) in self.prepared.iter().zip(aux) {
            let (main, counts) = match (p, a) {
                (Prepared::Scale(p), Aux::Scale(a)) => {
                    p.witness(a).map_err(|_| Error::Statement)?.into_parts()
                }
                (Prepared::Tensor(p), Aux::Tensor(a)) => {
                    p.witness(a).map_err(|_| Error::Statement)?.into_parts()
                }
                _ => return Err(Error::Statement),
            };
            histogram.merge(&counts).map_err(|_| Error::Statement)?;
            traces.push(main);
        }
        for &range in self.ranges {
            traces.push(histogram.trace(range).map_err(|_| Error::Statement)?);
        }
        Ok(traces)
    }
}
