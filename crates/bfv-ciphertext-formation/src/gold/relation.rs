//! Closed internal geometry and expectation dispatch; no caller-selected AIR or verifier.
use super::{Expected, Result, Val, data, geometry::Inputs, profile_digest};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RelationKind {
    Pair,
    Data,
}
impl RelationKind {
    pub(super) fn operands(self) -> usize {
        match self {
            Self::Pair => 2,
            Self::Data => 1,
        }
    }
    pub(super) fn products(self) -> usize {
        2 * self.operands()
    }
    pub(super) fn vectors(self) -> usize {
        13 + 13 * self.products()
    }
    pub(super) fn graph_rows(self) -> usize {
        (24576 + self.products() * (4096 + 24576)) / 32
    }
    pub(super) fn range_first(self) -> usize {
        match self {
            Self::Pair => super::program::RANGE_FIRST,
            Self::Data => self.graph_rows(),
        }
    }
    pub(super) fn cw_first(self, operand: usize) -> usize {
        match self {
            Self::Pair => match operand {
                0 => super::program::SOURCE_FIRST,
                1 => super::program::MASK_FIRST,
                _ => super::program::CS_FIRST,
            },
            Self::Data => self.range_first() + 2048 + 514 * operand,
        }
    }
    pub(super) fn cs_first(self) -> usize {
        match self {
            Self::Pair => super::program::CS_FIRST,
            Self::Data => self.cw_first(self.operands()),
        }
    }
    pub(super) fn padding_first(self) -> usize {
        match self {
            Self::Pair => super::program::PADDING_FIRST,
            Self::Data => self.cs_first() + 66,
        }
    }
    pub(super) fn public_values(self) -> usize {
        match self {
            Self::Pair => super::program::PUBLIC_VALUES,
            Self::Data => 32,
        }
    }
    pub(super) fn w_tag(self, operand: usize) -> usize {
        self.vectors() + operand
    }
    pub(super) fn cs_tag(self) -> usize {
        self.w_tag(self.operands())
    }
    pub(super) fn final_vector(self, job: usize) -> usize {
        13 + self.products() + 12 * job + 11
    }
    pub(super) fn range(self) -> RangeLayout {
        let e = 1;
        let k = e + self.operands();
        let w = k + self.products();
        let product = w + self.operands();
        let inverse = product + self.products();
        RangeLayout {
            e,
            k,
            w,
            product,
            inverse,
            stride: inverse + self.products(),
            bits: 12 * (1 + self.operands()) + 20 * self.products() + 34 * self.operands(),
        }
    }
    pub(super) fn profile(self) -> [u8; 32] {
        match self {
            Self::Pair => profile_digest(),
            Self::Data => data::profile_digest(),
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct RangeLayout {
    pub(super) e: usize,
    pub(super) k: usize,
    pub(super) w: usize,
    pub(super) product: usize,
    pub(super) inverse: usize,
    pub(super) stride: usize,
    pub(super) bits: usize,
}
#[derive(Clone, Copy)]
pub(super) enum ExpectedRef<'a> {
    Pair(&'a Expected),
    Data(&'a data::Expected),
}
impl<'a> ExpectedRef<'a> {
    pub(super) fn kind(self) -> RelationKind {
        match self {
            Self::Pair(_) => RelationKind::Pair,
            Self::Data(_) => RelationKind::Data,
        }
    }
    pub(super) fn binding(self) -> [u8; 64] {
        match self {
            Self::Pair(e) => e.binding(),
            Self::Data(e) => e.binding(),
        }
    }
    pub(super) fn values(self) -> &'a [Val] {
        match self {
            Self::Pair(e) => e.values(),
            Self::Data(e) => e.values(),
        }
    }
    pub(super) fn input(self, component: usize) -> &'a [Vec<u64>] {
        match self {
            Self::Pair(e) => e.request().input(component),
            Self::Data(e) => e.request().input(component),
        }
    }
    pub(super) fn context(self, index: usize) -> [Val; 8] {
        match self {
            Self::Pair(e) => e.contexts()[index],
            Self::Data(e) => e.contexts()[index],
        }
    }
    pub(super) fn root(self, index: usize) -> [Val; 4] {
        match self {
            Self::Pair(e) => e.roots()[index],
            Self::Data(e) => e.roots()[index],
        }
    }
    pub(super) fn inputs(self) -> Result<Inputs<'a>> {
        match self {
            Self::Pair(e) => Inputs::new(e.request()),
            Self::Data(e) => Inputs::data(e.request()),
        }
    }
    pub(super) fn captured(self) -> CapturedExpected {
        match self {
            Self::Pair(e) => CapturedExpected::Pair(e.clone()),
            Self::Data(e) => CapturedExpected::Data(e.clone()),
        }
    }
}
pub(super) enum CapturedExpected {
    Pair(Expected),
    Data(data::Expected),
}
impl CapturedExpected {
    pub(super) fn require_same(&self, expected: ExpectedRef<'_>) -> Result<()> {
        match (self, expected) {
            (Self::Pair(a), ExpectedRef::Pair(b)) => a.require_same(b),
            (Self::Data(a), ExpectedRef::Data(b)) => a.require_same(b),
            _ => Err(super::Error::Binding),
        }
    }
}
