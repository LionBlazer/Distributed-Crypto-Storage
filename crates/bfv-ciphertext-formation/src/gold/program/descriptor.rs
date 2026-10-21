use super::super::{
    Val, graph,
    relation::{ExpectedRef, RelationKind},
};
use super::*;
use std::sync::Arc;
pub(super) struct Descriptor {
    pub(super) graph: graph::Plan,
    pub(super) kind: RelationKind,
    pub(super) c0: Vec<Vec<u64>>,
    pub(super) contexts: Vec<[Val; 8]>,
    pub(super) roots: Vec<[Val; 4]>,
    pub(super) values: Vec<Val>,
}
impl Descriptor {
    pub(super) fn new(expected: ExpectedRef<'_>) -> Result<Self> {
        let kind = expected.kind();
        Ok(Self {
            graph: graph::Plan::new(expected.inputs()?)?,
            kind,
            c0: (0..kind.products())
                .map(|j| expected.input(2 * (j / 2))[j % 2].clone())
                .collect(),
            contexts: (0..=kind.operands()).map(|i| expected.context(i)).collect(),
            roots: (0..=kind.operands()).map(|i| expected.root(i)).collect(),
            values: expected.values().to_vec(),
        })
    }
    pub(super) fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}
