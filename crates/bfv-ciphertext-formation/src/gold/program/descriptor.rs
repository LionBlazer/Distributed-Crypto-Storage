use super::super::{Expected, Val, geometry::Inputs, graph};
use super::*;
use std::sync::Arc;
pub(super) struct Descriptor {
    pub(super) graph: graph::Plan,
    pub(super) c0: [Vec<u64>; 4],
    pub(super) contexts: [[Val; 8]; 3],
    pub(super) roots: [[Val; 4]; 3],
    pub(super) values: Vec<Val>,
}
impl Descriptor {
    pub(super) fn new(expected: Expected) -> Result<Self> {
        let request = expected.request();
        Ok(Self {
            graph: graph::Plan::new(Inputs::new(request)?)?,
            c0: core::array::from_fn(|j| request.input(2 * (j / 2))[j % 2].clone()),
            contexts: expected.contexts(),
            roots: expected.roots(),
            values: expected.values().to_vec(),
        })
    }
    pub(super) fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}
