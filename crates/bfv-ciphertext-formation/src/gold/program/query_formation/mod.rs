//! Fixed fused query backend; public mathematical contracts live in gold::query.
mod air;
mod layout;
mod plan;
#[cfg(test)]
mod projection_tests;
mod receiving;
#[cfg(test)]
mod tests;
use super::{descriptor::Descriptor, pp as old_pp};
#[cfg(test)]
use crate::gold::data;
#[cfg(test)]
use crate::gold::query::{profile_digest as profile, statement_root};
use crate::gold::{
    Error, Result, Val, graph,
    query::{Expected, Prepared},
    relation::{ExpectedRef, RelationKind},
};
use layout::*;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
#[cfg(test)]
use sha2::{Digest, Sha256};
super::dense_backend::instantiate_fixed_dense_backend!();
pub(in crate::gold) use layout::DOMAIN;
pub(in crate::gold) use native::{produce, receive};
pub(in crate::gold) use native_wire::MAX_FRAME_BYTES;
pub(in crate::gold) use receiving::ReceivingSetup;
pub(in crate::gold) fn wire_profile() -> [u8; 32] {
    native_wire::profile()
}
pub(in crate::gold) const WRITER_LAYOUT: [usize; 10] = [
    H,
    W,
    GRAPH_ROWS,
    CW_FIRST,
    CS_FIRST,
    RANGE_VALUES,
    BITS,
    CHECKPOINT,
    ACCUMULATOR,
    SLOTS,
];
