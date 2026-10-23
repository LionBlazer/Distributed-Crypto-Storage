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
pub(in crate::gold) fn transcript_manifest(
    expected: &Expected,
) -> Result<bfv_hiding_stark::transcript::ArgumentManifest> {
    let air = air::MetadataAir::new(expected)?;
    let report = assessment::assess(&air)?;
    report.require_resources()?;
    report.transcript_manifest(&air)
}
pub(in crate::gold) fn wire_profile() -> [u8; 32] {
    native_wire::profile()
}
/// Metadata diagnostics only; no native setup, proof or admission is created.
pub(in crate::gold) fn classical_bound(
    expected: &Expected,
) -> Result<bfv_hiding_stark::classical::AlgebraicBound> {
    let air = air::MetadataAir::new(expected)?;
    let report = assessment::assess(&air)?;
    report.require_resources()?;
    report.classical_bound()
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

#[cfg(test)]
mod ordered_constraint_tests {
    fn metadata() -> super::Expected {
        super::tests::metadata()
    }
    fn clear_first_statement_count(pp: &mut [bfv_hiding_stark::Challenge]) {
        pp[super::layout::STMT_LOOKUP] =
            <bfv_hiding_stark::Challenge as p3_field::PrimeCharacteristicRing>::ZERO;
    }
    include!("../ordered_constraint_tests.rs");
}
