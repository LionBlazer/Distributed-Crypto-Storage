//! Internal complete dense DATA packing and native proof backend. No SQL admission.
mod air;
mod layout;
mod plan;
#[cfg(test)]
mod snapshot;
#[cfg(test)]
mod tests;
use super::super::{
    Error, Result, Val, data, graph,
    relation::{ExpectedRef, RelationKind},
};
use super::{descriptor::Descriptor, pp as old_pp};
use data::{Expected, Prepared};
use layout::*;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
#[cfg(test)]
use sha2::{Digest, Sha256};

/// Canonical PUBLIC metadata fixture only; not an encryption or proof witness.
#[cfg(test)]
fn expected() -> Result<data::Expected> {
    let request =
        data::Request::checked([0xc7; 32], super::super::tests::pair_snapshot_ciphertext(0))?;
    data::Expected::checked(
        request,
        [0xd7; 64],
        [[Val::from_u8(9); 8], [Val::from_u8(10); 8]],
        [[Val::from_u8(11); 4], [Val::from_u8(12); 4]],
    )
}
#[cfg(test)]
fn hash_word(hash: &mut Sha256, value: usize) {
    hash.update((value as u64).to_le_bytes())
}
#[cfg(test)]
fn hex(bytes: impl AsRef<[u8]>) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    for byte in bytes.as_ref() {
        write!(&mut out, "{byte:02x}").unwrap()
    }
    out
}

// Fixed backend for the explicit data::prove_dense/verify_dense mathematical facade.
super::dense_backend::instantiate_fixed_dense_backend!();
#[cfg(test)]
mod native_tests;
pub(in crate::gold) use native::{produce, receive};
pub(in crate::gold) use native_wire::{MAX_FRAME_BYTES, profile};
pub(in crate::gold) fn transcript_manifest(
    expected: &Expected,
) -> Result<bfv_hiding_stark::transcript::ArgumentManifest> {
    let air = air::MetadataAir::new(expected)?;
    let report = assessment::assess(&air)?;
    report.require_resources()?;
    report.transcript_manifest(&air)
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
        super::expected().unwrap()
    }
    fn clear_first_statement_count(_pp: &mut [bfv_hiding_stark::Challenge]) {}
    include!("../ordered_constraint_tests.rs");
}
