//! Test-private complete DATA packing inventory; NO trace, proof or accepting API.
mod air;
mod assessment;
mod layout;
mod plan;
mod snapshot;
mod tests;
use super::super::{
    Error, Result, Val, data, graph,
    relation::{ExpectedRef, RelationKind},
};
use super::{descriptor::Descriptor, pp as old_pp};
use layout::*;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256};

/// Canonical PUBLIC metadata fixture only; not an encryption or proof witness.
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
fn hash_word(hash: &mut Sha256, value: usize) {
    hash.update((value as u64).to_le_bytes())
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    for byte in bytes.as_ref() {
        write!(&mut out, "{byte:02x}").unwrap()
    }
    out
}
