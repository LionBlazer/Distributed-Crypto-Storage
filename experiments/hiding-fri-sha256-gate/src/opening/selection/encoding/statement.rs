//! Public exact old-selection context plus a fresh encoded-vector commitment.
use super::{air, matrix};
use crate::backend::{Val, profile_digest};
use crate::opening::selection::statement::Statement as Selection;
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256};

pub(super) const PUBLIC_VALUES: usize = 100;
#[derive(Clone)]
pub(super) struct Statement {
    pub(super) selection: Selection,
    pub(super) encoded: [Val; 4],
}
impl Statement {
    pub(super) fn new(selection: &Selection, encoded: [Val; 4]) -> Self {
        Self {
            selection: selection.clone(),
            encoded,
        }
    }
    pub(super) fn context(&self) -> [Val; 8] {
        let mut h = Sha256::new();
        h.update(b"dcs/experiment/N4-selected-encoding-context/v1");
        h.update(profile_digest(Kind::SelectedEncoding));
        for value in self.selection.public_values() {
            h.update(value.as_canonical_u64().to_le_bytes());
        }
        let digest: [u8; 32] = h.finalize().into();
        core::array::from_fn(|i| {
            Val::from_u32(u32::from_le_bytes(
                digest[4 * i..4 * i + 4].try_into().unwrap(),
            ))
        })
    }
    pub(super) fn require_selection(
        &self,
        independently_expected: &Selection,
    ) -> Result<(), crate::backend::Error> {
        if self.selection.kind() != Kind::SelectionOpening
            || independently_expected.kind() != Kind::SelectionOpening
            || self.selection.public_values() != independently_expected.public_values()
        {
            return Err(crate::backend::Error::Shape);
        }
        Ok(())
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::SelectedEncoding
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::Encoding(Box::new(air::EncodingAir::new(self)))
    }
    fn public_values(&self) -> Vec<Val> {
        crate::opening::statement::words(&profile_digest(self.kind()))
            .chain(self.selection.public_values())
            .chain(self.encoded)
            .collect()
    }
}
pub(crate) fn profile(h: &mut Sha256) {
    h.update(b"DCS/experimental/selected-encoding-N4/v1/no-ciphertext-SQL-acceptance");
    h.update(profile_digest(Kind::SelectionOpening));
    h.update(b"exact-old-selected88/source-selection-first/canonical-4x12-private-fields");
    h.update(b"prefix-contextSHA8/salt4/zero4/W8192/P2-overwrite-rate8");
    h.update(b"16coeff-per-row/three-P2/first-source1to11-last511/carry8");
    h.update(matrix::digest());
    for x in [
        matrix::N as u64,
        matrix::T,
        matrix::Q_MOD_T,
        512,
        air::WIDTH as u64,
        205,
        100,
        5,
    ] {
        h.update(x.to_le_bytes());
    }
    for slot in matrix::SLOTS {
        h.update((slot as u64).to_le_bytes());
    }
    for q in [
        8796092858369_u64,
        8796092792833,
        17592186028033,
        17592185438209,
        17592184717313,
    ] {
        h.update(q.to_le_bytes());
    }
}
