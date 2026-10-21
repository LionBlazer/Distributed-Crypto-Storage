//! Complete private witness writer for the unchanged closed mathematical AIR.
//! It consumes openings, never fixture answers or a selected SQL result.
use super::{
    Expected,
    backend::{Error, Result},
    layout::*,
};
use crate::Val;
use bfv_hiding_stark::poseidon;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::default_goldilocks_poseidon2_12;
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;

/// Move-only private inputs; no getters, Clone, serialization or public API.
pub(super) struct Opening {
    statement: [Val; 96],
    mask: [u8; 32],
    salt: [Val; 4],
}
impl Drop for Opening {
    fn drop(&mut self) {
        self.statement.fill(Val::ZERO);
        self.mask.fill(0);
        self.salt.fill(Val::ZERO);
    }
}
impl Opening {
    pub(super) fn checked(
        expected: &Expected,
        statement: [Val; 96],
        mask: [u8; 32],
        salt: [Val; 4],
    ) -> Result<Self> {
        let opening = Self {
            statement,
            mask,
            salt,
        };
        opening.require(expected)?;
        Ok(opening)
    }
    fn require(&self, expected: &Expected) -> Result<()> {
        let header = super::super::header("statement");
        if self.statement[..13] != header[..] || self.statement[95] != Val::ZERO {
            return Err(Error::Shape);
        }
        for (word, bytes) in self.mask.as_chunks::<4>().0.iter().enumerate() {
            if self.statement[78 + word] != Val::from_u32(u32::from_le_bytes(*bytes)) {
                return Err(Error::Binding);
            }
        }
        if digest(&self.statement)? != expected.statement {
            return Err(Error::Binding);
        }
        let mut fields = PrivateFields(Vec::with_capacity(4112));
        fields.0.extend(expected.context);
        fields.0.extend(self.salt);
        fields.0.extend([Val::ZERO; 4]);
        fields.0.extend((0..4096).map(|index| {
            if index < 256 {
                self.bit(255 - index) * Val::from_u64(SCALE)
            } else {
                Val::ZERO
            }
        }));
        if digest(&fields.0)? != expected.vector {
            return Err(Error::Binding);
        }
        Ok(())
    }
    fn bit(&self, bit: usize) -> Val {
        Val::from_u8((self.mask[bit / 8] >> (bit % 8)) & 1)
    }
}
struct PrivateFields(Vec<Val>);
impl Drop for PrivateFields {
    fn drop(&mut self) {
        self.0.fill(Val::ZERO);
    }
}

/// Existing native Poseidon2 permutation, independent of gadget witness writing.
/// Exactly the two complete fixed stream lengths are accepted; no tail is ignored.
pub(super) fn digest(fields: &[Val]) -> Result<[Val; 4]> {
    if !matches!(fields.len(), 96 | 4112) {
        return Err(Error::Shape);
    }
    let permutation = default_goldilocks_poseidon2_12();
    let mut state = [Val::ZERO; 12];
    for block in fields.as_chunks::<8>().0 {
        state[..8].copy_from_slice(block);
        permutation.permute_mut(&mut state);
    }
    let root = state[..4].try_into().map_err(|_| Error::Shape)?;
    state.fill(Val::ZERO);
    Ok(root)
}

pub(super) struct PrivateTrace(pub RowMajorMatrix<Val>);
impl Drop for PrivateTrace {
    fn drop(&mut self) {
        self.0.values.fill(Val::ZERO);
    }
}
/// Best-effort buffer clearing is not a stack/compiler/allocator erasure claim.
pub(super) fn prepare(
    air: &super::air::QueryMaskAir,
    expected: &Expected,
    opening: &Opening,
) -> Result<PrivateTrace> {
    air.plan.inventory().map_err(|_| Error::Shape)?;
    opening.require(expected)?;
    let public = expected.values();
    let mut trace = PrivateTrace(RowMajorMatrix::new(vec![Val::ZERO; HEIGHT * WIDTH], WIDTH));
    let mut checkpoint = [Val::ZERO; 12];
    for (index, absorb) in air.plan.rows.iter().copied().enumerate() {
        let row = &mut trace.0.values[index * WIDTH..(index + 1) * WIDTH];
        row[CHECKPOINT..CHECKPOINT + 12].copy_from_slice(&checkpoint);
        row[STATEMENT..MASK].copy_from_slice(&opening.statement);
        for bit in 0..256 {
            row[MASK + bit] = opening.bit(bit);
        }
        row[VECTOR_SALT..PUBLIC].copy_from_slice(&opening.salt);
        row[PUBLIC..].copy_from_slice(&public);
        let mut input = [Val::ZERO; 12];
        for (lane, value) in input[..8].iter_mut().enumerate() {
            *value = match absorb.field(lane) {
                Field::Statement(word) => opening.statement[word],
                Field::Context(word) => expected.context[word],
                Field::VectorSalt(word) => opening.salt[word],
                Field::ScaledMask { bit, .. } => opening.bit(bit) * Val::from_u64(SCALE),
                Field::Zero => Val::ZERO,
            };
        }
        input[8..].copy_from_slice(&checkpoint[8..]);
        let output = poseidon::write(&mut row[..P2], input);
        let end = matches!(
            (absorb.stream, absorb.block),
            (Stream::Statement, 11) | (Stream::Vector, 513)
        );
        if end {
            let wanted = if absorb.stream == Stream::Statement {
                expected.statement
            } else {
                expected.vector
            };
            if output[..4] != wanted[..] {
                return Err(Error::Binding);
            }
            checkpoint.fill(Val::ZERO);
        } else {
            checkpoint = output;
        }
        input.fill(Val::ZERO);
    }
    checkpoint.fill(Val::ZERO);
    // Rows526..1023 remain completely zero, including private banks and providers.
    Ok(trace)
}

/// Native equation diagnostics only. Never a proof verifier or accepting result.
pub(super) fn check(
    air: &super::air::QueryMaskAir,
    trace: &PrivateTrace,
    expected: &Expected,
) -> Result<()> {
    if trace.0.width != WIDTH || trace.0.values.len() != HEIGHT * WIDTH {
        return Err(Error::Shape);
    }
    air.plan.inventory().map_err(|_| Error::Shape)?;
    let report = p3_air::check_all_constraints(air, &trace.0, &expected.values(), Some(1));
    if !report.is_ok() {
        return Err(Error::Proving);
    }
    Ok(())
}
