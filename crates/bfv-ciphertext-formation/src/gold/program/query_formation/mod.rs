//! Test-private fused Stmt96/mask/Cw/Cs/QueryCt mathematics; no SQL admission.
mod air;
mod layout;
mod plan;
mod tests;
use super::{descriptor::Descriptor, pp as old_pp};
use crate::gold::{
    Error, Result, Val, data, graph,
    relation::{ExpectedRef, RelationKind},
};
use layout::*;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256, Sha512};
super::dense_backend::instantiate_fixed_dense_backend!();

fn profile() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(native_wire::profile());
    h.update(data::profile_digest());
    h.update(b"all96-Stmt/header13/zero95/packedMask78..85;W[i]=16389*bit255-i/low256/high3840zero;originalCw4112/Cs528;all4096/same-S/E+-20/exact-K;no-Word-Source-admission");
    h.finalize().into()
}
#[derive(Clone)]
pub(in crate::gold) struct Expected {
    pub(in crate::gold) core: data::Expected,
    statement: [Val; 4],
    header: [Val; 13],
}
impl Expected {
    pub(in crate::gold) fn checked(
        original: &data::Expected,
        statement: [Val; 4],
        header: [Val; 13],
    ) -> Result<Self> {
        let mut h = Sha512::new();
        h.update(b"DCS/fused-query-formation/complete-Expected/v1");
        h.update(profile());
        h.update(original.binding());
        for value in statement.into_iter().chain(header) {
            h.update(value.as_canonical_u64().to_le_bytes());
        }
        let core = data::Expected::checked(
            original.request().clone(),
            h.finalize().into(),
            original.contexts(),
            original.roots(),
        )?;
        Ok(Self {
            core,
            statement,
            header,
        })
    }
    fn binding(&self) -> [u8; 64] {
        self.core.binding()
    }
    fn values(&self) -> &[Val] {
        self.core.values()
    }
    fn require_same(&self, other: &Self) -> Result<()> {
        self.core.require_same(&other.core)?;
        if self.statement != other.statement || self.header != other.header {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
struct Statement([Val; 96]);
impl Drop for Statement {
    fn drop(&mut self) {
        self.0.fill(Val::ZERO)
    }
}
pub(in crate::gold) struct Prepared {
    expected: Expected,
    input: data::Prepared,
    statement: Statement,
}
impl Prepared {
    pub(in crate::gold) fn new(
        expected: &Expected,
        input: data::Prepared,
        statement: [Val; 96],
    ) -> Result<Self> {
        let statement = Statement(statement);
        input.require_dense_expected(&expected.core)?;
        if statement.0[..13] != expected.header
            || statement.0[95] != Val::ZERO
            || statement.0[78..86]
                .iter()
                .any(|v| v.as_canonical_u64() > u32::MAX as u64)
            || statement_root(&statement.0) != expected.statement
        {
            return Err(Error::Binding);
        }
        Ok(Self {
            expected: expected.clone(),
            input,
            statement,
        })
    }
    fn require_dense_expected(&self, expected: &Expected) -> Result<()> {
        self.expected.require_same(expected)
    }
    fn dense_trace(self, expected: &Expected) -> Result<crate::gold::witness::PrivateTrace> {
        self.require_dense_expected(expected)?;
        self.input
            .inner
            .fused_query_trace(&expected.core, &self.statement.0, expected.statement)
    }
}
pub(in crate::gold) fn statement_root(words: &[Val; 96]) -> [Val; 4] {
    let mut state = [Val::ZERO; 12];
    for block in words.as_chunks::<8>().0 {
        let mut row = [Val::ZERO; bfv_hiding_stark::poseidon::WIDTH];
        state[..8].copy_from_slice(block);
        state = bfv_hiding_stark::poseidon::write(&mut row, state);
        row.fill(Val::ZERO);
    }
    let root = state[..4].try_into().expect("root4");
    state.fill(Val::ZERO);
    root
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
