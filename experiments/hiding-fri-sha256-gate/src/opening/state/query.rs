//! A fresh request/authorized plan over the SAME retained C_state.
//! Reuses SelectionAir; it does not assert state authority on its own.
use super::{StateStatement, salt};
use crate::backend::{Error, Val};
use crate::opening::{
    commitment,
    selection::{statement as selected, trace::Witness},
};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};

pub(super) struct QueryStatement {
    inner: selected::Statement,
}
impl QueryStatement {
    pub(super) fn checked(
        state: &StateStatement,
        request: [u8; 32],
        expected_plan: [u8; 32],
        result: [u8; 32],
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: selected::Statement::for_state(state, request, expected_plan, result)?,
        })
    }
    pub(super) fn require_state(&self, expected: &StateStatement) -> Result<(), Error> {
        if !expected.matches(&self.inner.source) {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(super) fn source(&self) -> &selected::Statement {
        &self.inner
    }
}
impl PublicStatement for QueryStatement {
    fn kind(&self) -> Kind {
        Kind::VersionSelection
    }
    fn air(&self) -> PrimitiveAir {
        self.inner.air()
    }
    fn public_values(&self) -> Vec<Val> {
        self.inner.public_values()
    }
}

pub(super) fn fixture(
    state: &StateStatement,
    plain: [u8; 2348],
    state_salt: [Val; 4],
    request: [u8; 32],
    empty: bool,
) -> Result<(QueryStatement, Witness), Error> {
    let mut mask = [0; 32];
    if !empty {
        mask[0] = 1;
        mask[31] = 128;
    }
    let plan = selected::Plan::new(
        [0x31; 32],
        mask,
        if empty { 0 } else { 2 },
        Some(if empty { 0 } else { 2 }),
    )?;
    let witness = Witness::new(plain, plan, [state_salt, salt()?, salt()?]);
    let mut statement = QueryStatement::checked(state, request, [0; 32], [0; 32])?;
    // Native commitments belong to the known nonsecret client fixture. They do
    // not constitute an SQL answer or replace any proof in the verifier.
    statement.inner.plan = commitment::digest(&selected::plan_fields(&statement.inner, &witness));
    statement.inner.selected =
        commitment::digest(&selected::selected_fields(&statement.inner, &witness));
    Ok((statement, witness))
}
