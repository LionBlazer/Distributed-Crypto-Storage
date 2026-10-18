//! Private producer composition for the non-admitting fixed AddAmount relation.
pub(super) mod compiler;
pub(super) mod frame;
pub(super) mod statement;
#[cfg(test)]
mod tests;
pub(super) mod trace;
use crate::{
    backend::{Backend, Config, Error},
    opening::trace as source_trace,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
use statement::{Expected, Statement};
pub(super) struct Pair {
    pub source: Proof<Config>,
    pub child: Proof<Config>,
}
/// Source must actually verify before this private factory can allocate a child trace.
pub(super) fn prove_child_with_factory(
    e: &Expected,
    s: &Statement,
    source: Option<&Proof<Config>>,
    factory: impl FnOnce() -> Result<RowMajorMatrix<crate::backend::Val>, Error>,
) -> Result<Proof<Config>, Error> {
    s.require_expected(e)?;
    Backend::new(e.source())?.verify(e.source(), source.ok_or(Error::Verification)?)?;
    let backend = Backend::new(s)?;
    let proof = backend.prove_with_trace(s, factory)?;
    backend.verify(s, &proof)?;
    Ok(proof)
}
pub(super) fn prove(
    e: &Expected,
    source: &source_trace::Witness,
    w: &trace::Witness,
) -> Result<(Statement, Pair), Error> {
    let source_proof = {
        let b = Backend::new(e.source())?;
        b.prove_with_trace(e.source(), || source.trace(e.source()))?
    };
    let statement = w.statement(e)?;
    let child =
        prove_child_with_factory(e, &statement, Some(&source_proof), || w.trace(&statement))?;
    Ok((
        statement,
        Pair {
            source: source_proof,
            child,
        },
    ))
}
