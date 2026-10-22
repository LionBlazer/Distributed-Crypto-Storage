//! Fixed Word admission used by the same durable voting/replay engine.
use super::{Binding, Candidate, Error, Result};
use registry200_joint::word::{Control, Verifier};
use version_journal::{Body, HeadPair, HeadRef, Journal};
use work_finality::consensus::Context;
pub(crate) fn parent_heads(b: &Binding, j: &Journal, parent: HeadRef) -> Result<HeadPair> {
    let d = b.application_descriptor();
    Ok(d.control(j.validated_shards(parent)?)?.heads(d))
}
pub(crate) fn candidate_control(b: &Binding, old: HeadPair, body: &[u8]) -> Result<Control> {
    let d = b.application_descriptor();
    let next = match Body::decode(body, &b.journal_genesis().profile)? {
        Body::Empty => old,
        Body::Transition(t) => {
            if t.updates.len() != 1 || t.updates[0].id != d.control_id() {
                return Err(Error::Context);
            }
            t.updates[0].new
        }
    };
    Ok(Control::decode(d, next)?)
}
pub(crate) fn verify_candidate(
    b: &Binding,
    j: &Journal,
    v: &Verifier,
    c: &Context,
    parent: HeadRef,
    d: &Candidate,
    body: &[u8],
) -> Result<Control> {
    require_candidate_context(b, c, parent, d)?;
    let old = parent_heads(b, j, parent)?;
    j.reverify_block(&d.header, body, crate::adapter::now()?, v)?;
    candidate_control(b, old, body)
}
pub(super) fn require_candidate_context(
    b: &Binding,
    c: &Context,
    parent: HeadRef,
    d: &Candidate,
) -> Result<()> {
    if c.rules().id() != b.rules().id()
        || c.network_id() != b.work_genesis().id()
        || c.journal_genesis() != b.journal_genesis().id()?
        || d.binding != b.id()
        || d.slot != c.slot()
        || d.previous != c.previous_decision()
        || d.header.genesis != parent.genesis
        || d.header.parent != parent.block
        || d.header.height != parent.height.checked_add(1).ok_or(Error::ResourceLimit)?
    {
        return Err(Error::Context);
    }
    Ok(())
}
