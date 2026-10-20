//! Fresh exact weighted-QC completion. No predicate, lock scan or window builder
//! is called here or on replay. The only SQL rows come from the actual encrypted
//! product AFTER its genuine fixed application/QC receipt and private Result160.
use super::*;
use super::{
    host::{ControlOutcome, Outcome, Reply, Row},
    prepare::Attempt,
    state::{Bank, Book, Kind},
};
use bfv_query_core::QueryContext;
use registry200_finality::{
    CandidateBlock,
    progress::{Checkpoint, History, OperationExpectation},
};
use registry200_joint::progress::ProgressEvidenceIngress;
use registry200_proof::registry_progress::{
    circuit::Status,
    control_result_opening::{ControlOpeningContext, ControlResultOpening},
    result_opening::ResultOpening,
};
use zeroize::Zeroize;

pub(super) struct Completion<'a> {
    pub pins: &'a Pins,
    pub history: &'a mut History,
    pub ingress: &'a ProgressEvidenceIngress,
    pub old: &'a Bank,
    pub book: &'a Book,
    pub attempt: &'a Attempt,
    pub block: &'a CandidateBlock,
    pub checkpoint: &'a Checkpoint,
    pub material: &'a Material<'a>,
    pub fetched: FetchedSource<'a>,
    pub record: u64,
}
impl Completion<'_> {
    pub fn check(self) -> Result<(Bank, Book, Outcome)> {
        self.check_with_recording(None)
    }
    pub(super) fn check_with_recording(
        self,
        recorded: Option<bfv_product_evidence::ScopedRecordedProduct<'_>>,
    ) -> Result<(Bank, Book, Outcome)> {
        let Self {
            pins,
            history,
            ingress,
            old,
            book,
            attempt: a,
            block,
            checkpoint,
            material,
            fetched,
            record,
        } = self;
        if recorded.is_some() && a.call.kind != Kind::Acquire {
            return Err(Error::Phase);
        }
        if a.custody != material.fingerprint(pins)? || book.flight != Some(a.call) {
            return Err(Error::Pins);
        }
        let source_owner = material.source(pins, again(&fetched))?;
        let loaded = source_owner.load(fetched).map_err(crypto)?;
        let plain: Zeroizing<[u8; 2348]> = Zeroizing::new(
            loaded
                .plain
                .as_slice()
                .try_into()
                .map_err(|_| Error::Shape)?,
        );
        let parent = history
            .checked_parent()
            .map_err(crypto)?
            .ok_or(Error::Phase)?
            .clone();
        old.require_parent(pins, &parent, &loaded.draft, &plain)?;
        if old
            .root(pins, parent.head().block, &loaded.draft, &plain)?
            .1
            != a.old_root
        {
            return Err(Error::Pins);
        }
        let manifest = a.manifest()?;
        let body =
            version_journal::Body::decode(block.body(), &pins.binding.journal_genesis().profile)
                .map_err(crypto)?;
        let expected = OperationExpectation::transition(
            &pins.binding,
            &parent,
            history.context().map_err(crypto)?,
            &a.request,
            manifest,
            &body,
        )
        .map_err(crypto)?;
        let public = if a.call.kind == Kind::Acquire {
            Some(a.inventory.load(ingress, pins, material, &a.request)?)
        } else {
            None
        };
        let e = a.expected(
            pins,
            old,
            public.as_ref().map(|p| &p.provenance.encodings()[1]),
        )?;
        if let Some(p) = &public {
            if Sha256::digest(&p.request).as_slice() != a.request_digest {
                return Err(Error::Pins);
            }
            let parsed = material
                .setup
                .private_coefficient_request(&p.request)
                .map_err(crypto)?;
            if parsed.context()
                != &QueryContext::new(a.context_id, e.source().heads[0], e.source().heads[1])
                || parsed.query() != a.request.inner().query
            {
                return Err(Error::Pins);
            }
        }
        // Any error after this operation may have advanced History. Its owner
        // unconditionally poisons itself until strict replay; no result escapes.
        let receipt = match recorded {
            Some(recorded) => {
                history.apply_recorded_operation(checkpoint, block, &expected, recorded)
            }
            None => history.apply_operation(checkpoint, block, &expected),
        }
        .map_err(crypto)?;
        let actual = receipt.operation();
        let step = actual.transition_step().ok_or(Error::Phase)?;
        step.statement().require_expected(&e).map_err(crypto)?;
        if actual.request() != a.request.encode().map_err(crypto)?.as_slice()
            || actual.next_root() != a.next_root
            || actual.result_root() != a.result_root
        {
            return Err(Error::Pins);
        }
        a.next
            .require_parent(pins, receipt.checked_parent(), &loaded.draft, &plain)?;
        let old_actor = old
            .state
            .registry
            .transactions
            .iter()
            .position(|t| t.id == a.call.transaction);
        let previous = old_actor.and_then(|t| old.state.progress[t].as_ref());
        let (book, outcome) = if let Some(original) = &a.original {
            let next_actor = a
                .next
                .state
                .registry
                .transactions
                .iter()
                .position(|t| t.id == a.call.transaction)
                .ok_or(Error::Pins)?;
            let parked = a.next.state.progress[next_actor].as_ref();
            let opened =
                ResultOpening::open(step, Zeroizing::new(*a.result), original, previous, parked)
                    .map_err(crypto)?;
            if original.client != pins.clients[a.call.slot].id
                || original.call != a.call.sequence
                || original.transaction != a.call.transaction
                || original.principal != pins.clients[a.call.slot].principal
            {
                return Err(Error::Pins);
            }
            let product = actual.product().ok_or(Error::Pins)?;
            let catalog =
                a.inventory
                    .require_catalog(ingress, pins, a.catalog.ok_or(Error::Phase)?)?;
            if catalog.graph_identity() != product.product().identity()
                || catalog.response().sha256()
                    != &<[u8; 32]>::from(Sha256::digest(product.encrypted_response()))
                || catalog.response().bytes() != product.encrypted_response().len() as u64
            {
                return Err(Error::Pins);
            }
            match opened.status() {
                Status::Parked => {
                    let progress = opened.parked_progress_root().ok_or(Error::Pins)?;
                    (
                        book.park(a.call, opened.statement_root(), progress, record)?,
                        Outcome::Waiting,
                    )
                }
                Status::Error => (book.terminal(a.call, record)?, Outcome::NoWaitError),
                Status::Done => {
                    let p = public.as_ref().ok_or(Error::Phase)?;
                    let owner = material.owner(pins)?;
                    let pending = owner
                        .restore_private_coefficient_predicate_for_experiment(
                            p.request.clone(),
                            QueryContext::new(
                                a.context_id,
                                e.source().heads[0],
                                e.source().heads[1],
                            ),
                            a.request.inner().query,
                            a.request_digest,
                        )
                        .map_err(crypto)?;
                    let mut decoded = owner
                        .decrypt_private_coefficient_predicate_unverified_for_experiment(
                            pending.pending,
                            product.encrypted_response(),
                        )
                        .map_err(crypto)?;
                    // A guard clears decrypted rows even if a later ordinal or
                    // presence check fails. No Source plaintext answer is used.
                    let rows = (|| {
                        let mut rows = Vec::with_capacity(4);
                        for (i, row) in decoded.rows.iter().enumerate() {
                            if usize::from(row.ordinal) != i {
                                return Err(Error::Pins);
                            }
                            if !opened.selected()[i] {
                                continue;
                            }
                            if !row.present {
                                return Err(Error::Pins);
                            }
                            rows.push(Row {
                                ordinal: row.ordinal,
                                row_id: plain[2220 + 32 * i..2252 + 32 * i].try_into().unwrap(),
                                age: (original.projection != 2).then_some(row.age),
                                amount: (original.projection != 1).then_some(row.amount),
                            });
                        }
                        Ok(rows)
                    })();
                    for row in &mut decoded.rows {
                        row.ordinal.zeroize();
                        row.present.zeroize();
                        row.age.zeroize();
                        row.amount.zeroize();
                    }
                    let reply = Reply {
                        rows: rows?,
                        head: receipt.head(),
                        decision: receipt.decision_id(),
                    };
                    (book.terminal(a.call, record)?, Outcome::Done(reply))
                }
            }
        } else {
            if actual.product().is_some() {
                return Err(Error::Pins);
            }
            let context = ControlOpeningContext::new(
                &e,
                &a.command,
                old.state.registry.revision,
                &old.controllers,
                &a.command_salt,
                previous,
            )
            .map_err(crypto)?;
            let opened = ControlResultOpening::open(step, Zeroizing::new(*a.result), &context)
                .map_err(crypto)?;
            if opened.transaction() != a.call.transaction
                || opened.operation() != a.call.kind.operation()
            {
                return Err(Error::Pins);
            }
            (book.terminal(a.call,record)?,Outcome::Control(if opened.status()==registry200_proof::registry_progress::control_result_opening::ControlStatus::Aborted{ControlOutcome::Aborted}else{match a.call.kind{Kind::Begin=>ControlOutcome::Begun,Kind::Savepoint=>ControlOutcome::SavepointCreated,Kind::RollbackTo=>ControlOutcome::RolledBackToSavepoint,Kind::Release=>ControlOutcome::SavepointReleased,Kind::EndClose=>ControlOutcome::Closed,_=>return Err(Error::Pins)}}))
        };
        book.audit(&a.next, pins)?;
        Ok((a.next.clone(), book, outcome))
    }
}
