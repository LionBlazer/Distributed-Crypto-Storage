//! Closed local proof composition. All premises are replayed on every check.
use crate::{
    AcquireExpected, Application, CheckedAcquire, Descriptor, Error, JointDepot, Lane, Manifest,
    Request, Result, SetupClaim,
};
use bfv_product_evidence::{CatalogId, SharedProductStore};
use bfv_query_core::PublicSetup;
use registry200_journal::Control;
use registry200_proof::{
    admission, coefficient_encoding, control_kind, lifecycle, predicate_acquire, source, wire,
};
use std::cell::RefCell;
use version_journal::{
    Genesis, Header, Journal, PendingImport, TransitionStatement, TransitionVerifier,
};

pub struct JointVerifier {
    application: Application,
    setup: PublicSetup,
    depot: JointDepot,
}
impl JointVerifier {
    /// Opens the original setup from the SAME depot and independently pinned
    /// descriptor before any proof check. Keep an ingress handle before moving
    /// the depot here when future candidates must upload public evidence.
    pub fn new(
        descriptor: Descriptor,
        genesis: &Genesis,
        claim: &SetupClaim,
        depot: JointDepot,
    ) -> Result<Self> {
        let application = Application::new(descriptor, genesis)?;
        let setup = depot.load_setup(application.descriptor(), claim)?;
        Ok(Self {
            application,
            setup,
            depot,
        })
    }
    /// Direct invocation checks historical computation consistency. The actual
    /// Journal must first authenticate the owner and validated parent. This
    /// method supplies no current-head, finality, lease, or SQL capability.
    pub fn check(&self, s: TransitionStatement<'_>) -> Result<()> {
        self.evaluate(s, None).map(|_| ())
    }
    /// Authenticate the actual complete block through the Journal and return
    /// this call's fresh Acquire result. The fixed private adapter below cannot
    /// accept a supplied verifier, callback, successor, or cached success flag.
    /// A generic Journal still supplies no finality/current-head authority.
    pub fn check_acquire_block(
        &self,
        journal: &Journal,
        header: &Header,
        body: &[u8],
        now: u64,
        expected: &AcquireExpected,
    ) -> Result<CheckedAcquire> {
        if expected.application_id() != self.application.id() {
            return Err(Error::Domain);
        }
        let verifier = AcquireBlockVerifier {
            verifier: self,
            expected,
            result: RefCell::new(None),
        };
        journal.reverify_block(header, body, now, &verifier)?;
        verifier.result.into_inner().ok_or(Error::Verification)
    }
    /// Freshly verify the exact own Acquire and prepare its unpublished import.
    /// The same private adapter returns the actual input16/output118/Life/Link
    /// result from THIS check. The exclusive pending Journal borrow must remain
    /// local until all owner semantics pass and commit() consumes it, or Drop
    /// publishes nothing. This is not a finality/current-head receipt or cache.
    /// ```compile_fail
    /// fn mutate(v: &registry200_joint::JointVerifier, j: &mut version_journal::Journal,
    ///     h: version_journal::Header, b: &[u8], e: &registry200_joint::AcquireExpected) {
    ///     let (pending, _) = v.prepare_acquire_import(j, h, b, 2000, e).unwrap();
    ///     let _ = j.best_validated();
    ///     pending.commit();
    /// }
    /// ```
    pub fn prepare_acquire_import<'journal>(
        &self,
        journal: &'journal mut Journal,
        header: Header,
        body: &[u8],
        now: u64,
        expected: &AcquireExpected,
    ) -> Result<(PendingImport<'journal>, CheckedAcquire)> {
        if expected.application_id() != self.application.id() {
            return Err(Error::Domain);
        }
        let verifier = AcquireBlockVerifier {
            verifier: self,
            expected,
            result: RefCell::new(None),
        };
        let pending = journal.prepare_import(header, body, now, &verifier)?;
        let acquired = verifier.result.into_inner().ok_or(Error::Verification)?;
        Ok((pending, acquired))
    }
    fn evaluate(
        &self,
        s: TransitionStatement<'_>,
        own: Option<&AcquireExpected>,
    ) -> Result<Option<CheckedAcquire>> {
        let a = &self.application;
        let spec = a.source_spec();
        if s.genesis != a.genesis()
            || s.database != spec.database
            || s.application_commitment != a.id()
            || s.parent.genesis != a.genesis()
            || s.parent.database != spec.database
            || s.previous_shards.len() != 2
            || s.next_shards.len() != 2
            || s.updates.len() != 1
        {
            return Err(Error::Domain);
        }
        if version_journal::state_root(s.previous_shards) != s.parent.state_root
            || version_journal::state_root(s.next_shards) != s.next_state_root
        {
            return Err(Error::Transition);
        }
        let old_heads = spec.control(s.previous_shards)?;
        let next_heads = spec.control(s.next_shards)?;
        let update = &s.updates[0];
        if update.id != spec.control_id
            || update.old != old_heads
            || update.new != next_heads
            || old_heads == next_heads
        {
            return Err(Error::Transition);
        }
        let old = Control::decode(spec, old_heads)?;
        let next = Control::decode(spec, next_heads)?;
        let request = Request::decode(s.request)?;
        request.require_application(a)?;
        if request.inner().parent != s.parent.block {
            return Err(Error::Domain);
        }
        let manifest = Manifest::decode(s.proof)?;
        if manifest.lane() != request.lane() {
            return Err(Error::Domain);
        }
        if let Some(own) = own {
            own.require_manifest(&request, &manifest)?;
        }
        let r = request.inner();
        let source = r.source(spec)?;
        let source =
            admission::CanonicalSource::checked_claim(&source).map_err(|_| Error::Domain)?;
        let expected = match (request.lane(), old) {
            (Lane::Bootstrap, Control::Pending) => {
                admission::Expected::bootstrap(&source, a.genesis(), s.parent.block, r.enrollment)
            }
            (
                Lane::Control | Lane::Acquire,
                Control::Active {
                    enrollment,
                    registry,
                },
            ) => {
                if r.enrollment != enrollment || manifest.next_root() == registry {
                    return Err(Error::Transition);
                }
                admission::Expected::transition(
                    &source,
                    a.genesis(),
                    s.parent.block,
                    enrollment,
                    registry,
                    r.command,
                )
            }
            _ => return Err(Error::Transition),
        }
        .map_err(|_| Error::Domain)?;
        let target = Control::Active {
            enrollment: r.enrollment,
            registry: manifest.next_root(),
        };
        if next != target {
            return Err(Error::Transition);
        }

        // Each bounded local read releases its store lock before actual proof
        // verification. Network fetch/upload remains outside application locks.
        let store = self.depot.store();
        match request.lane() {
            Lane::Bootstrap => {
                let pair = read(store, &manifest, 0)?;
                let checked = wire::verify(&expected, &pair).map_err(|_| Error::Verification)?;
                if checked.next_root() != manifest.next_root() || checked.result_root().is_some() {
                    return Err(Error::Verification);
                }
            }
            Lane::Control => {
                let pair = read(store, &manifest, 0)?;
                let statement = claim(&expected, &manifest)?;
                let kind = control_kind::Expected::new(&statement).map_err(|_| Error::Domain)?;
                let proof = read(store, &manifest, 1)?;
                // This genuinely verifies the complete Source/Life pair AND
                // private opcode membership. An outer Control tag is insufficient.
                control_kind::verify(
                    &kind,
                    &control_kind::Prerequisites { lifecycle: &pair },
                    &proof,
                )
                .map_err(|_| Error::Verification)?;
            }
            Lane::Acquire => {
                return self
                    .acquire(store, &request, manifest, &expected, own)
                    .map(Some);
            }
        }
        Ok(None)
    }
    fn acquire(
        &self,
        store: &SharedProductStore,
        r: &Request,
        m: Manifest,
        e: &admission::Expected,
        own: Option<&AcquireExpected>,
    ) -> Result<CheckedAcquire> {
        let id = CatalogId::from_blob(m.reference(0)?)?;
        let catalog = store.catalog_claim(id)?;
        let provenance = {
            let bytes = store.read_public_blob(
                catalog.provenance(),
                bfv_mul_relin_proof::MAX_PROVENANCE_CLAIM_BYTES,
            )?;
            bfv_mul_relin_proof::Provenance::decode_claim(self.setup.clone(), &bytes)
                .map_err(|_| Error::Domain)?
        };
        self.application
            .descriptor()
            .require_provenance(&provenance)?;
        let expected_source = &e.claim().source;
        for encoding in provenance.encodings() {
            let actual = encoding.expected.source_claim();
            if actual.request != r.inner().query
                || actual.values() != expected_source.values()
                || actual.heads != expected_source.heads
                || actual.packets != expected_source.packets
            {
                return Err(Error::Domain);
            }
        }
        let query_statement = provenance.encodings()[1].clone();
        let request = store.read_public_blob(
            catalog.request(),
            bfv_query_core::MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES,
        )?;
        let provenance_claim = provenance.encode_claim().map_err(|_| Error::Domain)?;
        if let Some(own) = own {
            own.require_inputs(&provenance_claim, &request)?;
        }
        // Replays original Key+Source+both Encoding+ten Basis+two Formation,
        // then ALL118 output records. No QC/catalog/cache replaces any proof.
        let replayed = store.replay(
            id,
            self.application.descriptor().source_object(),
            provenance,
            &request,
        )?;
        // Assemble unchanged bounded prerequisite envelopes from ONE literal
        // retained Source. These existing verifiers really recheck it again.
        let source = store.read_public_blob(catalog.source(), wire::frame::MAX_SOURCE_BYTES)?;
        let child = read(store, &m, 1)?;
        let pair = wire::frame::join(
            wire::frame::Role::Transition,
            &[m.next_root(), m.result_root()],
            &source,
            &child,
        )
        .map_err(|_| Error::Verification)?;
        drop(child);
        let query = {
            let child = store
                .read_public_blob(catalog.query_child(), coefficient_encoding::wire::MAX_CHILD)?;
            coefficient_encoding::wire::join(
                &query_statement.expected,
                source::statement::encode_digest(query_statement.encoded),
                &source,
                &child,
            )
            .map_err(|_| Error::Verification)?
        };
        drop(source);
        let lifecycle = claim(e, &m)?;
        let link = predicate_acquire::Expected::new(&query_statement, &lifecycle)
            .map_err(|_| Error::Domain)?;
        let bytes = read(store, &m, 2)?;
        predicate_acquire::verify(
            &link,
            &predicate_acquire::Prerequisites {
                query: &query,
                lifecycle: &pair,
            },
            &bytes,
        )
        .map_err(|_| Error::Verification)?;
        Ok(CheckedAcquire {
            request: r.encode()?,
            provenance: provenance_claim,
            encrypted_request: request,
            manifest: m,
            catalog: id,
            replayed,
        })
    }
}
// Per-call ownership only. Even a successful Journal check must have executed
// the Acquire branch exactly once; nothing is persisted or reused by this cell.
struct AcquireBlockVerifier<'a> {
    verifier: &'a JointVerifier,
    expected: &'a AcquireExpected,
    result: RefCell<Option<CheckedAcquire>>,
}
impl TransitionVerifier for AcquireBlockVerifier<'_> {
    fn verify(&self, s: TransitionStatement<'_>) -> version_journal::Result<()> {
        let checked = self
            .verifier
            .evaluate(s, Some(self.expected))
            .map_err(|_| version_journal::Error::RejectedComputationProof)?
            .ok_or(version_journal::Error::RejectedComputationProof)?;
        let mut slot = self.result.borrow_mut();
        if slot.is_some() {
            return Err(version_journal::Error::RejectedComputationProof);
        }
        *slot = Some(checked);
        Ok(())
    }
}
fn read(store: &SharedProductStore, m: &Manifest, i: usize) -> Result<Vec<u8>> {
    Ok(store.read_public_blob(m.reference(i)?, m.cap(i).ok_or(Error::Encoding)?)?)
}
fn claim(e: &admission::Expected, m: &Manifest) -> Result<lifecycle::statement::Statement> {
    Ok(lifecycle::statement::Statement {
        expected: e.claim().clone(),
        next: source::statement::decode_digest(m.next_root()).map_err(|_| Error::Encoding)?,
        result: source::statement::decode_digest(m.result_root()).map_err(|_| Error::Encoding)?,
    })
}
impl TransitionVerifier for JointVerifier {
    fn verify(&self, s: TransitionStatement<'_>) -> version_journal::Result<()> {
        self.check(s)
            .map_err(|_| version_journal::Error::RejectedComputationProof)
    }
}
