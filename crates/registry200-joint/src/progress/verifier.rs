//! Closed actual composition. Every call freshly checks its complete premises.
use super::{
    Application, Descriptor, Error, Lane, Manifest, OperationId, ProgressDepot, Request, Result,
    SetupClaim,
};
use bfv_product_evidence::{CatalogId, ReplayedProduct, SharedProductStore};
use bfv_query_core::PublicSetup;
use registry200_journal::Control;
use registry200_proof::{
    admission::CanonicalSource, coefficient_encoding, registry_progress as core, source,
};
use std::cell::RefCell;
use version_journal::{
    Genesis, Header, Journal, PendingImport, TransitionStatement, TransitionVerifier,
};

pub struct ProgressVerifier {
    application: Application,
    setup: PublicSetup,
    depot: ProgressDepot,
}
impl ProgressVerifier {
    pub fn new(
        descriptor: Descriptor,
        genesis: &Genesis,
        claim: &SetupClaim,
        depot: ProgressDepot,
    ) -> Result<Self> {
        let application = Application::new(descriptor, genesis)?;
        let setup = depot.load_setup(application.descriptor(), claim)?;
        Ok(Self {
            application,
            setup,
            depot,
        })
    }
    /// Historical mathematical check only. The Journal owns actual owner/Header
    /// authentication; Work/QC/current-head admission is a separate future layer.
    pub fn check(&self, s: TransitionStatement<'_>) -> Result<VerifiedOperation> {
        self.evaluate(s, None)
    }
    /// Fixed actual Journal path. The independent expected ID is checked before
    /// native application work; this read-only method imports/publishes nothing.
    /// An expected ID computed from submitted bytes supplies no owner intent pin.
    pub fn check_block(
        &self,
        journal: &Journal,
        header: &Header,
        body: &[u8],
        now: u64,
        expected: OperationId,
    ) -> Result<VerifiedOperation> {
        let adapter = BlockVerifier {
            verifier: self,
            expected,
            result: RefCell::new(None),
        };
        journal.reverify_block(header, body, now, &adapter)?;
        adapter.result.into_inner().ok_or(Error::Verification)
    }
    /// SAME fresh closed check with one unpublished exclusive Journal handoff.
    /// Complete independent finality/owner semantics before argument-free commit;
    /// dropping the pending import publishes nothing. This supplies no QC.
    pub fn prepare_import<'journal>(
        &self,
        journal: &'journal mut Journal,
        header: Header,
        body: &[u8],
        now: u64,
        expected: OperationId,
    ) -> Result<(PendingImport<'journal>, VerifiedOperation)> {
        let adapter = BlockVerifier {
            verifier: self,
            expected,
            result: RefCell::new(None),
        };
        let pending = journal.prepare_import(header, body, now, &adapter)?;
        let checked = adapter.result.into_inner().ok_or(Error::Verification)?;
        Ok((pending, checked))
    }
    fn evaluate(
        &self,
        s: TransitionStatement<'_>,
        own: Option<OperationId>,
    ) -> Result<VerifiedOperation> {
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
        let before = spec.control(s.previous_shards)?;
        let after = spec.control(s.next_shards)?;
        let update = &s.updates[0];
        if update.id != spec.control_id
            || update.old != before
            || update.new != after
            || before == after
        {
            return Err(Error::Transition);
        }
        let old = Control::decode(spec, before)?;
        let next = Control::decode(spec, after)?;
        let request = Request::decode(s.request)?;
        request.require_application(a)?;
        if request.inner().parent != s.parent.block {
            return Err(Error::Domain);
        }
        let manifest = Manifest::decode(s.proof)?;
        let id = OperationId::new(a, &request, &manifest)?;
        if own.is_some_and(|expected| expected != id) {
            return Err(Error::Domain);
        }
        let r = request.inner();
        let source = r.source(spec)?;
        let canonical = CanonicalSource::checked_claim(&source).map_err(|_| Error::Domain)?;
        let target = Control::Active {
            enrollment: r.enrollment,
            registry: manifest.next_root(),
        };
        if next != target {
            return Err(Error::Transition);
        }
        let store = self.depot.store();
        let proof = match (request.lane(), old) {
            (Lane::Bootstrap, Control::Pending) => {
                let e = core::BootstrapExpected::new(
                    &canonical,
                    a.genesis(),
                    s.parent.block,
                    r.enrollment,
                )
                .map_err(|_| Error::Domain)?;
                let statement = core::BootstrapStatement::from_claim(&e, manifest.next_root())
                    .map_err(|_| Error::Domain)?;
                let source = read(store, &manifest, 0)?;
                let child = read(store, &manifest, 1)?;
                let checked = core::bootstrap::verify_bootstrap(&e, &statement, &source, &child)
                    .map_err(|_| Error::Verification)?;
                OperationProof::Bootstrap(checked)
            }
            (
                Lane::Control | Lane::Predicate,
                Control::Active {
                    enrollment,
                    registry,
                },
            ) => {
                if r.enrollment != enrollment || manifest.next_root() == registry {
                    return Err(Error::Transition);
                }
                if request.lane() == Lane::Control {
                    let e = core::transition::Expected::control(
                        &canonical,
                        a.genesis(),
                        s.parent.block,
                        enrollment,
                        registry,
                        r.command,
                    )
                    .map_err(|_| Error::Domain)?;
                    let statement = core::transition::Statement::from_claim(
                        &e,
                        manifest.next_root(),
                        manifest.result_root(),
                    )
                    .map_err(|_| Error::Domain)?;
                    let source = read(store, &manifest, 0)?;
                    let child = read(store, &manifest, 1)?;
                    let checked = core::transition::verify(
                        &e,
                        &statement,
                        &core::transition::Prerequisites {
                            source: &source,
                            query: None,
                        },
                        &child,
                    )
                    .map_err(|_| Error::Verification)?;
                    OperationProof::Control(checked)
                } else {
                    self.predicate(store, &request, &manifest, &canonical, enrollment, registry)?
                }
            }
            _ => return Err(Error::Transition),
        };
        Ok(VerifiedOperation {
            id,
            request: request.encode()?,
            manifest,
            proof,
        })
    }
    fn predicate(
        &self,
        store: &SharedProductStore,
        r: &Request,
        m: &Manifest,
        source: &CanonicalSource,
        enrollment: [u8; 32],
        old: [u8; 32],
    ) -> Result<OperationProof> {
        let catalog_id = CatalogId::from_blob(m.reference(0))?;
        let catalog = store.catalog_claim(catalog_id)?;
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
        for encoding in provenance.encodings() {
            let actual = encoding.expected.source_claim();
            let wanted = source.claim();
            if actual.values() != wanted.values()
                || actual.heads != wanted.heads
                || actual.packets != wanted.packets
            {
                return Err(Error::Domain);
            }
        }
        let query = provenance.encodings()[1].clone();
        let request = store.read_public_blob(
            catalog.request(),
            bfv_query_core::MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES,
        )?;
        // G commits the NEW descriptor: object, BOTH setup hashes, full anchor,
        // ALL33 and graph/role profiles. No supplied checked result is accepted.
        let product = store.replay(
            catalog_id,
            self.application.descriptor().source_object(),
            provenance,
            &request,
        )?;
        let source = store.read_public_blob(
            catalog.source(),
            registry200_proof::wire::frame::MAX_SOURCE_BYTES,
        )?;
        let child =
            store.read_public_blob(catalog.query_child(), coefficient_encoding::wire::MAX_CHILD)?;
        let pair = coefficient_encoding::wire::join(
            &query.expected,
            source::statement::encode_digest(query.encoded),
            &source,
            &child,
        )
        .map_err(|_| Error::Verification)?;
        drop(child);
        let e = core::transition::Expected::predicate(
            &query,
            self.application.genesis(),
            r.inner().parent,
            enrollment,
            old,
            r.inner().command,
        )
        .map_err(|_| Error::Domain)?;
        let statement = core::transition::Statement::from_claim(&e, m.next_root(), m.result_root())
            .map_err(|_| Error::Domain)?;
        let proof = read(store, m, 1)?;
        let checked = core::transition::verify(
            &e,
            &statement,
            &core::transition::Prerequisites {
                source: &source,
                query: Some(&pair),
            },
            &proof,
        )
        .map_err(|_| Error::Verification)?;
        Ok(OperationProof::Predicate { checked, product })
    }
}
fn read(store: &SharedProductStore, m: &Manifest, i: usize) -> Result<Vec<u8>> {
    Ok(store.read_public_blob(m.reference(i), m.cap(i))?)
}
enum OperationProof {
    Bootstrap(core::bootstrap::VerifiedBootstrap),
    Control(core::transition::VerifiedStep),
    Predicate {
        checked: core::transition::VerifiedStep,
        product: ReplayedProduct,
    },
}
/// Fresh mathematical result only. It has no constructor, phase/status, rows,
/// owner authorization, Header/QC receipt, current lock or SQL capability.
/// ```compile_fail
/// fn expose(v: registry200_joint::progress::VerifiedOperation) { let _ = v.proof; }
/// ```
pub struct VerifiedOperation {
    id: OperationId,
    request: Vec<u8>,
    manifest: Manifest,
    proof: OperationProof,
}
impl VerifiedOperation {
    pub fn operation_id(&self) -> OperationId {
        self.id
    }
    pub fn request(&self) -> &[u8] {
        &self.request
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    /// Already-public mathematics needed to reopen Result160 privately. The
    /// accessor never validates a caller-supplied Status.
    pub fn transition_statement(&self) -> Option<&core::transition::Statement> {
        match &self.proof {
            OperationProof::Control(s) | OperationProof::Predicate { checked: s, .. } => {
                Some(s.statement())
            }
            _ => None,
        }
    }
    pub fn bootstrap_statement(&self) -> Option<&core::BootstrapStatement> {
        match &self.proof {
            OperationProof::Bootstrap(s) => Some(s.statement()),
            _ => None,
        }
    }
    pub fn next_root(&self) -> [u8; 32] {
        match &self.proof {
            OperationProof::Bootstrap(b) => b.statement().next(),
            OperationProof::Control(s) | OperationProof::Predicate { checked: s, .. } => {
                s.statement().next()
            }
        }
    }
    pub fn result_root(&self) -> [u8; 32] {
        match &self.proof {
            OperationProof::Bootstrap(_) => [0; 32],
            OperationProof::Control(s) | OperationProof::Predicate { checked: s, .. } => {
                s.statement().result()
            }
        }
    }
    /// Present iff Predicate, and only after BOTH product replay and Core896.
    pub fn product(&self) -> Option<&ReplayedProduct> {
        match &self.proof {
            OperationProof::Predicate { product, .. } => Some(product),
            _ => None,
        }
    }
}
struct BlockVerifier<'a> {
    verifier: &'a ProgressVerifier,
    expected: OperationId,
    result: RefCell<Option<VerifiedOperation>>,
}
impl TransitionVerifier for BlockVerifier<'_> {
    fn verify(&self, s: TransitionStatement<'_>) -> version_journal::Result<()> {
        let checked = self
            .verifier
            .evaluate(s, Some(self.expected))
            .map_err(|_| version_journal::Error::RejectedComputationProof)?;
        let mut result = self.result.borrow_mut();
        if result.is_some() {
            return Err(version_journal::Error::RejectedComputationProof);
        }
        *result = Some(checked);
        Ok(())
    }
}
impl TransitionVerifier for ProgressVerifier {
    fn verify(&self, s: TransitionStatement<'_>) -> version_journal::Result<()> {
        self.check(s)
            .map(|_| ())
            .map_err(|_| version_journal::Error::RejectedComputationProof)
    }
}
