//! Actual immutable Source verification, fresh native Word and fixed Journal handoff.
use super::{
    Application, Control, Descriptor, Error, Evidence, Lane, OperationId, Request, Result,
};
use registry200_proof::{registry_progress::word, source::version};
use std::cell::RefCell;
use version_journal::{
    Genesis, Header, Journal, PendingImport, TransitionStatement, TransitionVerifier,
};
pub struct Verifier {
    application: Application,
    source: version::VerifiedSourceVersion,
    word: word::Verifier,
}
impl Verifier {
    /// Verify the complete immutable Source once. It proves no current network head.
    pub fn new(descriptor: Descriptor, g: &Genesis, source_bytes: &[u8]) -> Result<Self> {
        let application = Application::new(descriptor, g)?;
        let source = version::verify(application.descriptor().source(), source_bytes)
            .map_err(|_| Error::RejectedComputationProof)?;
        let word = word::Verifier::new(word::Role::Control)
            .map_err(|_| Error::RejectedComputationProof)?;
        Ok(Self {
            application,
            source,
            word,
        })
    }
    pub fn application(&self) -> &Application {
        &self.application
    }
    /// Mathematical consistency only; an independent intent pin is mandatory.
    pub fn check(
        &self,
        s: TransitionStatement<'_>,
        expected: OperationId,
    ) -> Result<VerifiedOperation> {
        let a = &self.application;
        let d = a.descriptor();
        if s.genesis != a.genesis()
            || s.database != d.database()
            || s.application_commitment != a.id()
            || s.parent.genesis != a.genesis()
            || s.parent.database != d.database()
        {
            return Err(Error::WrongDomain);
        }
        if version_journal::state_root(s.previous_shards) != s.parent.state_root
            || version_journal::state_root(s.next_shards) != s.next_state_root
            || s.updates.len() != 1
        {
            return Err(Error::InvalidTransition);
        }
        let before = d.control(s.previous_shards)?;
        let after = d.control(s.next_shards)?;
        let u = &s.updates[0];
        if u.id != d.control_id()
            || u.old != before.heads(d)
            || u.new != after.heads(d)
            || u.old == u.new
        {
            return Err(Error::InvalidTransition);
        }
        let r = Request::decode(s.request)?;
        r.require_application(a)?;
        if r.parent() != s.parent.block || OperationId::new(a, &r, s.proof)? != expected {
            return Err(Error::WrongDomain);
        }
        let (source, child) = Evidence::split(r.lane(), s.proof)?;
        let c = r.claims();
        if after
            != (Control::Active {
                enrollment: r.enrollment(),
                registry: c.next,
            })
        {
            return Err(Error::InvalidTransition);
        }
        let proof = match (r.lane(), before) {
            (Lane::Bootstrap, Control::Pending) => {
                let e = word::bootstrap::Expected::checked(
                    self.source.expected(),
                    a.genesis(),
                    r.enrollment(),
                    c.next,
                )
                .map_err(|_| Error::WrongDomain)?;
                Proof::Bootstrap(
                    word::bootstrap::verify(&e, source, child)
                        .map_err(|_| Error::RejectedComputationProof)?,
                )
            }
            (
                Lane::Control,
                Control::Active {
                    enrollment,
                    registry,
                },
            ) => {
                if enrollment != r.enrollment() || registry != c.old || registry == c.next {
                    return Err(Error::InvalidTransition);
                }
                let e = word::Expected::checked(
                    self.source.expected(),
                    word::Role::Control,
                    a.genesis(),
                    s.parent.block,
                    enrollment,
                    c,
                )
                .map_err(|_| Error::WrongDomain)?;
                Proof::Control(
                    self.word
                        .verify(&e, child)
                        .map_err(|_| Error::RejectedComputationProof)?,
                )
            }
            _ => return Err(Error::InvalidTransition),
        };
        Ok(VerifiedOperation {
            id: expected,
            request: r,
            proof,
        })
    }
    pub fn check_block(
        &self,
        journal: &Journal,
        header: &Header,
        body: &[u8],
        now: u64,
        expected: OperationId,
    ) -> Result<VerifiedOperation> {
        let adapter = Adapter {
            verifier: self,
            expected,
            result: RefCell::new(None),
        };
        journal.reverify_block(header, body, now, &adapter)?;
        adapter
            .result
            .into_inner()
            .ok_or(Error::RejectedComputationProof)
    }
    /// Exclusive unpublished import. Finality/QC must precede argument-free commit.
    pub fn prepare_import<'j>(
        &self,
        journal: &'j mut Journal,
        header: Header,
        body: &[u8],
        now: u64,
        expected: OperationId,
    ) -> Result<(PendingImport<'j>, VerifiedOperation)> {
        let adapter = Adapter {
            verifier: self,
            expected,
            result: RefCell::new(None),
        };
        let pending = journal.prepare_import(header, body, now, &adapter)?;
        let result = adapter
            .result
            .into_inner()
            .ok_or(Error::RejectedComputationProof)?;
        Ok((pending, result))
    }
}
enum Proof {
    Bootstrap(word::bootstrap::VerifiedBootstrap),
    Control(word::VerifiedWord),
}
/// Native mathematical receipt. No owner/QC/currentness or accepting flag is stored.
/// ```compile_fail
/// fn duplicate(v: &registry200_joint::word::VerifiedOperation)->registry200_joint::word::VerifiedOperation { v.clone() }
/// ```
/// ```compile_fail
/// fn forge(){ let _=registry200_joint::word::VerifiedOperation { id:todo!(), request:todo!(), proof:todo!() }; }
/// ```
pub struct VerifiedOperation {
    id: OperationId,
    request: Request,
    proof: Proof,
}
impl VerifiedOperation {
    pub fn operation_id(&self) -> OperationId {
        self.id
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn bootstrap(&self) -> Option<&word::bootstrap::VerifiedBootstrap> {
        match &self.proof {
            Proof::Bootstrap(v) => Some(v),
            _ => None,
        }
    }
    pub fn control(&self) -> Option<&word::VerifiedWord> {
        match &self.proof {
            Proof::Control(v) => Some(v),
            _ => None,
        }
    }
}
struct Adapter<'a> {
    verifier: &'a Verifier,
    expected: OperationId,
    result: RefCell<Option<VerifiedOperation>>,
}
/// Validators receive owner authorization from the actual Journal before this
/// fixed callback. Deriving association metadata here grants no caller intent,
/// owner, currentness or SQL capability, and still runs every native Word check.
impl TransitionVerifier for Verifier {
    fn verify(&self, s: TransitionStatement<'_>) -> Result<()> {
        let r = Request::decode(s.request)?;
        let id = OperationId::new(&self.application, &r, s.proof)?;
        self.check(s, id).map(|_| ())
    }
}
impl TransitionVerifier for Adapter<'_> {
    fn verify(&self, s: TransitionStatement<'_>) -> Result<()> {
        let checked = self.verifier.check(s, self.expected)?;
        let mut out = self.result.borrow_mut();
        if out.is_some() {
            return Err(Error::RejectedComputationProof);
        }
        *out = Some(checked);
        Ok(())
    }
}
