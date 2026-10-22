//! Originating-owner Control preparation and private bank confirmation.
//! An own ordered mutation is not a general latest-head oracle or SQL/row lease.
mod recovery;
use ed25519_dalek::SigningKey;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
pub use recovery::{
    RecoveryIdentity, RecoveryKey, StoredConfirmation, StoredPending, recovery_profile_digest,
};
use registry200_finality::{
    CandidateBlock,
    word::{Checkpoint, History, VerifiedOperation, VerifiedParent},
};
use registry200_joint::word::{Application, Control, Evidence, OperationId, Request};
use registry200_proof::{Val, registry_progress::word, source};
use version_journal::{AuthorizedTransition, Body, ShardUpdate};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum Error {
    Binding,
    Shape,
    Entropy,
    Consumed,
    Pending,
    Poisoned,
    Recovery,
    Storage(protocol_storage::Error),
    Io(std::io::Error),
    Word(word::Error),
    Journal(version_journal::Error),
    Finality(registry200_finality::joint::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Word owner control rejected: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<protocol_storage::Error> for Error {
    fn from(e: protocol_storage::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<word::Error> for Error {
    fn from(e: word::Error) -> Self {
        Self::Word(e)
    }
}
impl From<version_journal::Error> for Error {
    fn from(e: version_journal::Error) -> Self {
        Self::Journal(e)
    }
}
impl From<registry200_finality::joint::Error> for Error {
    fn from(e: registry200_finality::joint::Error) -> Self {
        Self::Finality(e)
    }
}
impl From<registry200_finality::Error> for Error {
    fn from(e: registry200_finality::Error) -> Self {
        Self::Finality(e.into())
    }
}
pub type Result<T> = core::result::Result<T, Error>;

/// Owner-held opening of its already checked historical registry. Construction
/// is not authentication; Owner::new checks its commitment against actual History.
pub struct Material {
    pub registry: Zeroizing<[u64; 208]>,
    pub controllers: Zeroizing<[[u8; 32]; 2]>,
    pub enrollment_salt: Zeroizing<[u64; 4]>,
}
/// Bounded real mining policy. Header/target/parent come from the owned History.
pub struct Mining {
    pub timestamp: u64,
    pub now: u64,
    pub attempts: u64,
}
/// Originating-owner control state. Private words and key cannot be exported or
/// cloned. Optional encrypted snapshots require separately retained custody pins.
/// ```compile_fail
/// fn expose(x:storage_client::word_control::Owner){let _=x.material.registry;}
/// ```
pub struct Owner {
    history: History,
    key: SigningKey,
    material: Material,
    prover: word::Prover,
    pending: Option<Draft>,
    poisoned: bool,
}
impl Owner {
    pub fn new(history: History, key: SigningKey, material: Material) -> Result<Self> {
        let parent = history.checked_parent()?.ok_or(Error::Binding)?;
        let Control::Active {
            enrollment,
            registry,
        } = parent.control()
        else {
            return Err(Error::Binding);
        };
        if key.verifying_key().to_bytes() != history.binding().journal_genesis().owner
            || material.controllers.contains(&[0; 32])
            || material
                .enrollment_salt
                .iter()
                .any(|&v| v >= Val::ORDER_U64)
            || word::registry_root(&material.registry)? != registry
        {
            return Err(Error::Binding);
        }
        let zero = [Val::ZERO; 4];
        let expected = word::Expected::checked(
            history.binding().application_descriptor().source(),
            word::Role::Control,
            history.binding().journal_genesis().id()?,
            parent.head().block,
            enrollment,
            word::Claims {
                old: registry,
                command: zero,
                statement: zero,
                next: zero,
                result: zero,
                blind_sql: [Val::ZERO; 8],
            },
        )?;
        if word::enrollment_root(
            expected.enrollment_header(),
            material.registry[37..45]
                .try_into()
                .map_err(|_| Error::Shape)?,
            &material.controllers,
            &material.enrollment_salt,
        )? != enrollment
        {
            return Err(Error::Binding);
        }
        let prover = word::Prover::new(word::Role::Control)?;
        Ok(Self {
            history,
            key,
            material,
            prover,
            pending: None,
            poisoned: false,
        })
    }
    /// The last independently checked own historical decision, not global currentness.
    pub fn confirmed_parent(&self) -> Result<&VerifiedParent> {
        self.live()?;
        self.history.checked_parent()?.ok_or(Error::Binding)
    }
    /// Prepare only original Control opcodes 0/3/4/5/6. Predicate/FHE/SQL admission
    /// stays closed. No bank is installed while proof, transport or QC is pending.
    /// One mutable owner borrow prevents interleaving private state changes.
    pub fn prepare(
        &mut self,
        source_opening: word::SourceOpening,
        command: word::CommandInput,
        mining: Mining,
    ) -> Result<Pending<'_>> {
        self.live()?;
        if self.pending.is_some() {
            return Err(Error::Pending);
        }
        if !matches!(command.op, 0 | 3..=6) || mining.attempts == 0 {
            return Err(Error::Shape);
        }
        let parent = self.confirmed_parent()?.clone();
        let Control::Active {
            enrollment,
            registry,
        } = parent.control()
        else {
            return Err(Error::Binding);
        };
        let binding = self.history.binding();
        let application = Application::new(
            binding.application_descriptor().clone(),
            binding.journal_genesis(),
        )?;
        let zero = [Val::ZERO; 4];
        let draft = word::Expected::checked(
            binding.application_descriptor().source(),
            word::Role::Control,
            application.genesis(),
            parent.head().block,
            enrollment,
            word::Claims {
                old: registry,
                command: zero,
                statement: zero,
                next: zero,
                result: zero,
                blind_sql: [Val::ZERO; 8],
            },
        )?;
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Entropy)?;
        let next_salt = fields()?;
        let command_salt = fields()?;
        let result_salt = fields()?;
        let mut controllers = [[Val::ZERO; 8]; 2];
        for (out, bytes) in controllers.iter_mut().zip(self.material.controllers.iter()) {
            *out = source::statement::words(bytes)
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| Error::Shape)?;
        }
        let registry = word::CurrentRegistry::new(
            controllers,
            Zeroizing::new(*self.material.registry),
            next_salt,
        )?;
        controllers.iter_mut().for_each(|c| c.fill(Val::ZERO));
        let transition = word::prepare_transition(
            &draft,
            word::TransitionMaterial {
                source: source_opening,
                registry,
                command,
                walk: Default::default(),
                mask: Zeroizing::new([0; 32]),
                salts: [
                    self.material.enrollment_salt.map(Val::from_u64),
                    command_salt.map(Val::from_u64),
                    result_salt.map(Val::from_u64),
                ],
            },
        )?;
        let (expected, inputs, opening) = transition.into_parts();
        let (next, result) = opening.into_words();
        if word::registry_root(&next)? != expected.claims().next {
            return Err(Error::Binding);
        }
        let evidence = self.prover.produce(&expected, inputs)?;
        let evidence = Evidence::control(evidence.as_bytes())?;
        let request = Request::control(
            &application,
            parent.head().block,
            nonce,
            enrollment,
            expected.claims(),
        )?;
        let intent = OperationId::new(&application, &request, evidence.as_bytes())?;
        let descriptor = binding.application_descriptor();
        let after = Control::Active {
            enrollment,
            registry: expected.claims().next,
        };
        let mut transition = AuthorizedTransition {
            parent: parent.head().block,
            request: request.encode(),
            updates: vec![ShardUpdate {
                id: descriptor.control_id(),
                old: parent.control().heads(descriptor),
                new: after.heads(descriptor),
            }],
            proof: evidence.as_bytes().to_vec(),
            owner_signature: [0; 64],
        };
        transition.sign(application.genesis(), &self.key);
        let body = Body::Transition(transition);
        let mut header = self
            .history
            .candidate_header(&body, mining.timestamp, mining.now)?;
        header.mine(mining.attempts)?;
        let bytes = body.encode(&binding.journal_genesis().profile)?;
        let block = CandidateBlock::new(header, bytes)?;
        self.pending = Some(Draft {
            block,
            intent,
            expected,
            next,
            result,
        });
        Ok(Pending { owner: self })
    }
    /// Resume the exact original candidate/nonce/openings after losing a handle.
    /// Preparing another mutation is blocked while any draft remains pending.
    pub fn resume_pending(&mut self) -> Result<Pending<'_>> {
        self.live()?;
        if self.pending.is_none() {
            return Err(Error::Consumed);
        }
        Ok(Pending { owner: self })
    }
    fn live(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
}
fn fields() -> Result<Zeroizing<[u64; 4]>> {
    let mut fields = Zeroizing::new([0; 4]);
    for field in fields.iter_mut() {
        let mut selected = None;
        for _ in 0..8 {
            let mut bytes = Zeroizing::new([0; 8]);
            getrandom::getrandom(bytes.as_mut()).map_err(|_| Error::Entropy)?;
            let value = u64::from_le_bytes(*bytes);
            if value < Val::ORDER_U64 {
                selected = Some(value);
                break;
            }
        }
        *field = selected.ok_or(Error::Entropy)?;
    }
    Ok(fields)
}
struct Draft {
    block: CandidateBlock,
    intent: OperationId,
    expected: word::Expected,
    next: Zeroizing<[u64; 208]>,
    result: Zeroizing<[u64; 160]>,
}
/// Original candidate and private openings remain in Owner until a matching QC.
/// Rejected replies and dropped handles retain the pending candidate and bank.
/// There is no accepting flag, supplied verifier or alternate response Body.
pub struct Pending<'a> {
    owner: &'a mut Owner,
}
impl Pending<'_> {
    pub fn candidate(&self) -> Result<&CandidateBlock> {
        self.owner.live()?;
        Ok(&self.owner.pending.as_ref().ok_or(Error::Consumed)?.block)
    }
    pub fn confirmed_parent(&self) -> Result<&VerifiedParent> {
        self.owner.confirmed_parent()
    }
    /// Fresh OS owner nonce, exact retained intent/Body, full native checks and
    /// weighted QC precede installing this own ordered mutation's private bank.
    /// A later concurrent decision still requires normal lineage catch-up.
    pub fn confirm(&mut self, checkpoint: &Checkpoint) -> Result<Confirmation> {
        self.owner.live()?;
        let draft = self.owner.pending.as_ref().ok_or(Error::Consumed)?;
        let checked = self
            .owner
            .history
            .apply_operation(checkpoint, &draft.block, draft.intent)?;
        if checked
            .operation()
            .control()
            .is_none_or(|v| v.expected().binding() != draft.expected.binding())
        {
            // A fixed internal invariant after History publication cannot leave
            // a usable owner with an unmatched private bank.
            self.owner.poisoned = true;
            return Err(Error::Binding);
        }
        let draft = self.owner.pending.take().expect("checked original draft");
        self.owner.material.registry = draft.next;
        Ok(Confirmation {
            checked,
            result: draft.result,
        })
    }
}
/// Own Control math/QC and its guarded original Result160 opening. This is not
/// an accepted SQL result, current-head oracle, durable owner floor or lock lease.
pub struct Confirmation {
    checked: VerifiedOperation,
    result: Zeroizing<[u64; 160]>,
}
impl Confirmation {
    pub fn operation(&self) -> &VerifiedOperation {
        &self.checked
    }
    pub fn result_words(&self) -> &[u64; 160] {
        &self.result
    }
}
