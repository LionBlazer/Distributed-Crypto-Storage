use crate::*;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use version_journal::{HeadPair, ShardUpdate, TransitionStatement, TransitionVerifier};

/// Controller intent, separately authenticated from the journal owner's permission.
/// Construct the signature externally over `Intent::signing_message(context)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedIntent {
    pub intent: Intent,
    pub signature: [u8; 64],
}
impl SignedIntent {
    pub fn encode(&self, context: Context) -> Result<Vec<u8>> {
        wire::encode_intent(self, context)
    }
    /// Canonical bounded decoding, without trusting the decoded signature.
    pub fn decode(bytes: &[u8], context: Context) -> Result<Self> {
        wire::decode_intent(bytes, context)
    }
    pub fn verify(&self, context: Context) -> Result<()> {
        let key = VerifyingKey::from_bytes(&self.intent.controller.0)
            .map_err(|_| Error::InvalidSignature)?;
        if key.is_weak() {
            return Err(Error::InvalidSignature);
        }
        key.verify_strict(
            &self.intent.signing_message(context)?,
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::InvalidSignature)
    }
}

/// Prepared control transition, not accepted SQL, a confirmed lock grant or finality.
pub struct PreparedTransition {
    pub request: Vec<u8>,
    pub witness: Vec<u8>,
    pub update: ShardUpdate,
    pub state: State,
    pub outcome: Outcome,
}

/// Verified metadata semantics bound to one exact parent. The caller still checks
/// journal authorization, work, confirmations and ancestry before relying on it.
pub struct VerifiedControl {
    state: State,
    outcome: Outcome,
    parent: Digest,
    genesis: Digest,
    request: Digest,
}
impl VerifiedControl {
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }
    pub fn parent(&self) -> Digest {
        self.parent
    }
    pub fn genesis(&self) -> Digest {
        self.genesis
    }
    /// Identity of the exact canonical signed request, including its statement.
    pub fn request_digest(&self) -> Digest {
        self.request
    }
    /// Match a pending request before using this receipt's metadata outcome.
    /// This does not establish SQL proof validity, confirmation or ancestry.
    pub fn matches_request(&self, request: &[u8]) -> bool {
        self.request == request_digest(request)
    }
}

fn request_digest(request: &[u8]) -> Digest {
    let mut hash = Sha256::new();
    hash.update(b"dcs/transaction-state/verified-request/v2");
    hash.update(request);
    hash.finalize().into()
}

/// A separate metadata-only application domain. This adapter rejects every data
/// shard update. Full SQL needs a composite verifier AND genuine encrypted jobs;
/// this authenticated control-state witness cannot substitute for their proofs.
pub struct MetadataVerifier {
    context: Context,
    shard: u64,
    application: Digest,
}
impl MetadataVerifier {
    pub fn new(context: Context, metadata_shard: u64) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"dcs/transaction-state/metadata-application/v2");
        hash.update(context.network);
        hash.update(context.database);
        hash.update(context.profile.commitment());
        hash.update(metadata_shard.to_le_bytes());
        Self {
            context,
            shard: metadata_shard,
            application: hash.finalize().into(),
        }
    }
    pub fn application_commitment(&self) -> Digest {
        self.application
    }
    pub fn heads(&self, state: &State) -> Result<HeadPair> {
        if state.context() != self.context {
            return Err(Error::WrongDomain);
        }
        let committed = state.commitment()?;
        let head = |component: u8, root: Digest, count: u32| {
            let mut bytes = [0; version_journal::HEAD_BYTES];
            bytes[..8].copy_from_slice(b"DCSTXH02");
            bytes[8..24].copy_from_slice(&self.context.database);
            bytes[24] = component;
            bytes[32..40].copy_from_slice(&committed.revision.to_le_bytes());
            bytes[40..72].copy_from_slice(&root);
            bytes[72..80].copy_from_slice(&u64::from(count).to_le_bytes());
            bytes[80..112].copy_from_slice(&self.context.profile.commitment());
            bytes
        };
        Ok(HeadPair {
            data: head(1, committed.transactions, committed.transaction_count),
            index: head(2, committed.locks, committed.holder_count),
        })
    }
    pub fn prepare(&self, previous: &State, signed: &SignedIntent) -> Result<PreparedTransition> {
        if previous.context() != self.context {
            return Err(Error::WrongDomain);
        }
        signed.verify(self.context)?;
        let transitioned = previous.transition(signed.intent.controller, &signed.intent.command)?;
        Ok(PreparedTransition {
            request: signed.encode(self.context)?,
            witness: previous.encode()?,
            update: ShardUpdate {
                id: self.shard,
                old: self.heads(previous)?,
                new: self.heads(&transitioned.state)?,
            },
            state: transitioned.state,
            outcome: transitioned.outcome,
        })
    }
    pub fn verify_control(&self, statement: &TransitionStatement<'_>) -> Result<VerifiedControl> {
        if statement.application_commitment != self.application
            || statement.database != self.context.database
        {
            return Err(Error::WrongDomain);
        }
        if statement.updates.len() != 1 || statement.updates[0].id != self.shard {
            return Err(Error::InvalidTransition);
        }
        let signed = SignedIntent::decode(statement.request, self.context)?;
        if signed.intent.genesis != statement.genesis
            || signed.intent.parent != statement.parent.block
            || statement.parent.genesis != statement.genesis
            || statement.parent.database != self.context.database
        {
            return Err(Error::WrongDomain);
        }
        signed.verify(self.context)?;
        let previous = State::decode(statement.proof, self.context)?;
        let update = &statement.updates[0];
        if update.old != self.heads(&previous)? {
            return Err(Error::InvalidTransition);
        }
        let transitioned = previous.transition(signed.intent.controller, &signed.intent.command)?;
        if update.new != self.heads(&transitioned.state)? {
            return Err(Error::InvalidTransition);
        }
        let mut expected = statement.previous_shards.to_vec();
        let metadata = expected
            .iter_mut()
            .find(|shard| shard.id == self.shard)
            .ok_or(Error::InvalidTransition)?;
        if metadata.heads != update.old {
            return Err(Error::InvalidTransition);
        }
        metadata.heads = update.new;
        if expected != statement.next_shards
            || version_journal::state_root(&expected) != statement.next_state_root
            || version_journal::state_root(statement.previous_shards) != statement.parent.state_root
        {
            return Err(Error::InvalidTransition);
        }
        Ok(VerifiedControl {
            state: transitioned.state,
            outcome: transitioned.outcome,
            parent: signed.intent.parent,
            genesis: signed.intent.genesis,
            request: request_digest(statement.request),
        })
    }
}
impl TransitionVerifier for MetadataVerifier {
    fn verify(&self, statement: TransitionStatement<'_>) -> version_journal::Result<()> {
        self.verify_control(&statement)
            .map(|_| ())
            .map_err(|_| version_journal::Error::RejectedComputationProof)
    }
}
