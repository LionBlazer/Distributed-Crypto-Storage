//! Bounded encrypted private snapshots; native proof/QC state is never decoded.
use super::*;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, Tag},
};
use protocol_storage::{BlobId, EvidenceStore};
use sha2::{Digest, Sha256};
use std::io::Read;

const HEADER: usize = 136;
const TAG: usize = 16;
const MAGIC: &[u8; 8] = b"DCSWOR01";
const PRIVATE_MAGIC: &[u8; 8] = b"WOPRIV01";
const BASE: usize = 8 + 8 + 32 + 32 + 8 + 32 + 208 * 8 + 64 + 4 * 8;
pub const MAX_RECORD_BYTES: usize = protocol_storage::MAX_BLOB_BYTES as usize;

pub fn recovery_profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DCS/Word-owner/recovery/v1/DCSWOR01/WOPRIV01/XChaCha20Poly1305");
    hash.update(registry200_finality::word::profile_digest());
    hash.update(word::profile_digest());
    hash.update(word::wire_profile_digest());
    hash.update(b"full-binding-identity-context-parent-slot-decision/Registry208-controllers-enrollment-salt/pending-original-block-intent-binding-Next208-Result160/no-serialized-verdict/native-owner-recheck/no-latest-or-antirollback-floor");
    for n in [HEADER, TAG, BASE, MAX_RECORD_BYTES] {
        hash.update((n as u64).to_le_bytes());
    }
    hash.finalize().into()
}
/// Independently custodied high-entropy wrapping key. It is not a database
/// decryption key or an authority to bypass native verification.
pub struct RecoveryKey(Zeroizing<[u8; 32]>);
impl RecoveryKey {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }
}
/// Owner-selected record family. This identity is metadata, not an anti-rollback floor.
#[derive(Clone, Copy)]
pub struct RecoveryIdentity([u8; 32]);
impl RecoveryIdentity {
    pub fn new(identity: [u8; 32]) -> Result<Self> {
        if identity == [0; 32] {
            Err(Error::Shape)
        } else {
            Ok(Self(identity))
        }
    }
}

impl Owner {
    /// Store ONLY an encrypted immutable snapshot. The returned exact BlobId
    /// must be retained independently with the wrapping key and original pins.
    /// Selecting an old authentic record is not prevented by encryption alone.
    pub fn checkpoint(
        &self,
        store: &mut EvidenceStore,
        key: &RecoveryKey,
        identity: RecoveryIdentity,
    ) -> Result<BlobId> {
        self.live()?;
        let encoded_block_len = self
            .pending
            .as_ref()
            .map(|draft| 8 + version_journal::HEADER_BYTES + 4 + draft.block.body().len());
        let private_len = BASE
            .checked_add(match encoded_block_len {
                None => 0,
                Some(n) => 4usize
                    .checked_add(n)
                    .and_then(|n| n.checked_add(32 + 64 + (208 + 160) * 8))
                    .ok_or(Error::Shape)?,
            })
            .ok_or(Error::Shape)?;
        let total = HEADER
            .checked_add(private_len)
            .and_then(|n| n.checked_add(TAG))
            .filter(|&n| n <= MAX_RECORD_BYTES)
            .ok_or(Error::Shape)?;
        let block = self.pending.as_ref().map(|draft| draft.block.encode());
        let parent = self.confirmed_parent()?;
        let mut private = Zeroizing::new(Vec::with_capacity(private_len));
        private.extend(PRIVATE_MAGIC);
        private.push(u8::from(self.pending.is_some()));
        private.extend([0; 7]);
        private.extend(self.history.context()?.id());
        private.extend(parent.head().block);
        private.extend(parent.slot().to_le_bytes());
        private.extend(parent.decision_id());
        write_words(&mut private, &self.material.registry);
        for controller in self.material.controllers.iter() {
            private.extend(controller);
        }
        write_words(&mut private, &self.material.enrollment_salt);
        if let (Some(draft), Some(block)) = (&self.pending, &block) {
            private.extend((block.len() as u32).to_le_bytes());
            private.extend(block);
            private.extend(draft.intent.bytes());
            private.extend(draft.expected.binding());
            write_words(&mut private, &draft.next);
            write_words(&mut private, &draft.result);
        }
        if private.len() != private_len {
            return Err(Error::Shape);
        }
        let mut header = [0; HEADER];
        header[..8].copy_from_slice(MAGIC);
        header[8..40].copy_from_slice(&recovery_profile_digest());
        header[40..72].copy_from_slice(&self.history.binding().id());
        header[72..104].copy_from_slice(&identity.0);
        getrandom::getrandom(&mut header[104..128]).map_err(|_| Error::Entropy)?;
        header[128..132].copy_from_slice(&((private_len + TAG) as u32).to_le_bytes());
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| Error::Recovery)?;
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&header[104..128]),
                &header,
                private.as_mut(),
            )
            .map_err(|_| Error::Recovery)?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend(header);
        bytes.extend(private.iter());
        bytes.extend(tag);
        let id = BlobId::new(Sha256::digest(&bytes).into(), bytes.len() as u64)?;
        let mut stage = store.stage(id)?;
        for chunk in bytes.chunks(64 * 1024) {
            stage.write_chunk(chunk)?;
        }
        Ok(stage.finish()?)
    }
    /// Recreate only under independently installed Source/History/owner pins and
    /// the independently retained EXACT encrypted record identity. The caller
    /// must replay public history natively first. No query is reexecuted and no
    /// accepting proof/currentness flag is read from the record.
    pub fn restore(
        history: History,
        signing: SigningKey,
        store: &mut EvidenceStore,
        key: &RecoveryKey,
        identity: RecoveryIdentity,
        expected: BlobId,
    ) -> Result<Self> {
        let n = usize::try_from(expected.bytes()).map_err(|_| Error::Shape)?;
        if !(HEADER + TAG + BASE..=MAX_RECORD_BYTES).contains(&n) {
            return Err(Error::Shape);
        }
        let mut bytes = vec![0; n];
        let mut reader = store.reader(expected)?;
        reader.read_exact(&mut bytes)?;
        reader.finish()?;
        let header = &bytes[..HEADER];
        let cipher_len =
            u32::from_le_bytes(header[128..132].try_into().map_err(|_| Error::Shape)?) as usize;
        if &header[..8] != MAGIC
            || header[8..40] != recovery_profile_digest()
            || header[40..72] != history.binding().id()
            || header[72..104] != identity.0
            || header[132..136] != [0; 4]
            || cipher_len != n - HEADER
        {
            return Err(Error::Recovery);
        }
        let mut private = Zeroizing::new(bytes[HEADER..n - TAG].to_vec());
        XChaCha20Poly1305::new_from_slice(key.0.as_ref())
            .map_err(|_| Error::Recovery)?
            .decrypt_in_place_detached(
                XNonce::from_slice(&header[104..128]),
                header,
                private.as_mut(),
                Tag::<XChaCha20Poly1305>::from_slice(&bytes[n - TAG..]),
            )
            .map_err(|_| Error::Recovery)?;
        let mut r = Reader {
            bytes: &private,
            at: 0,
        };
        if r.take(8)? != PRIVATE_MAGIC {
            return Err(Error::Recovery);
        }
        let phase = r.take(1)?[0];
        if phase > 1 || r.take(7)? != [0; 7] {
            return Err(Error::Recovery);
        }
        let parent = history.checked_parent()?.ok_or(Error::Binding)?;
        if r.take(32)? != history.context()?.id()
            || r.take(32)? != parent.head().block
            || r.u64()? != parent.slot()
            || r.take(32)? != parent.decision_id()
        {
            return Err(Error::Binding);
        }
        let material = Material {
            registry: r.words()?,
            controllers: Zeroizing::new([
                r.take(32)?.try_into().map_err(|_| Error::Shape)?,
                r.take(32)?.try_into().map_err(|_| Error::Shape)?,
            ]),
            enrollment_salt: r.words()?,
        };
        let draft = if phase == 1 {
            let n = r.u32()? as usize;
            if n == 0 || n > MAX_RECORD_BYTES - HEADER - TAG - BASE {
                return Err(Error::Shape);
            }
            let block = CandidateBlock::decode(r.take(n)?)?;
            let intent: [u8; 32] = r.take(32)?.try_into().map_err(|_| Error::Shape)?;
            let binding: [u8; 64] = r.take(64)?.try_into().map_err(|_| Error::Shape)?;
            Some((block, intent, binding, r.words::<208>()?, r.words::<160>()?))
        } else {
            None
        };
        if r.at != private.len() {
            return Err(Error::Shape);
        }
        let mut owner = Owner::new(history, signing, material)?;
        if let Some((block, intent_bytes, binding, next, result)) = draft {
            let b = owner.history.binding();
            let app = Application::new(b.application_descriptor().clone(), b.journal_genesis())?;
            let Body::Transition(transition) =
                Body::decode(block.body(), &b.journal_genesis().profile)?
            else {
                return Err(Error::Recovery);
            };
            let request = Request::decode(&transition.request)?;
            let intent = OperationId::new(&app, &request, &transition.proof)?;
            if intent.bytes() != intent_bytes {
                return Err(Error::Binding);
            }
            let checked = owner.history.check_operation_candidate(&block, intent)?;
            let verified = checked.control().ok_or(Error::Binding)?;
            let expected = verified.expected();
            if expected.binding() != binding
                || word::registry_root(&next)? != expected.claims().next
                || word::result_root(&result)? != expected.claims().result
            {
                return Err(Error::Binding);
            }
            owner.pending = Some(Draft {
                block,
                intent,
                expected: expected.clone(),
                next,
                result,
            });
        }
        Ok(owner)
    }
    /// Persist the complete private draft BEFORE exposing its candidate. A
    /// failure before publication discards only this unexposed draft.
    pub fn prepare_stored<'a>(
        &'a mut self,
        source: word::SourceOpening,
        command: word::CommandInput,
        mining: Mining,
        store: &'a mut EvidenceStore,
        authority: &'a RecoveryKey,
        identity: RecoveryIdentity,
    ) -> Result<StoredPending<'a>> {
        self.prepare(source, command, mining)?;
        let record = match self.checkpoint(store, authority, identity) {
            Ok(record) => record,
            Err(error) => {
                self.pending = None;
                return Err(error);
            }
        };
        Ok(StoredPending {
            owner: self,
            store,
            authority,
            identity,
            record,
        })
    }
    /// Re-seal the SAME retained/restored draft; no operation nonce or native
    /// argument is regenerated. This produces a new ciphertext record identity.
    pub fn resume_stored<'a>(
        &'a mut self,
        store: &'a mut EvidenceStore,
        authority: &'a RecoveryKey,
        identity: RecoveryIdentity,
    ) -> Result<StoredPending<'a>> {
        self.live()?;
        if self.pending.is_none() {
            return Err(Error::Consumed);
        }
        let record = self.checkpoint(store, authority, identity)?;
        Ok(StoredPending {
            owner: self,
            store,
            authority,
            identity,
            record,
        })
    }
}
fn write_words<const N: usize>(bytes: &mut Vec<u8>, words: &[u64; N]) {
    for word in words {
        bytes.extend(word.to_le_bytes());
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(Error::Shape)?;
        let result = self.bytes.get(self.at..end).ok_or(Error::Shape)?;
        self.at = end;
        Ok(result)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Shape)?,
        ))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Shape)?,
        ))
    }
    fn words<const N: usize>(&mut self) -> Result<Zeroizing<[u64; N]>> {
        let mut words = Zeroizing::new([0; N]);
        for word in words.iter_mut() {
            *word = self.u64()?;
        }
        Ok(words)
    }
}
/// The candidate becomes readable only after an encrypted snapshot was synced
/// through the actual immutable store. Keep `record` independently before send.
pub struct StoredPending<'a> {
    owner: &'a mut Owner,
    store: &'a mut EvidenceStore,
    authority: &'a RecoveryKey,
    identity: RecoveryIdentity,
    record: BlobId,
}
impl StoredPending<'_> {
    pub fn record(&self) -> BlobId {
        self.record
    }
    pub fn candidate(&self) -> Result<&CandidateBlock> {
        self.owner.live()?;
        Ok(&self.owner.pending.as_ref().ok_or(Error::Consumed)?.block)
    }
    pub fn confirmed_parent(&self) -> Result<&VerifiedParent> {
        self.owner.confirmed_parent()
    }
    /// Check the real original proof/QC, then sync the encrypted confirmed bank
    /// BEFORE exposing the result. Uncertain storage failure poisons this owner;
    /// its original stored pending record can still be restored and checked.
    pub fn confirm(&mut self, checkpoint: &Checkpoint) -> Result<StoredConfirmation> {
        let confirmation = Pending { owner: self.owner }.confirm(checkpoint)?;
        let confirmed_record =
            match self
                .owner
                .checkpoint(self.store, self.authority, self.identity)
            {
                Ok(record) => record,
                Err(error) => {
                    self.owner.poisoned = true;
                    return Err(error);
                }
            };
        Ok(StoredConfirmation {
            confirmation,
            confirmed_record,
            original_record: self.record,
        })
    }
}
pub struct StoredConfirmation {
    confirmation: Confirmation,
    confirmed_record: BlobId,
    original_record: BlobId,
}
impl StoredConfirmation {
    pub fn confirmation(&self) -> &Confirmation {
        &self.confirmation
    }
    pub fn confirmed_record(&self) -> BlobId {
        self.confirmed_record
    }
    pub fn original_record(&self) -> BlobId {
        self.original_record
    }
}
