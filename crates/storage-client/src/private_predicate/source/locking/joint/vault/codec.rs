//! Fixed owner-secret grammar and AEAD; no proof/SQL authority or file I/O.
use super::*;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, Tag},
};
use p3_field::PrimeField64;
use registry200_proof::lifecycle::circuit::model::{Registry, Savepoint, Transaction};
use sha2::{Digest, Sha512};

pub(super) const HEADER: usize = 144;
const FRAME: usize = 1 + 32 + 4;
const TRANSACTION: usize = 1 + 8 + 1 + 8 + 1 + 32 + 4 + 2 * FRAME;
const REGISTRY: usize = 16 + 2 * TRANSACTION;
const LINK: usize = 32 + 8 + 1 + 32 + 8 + 8 + 5 + 12 + 3 * 32;
const PRIVATE: usize = 8 + 2 * REGISTRY + 64 + 3 * 32 + 32 + 4 * 32 + 4 + LINK;
const TAG: usize = 16;
pub(super) const RECORD: usize = HEADER + PRIVATE + TAG;
const MAGIC: &[u8; 8] = b"DCSJRC01";
const PRIVATE_MAGIC: &[u8; 8] = b"JCPRIV01";

pub(super) fn validate(bytes: &[u8]) -> crate::Result<()> {
    if bytes.len() != RECORD {
        return Err(invalid(
            "Joint recovery requires its exact bounded record length",
        ));
    }
    if &bytes[..8] != MAGIC
        || bytes[8..10] != 1u16.to_le_bytes()
        || bytes[10] != 1
        || bytes[11..16] != [0; 5]
        || bytes[136..140] != ((PRIVATE + TAG) as u32).to_le_bytes()
        || bytes[140..144] != [0; 4]
    {
        return Err(invalid("Noncanonical Joint recovery envelope"));
    }
    Ok(())
}
fn header(identity: &JointRecoveryIdentity, association: [u8; 64], nonce: &[u8; 24]) -> Vec<u8> {
    let mut out = vec![0; HEADER];
    out[..8].copy_from_slice(MAGIC);
    out[8..10].copy_from_slice(&1u16.to_le_bytes());
    out[10] = 1;
    out[16..48].copy_from_slice(&identity.record);
    out[48..112].copy_from_slice(&association);
    out[112..136].copy_from_slice(nonce);
    out[136..140].copy_from_slice(&((PRIVATE + TAG) as u32).to_le_bytes());
    out
}
fn hash_bytes(hash: &mut Sha512, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}
pub(super) fn association(
    parent: &JointLockingParent,
    p: &JointRecoveryInputs<'_>,
) -> crate::Result<[u8; 64]> {
    // Reject every announced bound before hashing or cloning public claim bytes.
    p.proofs.byte_len().map_err(cryptography)?;
    if p.proofs.frames().iter().any(|bytes| bytes.is_empty())
        || p.encrypted_request.is_empty()
        || p.encrypted_request.len() > bfv_query_core::MAX_PRIVATE_COEFFICIENT_REQUEST_BYTES
        || p.lifecycle.len() > registry200_proof::wire::frame::MAX_BUNDLE_BYTES
        || p.link.len() > predicate_acquire::wire::MAX_FRAME
    {
        return Err(invalid("Joint recovery public input bound"));
    }
    let request = p.request.encode().map_err(cryptography)?;
    let provenance = p.provenance.encode_claim().map_err(cryptography)?;
    let head = parent.head();
    let mut h = Sha512::new();
    h.update(b"DCS/owner-joint/ComputePrepared/full-association/v1");
    hash_bytes(&mut h, &parent.binding.id());
    hash_bytes(&mut h, &parent.binding.application_descriptor().encode());
    hash_bytes(
        &mut h,
        &parent
            .binding
            .journal_genesis()
            .encode()
            .map_err(cryptography)?,
    );
    hash_bytes(&mut h, &head.genesis);
    hash_bytes(&mut h, &head.database);
    hash_bytes(&mut h, &head.block);
    hash_bytes(&mut h, &head.state_root);
    h.update(head.height.to_le_bytes());
    h.update(parent.verified.slot().to_le_bytes());
    hash_bytes(&mut h, &parent.verified.decision_id());
    hash_bytes(&mut h, &parent.enrollment());
    hash_bytes(&mut h, &parent.registry());
    for bytes in [&request[..], &provenance, p.encrypted_request] {
        hash_bytes(&mut h, bytes);
    }
    for bytes in p.proofs.frames() {
        hash_bytes(&mut h, bytes);
    }
    hash_bytes(&mut h, p.lifecycle);
    hash_bytes(&mut h, p.link);
    Ok(h.finalize().into())
}
pub(super) fn seal(
    identity: &JointRecoveryIdentity,
    key: &JointRecoveryKey,
    association: [u8; 64],
    payload: &Payload,
) -> crate::Result<EncryptedJointRecovery> {
    let mut nonce = [0; 24];
    getrandom::getrandom(&mut nonce).map_err(cryptography)?;
    let mut bytes = header(identity, association, &nonce);
    let mut plain = payload.encode()?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(cryptography)?;
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &bytes, plain.as_mut())
        .map_err(cryptography)?;
    bytes.extend_from_slice(plain.as_ref());
    bytes.extend_from_slice(&tag);
    validate(&bytes)?;
    Ok(EncryptedJointRecovery { bytes })
}
pub(super) fn open(
    identity: &JointRecoveryIdentity,
    key: &JointRecoveryKey,
    association: [u8; 64],
    record: &EncryptedJointRecovery,
) -> crate::Result<Payload> {
    validate(record.as_bytes())?;
    let bytes = record.as_bytes();
    let expected = header(identity, association, bytes[112..136].try_into().unwrap());
    if bytes[..HEADER] != expected {
        return Err(invalid("Joint recovery independent association differs"));
    }
    let mut plain = Zeroizing::new([0; PRIVATE]);
    plain.copy_from_slice(&bytes[HEADER..HEADER + PRIVATE]);
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(cryptography)?;
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&bytes[112..136]),
            &expected,
            plain.as_mut(),
            Tag::<XChaCha20Poly1305>::from_slice(&bytes[HEADER + PRIVATE..]),
        )
        .map_err(cryptography)?;
    Payload::decode(plain.as_ref())
}

// Private copies are guarded immediately; no DATA ages/amounts or Source salt.
pub(super) struct Payload {
    pub(super) old: Zeroizing<Registry>,
    pub(super) next: Zeroizing<Registry>,
    pub(super) controllers: Zeroizing<[[u8; 32]; 2]>,
    pub(super) salts: Zeroizing<[[u64; 4]; 3]>, // enrollment, old, next
    pub(super) table: Zeroizing<[u8; 32]>,
    pub(super) ids: Zeroizing<[[u8; 32]; 4]>,
    pub(super) ordinals: Zeroizing<[u8; 4]>,
    pub(super) link: predicate_acquire::circuit::Opening,
}
pub(super) fn copy_opening(
    o: &predicate_acquire::circuit::Opening,
) -> predicate_acquire::circuit::Opening {
    predicate_acquire::circuit::Opening {
        mask: o.mask,
        transaction: o.transaction,
        principal: o.principal,
        controller: o.controller,
        revision: o.revision,
        sequence: o.sequence,
        mode: o.mode,
        wait: o.wait,
        offset: o.offset,
        limit: o.limit,
        projection: o.projection,
        flags: o.flags,
        salts: o.salts,
    }
}
impl Payload {
    pub(super) fn capture(
        o: &NextOwnerOpening,
        c: &LockingCompletion,
        link: &predicate_acquire::circuit::Opening,
    ) -> Self {
        Self {
            old: Zeroizing::new((*o.control.old).clone()),
            next: Zeroizing::new((*o.next).clone()),
            controllers: Zeroizing::new(*o.control.controllers),
            salts: Zeroizing::new([o.control.salts[0], o.control.salts[1], *o.next_salt]),
            table: Zeroizing::new(*c.table),
            ids: Zeroizing::new(*c.row_ids),
            ordinals: Zeroizing::new(*c.ordinals),
            link: copy_opening(link),
        }
    }
    fn validate(&self) -> crate::Result<()> {
        self.old.require_canonical().map_err(cryptography)?;
        self.next.require_canonical().map_err(cryptography)?;
        let o = &self.link;
        if self.controllers.contains(&[0; 32])
            || *self.ordinals != [0, 1, 2, 3]
            || self
                .salts
                .iter()
                .flatten()
                .chain(o.salts.iter().flatten())
                .any(|v| *v >= Val::ORDER_U64)
            || o.transaction == 0
            || !(1..=2).contains(&o.principal)
            || o.controller == [0; 32]
            || o.sequence == 0
            || !(1..=4).contains(&o.mode)
            || o.wait > 2
            || o.offset > 4
            || o.limit > 4
            || !(1..=3).contains(&o.projection)
        {
            return Err(invalid("Noncanonical Joint recovery private opening"));
        }
        Ok(())
    }
    fn encode(&self) -> crate::Result<Zeroizing<[u8; PRIVATE]>> {
        self.validate()?;
        let mut out = Zeroizing::new([0; PRIVATE]);
        let mut w = Writer {
            bytes: out.as_mut(),
            at: 0,
        };
        w.put(PRIVATE_MAGIC);
        w.registry(&self.old);
        w.registry(&self.next);
        for c in self.controllers.iter() {
            w.put(c);
        }
        for s in self.salts.iter().flatten() {
            w.word(*s);
        }
        w.put(self.table.as_ref());
        for id in self.ids.iter() {
            w.put(id);
        }
        w.put(self.ordinals.as_ref());
        let o = &self.link;
        w.put(&o.mask);
        w.word(o.transaction);
        w.byte(o.principal);
        w.put(&o.controller);
        w.word(o.revision);
        w.word(o.sequence);
        w.put(&[o.mode, o.wait, o.offset, o.limit, o.projection]);
        for flag in o.flags.iter().flatten() {
            w.byte(u8::from(*flag));
        }
        for salt in o.salts.iter().flatten() {
            w.word(*salt);
        }
        assert_eq!(w.at, PRIVATE);
        Ok(out)
    }
    fn decode(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != PRIVATE {
            return Err(invalid("Joint recovery private length"));
        }
        let mut r = Reader { bytes, at: 0 };
        if r.array::<8>()? != *PRIVATE_MAGIC {
            return Err(invalid("Joint recovery private role"));
        }
        let old = r.registry()?;
        let next = r.registry()?;
        let mut controllers = Zeroizing::new([[0; 32]; 2]);
        for c in controllers.iter_mut() {
            *c = r.array()?;
        }
        let mut salts = Zeroizing::new([[0; 4]; 3]);
        for s in salts.iter_mut().flatten() {
            *s = r.word()?;
        }
        let table = Zeroizing::new(r.array()?);
        let mut ids = Zeroizing::new([[0; 32]; 4]);
        for id in ids.iter_mut() {
            *id = r.array()?;
        }
        let ordinals = Zeroizing::new(r.array()?);
        let mut link = predicate_acquire::circuit::Opening {
            mask: [0; 32],
            transaction: 0,
            principal: 0,
            controller: [0; 32],
            revision: 0,
            sequence: 0,
            mode: 0,
            wait: 0,
            offset: 0,
            limit: 0,
            projection: 0,
            flags: [[false; 4]; 3],
            salts: [[0; 4]; 3],
        };
        link.mask = r.array()?;
        link.transaction = r.word()?;
        link.principal = r.byte()?;
        link.controller = r.array()?;
        link.revision = r.word()?;
        link.sequence = r.word()?;
        link.mode = r.byte()?;
        link.wait = r.byte()?;
        link.offset = r.byte()?;
        link.limit = r.byte()?;
        link.projection = r.byte()?;
        for flag in link.flags.iter_mut().flatten() {
            *flag = r.boolean()?;
        }
        for salt in link.salts.iter_mut().flatten() {
            *salt = r.word()?;
        }
        if r.at != PRIVATE {
            return Err(invalid("Joint recovery trailing private bytes"));
        }
        let payload = Self {
            old,
            next,
            controllers,
            salts,
            table,
            ids,
            ordinals,
            link,
        };
        payload.validate()?;
        Ok(payload)
    }
}
struct Writer<'a> {
    bytes: &'a mut [u8],
    at: usize,
}
impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        self.bytes[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
    }
    fn byte(&mut self, n: u8) {
        self.put(&[n]);
    }
    fn word(&mut self, n: u64) {
        self.put(&n.to_le_bytes());
    }
    fn registry(&mut self, registry: &Registry) {
        self.word(registry.revision);
        self.word(registry.allocator);
        for i in 0..2 {
            if let Some(tx) = registry.transactions.get(i) {
                self.byte(1);
                self.word(tx.id);
                self.byte(tx.principal);
                self.word(tx.sequence);
                self.byte(u8::from(tx.failed));
                self.put(&tx.snapshot);
                self.put(&tx.held);
                for j in 0..2 {
                    if let Some(frame) = tx.savepoints.get(j) {
                        self.byte(1);
                        self.put(&frame.name);
                        self.put(&frame.held);
                    } else {
                        self.put(&[0; FRAME]);
                    }
                }
            } else {
                self.put(&[0; TRANSACTION]);
            }
        }
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> crate::Result<[u8; N]> {
        let end = self
            .at
            .checked_add(N)
            .ok_or_else(|| invalid("Joint recovery private extent"))?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| invalid("Joint recovery truncated private field"))?
            .try_into()
            .unwrap();
        self.at = end;
        Ok(value)
    }
    fn byte(&mut self) -> crate::Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn word(&mut self) -> crate::Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn boolean(&mut self) -> crate::Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("Joint recovery nonbinary field")),
        }
    }
    fn registry(&mut self) -> crate::Result<Zeroizing<Registry>> {
        let mut state = Zeroizing::new(Registry::default());
        state.revision = self.word()?;
        state.allocator = self.word()?;
        let mut absent = false;
        for _ in 0..2 {
            let present = self.boolean()?;
            if !present {
                if self.array::<{ TRANSACTION - 1 }>()? != [0; TRANSACTION - 1] {
                    return Err(invalid("Joint recovery absent transaction padding"));
                }
                absent = true;
                continue;
            }
            if absent {
                return Err(invalid("Joint recovery transaction compaction"));
            }
            state.transactions.push(Transaction {
                id: 0,
                principal: 0,
                sequence: 0,
                failed: false,
                snapshot: [0; 32],
                held: [0; 4],
                savepoints: Vec::new(),
            });
            let tx = state.transactions.last_mut().unwrap();
            tx.id = self.word()?;
            tx.principal = self.byte()?;
            tx.sequence = self.word()?;
            tx.failed = self.boolean()?;
            tx.snapshot = self.array()?;
            tx.held = self.array()?;
            let mut missing = false;
            for _ in 0..2 {
                if !self.boolean()? {
                    if self.array::<{ FRAME - 1 }>()? != [0; FRAME - 1] {
                        return Err(invalid("Joint recovery absent savepoint padding"));
                    }
                    missing = true;
                    continue;
                }
                if missing {
                    return Err(invalid("Joint recovery savepoint compaction"));
                }
                tx.savepoints.push(Savepoint::default());
                let frame = tx.savepoints.last_mut().unwrap();
                frame.name = self.array()?;
                frame.held = self.array()?;
            }
        }
        state.require_canonical().map_err(cryptography)?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_grammar_rejects_nonbinary_absent_padding_compaction_and_field_aliases() {
        // Mathematical storage grammar fixture only: these are NOT verified
        // Registry/Link/proof receipts and cannot construct restored candidates.
        let mut payload = Payload {
            old: Zeroizing::new(Registry::default()),
            next: Zeroizing::new(Registry::default()),
            controllers: Zeroizing::new([[1; 32], [2; 32]]),
            salts: Zeroizing::new([[0, 1, 2, Val::ORDER_U64 - 1]; 3]),
            table: Zeroizing::new([3; 32]),
            ids: Zeroizing::new([[4; 32]; 4]),
            ordinals: Zeroizing::new([0, 1, 2, 3]),
            link: predicate_acquire::circuit::Opening {
                mask: [0xff; 32],
                transaction: 1,
                principal: 1,
                controller: [1; 32],
                revision: 0,
                sequence: 1,
                mode: 4,
                wait: 2,
                offset: 0,
                limit: 4,
                projection: 3,
                flags: [[true; 4], [false; 4], [true; 4]],
                salts: [[0, 1, 2, Val::ORDER_U64 - 1]; 3],
            },
        };
        let bytes = payload.encode().unwrap();
        let decoded = Payload::decode(bytes.as_ref()).unwrap();
        assert_eq!(decoded.link.mask[31], 255);
        assert_eq!(decoded.salts[2][3], Val::ORDER_U64 - 1);
        assert_eq!(decoded.link.projection, 3);
        for (at, value) in [
            (8 + 16, 2),                  // transaction presence is Boolean
            (8 + 16 + 1, 1),              // absent transaction padding is zero
            (8 + 16 + TRANSACTION, 1),    // cannot place tx1 after absent tx0
            (PRIVATE - 12 - 3 * 32, 2),   // returned flag is Boolean
            (PRIVATE - LINK + 32 + 8, 3), // principal label must be1/2
        ] {
            let mut bad = Zeroizing::new(*bytes);
            bad[at] = value;
            assert!(
                Payload::decode(bad.as_ref()).is_err(),
                "private grammar offset {at}"
            );
        }
        let mut bad = Zeroizing::new(*bytes);
        bad[PRIVATE - 8..].copy_from_slice(&Val::ORDER_U64.to_le_bytes());
        assert!(Payload::decode(bad.as_ref()).is_err());
        assert!(Payload::decode(&bytes[..PRIVATE - 1]).is_err());
        payload.old.revision = u64::MAX - 1;
        payload.old.allocator = 2;
        for i in 1..=2 {
            payload.old.transactions.push(Transaction {
                id: i,
                principal: i as u8,
                sequence: u64::MAX - 2,
                failed: false,
                snapshot: [i as u8 + 10; 32],
                held: [1; 4],
                savepoints: vec![
                    Savepoint {
                        name: [21; 32],
                        held: [0; 4],
                    },
                    Savepoint {
                        name: [22; 32],
                        held: [1; 4],
                    },
                ],
            });
        }
        payload.next = Zeroizing::new((*payload.old).clone());
        let full = payload.encode().unwrap();
        let decoded = Payload::decode(full.as_ref()).unwrap();
        assert_eq!(*decoded.old, *payload.old);
        assert_eq!(*decoded.next, *payload.next);
        assert_eq!(decoded.old.transactions[1].savepoints[1].name, [22; 32]);
    }
}
