//! Fixed owner-private retry grammar. These bytes prove no Registry or SQL result.
use super::super::{MAX_RECORDS, OwnerVaultError, VaultResult, hash};
use crate::private_predicate::source::locking::joint::control::JointControlOutcome;
use zeroize::{Zeroize, Zeroizing};

pub(super) const CLIENTS_BYTES: usize = 200;
pub(super) const CALL_BYTES: usize = 56;

/// Independently configured logical retry identity, not client authentication.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct JointSqlClientBinding {
    pub(super) id: [u8; 32],
    pub(super) principal: u8,
}
impl JointSqlClientBinding {
    pub fn new(id: [u8; 32], principal: u8) -> VaultResult<Self> {
        if id == [0; 32] || !(1..=2).contains(&principal) {
            return Err(OwnerVaultError::Pins);
        }
        Ok(Self { id, principal })
    }
    pub fn client_id(self) -> [u8; 32] {
        self.id
    }
    pub fn principal(self) -> u8 {
        self.principal
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(in crate::private_predicate::source::locking::joint::vault) struct Bindings(
    pub [JointSqlClientBinding; 2],
);
impl Bindings {
    pub(super) fn new(entries: [JointSqlClientBinding; 2]) -> VaultResult<Self> {
        for e in entries {
            JointSqlClientBinding::new(e.id, e.principal)?;
        }
        if entries[0].id >= entries[1].id {
            return Err(OwnerVaultError::Pins);
        }
        Ok(Self(entries))
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn identity(&self) -> [u8; 32] {
        hash(&[
            b"DCS/Joint-SQL-Host/client-bindings/v3",
            &self.0[0].id,
            &[self.0[0].principal],
            &self.0[1].id,
            &[self.0[1].principal],
        ])
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::private_predicate::source::locking::joint::vault) enum Verb {
    Begin,
    EndClose,
    EndAbort,
    Acquire,
}
impl Verb {
    fn tag(self) -> u8 {
        match self {
            Self::Begin => 1,
            Self::EndClose => 2,
            Self::EndAbort => 3,
            Self::Acquire => 4,
        }
    }
    fn decode(tag: u8) -> VaultResult<Self> {
        match tag {
            1 => Ok(Self::Begin),
            2 => Ok(Self::EndClose),
            3 => Ok(Self::EndAbort),
            4 => Ok(Self::Acquire),
            _ => Err(OwnerVaultError::Encoding),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::private_predicate::source::locking::joint::vault) struct Client {
    pub binding: JointSqlClientBinding,
    pub active: u64,
    pub last: u64,
    pub digest: [u8; 32],
    pub record: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::private_predicate::source::locking::joint::vault) struct Call {
    pub slot: usize,
    pub verb: Verb,
    pub sequence: u64,
    pub digest: [u8; 32],
    pub transaction: u64,
}
impl Call {
    fn encode(self) -> Zeroizing<[u8; CALL_BYTES]> {
        let mut b = Zeroizing::new([0; CALL_BYTES]);
        b[0] = 1;
        b[1] = self.slot as u8;
        b[2] = self.verb.tag();
        b[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        b[16..48].copy_from_slice(&self.digest);
        b[48..56].copy_from_slice(&self.transaction.to_le_bytes());
        b
    }
    fn decode(b: &[u8]) -> VaultResult<Option<Self>> {
        if b.len() != CALL_BYTES {
            return Err(OwnerVaultError::Encoding);
        }
        if b.iter().all(|v| *v == 0) {
            return Ok(None);
        }
        if b[0] != 1 || b[1] > 1 || b[3..8] != [0; 5] {
            return Err(OwnerVaultError::Encoding);
        }
        let c = Self {
            slot: b[1] as usize,
            verb: Verb::decode(b[2])?,
            sequence: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            digest: b[16..48].try_into().unwrap(),
            transaction: u64::from_le_bytes(b[48..56].try_into().unwrap()),
        };
        if c.sequence == 0 || c.transaction == 0 {
            return Err(OwnerVaultError::Encoding);
        }
        Ok(Some(c))
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(in crate::private_predicate::source::locking::joint::vault) struct Managed {
    pub clients: [Client; 2],
    pub call: Option<Call>,
}
impl Drop for Managed {
    fn drop(&mut self) {
        for c in &mut self.clients {
            c.active.zeroize();
            c.last.zeroize();
            c.digest.zeroize();
            c.record.zeroize();
        }
        if let Some(c) = &mut self.call {
            c.sequence.zeroize();
            c.digest.zeroize();
            c.transaction.zeroize();
        }
    }
}
impl Managed {
    pub(in crate::private_predicate::source::locking::joint::vault) fn empty(
        bindings: &Bindings,
    ) -> Self {
        Self {
            clients: bindings.0.map(|binding| Client {
                binding,
                active: 0,
                last: 0,
                digest: [0; 32],
                record: 0,
            }),
            call: None,
        }
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn encode(
        &self,
    ) -> Zeroizing<[u8; CLIENTS_BYTES + CALL_BYTES]> {
        let mut b = Zeroizing::new([0; CLIENTS_BYTES + CALL_BYTES]);
        b[..8].copy_from_slice(b"JSQLCL03");
        for (i, c) in self.clients.iter().enumerate() {
            let s = 8 + 96 * i;
            b[s..s + 32].copy_from_slice(&c.binding.id);
            b[s + 32] = c.binding.principal;
            b[s + 40..s + 48].copy_from_slice(&c.active.to_le_bytes());
            b[s + 48..s + 56].copy_from_slice(&c.last.to_le_bytes());
            b[s + 56..s + 88].copy_from_slice(&c.digest);
            b[s + 88..s + 96].copy_from_slice(&c.record.to_le_bytes());
        }
        if let Some(c) = self.call {
            b[CLIENTS_BYTES..].copy_from_slice(c.encode().as_ref());
        }
        b
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn decode(
        b: &[u8],
        bindings: &Bindings,
    ) -> VaultResult<Self> {
        if b.len() != CLIENTS_BYTES + CALL_BYTES || &b[..8] != b"JSQLCL03" {
            return Err(OwnerVaultError::Encoding);
        }
        let mut value = Self::empty(bindings);
        for (i, c) in value.clients.iter_mut().enumerate() {
            let s = 8 + 96 * i;
            if b[s..s + 32] != c.binding.id
                || b[s + 32] != c.binding.principal
                || b[s + 33..s + 40] != [0; 7]
            {
                return Err(OwnerVaultError::Pins);
            }
            c.active = u64::from_le_bytes(b[s + 40..s + 48].try_into().unwrap());
            c.last = u64::from_le_bytes(b[s + 48..s + 56].try_into().unwrap());
            c.digest = b[s + 56..s + 88].try_into().unwrap();
            c.record = u64::from_le_bytes(b[s + 88..s + 96].try_into().unwrap());
            if (c.last == 0) != (c.record == 0)
                || (c.last == 0 && c.digest != [0; 32])
                || c.record > MAX_RECORDS as u64
            {
                return Err(OwnerVaultError::Encoding);
            }
        }
        if value.clients[0].active != 0 && value.clients[0].active == value.clients[1].active {
            return Err(OwnerVaultError::Pins);
        }
        value.call = Call::decode(&b[CLIENTS_BYTES..])?;
        Ok(value)
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn start(
        &self,
        c: Call,
    ) -> VaultResult<Self> {
        let client = self.clients.get(c.slot).ok_or(OwnerVaultError::Pins)?;
        if self.call.is_some()
            || c.sequence
                != client
                    .last
                    .checked_add(1)
                    .ok_or(OwnerVaultError::ResourceLimit)?
            || c.transaction == 0
        {
            return Err(OwnerVaultError::Cas);
        }
        match c.verb {
            Verb::Begin if client.active == 0 => {}
            Verb::EndClose | Verb::EndAbort | Verb::Acquire
                if client.active == c.transaction && client.active != 0 => {}
            _ => return Err(OwnerVaultError::Phase),
        }
        let mut next = self.clone();
        next.call = Some(c);
        Ok(next)
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn completed(
        &self,
        record: u64,
        outcome: Option<JointControlOutcome>,
    ) -> VaultResult<Self> {
        if record == 0 || record > MAX_RECORDS as u64 {
            return Err(OwnerVaultError::ResourceLimit);
        }
        let call = self.call.ok_or(OwnerVaultError::Encoding)?;
        let mut next = self.clone();
        let client = &mut next.clients[call.slot];
        match (call.verb, outcome) {
            (Verb::Begin, Some(JointControlOutcome::Begun)) if client.active == 0 => {
                client.active = call.transaction
            }
            (
                Verb::EndClose,
                Some(JointControlOutcome::ClosedRegistry | JointControlOutcome::AbortedRegistry),
            )
            | (Verb::EndAbort, Some(JointControlOutcome::AbortedRegistry))
                if client.active == call.transaction =>
            {
                client.active = 0
            }
            (Verb::Acquire, None) if client.active == call.transaction => {}
            _ => return Err(OwnerVaultError::Pins),
        }
        client.last = call.sequence;
        client.digest = call.digest;
        client.record = record;
        Ok(next)
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn acknowledged(&self) -> Self {
        let mut next = self.clone();
        next.call = None;
        next
    }
    pub(in crate::private_predicate::source::locking::joint::vault) fn rows(
        &self,
    ) -> [(u64, u8); 2] {
        self.clients.map(|c| (c.active, c.binding.principal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Codec tests supply no Registry acceptance. Actual bank/proof/QC binding
    // is exercised by the separate owning Host tests.
    #[test]
    fn fixed_client_grammar_rejects_padding_counter_and_reference_overflow() {
        let a = JointSqlClientBinding::new([1; 32], 1).unwrap();
        let b = JointSqlClientBinding::new([2; 32], 1).unwrap();
        let bindings = Bindings::new([a, b]).unwrap();
        assert!(Bindings::new([b, a]).is_err());
        assert!(Bindings::new([a, a]).is_err());
        assert!(JointSqlClientBinding::new([0; 32], 1).is_err());
        let empty = Managed::empty(&bindings);
        let bytes = empty.encode();
        assert_eq!(bytes.len(), 256);
        assert!(Managed::decode(bytes.as_ref(), &bindings).unwrap() == empty);
        for index in [41, 137, 200, 203, 255] {
            let mut changed = Zeroizing::new(*bytes);
            changed[index] = 1;
            assert!(
                Managed::decode(changed.as_ref(), &bindings).is_err(),
                "byte {index}"
            );
        }
        let c = Call {
            slot: 0,
            verb: Verb::Begin,
            sequence: 1,
            digest: [3; 32],
            transaction: 1,
        };
        let pending = empty.start(c).unwrap();
        assert!(Managed::decode(pending.encode().as_ref(), &bindings).unwrap() == pending);
        let completed = pending
            .completed(3, Some(JointControlOutcome::Begun))
            .unwrap();
        let mut invalid = completed.encode();
        invalid[96..104].copy_from_slice(&129u64.to_le_bytes());
        assert!(Managed::decode(invalid.as_ref(), &bindings).is_err());
        let mut duplicate = completed.encode();
        duplicate[144..152].copy_from_slice(&1u64.to_le_bytes());
        assert!(Managed::decode(duplicate.as_ref(), &bindings).is_err());
        assert!(matches!(
            pending.completed(129, Some(JointControlOutcome::Begun)),
            Err(OwnerVaultError::ResourceLimit)
        ));
        let mut exhausted = empty.clone();
        exhausted.clients[0].last = u64::MAX;
        assert!(matches!(
            exhausted.start(c),
            Err(OwnerVaultError::ResourceLimit)
        ));
        let wrong = Bindings::new([a, JointSqlClientBinding::new([2; 32], 2).unwrap()]).unwrap();
        assert!(matches!(
            Managed::decode(bytes.as_ref(), &wrong),
            Err(OwnerVaultError::Pins)
        ));
    }
}
