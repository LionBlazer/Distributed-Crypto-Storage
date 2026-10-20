//! Fixed owner-private Registry grammar. No envelope, proof, phase or I/O authority.
use crate::private_predicate::{cryptography, invalid};
use registry200_proof::lifecycle::circuit::model::{Registry, Savepoint, Transaction};
use zeroize::Zeroizing;

pub(super) const FRAME: usize = 1 + 32 + 4;
pub(super) const TRANSACTION: usize = 1 + 8 + 1 + 8 + 1 + 32 + 4 + 2 * FRAME;
pub(super) const REGISTRY: usize = 16 + 2 * TRANSACTION;

pub(super) struct Writer<'a> {
    pub(super) bytes: &'a mut [u8],
    pub(super) at: usize,
}
impl Writer<'_> {
    pub(super) fn put(&mut self, bytes: &[u8]) {
        self.bytes[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
    }
    pub(super) fn byte(&mut self, n: u8) {
        self.put(&[n]);
    }
    pub(super) fn word(&mut self, n: u64) {
        self.put(&n.to_le_bytes());
    }
    pub(super) fn registry(&mut self, registry: &Registry) {
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
pub(super) struct Reader<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) at: usize,
}
impl Reader<'_> {
    pub(super) fn array<const N: usize>(&mut self) -> crate::Result<[u8; N]> {
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
    pub(super) fn byte(&mut self) -> crate::Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub(super) fn word(&mut self) -> crate::Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub(super) fn boolean(&mut self) -> crate::Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("Joint recovery nonbinary field")),
        }
    }
    pub(super) fn registry(&mut self) -> crate::Result<Zeroizing<Registry>> {
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
