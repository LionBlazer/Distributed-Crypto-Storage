//! Full independent parent, separate SQL identity, and the new encoding commitment.
use super::super::statement as lifecycle;
use super::{air::EncodingAir, compiler};
use crate::backend::{Error, Val, profile_digest};
use crate::opening::statement as source;
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};
pub(super) const PUBLIC_VALUES: usize = 136;
#[derive(Clone)]
pub(in crate::opening) struct Expected {
    pub(super) parent: lifecycle::Expected,
    pub(super) producer: lifecycle::Statement,
    pub(super) sql_identity: [u8; 32],
    pub(super) projection: u8,
}
impl Expected {
    pub(super) fn require_contract(&self) -> Result<(), Error> {
        self.parent.require_contract()?;
        self.producer.require_expected(&self.parent)?;
        if !matches!(self.parent.phase, lifecycle::Phase::Transition { .. })
            || !(1..=3).contains(&self.projection)
        {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(super) fn require_same(&self, other: &Self) -> Result<(), Error> {
        compiler::require_same(self, other)
    }
}
#[derive(Clone)]
pub(in crate::opening) struct Statement {
    pub(super) expected: Expected,
    pub(super) encoded: [Val; 4],
}
impl Statement {
    pub(super) fn new(expected: Expected, encoded: [Val; 4]) -> Self {
        Self { expected, encoded }
    }
    pub(super) fn require_expected(&self, e: &Expected) -> Result<(), Error> {
        self.expected.require_same(e)
    }
    pub(super) fn context(&self) -> [Val; 8] {
        let mut h = Sha256::new();
        h.update(b"DCS/Registry200/Result144-originals-full8192W/context/v1");
        h.update(profile_digest(Kind::RegistryLifecycleEncoding));
        h.update(self.expected.sql_identity);
        for x in self.expected.producer.public_values() {
            h.update(x.as_canonical_u64().to_le_bytes());
        }
        source::words(&<[u8; 32]>::from(h.finalize()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::RegistryLifecycleEncoding
    }
    fn public_values(&self) -> Vec<Val> {
        source::words(&profile_digest(self.kind()))
            .chain(self.expected.producer.public_values())
            .chain(source::words(&self.expected.sql_identity))
            .chain(self.encoded)
            .collect()
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::LifecycleEncoding(Box::new(EncodingAir::new(self)))
    }
}

impl Statement {
    pub(in crate::opening) fn formation_expected(&self) -> &Expected {
        &self.expected
    }
    pub(in crate::opening) fn formation_source(&self) -> &source::Statement {
        &self.expected.parent.source
    }
    pub(in crate::opening) fn require_complete_formation_statement(
        &self,
        other: &Self,
    ) -> Result<(), Error> {
        self.expected.require_same(&other.expected)?;
        if self.public_values() != other.public_values() {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(in crate::opening) fn formation_commitment(
        &self,
    ) -> Result<bfv_ciphertext_formation::EncodedCommitment, Error> {
        self.expected.require_contract()?;
        let mut h = Sha256::new();
        h.update(b"DCS/Registry200/FULL-Encoding136-compiled-projection-formation-producer/v1");
        // Projection is independently compiled metadata, outside the original Encoding PV136.
        h.update([self.expected.projection]);
        let values = self.public_values();
        h.update((values.len() as u64).to_le_bytes());
        for v in values {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        let source = self.formation_source();
        for v in source.public_values() {
            h.update(v.as_canonical_u64().to_le_bytes());
        }
        for bytes in source
            .heads
            .iter()
            .map(|b| b.as_slice())
            .chain(source.packets.iter().map(|b| b.as_slice()))
        {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        bfv_ciphertext_formation::EncodedCommitment::new(
            h.finalize().into(),
            self.context().map(|v| v.as_canonical_u64()),
            self.encoded.map(|v| v.as_canonical_u64()),
        )
    }
}

#[cfg(test)]
impl Statement {
    pub(in crate::opening) fn formation_context_attack_cases(&self) -> Vec<Self> {
        use p3_field::PrimeCharacteristicRing;
        let mut values = Vec::new();
        for case in 0..17 {
            let mut s = self.clone();
            let e = &mut s.expected;
            match case {
                0 => e.parent.source.request[31] ^= 1,
                1 => e.producer.next[3] += Val::ONE,
                2 => e.producer.result[3] += Val::ONE,
                3 => e.sql_identity[31] ^= 1,
                4 => e.projection = if e.projection == 1 { 2 } else { 1 },
                5 => *e.parent.source.packets[0].last_mut().unwrap() ^= 1,
                6 => *e.parent.source.packets[1].last_mut().unwrap() ^= 1,
                7 => *e.parent.source.heads[0].last_mut().unwrap() ^= 1,
                8 => *e.parent.source.heads[1].last_mut().unwrap() ^= 1,
                9 => e.parent.genesis[31] ^= 1,
                10 => e.parent.parent[31] ^= 1,
                11 => e.parent.enrollment[3] += Val::ONE,
                12 => {
                    if let lifecycle::Phase::Transition { old, .. } = &mut e.parent.phase {
                        old[3] += Val::ONE;
                    }
                }
                13 => {
                    if let lifecycle::Phase::Transition { command, .. } = &mut e.parent.phase {
                        command[3] += Val::ONE;
                    }
                }
                14 => e.parent.source.key_commitment[3] += Val::ONE,
                15 => e.parent.source.open_commitment[3] += Val::ONE,
                _ => {
                    e.parent.source.packets[1].pop();
                }
            }
            values.push(s);
        }
        values
    }
}
