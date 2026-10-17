//! Sealed Return168 producer and full canonical ciphertext identities; no root cast.
use super::{NOISE_DOMAIN, air, basis, returned};
use crate::backend::{Error, Val, profile_digest};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeField64;
use sha2::{Digest, Sha256};

pub(in crate::opening) const PUBLIC_VALUES: usize = 44;
#[derive(Clone)]
pub(in crate::opening) struct Expected {
    pub(super) producer: returned::statement::Expected,
    pub(super) encoding: returned::statement::Statement,
    pub(in crate::opening) bases: [basis::statement::Statement; 5],
}
impl Expected {
    pub(in crate::opening) fn new(
        producer: returned::statement::Expected,
        encoding: returned::statement::Statement,
        bases: [basis::statement::Statement; 5],
    ) -> Result<Self, Error> {
        let out = Self {
            producer,
            encoding,
            bases,
        };
        out.validate()?;
        Ok(out)
    }
    pub(in crate::opening) fn validate(&self) -> Result<(), Error> {
        // This checks BOTH independently supplied sealed parent contracts and all
        // source field boundaries before converting either to public words.
        self.encoding.require_expected(&self.producer)?;
        if self.encoding.kind() != Kind::LockReturnedEncoding {
            return Err(Error::Shape);
        }
        let lock = self.producer.lock();
        let first = &self.bases[0].expected;
        if first.key().expected.descriptor.database.as_slice()
            != &lock.expected.source.heads[0][8..24]
        {
            return Err(Error::Shape);
        }
        for (i, s) in self.bases.iter().enumerate() {
            let e = &s.expected;
            if e.ciphertext().basis() != i
                || e.request() != *lock.expected.request()
                || e.key().public_values() != first.key().public_values()
                || e.ciphertext().bytes() != first.ciphertext().bytes()
                || e.ciphertext().parameter_bytes() != first.ciphertext().parameter_bytes()
                || e.ciphertext().b_coefficients().len() != super::N
            {
                return Err(Error::Shape);
            }
        }
        Ok(())
    }
    pub(in crate::opening) fn producer(&self) -> &returned::statement::Expected {
        &self.producer
    }
    pub(in crate::opening) fn encoding(&self) -> &returned::statement::Statement {
        &self.encoding
    }
    fn same(&self, other: &Self) -> Result<(), Error> {
        self.validate()?;
        other.validate()?;
        self.encoding.require_expected(&other.producer)?;
        other.encoding.require_expected(&self.producer)?;
        // require_expected deliberately checks the parent, not the child output:
        // the independently expected COMPLETE PV128 must also pin exact C_enc.
        if self.encoding.public_values() != other.encoding.public_values() {
            return Err(Error::Shape);
        }
        for (a, b) in self.bases.iter().zip(&other.bases) {
            a.require_expected(&b.expected)?;
            if a.result != b.result {
                return Err(Error::Shape);
            }
        }
        Ok(())
    }
    pub(super) fn context(&self) -> [Val; 8] {
        let mut h = Sha256::new();
        h.update(b"DCS/BFV-LOCK-RETURNED-FORMATION-CONTEXT/v1");
        h.update(profile_digest(Kind::BfvLockReturnedFormation));
        for values in core::iter::once(self.encoding.public_values())
            .chain(self.bases.iter().map(PublicStatement::public_values))
        {
            h.update((values.len() as u64).to_le_bytes());
            for value in values {
                h.update(value.as_canonical_u64().to_le_bytes());
            }
        }
        for bytes in [
            self.bases[0].expected.ciphertext().parameter_bytes(),
            self.bases[0].expected.ciphertext().bytes(),
        ] {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        h.update(
            b"successful-Return168/original12/age0..4/amount4096..4100/presence512..516/raw-W8192",
        );
        basis::statement::words(&h.finalize().into())
    }
}
#[derive(Clone)]
pub(in crate::opening) struct Statement {
    pub(in crate::opening) expected: Expected,
    pub(in crate::opening) noise: [Val; 4],
}
impl Statement {
    pub(in crate::opening) fn require_expected(&self, expected: &Expected) -> Result<(), Error> {
        self.expected.same(expected)
    }
    pub(in crate::opening) fn noise_context(&self) -> [Val; 8] {
        let mut h = Sha256::new();
        h.update(NOISE_DOMAIN);
        for value in self.expected.context() {
            h.update(value.as_canonical_u64().to_le_bytes());
        }
        basis::statement::words(&h.finalize().into())
    }
    pub(in crate::opening) fn contexts(&self) -> [[Val; 8]; 7] {
        core::array::from_fn(|stream| match stream {
            0..=4 => self.expected.bases[stream].contexts()[1],
            5 => self.expected.encoding.context(),
            _ => self.noise_context(),
        })
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::BfvLockReturnedFormation
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::LocalFormation(Box::new(air::LocalAir::returned(self)))
    }
    fn public_values(&self) -> Vec<Val> {
        basis::statement::words(&profile_digest(self.kind()))
            .into_iter()
            .chain(self.expected.context())
            .chain(self.expected.encoding.encoded)
            .chain(self.expected.bases.iter().flat_map(|s| s.result))
            .chain(self.noise)
            .collect()
    }
}
