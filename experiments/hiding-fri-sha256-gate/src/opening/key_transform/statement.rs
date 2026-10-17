//! Public setup/roots only. Neither descriptor nor support proves key authority.
use super::{INPUT_DOMAIN, OUTPUT_DOMAIN};
use crate::backend::{Error, Val, profile_digest};
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256};

pub(in crate::opening) const PUBLIC_VALUES: usize = 8 + 17 + 4 + 4;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::opening) struct SetupDescriptor {
    pub(in crate::opening) database: [u8; 16],
    pub(in crate::opening) key_domain: [u8; 16],
    pub(in crate::opening) public_setup_digest: [u8; 32],
    pub(in crate::opening) key_epoch: u32,
}
impl SetupDescriptor {
    fn bytes(&self) -> Vec<u8> {
        self.database
            .into_iter()
            .chain(self.key_domain)
            .chain(self.public_setup_digest)
            .chain(self.key_epoch.to_le_bytes())
            .collect()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::opening) struct Expected {
    pub(in crate::opening) descriptor: SetupDescriptor,
    pub(in crate::opening) coefficients: [Val; 4],
}
#[derive(Clone)]
pub(in crate::opening) struct Statement {
    pub(in crate::opening) expected: Expected,
    pub(in crate::opening) transformed: [Val; 4],
}
fn words(bytes: &[u8]) -> impl Iterator<Item = Val> + '_ {
    assert_eq!(bytes.len() % 4, 0);
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| Val::from_u32(u32::from_le_bytes(*b)))
}
impl Statement {
    pub(in crate::opening) fn require_expected(&self, expected: &Expected) -> Result<(), Error> {
        if &self.expected != expected {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(in crate::opening) fn contexts(&self) -> [[Val; 8]; 2] {
        core::array::from_fn(|role| {
            let mut h = Sha256::new();
            h.update(b"DCS/BFV-KEY-TRANSFORM-CONTEXT/v1");
            let domain = if role == 0 {
                INPUT_DOMAIN
            } else {
                OUTPUT_DOMAIN
            };
            h.update((domain.len() as u32).to_le_bytes());
            h.update(domain);
            h.update(profile_digest(Kind::BfvKeyTransform));
            h.update(self.expected.descriptor.bytes());
            // No circular output digest; the derived-root context pins SAME input anchor.
            if role == 1 {
                for v in self.expected.coefficients {
                    h.update(v.as_canonical_u64().to_le_bytes());
                }
            }
            words(&h.finalize()).collect::<Vec<_>>().try_into().unwrap()
        })
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::BfvKeyTransform
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::KeyTransform(Box::new(super::air::TransformAir::new(self)))
    }
    fn public_values(&self) -> Vec<Val> {
        words(&profile_digest(self.kind()))
            .chain(words(&self.expected.descriptor.bytes()))
            .chain(self.expected.coefficients)
            .chain(self.transformed)
            .collect()
    }
}
