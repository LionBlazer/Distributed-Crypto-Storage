//! Public setup/roots only. Neither descriptor nor support proves key authority.
use super::{INPUT_DOMAIN, OUTPUT_DOMAIN};
use crate::profile_digest;
use bfv_hiding_stark::{Error, Val};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256};

pub const PUBLIC_VALUES: usize = 8 + 17 + 4 + 4;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupDescriptor {
    pub database: [u8; 16],
    pub key_domain: [u8; 16],
    pub public_setup_digest: [u8; 32],
    pub key_epoch: u32,
}
impl SetupDescriptor {
    pub fn bytes(&self) -> Vec<u8> {
        self.database
            .into_iter()
            .chain(self.key_domain)
            .chain(self.public_setup_digest)
            .chain(self.key_epoch.to_le_bytes())
            .collect()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    pub descriptor: SetupDescriptor,
    pub coefficients: [Val; 4],
}
#[derive(Clone)]
pub struct Statement {
    pub expected: Expected,
    pub transformed: [Val; 4],
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
    pub fn require_expected(&self, expected: &Expected) -> Result<(), Error> {
        if &self.expected != expected {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub fn contexts(&self) -> [[Val; 8]; 2] {
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
            h.update(profile_digest());
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
impl Statement {
    pub fn public_values(&self) -> Vec<Val> {
        words(&profile_digest())
            .chain(words(&self.expected.descriptor.bytes()))
            .chain(self.expected.coefficients)
            .chain(self.transformed)
            .collect()
    }
    pub fn air(&self) -> crate::circuit::TransformAir {
        crate::circuit::TransformAir::new(self)
    }
}
