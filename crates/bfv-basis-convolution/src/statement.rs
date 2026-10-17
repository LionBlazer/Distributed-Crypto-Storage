//! Independent key-root and complete public ciphertext binding; no inferred key authority.
use super::{
    OUTPUT_DOMAIN,
    ciphertext::{self, CanonicalCiphertext},
};
use crate::profile_digest;
use bfv_hiding_stark::{Error, Val};
use bfv_key_transform::Statement as KeyStatement;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256};

pub const PUBLIC_VALUES: usize = 62;
pub const INPUT_ROOT: usize = 37;
pub const OUTPUT_ROOT: usize = 58;

/// Independently selected complete public wire/request/basis, never an external evaluation table.
#[derive(Clone)]
pub struct PublicInput {
    ciphertext: CanonicalCiphertext,
    request: [u8; 32],
}
impl PublicInput {
    pub fn new(
        parameters: &[u8],
        ciphertext: &[u8],
        request: [u8; 32],
        basis: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            ciphertext: CanonicalCiphertext::decode(parameters, ciphertext, basis)?,
            request,
        })
    }
    pub(crate) fn expected(&self, key: KeyStatement) -> Result<Expected, Error> {
        Expected::from_ciphertext(key, self.ciphertext.clone(), self.request)
    }
}
#[derive(Clone)]
pub struct Expected {
    key: KeyStatement,
    ciphertext: CanonicalCiphertext,
    request: [u8; 32],
}
impl Expected {
    pub fn new(
        key: KeyStatement,
        parameter_bytes: &[u8],
        bytes: &[u8],
        request: [u8; 32],
        basis: usize,
    ) -> Result<Self, Error> {
        if key.expected.descriptor.public_setup_digest != ciphertext::setup_digest() {
            return Err(Error::Shape);
        }
        Ok(Self {
            key,
            ciphertext: CanonicalCiphertext::decode(parameter_bytes, bytes, basis)?,
            request,
        })
    }
    pub fn from_ciphertext(
        key: KeyStatement,
        ciphertext: CanonicalCiphertext,
        request: [u8; 32],
    ) -> Result<Self, Error> {
        if key.expected.descriptor.public_setup_digest != ciphertext::setup_digest() {
            return Err(Error::Shape);
        }
        Ok(Self {
            key,
            ciphertext,
            request,
        })
    }
    /// Fixed-domain, length-delimited binding of the COMPLETE original public wire.
    pub fn ciphertext_binding(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"DCS/BFV-BASIS-CANONICAL-CIPHERTEXT/v1");
        for bytes in [self.ciphertext.parameter_bytes(), self.ciphertext.bytes()] {
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        hash.finalize().into()
    }
    pub fn key(&self) -> &KeyStatement {
        &self.key
    }
    pub fn ciphertext(&self) -> &CanonicalCiphertext {
        &self.ciphertext
    }
    pub fn request(&self) -> [u8; 32] {
        self.request
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        self.key.expected == other.key.expected
            && self.key.transformed == other.key.transformed
            && self.ciphertext == other.ciphertext
            && self.request == other.request
    }
}
#[derive(Clone)]
pub struct Statement {
    pub expected: Expected,
    pub result: [Val; 4],
}
pub fn words(bytes: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[4 * i..4 * i + 4].try_into().unwrap(),
        ))
    })
}
impl Statement {
    pub fn require_expected(&self, expected: &Expected) -> Result<(), Error> {
        if !self.expected.same(expected) {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub fn contexts(&self) -> [[Val; 8]; 2] {
        let mut h = Sha256::new();
        h.update(b"DCS/BFV-BASIS-CONVOLUTION-CONTEXT/v1");
        h.update((OUTPUT_DOMAIN.len() as u32).to_le_bytes());
        h.update(OUTPUT_DOMAIN);
        h.update(profile_digest());
        for value in self.expected.key.public_values() {
            h.update(value.as_canonical_u64().to_le_bytes());
        }
        h.update(self.expected.request);
        h.update((self.expected.ciphertext.basis() as u32).to_le_bytes());
        h.update(ciphertext::MODULI[self.expected.ciphertext.basis()].to_le_bytes());
        h.update(0u32.to_le_bytes()); // fixed level0
        for bytes in [
            self.expected.ciphertext.parameter_bytes(),
            self.expected.ciphertext.bytes(),
        ] {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        // Exact original producer role1 context and raw field encoding, not a relabelled root.
        [self.expected.key.contexts()[1], words(&h.finalize().into())]
    }
}
impl Statement {
    pub fn air(&self) -> crate::circuit::ConvolutionAir {
        crate::circuit::ConvolutionAir::new(self)
    }
    pub fn public_values(&self) -> Vec<Val> {
        words(&profile_digest())
            .into_iter()
            .chain(self.expected.key.public_values())
            .chain(words(&self.expected.request))
            .chain(self.contexts()[1])
            .chain([Val::from_usize(self.expected.ciphertext.basis())])
            .chain(self.result)
            .collect()
    }
}
