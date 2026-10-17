//! Independent key-root and complete public ciphertext binding; no inferred key authority.
use super::{
    OUTPUT_DOMAIN,
    ciphertext::{self, CanonicalCiphertext},
};
use crate::backend::{Error, Val, profile_digest};
use crate::opening::key_transform::statement::Statement as KeyStatement;
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha256};

pub(in crate::opening) const PUBLIC_VALUES: usize = 62;
pub(in crate::opening) const INPUT_ROOT: usize = 37;
pub(in crate::opening) const OUTPUT_ROOT: usize = 58;

#[derive(Clone)]
pub(in crate::opening) struct Expected {
    key: KeyStatement,
    ciphertext: CanonicalCiphertext,
    request: [u8; 32],
}
impl Expected {
    pub(in crate::opening) fn new(
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
    pub(in crate::opening) fn key(&self) -> &KeyStatement {
        &self.key
    }
    pub(in crate::opening) fn ciphertext(&self) -> &CanonicalCiphertext {
        &self.ciphertext
    }
    pub(in crate::opening) fn request(&self) -> [u8; 32] {
        self.request
    }
    fn same(&self, other: &Self) -> bool {
        self.key.expected == other.key.expected
            && self.key.transformed == other.key.transformed
            && self.ciphertext == other.ciphertext
            && self.request == other.request
    }
}
#[derive(Clone)]
pub(in crate::opening) struct Statement {
    pub(in crate::opening) expected: Expected,
    pub(in crate::opening) result: [Val; 4],
}
pub(in crate::opening) fn words(bytes: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[4 * i..4 * i + 4].try_into().unwrap(),
        ))
    })
}
impl Statement {
    pub(in crate::opening) fn require_expected(&self, expected: &Expected) -> Result<(), Error> {
        if !self.expected.same(expected) {
            return Err(Error::Shape);
        }
        Ok(())
    }
    pub(in crate::opening) fn contexts(&self) -> [[Val; 8]; 2] {
        let mut h = Sha256::new();
        h.update(b"DCS/BFV-BASIS-CONVOLUTION-CONTEXT/v1");
        h.update((OUTPUT_DOMAIN.len() as u32).to_le_bytes());
        h.update(OUTPUT_DOMAIN);
        h.update(profile_digest(Kind::BfvBasisConvolution));
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
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::BfvBasisConvolution
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::BasisConvolution(Box::new(super::air::ConvolutionAir::new(self)))
    }
    fn public_values(&self) -> Vec<Val> {
        words(&profile_digest(self.kind()))
            .into_iter()
            .chain(self.expected.key.public_values())
            .chain(words(&self.expected.request))
            .chain(self.contexts()[1])
            .chain([Val::from_usize(self.expected.ciphertext.basis())])
            .chain(self.result)
            .collect()
    }
}
