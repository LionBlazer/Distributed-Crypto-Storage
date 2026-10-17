//! Independent key-root and complete public ciphertext binding; no inferred key authority.
use super::ciphertext::{self, CanonicalCiphertext};
use crate::backend::{Error, Val, profile_digest};
use crate::opening::key_transform::statement::Statement as KeyStatement;
use crate::primitive::{Kind, PrimitiveAir, PublicStatement};
use p3_field::PrimeCharacteristicRing;

pub(in crate::opening) const PUBLIC_VALUES: usize = 62;
pub(in crate::opening) const INPUT_ROOT: usize = 37;
pub(in crate::opening) const OUTPUT_ROOT: usize = 58;
const _: () = assert!(
    PUBLIC_VALUES == bfv_basis_convolution::PUBLIC_VALUES
        && INPUT_ROOT == bfv_basis_convolution::INPUT_ROOT
        && OUTPUT_ROOT == bfv_basis_convolution::OUTPUT_ROOT
);

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
    pub(in crate::opening) fn shared(&self) -> bfv_basis_convolution::Statement {
        bfv_basis_convolution::Statement {
            expected: bfv_basis_convolution::Expected::from_ciphertext(
                self.expected.key.shared(),
                self.expected.ciphertext.clone(),
                self.expected.request,
            )
            .expect("validated fixed ciphertext and descriptor"),
            result: self.result,
        }
    }
    pub(in crate::opening) fn contexts(&self) -> [[Val; 8]; 2] {
        self.shared().contexts()
    }
}
impl PublicStatement for Statement {
    fn kind(&self) -> Kind {
        Kind::BfvBasisConvolution
    }
    fn air(&self) -> PrimitiveAir {
        PrimitiveAir::BasisConvolution(Box::new(super::air::ConvolutionAir::new(&self.shared())))
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
