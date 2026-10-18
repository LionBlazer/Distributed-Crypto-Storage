//! Complete PUBLIC native-NTT operands, never SDK protobuf PowerBasis payloads.
use crate::{COEFFICIENTS, DEGREE, Error, MODULI, Result};
use sha2::{Digest, Sha512};

pub struct Input {
    query: [u8; 32],
    components: [Vec<u64>; 3],
    digest: [u8; 64],
}
impl Input {
    pub fn new(query: [u8; 32], components: [Vec<u64>; 3]) -> Result<Self> {
        if components.iter().any(|v| v.len() != COEFFICIENTS) {
            return Err(Error::Shape);
        }
        if components
            .iter()
            .any(|v| v.iter().enumerate().any(|(i, &x)| x >= MODULI[i / DEGREE]))
        {
            return Err(Error::Shape);
        }
        let mut h = Sha512::new();
        h.update(b"DCS/COMPLETE-RELIN/v1/input/nativeNTT3-Q5/full8192/");
        h.update(query);
        for component in &components {
            for value in component {
                h.update(value.to_le_bytes());
            }
        }
        Ok(Self {
            query,
            components,
            digest: h.finalize().into(),
        })
    }
    pub fn query(&self) -> [u8; 32] {
        self.query
    }
    pub fn component(&self, index: usize) -> Option<&[u64]> {
        self.components.get(index).map(Vec::as_slice)
    }
    pub(crate) fn digest(&self) -> [u8; 64] {
        self.digest
    }
}
