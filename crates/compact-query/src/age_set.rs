//! Owner-side exact selection domain; never serialized into a peer request.
use crate::{AgeRange, Error, Result};

/// A canonical set over all 256 nonnullable age values, independent of SQL syntax.
/// Bit `age % 8` of byte `age / 8` is selected. Every 32-byte pattern is valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgeSet256([u8; 32]);
impl AgeSet256 {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
    pub const fn all() -> Self {
        Self([255; 32])
    }
    pub const fn empty() -> Self {
        Self([0; 32])
    }
    pub fn equal(age: u8) -> Self {
        let mut bytes = [0; 32];
        bytes[usize::from(age) / 8] = 1 << (age % 8);
        Self(bytes)
    }
    pub fn contains(self, age: u8) -> bool {
        self.0[usize::from(age) / 8] & (1 << (age % 8)) != 0
    }
    /// Each selected age exactly once, in ascending order.
    pub fn ages(self) -> impl Iterator<Item = u8> {
        (0..=u8::MAX).filter(move |age| self.contains(*age))
    }
}
impl TryFrom<AgeRange> for AgeSet256 {
    type Error = Error;
    fn try_from(range: AgeRange) -> Result<Self> {
        range.validate()?;
        let mut result = Self::empty();
        for age in range.lower..=range.upper {
            result.0[usize::from(age) / 8] |= 1 << (age % 8);
        }
        Ok(result)
    }
}
