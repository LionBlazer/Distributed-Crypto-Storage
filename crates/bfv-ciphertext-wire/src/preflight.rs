//! Borrowed fixed protobuf envelope checked before upstream Poly allocation/NTT.
//! Canonical semantic verification and exact SDK roundtrip remain mandatory afterward.
use crate::{MAX_CIPHERTEXT_BYTES, PACKED_POLYNOMIAL_BYTES, WireError as Error};
use bfv_fixed_geometry::{DEGREE, MODULI};

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn byte(&mut self, expected: u8) -> Result<(), Error> {
        if self.bytes.get(self.offset) != Some(&expected) {
            return Err(Error::InvalidEncoding);
        }
        self.offset += 1;
        Ok(())
    }
    fn varint(&mut self) -> Result<usize, Error> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = *self.bytes.get(self.offset).ok_or(Error::InvalidEncoding)?;
            self.offset += 1;
            if index == 9 && byte > 1 {
                return Err(Error::InvalidEncoding);
            }
            value |= u64::from(byte & 127) << (index * 7);
            if byte & 128 == 0 {
                if index != 0 && byte == 0 {
                    return Err(Error::InvalidEncoding);
                }
                return usize::try_from(value).map_err(|_| Error::InvalidEncoding);
            }
        }
        Err(Error::InvalidEncoding)
    }
    fn blob(&mut self) -> Result<&'a [u8], Error> {
        let length = self.varint()?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Error::InvalidEncoding)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::InvalidEncoding)?;
        self.offset = end;
        Ok(bytes)
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
fn polynomial(bytes: &[u8]) -> Result<(), Error> {
    let mut input = Cursor::new(bytes);
    input.byte(8)?; // representation field1
    input.byte(2)?; // exact Ntt, never NttShoup/PowerBasis
    input.byte(16)?;
    if input.varint()? != DEGREE {
        return Err(Error::InvalidEncoding);
    }
    input.byte(26)?;
    let packed = input.blob()?;
    if packed.len() != PACKED_POLYNOMIAL_BYTES {
        return Err(Error::InvalidEncoding);
    }
    // Fixed LSB-first packed rows; reject EVERY noncanonical residue before SDK NTT.
    let mut offset = 0usize;
    for modulus in MODULI {
        let width = (u64::BITS - (modulus - 1).leading_zeros()) as usize;
        let length = width * DEGREE / 8;
        let row = &packed[offset..offset + length];
        for index in 0..DEGREE {
            let bit = index * width;
            let first = bit / 8;
            let shift = bit % 8;
            let count = (shift + width).div_ceil(8);
            let word = row[first..first + count]
                .iter()
                .enumerate()
                .fold(0u64, |value, (i, byte)| {
                    value | (u64::from(*byte) << (8 * i))
                });
            let value = (word >> shift) & ((1u64 << width) - 1);
            if value >= modulus {
                return Err(Error::InvalidEncoding);
            }
        }
        offset += length;
    }
    // Proto3 false is omitted. True is exactly field4/bool1; preserve BOTH valid policies.
    if !input.finished() {
        input.byte(32)?;
        input.byte(1)?;
    }
    if !input.finished() {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}
/// Check the fixed canonical ciphertext without allocating, decoding an SDK polynomial,
/// transforming coefficients or copying the wire. Exactly two NTT polynomials or one
/// NTT polynomial plus a 32-byte seed are accepted; level zero is canonically omitted.
/// Every packed residue and both canonical variable-time policies are checked.
/// Callers must still run the SDK semantic checks and exact roundtrip afterward.
pub fn validate(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_CIPHERTEXT_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut input = Cursor::new(bytes);
    input.byte(10)?;
    polynomial(input.blob()?)?;
    match input.bytes.get(input.offset) {
        Some(10) => {
            input.byte(10)?;
            polynomial(input.blob()?)?;
        }
        Some(18) => {
            input.byte(18)?;
            if input.blob()?.len() != 32 {
                return Err(Error::InvalidEncoding);
            }
        }
        _ => return Err(Error::InvalidEncoding),
    }
    // level0 is canonically omitted; exactly2 unseeded OR1+seed32, no extra fields.
    if !input.finished() {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}
