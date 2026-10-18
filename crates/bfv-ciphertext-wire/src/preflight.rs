//! Borrowed fixed protobuf envelope checked before upstream Poly allocation/NTT.
//! Existing SDK consumers retain their semantic and exact-roundtrip checks.
use crate::{
    CiphertextView, MAX_CIPHERTEXT_BYTES, PACKED_POLYNOMIAL_BYTES, SecondComponent,
    StoredPowerBasis, WireError as Error,
};
use bfv_fixed_geometry::{DEGREE, MODULI};

struct ParsedPolynomial<'a> {
    packed: &'a [u8],
    variable_time: bool,
}
enum ParsedSecond<'a> {
    Stored(ParsedPolynomial<'a>),
    Seed(&'a [u8; 32]),
}

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
fn polynomial(bytes: &[u8]) -> Result<ParsedPolynomial<'_>, Error> {
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
    // Proto3 false is omitted. True is exactly field4/bool1; preserve BOTH valid policies.
    let variable_time = !input.finished();
    if variable_time {
        input.byte(32)?;
        input.byte(1)?;
    }
    if !input.finished() {
        return Err(Error::InvalidEncoding);
    }
    // The same bounded iterator is used for validation and public row reads.
    // Every value is checked before any complete view can reach a caller.
    for (index, modulus) in MODULI.into_iter().enumerate() {
        if crate::view::packed_row(packed, index)
            .ok_or(Error::InvalidEncoding)?
            .any(|value| value >= modulus)
        {
            return Err(Error::InvalidEncoding);
        }
    }
    Ok(ParsedPolynomial {
        packed,
        variable_time,
    })
}
/// Borrow one complete canonical ciphertext after checking all fields and residues.
///
/// The fixed Ntt-tagged polynomial payloads contain PowerBasis coefficients.
/// Exactly two stored polynomials, or one stored polynomial plus a borrowed
/// seed32, are accepted. Level zero is canonically omitted. No allocation,
/// polynomial transform, seed expansion or SDK decoding runs here.
pub fn parse(bytes: &[u8]) -> Result<CiphertextView<'_>, Error> {
    if bytes.len() > MAX_CIPHERTEXT_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut input = Cursor::new(bytes);
    input.byte(10)?;
    let c0 = polynomial(input.blob()?)?;
    let second = match input.bytes.get(input.offset) {
        Some(10) => {
            input.byte(10)?;
            ParsedSecond::Stored(polynomial(input.blob()?)?)
        }
        Some(18) => {
            input.byte(18)?;
            ParsedSecond::Seed(
                input
                    .blob()?
                    .try_into()
                    .map_err(|_| Error::InvalidEncoding)?,
            )
        }
        _ => return Err(Error::InvalidEncoding),
    };
    // level0 is canonically omitted; exactly2 unseeded OR1+seed32, no extra fields.
    if !input.finished() {
        return Err(Error::InvalidEncoding);
    }
    // No public view is constructed before the complete ciphertext has passed EOF.
    let c0 = StoredPowerBasis::new(c0.packed, c0.variable_time);
    let second = match second {
        ParsedSecond::Stored(p) => {
            SecondComponent::Stored(StoredPowerBasis::new(p.packed, p.variable_time))
        }
        ParsedSecond::Seed(seed) => SecondComponent::Seed(seed),
    };
    Ok(CiphertextView::new(bytes, c0, second))
}

/// Check the same complete canonical syntax as [`parse`], without retaining a view.
///
/// Callers still own SDK semantic checks, exact roundtrip and every required
/// source, key, computation and freshness proof.
pub fn validate(bytes: &[u8]) -> Result<(), Error> {
    parse(bytes).map(|_| ())
}
