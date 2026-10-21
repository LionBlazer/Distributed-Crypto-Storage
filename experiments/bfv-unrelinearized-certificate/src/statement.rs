//! Fixed unseeded SDK endpoints, parsed without a transform, seed expansion or evaluator.
use crate::{
    Error, Polynomial, Result,
    geometry::{N, Q},
};

const MAX_CT: usize = 128 * 1024;
const POLY_BYTES: usize = N * 60 / 8;
const REQUEST_MAGIC: &[u8; 8] = b"UCPITQ01";

pub(crate) struct Statement {
    inputs: [Polynomial; 4],
    outputs: [Polynomial; 3],
    request: Vec<u8>,
    output: Vec<u8>,
    binding: [u8; 32],
}
impl Statement {
    pub(crate) fn new(binding: [u8; 32], inputs: [Vec<u8>; 2], output: Vec<u8>) -> Result<Self> {
        if binding == [0; 32] {
            return Err(Error::Binding);
        }
        let [a, b] = inputs;
        let a_polys: [Polynomial; 2] = parse(&a, 2)?.try_into().map_err(|_| Error::Shape)?;
        let b_polys: [Polynomial; 2] = parse(&b, 2)?.try_into().map_err(|_| Error::Shape)?;
        let outputs = parse(&output, 3)?.try_into().map_err(|_| Error::Shape)?;
        let mut request = Vec::with_capacity(112 + a.len() + b.len());
        request.extend_from_slice(REQUEST_MAGIC);
        request.extend_from_slice(&crate::profile_digest());
        request.extend_from_slice(&binding);
        request.extend_from_slice(&(a.len() as u32).to_le_bytes());
        request.extend_from_slice(&(b.len() as u32).to_le_bytes());
        request.extend_from_slice(&a);
        request.extend_from_slice(&b);
        let [a0, a1] = a_polys;
        let [b0, b1] = b_polys;
        Ok(Self {
            inputs: [a0, a1, b0, b1],
            outputs,
            request,
            output,
            binding,
        })
    }
    pub(crate) fn input(&self, index: usize) -> &Polynomial {
        &self.inputs[index]
    }
    pub(crate) fn output(&self, index: usize) -> &Polynomial {
        &self.outputs[index]
    }
    pub(crate) fn request_wire(&self) -> &[u8] {
        &self.request
    }
    pub(crate) fn output_wire(&self) -> &[u8] {
        &self.output
    }
    pub(crate) fn binding(&self) -> [u8; 32] {
        self.binding
    }

    /// Hostile-public-endpoint construction for the repaired-certificate test.
    /// No production caller can supply a replacement output through this API.
    #[cfg(test)]
    pub(crate) fn with_public_test_outputs(&self, outputs: &[Polynomial; 3]) -> Result<Self> {
        use fhe::bfv::{BfvParametersBuilder, Ciphertext};
        use fhe_traits::DeserializeParametrized;
        fn varint(bytes: &mut Vec<u8>, mut value: usize) {
            while value >= 128 {
                bytes.push((value as u8 & 127) | 128);
                value >>= 7;
            }
            bytes.push(value as u8);
        }
        let mut output = Vec::new();
        for rows in outputs {
            crate::geometry::validate_polynomials(rows, &Q)?;
            let mut packed = Vec::with_capacity(POLY_BYTES);
            let mut word = 0u128;
            let mut bits = 0;
            for row in rows {
                for &value in row {
                    word |= u128::from(value) << bits;
                    bits += 30;
                    while bits >= 8 {
                        packed.push(word as u8);
                        word >>= 8;
                        bits -= 8;
                    }
                }
            }
            assert_eq!(bits, 0);
            let mut poly = vec![8, 2, 16];
            varint(&mut poly, N);
            poly.push(26);
            varint(&mut poly, packed.len());
            poly.extend_from_slice(&packed);
            output.push(10);
            varint(&mut output, poly.len());
            output.extend_from_slice(&poly);
        }
        // A fake endpoint must still be an actual SDK-readable ciphertext.
        let parameters = BfvParametersBuilder::new()
            .set_degree(N)
            .set_plaintext_modulus(crate::geometry::T)
            .set_moduli(&Q)
            .set_variance(10)
            .build_arc()
            .map_err(|_| Error::Backend)?;
        Ciphertext::from_bytes(&output, &parameters).map_err(|_| Error::Backend)?;
        let a_len = u32::from_le_bytes(self.request[104..108].try_into().unwrap()) as usize;
        let inputs = [
            self.request[112..112 + a_len].to_vec(),
            self.request[112 + a_len..].to_vec(),
        ];
        Self::new(self.binding, inputs, output)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn byte(&mut self, expected: u8) -> Result<()> {
        if self.bytes.get(self.at) != Some(&expected) {
            return Err(Error::Shape);
        }
        self.at += 1;
        Ok(())
    }
    fn varint(&mut self) -> Result<usize> {
        let mut out = 0u64;
        for shift in 0..10 {
            let byte = *self.bytes.get(self.at).ok_or(Error::Shape)?;
            self.at += 1;
            if shift == 9 && byte > 1 {
                return Err(Error::Shape);
            }
            out |= u64::from(byte & 127) << (shift * 7);
            if byte & 128 == 0 {
                if shift != 0 && byte == 0 {
                    return Err(Error::Shape);
                }
                return usize::try_from(out).map_err(|_| Error::Shape);
            }
        }
        Err(Error::Shape)
    }
    fn blob(&mut self) -> Result<&'a [u8]> {
        let len = self.varint()?;
        let end = self.at.checked_add(len).ok_or(Error::Resource)?;
        let out = self.bytes.get(self.at..end).ok_or(Error::Shape)?;
        self.at = end;
        Ok(out)
    }
    fn finished(&self) -> bool {
        self.at == self.bytes.len()
    }
}
fn polynomial(bytes: &[u8]) -> Result<Polynomial> {
    let mut cursor = Cursor::new(bytes);
    cursor.byte(8)?;
    cursor.byte(2)?; // Ntt wire tag: the SDK stores PowerBasis coefficients.
    cursor.byte(16)?;
    if cursor.varint()? != N {
        return Err(Error::Shape);
    }
    cursor.byte(26)?;
    let packed = cursor.blob()?;
    if packed.len() != POLY_BYTES {
        return Err(Error::Shape);
    }
    if !cursor.finished() {
        cursor.byte(32)?;
        cursor.byte(1)?;
    }
    if !cursor.finished() {
        return Err(Error::Shape);
    }
    let mut rows = Vec::with_capacity(2);
    for (basis, &p) in Q.iter().enumerate() {
        let row = &packed[basis * (POLY_BYTES / 2)..(basis + 1) * (POLY_BYTES / 2)];
        let mut values = Vec::with_capacity(N);
        for index in 0..N {
            let bit = index * 30;
            let first = bit / 8;
            let shift = bit % 8;
            let count = (shift + 30).div_ceil(8);
            let value = row[first..first + count]
                .iter()
                .enumerate()
                .fold(0u64, |word, (i, byte)| word | (u64::from(*byte) << (i * 8)));
            let value = (value >> shift) & ((1 << 30) - 1);
            if value >= p {
                return Err(Error::Arithmetic);
            }
            values.push(value);
        }
        rows.push(values);
    }
    Ok(rows)
}
fn parse(bytes: &[u8], components: usize) -> Result<Vec<Polynomial>> {
    if bytes.is_empty() || bytes.len() > MAX_CT || !matches!(components, 2 | 3) {
        return Err(Error::Resource);
    }
    let mut cursor = Cursor::new(bytes);
    let mut out = Vec::with_capacity(components);
    for _ in 0..components {
        cursor.byte(10)?;
        out.push(polynomial(cursor.blob()?)?);
    }
    // Seeded endpoints, nonzero levels, trailing and unknown fields hard reject.
    if !cursor.finished() {
        return Err(Error::Shape);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_and_oversized_endpoints_are_rejected_before_sdk_decoding() {
        assert!(parse(&[], 2).is_err());
        assert!(parse(&vec![0; MAX_CT + 1], 2).is_err());
        assert!(parse(&[10, 0, 18, 32], 2).is_err());
        assert!(parse(&[10, 128, 0], 2).is_err());
        assert!(parse(&[10, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2], 2).is_err());
    }
}
