//! Canonical literal input request; decoding is metadata, never Formation authority.
use super::{
    Error, Result,
    geometry::{N, Polynomial, Q},
    profile_digest,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
const MAGIC: &[u8; 8] = b"GFMRQ001";
const HEADER: usize = 80;
const MAX_CT: usize = 128 * 1024;
const POLY_BYTES: usize = N * 60 / 8;
#[derive(Clone)]
pub struct Request {
    inner: Arc<Data>,
}
struct Data {
    nonce: [u8; 32],
    bytes: Vec<u8>,
    inputs: [Polynomial; 4],
}
impl Request {
    pub fn checked(nonce: [u8; 32], ciphertexts: [Vec<u8>; 2]) -> Result<Self> {
        if nonce == [0; 32] {
            return Err(Error::Binding);
        }
        let [a, b] = ciphertexts;
        let [a0, a1] = parse(&a)?;
        let [b0, b1] = parse(&b)?;
        let mut bytes = Vec::with_capacity(HEADER + a.len() + b.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&profile_digest());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&(a.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(b.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&a);
        bytes.extend_from_slice(&b);
        Ok(Self {
            inner: Arc::new(Data {
                nonce,
                bytes,
                inputs: [a0, a1, b0, b1],
            }),
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER || bytes.len() > HEADER + 2 * MAX_CT {
            return Err(Error::Resource);
        }
        if &bytes[..8] != MAGIC || bytes[8..40] != profile_digest() {
            return Err(Error::Encoding);
        }
        let nonce = bytes[40..72].try_into().map_err(|_| Error::Encoding)?;
        let a = u32::from_le_bytes(bytes[72..76].try_into().map_err(|_| Error::Encoding)?) as usize;
        let b = u32::from_le_bytes(bytes[76..80].try_into().map_err(|_| Error::Encoding)?) as usize;
        if a == 0 || b == 0 || a > MAX_CT || b > MAX_CT || HEADER + a + b != bytes.len() {
            return Err(Error::Encoding);
        }
        let request = Self::checked(
            nonce,
            [
                bytes[HEADER..HEADER + a].to_vec(),
                bytes[HEADER + a..].to_vec(),
            ],
        )?;
        if request.bytes() != bytes {
            return Err(Error::Encoding);
        }
        Ok(request)
    }
    pub fn nonce(&self) -> [u8; 32] {
        self.inner.nonce
    }
    pub fn bytes(&self) -> &[u8] {
        &self.inner.bytes
    }
    /// Public natural-PB coefficients; fixed indices0..4, basis-major Q0/Q1.
    pub fn input(&self, component: usize) -> &[Vec<u64>] {
        &self.inner.inputs[component]
    }
    pub fn q(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"DCS/CoreGold/FormationRequest/q/v1");
        h.update((self.bytes().len() as u64).to_le_bytes());
        h.update(self.bytes());
        h.finalize().into()
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
    let mut c = Cursor::new(bytes);
    c.byte(8)?;
    c.byte(2)?;
    c.byte(16)?;
    if c.varint()? != N {
        return Err(Error::Shape);
    }
    c.byte(26)?;
    let packed = c.blob()?;
    if packed.len() != POLY_BYTES {
        return Err(Error::Shape);
    }
    if !c.finished() {
        c.byte(32)?;
        c.byte(1)?;
    }
    if !c.finished() {
        return Err(Error::Shape);
    }
    let mut rows = Vec::with_capacity(2);
    for (b, &p) in Q.iter().enumerate() {
        let row = &packed[b * (POLY_BYTES / 2)..(b + 1) * (POLY_BYTES / 2)];
        let mut values = Vec::with_capacity(N);
        for index in 0..N {
            let bit = index * 30;
            let first = bit / 8;
            let shift = bit % 8;
            let count = (shift + 30).div_ceil(8);
            let value = row[first..first + count]
                .iter()
                .enumerate()
                .fold(0u64, |v, (i, byte)| v | (u64::from(*byte) << (i * 8)));
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
fn parse(bytes: &[u8]) -> Result<[Polynomial; 2]> {
    if bytes.is_empty() || bytes.len() > MAX_CT {
        return Err(Error::Resource);
    }
    let mut c = Cursor::new(bytes);
    let mut out = Vec::with_capacity(2);
    for _ in 0..2 {
        c.byte(10)?;
        out.push(polynomial(c.blob()?)?);
    }
    if !c.finished() {
        return Err(Error::Shape);
    }
    out.try_into().map_err(|_| Error::Shape)
}
