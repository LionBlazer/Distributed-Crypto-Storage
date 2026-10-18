//! Sealed bounded public tensor frames. Decode never multiplies or divides coefficients.
use crate::{
    AUXILIARY_ROW_BYTES, Basis, CARRIES, DEGREE, Error, INPUT_POLYNOMIALS, OUTPUT_POLYNOMIALS,
    Result, profile_digest,
};
use sha2::{Digest, Sha256};
const REQUEST: &[u8; 8] = b"BFVTENQ1";
const OUTPUT: &[u8; 8] = b"BFVTENR1";
const AUX: &[u8; 8] = b"BFVTENC1";
pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn header(
    magic: &[u8; 8],
    basis: Basis,
    binding: [u8; 32],
    capacity: usize,
    representation: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(magic);
    out.extend(profile_digest(basis));
    out.extend(binding);
    out.extend([basis.index(), representation, 4, 3, 0, 0, 0, 0]);
    out
}
fn read_header(bytes: &[u8], magic: &[u8; 8], representation: u8) -> Result<(Basis, [u8; 32])> {
    if bytes.len() < 80
        || &bytes[..8] != magic
        || bytes[73] != representation
        || bytes[74..80] != [4, 3, 0, 0, 0, 0]
    {
        return Err(Error::Shape);
    }
    let basis = Basis::new(bytes[72])?;
    if bytes[8..40] != profile_digest(basis) {
        return Err(Error::Profile);
    }
    Ok((basis, bytes[40..72].try_into().unwrap()))
}
fn values(bytes: &[u8], basis: Basis, count: usize) -> Result<Vec<u64>> {
    if bytes.len() != count * DEGREE * 8 {
        return Err(Error::Shape);
    }
    let mut out = Vec::with_capacity(count * DEGREE);
    for b in bytes.as_chunks::<8>().0 {
        let x = u64::from_le_bytes(*b);
        if x >= basis.modulus() {
            return Err(Error::NonCanonicalResidue);
        }
        out.push(x);
    }
    Ok(out)
}
#[derive(Clone)]
pub struct Request {
    pub(crate) basis: Basis,
    pub(crate) binding: [u8; 32],
    pub(crate) input: Vec<u64>,
}
impl Request {
    pub fn basis(&self) -> Basis {
        self.basis
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub fn input(&self) -> &[u64] {
        &self.input
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = header(
            REQUEST,
            self.basis,
            self.binding,
            self.basis.request_bytes(),
            2,
        );
        for &x in &self.input {
            out.extend(x.to_le_bytes());
        }
        out
    }
}
pub fn encode_request(basis: Basis, binding: [u8; 32], input: &[u64]) -> Result<Vec<u8>> {
    if input.len() != INPUT_POLYNOMIALS * DEGREE {
        return Err(Error::Shape);
    }
    if input.iter().any(|&x| x >= basis.modulus()) {
        return Err(Error::NonCanonicalResidue);
    }
    let mut out = header(REQUEST, basis, binding, basis.request_bytes(), 2);
    for &x in input {
        out.extend(x.to_le_bytes());
    }
    Ok(out)
}
pub fn decode_request(bytes: &[u8]) -> Result<Request> {
    if bytes.len() != 80 + INPUT_POLYNOMIALS * DEGREE * 8 {
        return Err(Error::Shape);
    }
    let (basis, binding) = read_header(bytes, REQUEST, 2)?;
    let input = values(&bytes[80..], basis, INPUT_POLYNOMIALS)?;
    Ok(Request {
        basis,
        binding,
        input,
    })
}
#[derive(Clone)]
pub struct Output {
    pub(crate) basis: Basis,
    pub(crate) binding: [u8; 32],
    pub(crate) input_digest: [u8; 32],
    pub(crate) coefficients: Vec<u64>,
}
impl Output {
    pub fn basis(&self) -> Basis {
        self.basis
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = header(
            OUTPUT,
            self.basis,
            self.binding,
            self.basis.output_bytes(),
            2,
        );
        out.extend(self.input_digest);
        for &x in &self.coefficients {
            out.extend(x.to_le_bytes());
        }
        out
    }
}
pub fn decode_output(bytes: &[u8]) -> Result<Output> {
    if bytes.len() != 112 + OUTPUT_POLYNOMIALS * DEGREE * 8 {
        return Err(Error::Shape);
    }
    let (basis, binding) = read_header(bytes, OUTPUT, 2)?;
    let coefficients = values(&bytes[112..], basis, OUTPUT_POLYNOMIALS)?;
    Ok(Output {
        basis,
        binding,
        input_digest: bytes[80..112].try_into().unwrap(),
        coefficients,
    })
}
#[derive(Clone, Debug)]
pub struct AuxiliaryRow {
    pub(crate) quotients: [u64; 3],
    pub(crate) carries: [[u32; CARRIES]; 3],
}
impl AuxiliaryRow {
    pub fn quotients(&self) -> &[u64; 3] {
        &self.quotients
    }
    pub fn carries(&self) -> &[[u32; CARRIES]; 3] {
        &self.carries
    }
    pub(crate) fn validate(&self, basis: Basis) -> Result<()> {
        let p = basis.modulus();
        if self.quotients[0] >= p
            || self.quotients[1] >= 2 * p
            || self.quotients[2] >= p
            || self.carries.iter().flatten().any(|&d| d >= 1 << 25)
        {
            return Err(Error::AuxiliaryRange);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct Aux {
    pub(crate) basis: Basis,
    pub(crate) binding: [u8; 32],
    pub(crate) input_digest: [u8; 32],
    pub(crate) output_digest: [u8; 32],
    pub(crate) rows: Vec<AuxiliaryRow>,
}
impl Aux {
    pub fn basis(&self) -> Basis {
        self.basis
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub fn rows(&self) -> &[AuxiliaryRow] {
        &self.rows
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = header(AUX, self.basis, self.binding, self.basis.aux_bytes(), 3);
        out.extend(self.input_digest);
        out.extend(self.output_digest);
        for row in &self.rows {
            for &q in &row.quotients {
                out.extend(q.to_le_bytes());
            }
            for chain in &row.carries {
                for &d in chain {
                    out.extend(d.to_le_bytes());
                }
            }
        }
        out
    }
}
pub fn decode_aux(bytes: &[u8]) -> Result<Aux> {
    if bytes.len() != 144 + DEGREE * AUXILIARY_ROW_BYTES {
        return Err(Error::Shape);
    }
    let (basis, binding) = read_header(bytes, AUX, 3)?;
    let mut rows = Vec::with_capacity(DEGREE);
    for b in bytes[144..].as_chunks::<AUXILIARY_ROW_BYTES>().0 {
        let row = AuxiliaryRow {
            quotients: core::array::from_fn(|i| {
                u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap())
            }),
            carries: core::array::from_fn(|i| {
                core::array::from_fn(|j| {
                    u32::from_le_bytes(
                        b[24 + 28 * i + 4 * j..28 + 28 * i + 4 * j]
                            .try_into()
                            .unwrap(),
                    )
                })
            }),
        };
        row.validate(basis)?;
        rows.push(row);
    }
    Ok(Aux {
        basis,
        binding,
        input_digest: bytes[80..112].try_into().unwrap(),
        output_digest: bytes[112..144].try_into().unwrap(),
        rows,
    })
}
pub struct Evaluation {
    pub output: Output,
    pub aux: Aux,
}
/// Exact public statement binding only, without an auxiliary certificate.
pub(crate) fn check_output_binding(r: &Request, o: &Output) -> Result<()> {
    if r.basis != o.basis || r.binding != o.binding || o.input_digest != digest(&r.encode()) {
        return Err(Error::Binding);
    }
    Ok(())
}
/// Canonical range/binding checks only, never tensor multiplication or quotient evaluation.
pub(crate) fn check_binding(r: &Request, o: &Output, a: &Aux) -> Result<()> {
    check_output_binding(r, o)?;
    if r.basis != a.basis
        || r.binding != a.binding
        || a.input_digest != o.input_digest
        || a.output_digest != digest(&o.encode())
        || a.rows.len() != DEGREE
    {
        return Err(Error::Binding);
    }
    for row in &a.rows {
        row.validate(r.basis)?;
    }
    Ok(())
}
