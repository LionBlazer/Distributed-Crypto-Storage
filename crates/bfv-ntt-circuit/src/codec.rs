//! Exact bounded public frames. Decoding does not evaluate any butterfly/NTT.
use crate::{
    AUXILIARY_ROW_BYTES, Basis, CARRIES, DEGREE, Direction, Error, Result, profile_digest,
};
use sha2::{Digest, Sha256};
const REQUEST: &[u8; 8] = b"BFVNTTQ1";
const OUTPUT: &[u8; 8] = b"BFVNTTR1";
const AUX: &[u8; 8] = b"BFVNTTC1";
pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn representation(direction: Direction, output: bool) -> u8 {
    match (direction, output) {
        (Direction::Forward, false) | (Direction::Inverse, true) => 1,
        _ => 2,
    }
}
fn header(
    magic: &[u8; 8],
    direction: Direction,
    basis: Basis,
    binding: [u8; 32],
    capacity: usize,
    rep: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(magic);
    out.extend(profile_digest(direction, basis));
    out.extend(binding);
    out.extend([direction as u8, basis.index(), rep, 0, 0, 0, 0, 0]);
    out
}
fn read_header(
    bytes: &[u8],
    magic: &[u8; 8],
    output: Option<bool>,
) -> Result<(Direction, Basis, [u8; 32])> {
    if bytes.len() < 80 || &bytes[..8] != magic || bytes[75..80] != [0; 5] {
        return Err(Error::Shape);
    }
    let direction = match bytes[72] {
        1 => Direction::Forward,
        2 => Direction::Inverse,
        _ => return Err(Error::Shape),
    };
    let basis = Basis::new(bytes[73])?;
    let rep = output.map_or(3, |output| representation(direction, output));
    if bytes[74] != rep {
        return Err(Error::Shape);
    }
    if bytes[8..40] != profile_digest(direction, basis) {
        return Err(Error::Profile);
    }
    Ok((direction, basis, bytes[40..72].try_into().unwrap()))
}
fn read_values(bytes: &[u8], p: u64) -> Result<Vec<u64>> {
    if bytes.len() != DEGREE * 8 {
        return Err(Error::Shape);
    }
    let mut values = Vec::with_capacity(DEGREE);
    for b in bytes.as_chunks::<8>().0 {
        let v = u64::from_le_bytes(*b);
        if v >= p {
            return Err(Error::NonCanonicalResidue);
        }
        values.push(v);
    }
    Ok(values)
}
#[derive(Clone)]
pub struct Request {
    pub(crate) direction: Direction,
    pub(crate) basis: Basis,
    pub(crate) binding: [u8; 32],
    pub(crate) input: Vec<u64>,
}
impl Request {
    pub fn direction(&self) -> Direction {
        self.direction
    }
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
            self.direction,
            self.basis,
            self.binding,
            self.direction.request_bytes(),
            representation(self.direction, false),
        );
        for &v in &self.input {
            out.extend(v.to_le_bytes());
        }
        out
    }
}
pub fn encode_request(
    direction: Direction,
    basis: Basis,
    binding: [u8; 32],
    input: &[u64],
) -> Result<Vec<u8>> {
    if input.len() != DEGREE {
        return Err(Error::Shape);
    }
    if input.iter().any(|&v| v >= basis.modulus()) {
        return Err(Error::NonCanonicalResidue);
    }
    Ok(Request {
        direction,
        basis,
        binding,
        input: input.to_vec(),
    }
    .encode())
}
pub fn decode_request(bytes: &[u8]) -> Result<Request> {
    if bytes.len() != Direction::Forward.request_bytes() {
        return Err(Error::Shape);
    }
    let (direction, basis, binding) = read_header(bytes, REQUEST, Some(false))?;
    let input = read_values(&bytes[80..], basis.modulus())?;
    Ok(Request {
        direction,
        basis,
        binding,
        input,
    })
}
#[derive(Clone)]
pub struct Output {
    pub(crate) direction: Direction,
    pub(crate) basis: Basis,
    pub(crate) binding: [u8; 32],
    pub(crate) input_digest: [u8; 32],
    pub(crate) coefficients: Vec<u64>,
}
impl Output {
    pub fn direction(&self) -> Direction {
        self.direction
    }
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
            self.direction,
            self.basis,
            self.binding,
            self.direction.output_bytes(),
            representation(self.direction, true),
        );
        out.extend(self.input_digest);
        for &v in &self.coefficients {
            out.extend(v.to_le_bytes());
        }
        out
    }
}
pub fn decode_output(bytes: &[u8]) -> Result<Output> {
    if bytes.len() != Direction::Forward.output_bytes() {
        return Err(Error::Shape);
    }
    let (direction, basis, binding) = read_header(bytes, OUTPUT, Some(true))?;
    let coefficients = read_values(&bytes[112..], basis.modulus())?;
    Ok(Output {
        direction,
        basis,
        binding,
        input_digest: bytes[80..112].try_into().unwrap(),
        coefficients,
    })
}
#[derive(Clone, Debug)]
pub struct AuxiliaryRow {
    pub(crate) biased_quotient: u128,
    pub(crate) carries: [u32; CARRIES],
}
impl AuxiliaryRow {
    pub fn biased_quotient(&self) -> u128 {
        self.biased_quotient
    }
    pub fn carries(&self) -> &[u32; CARRIES] {
        &self.carries
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.biased_quotient >= 1u128 << 66 || self.carries.iter().any(|&v| v >= 1 << 25) {
            Err(Error::AuxiliaryRange)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone)]
pub struct Stage {
    pub(crate) coefficients: Vec<u64>,
    pub(crate) rows: Vec<AuxiliaryRow>,
}
impl Stage {
    pub fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }
    pub fn rows(&self) -> &[AuxiliaryRow] {
        &self.rows
    }
}
#[derive(Clone)]
pub struct Aux {
    pub(crate) direction: Direction,
    pub(crate) basis: Basis,
    pub(crate) binding: [u8; 32],
    pub(crate) input_digest: [u8; 32],
    pub(crate) output_digest: [u8; 32],
    pub(crate) stages: Vec<Stage>,
}
impl Aux {
    pub fn direction(&self) -> Direction {
        self.direction
    }
    pub fn basis(&self) -> Basis {
        self.basis
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub fn stages(&self) -> &[Stage] {
        &self.stages
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = header(
            AUX,
            self.direction,
            self.basis,
            self.binding,
            self.direction.aux_bytes(),
            3,
        );
        out.extend(self.input_digest);
        out.extend(self.output_digest);
        for stage in &self.stages {
            for (&coefficient, row) in stage.coefficients.iter().zip(&stage.rows) {
                out.extend(coefficient.to_le_bytes());
                out.extend(&row.biased_quotient.to_le_bytes()[..9]);
                for &d in &row.carries {
                    out.extend(d.to_le_bytes());
                }
            }
        }
        out
    }
}
pub fn decode_aux(bytes: &[u8]) -> Result<Aux> {
    if ![
        Direction::Forward.aux_bytes(),
        Direction::Inverse.aux_bytes(),
    ]
    .contains(&bytes.len())
    {
        return Err(Error::Shape);
    }
    let (direction, basis, binding) = read_header(bytes, AUX, None)?;
    if bytes.len() != direction.aux_bytes() {
        return Err(Error::Shape);
    }
    let mut stages = Vec::with_capacity(direction.stages());
    for frame in bytes[144..]
        .as_chunks::<{ DEGREE * AUXILIARY_ROW_BYTES }>()
        .0
    {
        let mut coefficients = Vec::with_capacity(DEGREE);
        let mut rows = Vec::with_capacity(DEGREE);
        for row in frame.as_chunks::<AUXILIARY_ROW_BYTES>().0 {
            let coefficient = u64::from_le_bytes(row[..8].try_into().unwrap());
            if coefficient >= basis.modulus() {
                return Err(Error::NonCanonicalResidue);
            }
            let mut u = [0u8; 16];
            u[..9].copy_from_slice(&row[8..17]);
            let a = AuxiliaryRow {
                biased_quotient: u128::from_le_bytes(u),
                carries: core::array::from_fn(|i| {
                    u32::from_le_bytes(row[17 + 4 * i..21 + 4 * i].try_into().unwrap())
                }),
            };
            a.validate()?;
            coefficients.push(coefficient);
            rows.push(a);
        }
        stages.push(Stage { coefficients, rows });
    }
    Ok(Aux {
        direction,
        basis,
        binding,
        input_digest: bytes[80..112].try_into().unwrap(),
        output_digest: bytes[112..144].try_into().unwrap(),
        stages,
    })
}
pub struct Evaluation {
    pub output: Output,
    pub aux: Aux,
}
/// Canonical binding/copy checks only; no butterfly, quotient or NTT evaluation.
pub(crate) fn check_binding(r: &Request, o: &Output, a: &Aux) -> Result<()> {
    if r.direction != o.direction
        || r.direction != a.direction
        || r.basis != o.basis
        || r.basis != a.basis
        || r.binding != o.binding
        || r.binding != a.binding
        || o.input_digest != digest(&r.encode())
        || a.input_digest != o.input_digest
        || a.output_digest != digest(&o.encode())
        || a.stages.len() != r.direction.stages()
    {
        return Err(Error::Binding);
    }
    if a.stages.last().ok_or(Error::Shape)?.coefficients != o.coefficients {
        return Err(Error::Binding);
    }
    for stage in &a.stages {
        if stage.coefficients.len() != DEGREE || stage.rows.len() != DEGREE {
            return Err(Error::Shape);
        }
        for row in &stage.rows {
            row.validate()?;
        }
    }
    Ok(())
}
