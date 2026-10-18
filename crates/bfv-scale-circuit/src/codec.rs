//! Fixed-size, canonical, public-only codecs. Decoding never executes the scaler.
use crate::{AUXILIARY_ROW_BYTES, CARRIES, DEGREE, Error, Result, Role, profile_digest};
use sha2::{Digest, Sha256};
const REQUEST: &[u8; 8] = b"BFVSCLQ1";
const OUTPUT: &[u8; 8] = b"BFVSCLR1";
const AUX: &[u8; 8] = b"BFVSCLC1";
pub(crate) fn digest(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn header(magic: &[u8; 8], role: Role, binding: [u8; 32], capacity: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(magic);
    out.extend_from_slice(&profile_digest(role));
    out.extend_from_slice(&binding);
    out.extend([role as u8, 1, 0, 0, 0, 0, 0, 0]);
    out
}
fn read_header(bytes: &[u8], magic: &[u8; 8]) -> Result<(Role, [u8; 32])> {
    if bytes.len() < 80 || &bytes[..8] != magic || bytes[73] != 1 || bytes[74..80] != [0; 6] {
        return Err(Error::Shape);
    }
    let role = match bytes[72] {
        1 => Role::Extend5To10,
        2 => Role::Scale10To5,
        _ => return Err(Error::Shape),
    };
    if bytes[8..40] != profile_digest(role) {
        return Err(Error::Profile);
    }
    Ok((role, bytes[40..72].try_into().unwrap()))
}
fn values(bytes: &[u8], moduli: &[u64]) -> Result<Vec<u64>> {
    if bytes.len() != moduli.len() * DEGREE * 8 {
        return Err(Error::Shape);
    }
    // All fixed lengths/header checks precede the sole allocating vector.
    let mut out = Vec::with_capacity(bytes.len() / 8);
    for (i, b) in bytes.as_chunks::<8>().0.iter().enumerate() {
        let v = u64::from_le_bytes(*b);
        if v >= moduli[i / DEGREE] {
            return Err(Error::NonCanonicalResidue);
        }
        out.push(v);
    }
    Ok(out)
}
fn put_values(out: &mut Vec<u8>, v: &[u64]) {
    for &n in v {
        out.extend_from_slice(&n.to_le_bytes());
    }
}
#[derive(Clone)]
pub struct Request {
    pub(crate) role: Role,
    pub(crate) binding: [u8; 32],
    pub(crate) input: Vec<u64>,
}
impl Request {
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub fn input(&self) -> &[u64] {
        &self.input
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = header(REQUEST, self.role, self.binding, self.role.request_bytes());
        put_values(&mut b, &self.input);
        b
    }
}
pub fn encode_request(role: Role, binding: [u8; 32], input: &[u64]) -> Result<Vec<u8>> {
    if input.len() != role.input_coefficients() {
        return Err(Error::Shape);
    }
    for (i, &v) in input.iter().enumerate() {
        if v >= role.input_moduli()[i / DEGREE] {
            return Err(Error::NonCanonicalResidue);
        }
    }
    let mut b = header(REQUEST, role, binding, role.request_bytes());
    put_values(&mut b, input);
    Ok(b)
}
pub fn decode_request(bytes: &[u8]) -> Result<Request> {
    if ![
        Role::Extend5To10.request_bytes(),
        Role::Scale10To5.request_bytes(),
    ]
    .contains(&bytes.len())
    {
        return Err(Error::Shape);
    }
    let (role, binding) = read_header(bytes, REQUEST)?;
    if bytes.len() != role.request_bytes() {
        return Err(Error::Shape);
    }
    let input = values(&bytes[80..], role.input_moduli())?;
    Ok(Request {
        role,
        binding,
        input,
    })
}
#[derive(Clone)]
pub struct Output {
    pub(crate) role: Role,
    pub(crate) binding: [u8; 32],
    pub(crate) input_digest: [u8; 32],
    pub(crate) coefficients: Vec<u64>,
}
impl Output {
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = header(OUTPUT, self.role, self.binding, self.role.output_bytes());
        b.extend(self.input_digest);
        put_values(&mut b, &self.coefficients);
        b
    }
}
pub fn decode_output(bytes: &[u8]) -> Result<Output> {
    if ![
        Role::Extend5To10.output_bytes(),
        Role::Scale10To5.output_bytes(),
    ]
    .contains(&bytes.len())
    {
        return Err(Error::Shape);
    }
    let (role, binding) = read_header(bytes, OUTPUT)?;
    if bytes.len() != role.output_bytes() {
        return Err(Error::Shape);
    }
    let coefficients = values(&bytes[112..], role.output_moduli())?;
    Ok(Output {
        role,
        binding,
        input_digest: bytes[80..112].try_into().unwrap(),
        coefficients,
    })
}
/// Public auxiliary arithmetic, not proof evidence. Values remain sealed inside Aux.
#[derive(Clone, Debug)]
pub struct AuxiliaryRow {
    pub v: u64,
    pub remainder_v: u128,
    pub biased_w: u64,
    pub remainder_e: u128,
    pub biased_quotients: [u128; 5],
    pub carries: [u32; CARRIES],
}
impl AuxiliaryRow {
    pub(crate) fn validate(&self, role: Role) -> Result<()> {
        if self.remainder_v >= (1u128 << crate::constants(role).garner_shift())
            || self.biased_w >= 1u64 << 46
            || self.remainder_e >= 1u128 << 127
            || self.biased_quotients.iter().any(|&v| v >= 1u128 << 66)
            || self.carries.iter().any(|&d| d >= 1 << 25)
        {
            return Err(Error::AuxiliaryRange);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct Aux {
    pub(crate) role: Role,
    pub(crate) binding: [u8; 32],
    pub(crate) input_digest: [u8; 32],
    pub(crate) output_digest: [u8; 32],
    pub(crate) rows: Vec<AuxiliaryRow>,
}
impl Aux {
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub fn rows(&self) -> &[AuxiliaryRow] {
        &self.rows
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = header(AUX, self.role, self.binding, self.role.aux_bytes());
        b.extend(self.input_digest);
        b.extend(self.output_digest);
        for row in &self.rows {
            b.extend(row.v.to_le_bytes());
            b.extend(row.remainder_v.to_le_bytes());
            b.extend(&row.biased_w.to_le_bytes()[..6]);
            b.extend(row.remainder_e.to_le_bytes());
            for u in row.biased_quotients {
                b.extend(&u.to_le_bytes()[..9]);
            }
            for d in row.carries {
                b.extend(d.to_le_bytes());
            }
        }
        b
    }
}
pub fn decode_aux(bytes: &[u8]) -> Result<Aux> {
    if bytes.len() != Role::Extend5To10.aux_bytes() {
        return Err(Error::Shape);
    }
    let (role, binding) = read_header(bytes, AUX)?;
    if bytes.len() != role.aux_bytes() {
        return Err(Error::Shape);
    }
    let mut rows = Vec::with_capacity(DEGREE);
    for b in bytes[144..].as_chunks::<AUXILIARY_ROW_BYTES>().0 {
        let mut w = [0u8; 8];
        w[..6].copy_from_slice(&b[24..30]);
        let row = AuxiliaryRow {
            v: u64::from_le_bytes(b[..8].try_into().unwrap()),
            remainder_v: u128::from_le_bytes(b[8..24].try_into().unwrap()),
            biased_w: u64::from_le_bytes(w),
            remainder_e: u128::from_le_bytes(b[30..46].try_into().unwrap()),
            biased_quotients: core::array::from_fn(|i| {
                let mut u = [0u8; 16];
                u[..9].copy_from_slice(&b[46 + 9 * i..55 + 9 * i]);
                u128::from_le_bytes(u)
            }),
            carries: core::array::from_fn(|i| {
                u32::from_le_bytes(b[91 + 4 * i..95 + 4 * i].try_into().unwrap())
            }),
        };
        row.validate(role)?;
        rows.push(row);
    }
    Ok(Aux {
        role,
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
/// Public statement checks only; no auxiliary or scaler arithmetic is needed.
pub(crate) fn check_output_binding(r: &Request, o: &Output) -> Result<()> {
    if r.role != o.role || r.binding != o.binding || o.input_digest != digest(&r.encode()) {
        return Err(Error::Binding);
    }
    if r.role == Role::Extend5To10 && o.coefficients[..5 * DEGREE] != r.input {
        return Err(Error::Binding);
    }
    Ok(())
}
/// Only exact identity/canonical-copy checks; never S/v/W/scaler/quotient evaluation.
pub(crate) fn check_binding(r: &Request, o: &Output, a: &Aux) -> Result<()> {
    check_output_binding(r, o)?;
    if r.role != a.role
        || r.binding != a.binding
        || a.input_digest != o.input_digest
        || a.output_digest != digest(&o.encode())
        || a.rows.len() != DEGREE
    {
        return Err(Error::Binding);
    }
    for row in &a.rows {
        row.validate(r.role)?;
    }
    Ok(())
}
