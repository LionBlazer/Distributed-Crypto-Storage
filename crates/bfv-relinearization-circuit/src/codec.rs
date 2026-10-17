//! Fixed canonical public frames; no ciphertext/key decoding or coefficient reevaluation.
use crate::{
    ACCUMULATION_AUXILIARY_ROW_BYTES, CARRIES, DEGREE, EMBEDDING_AUXILIARY_ROW_BYTES,
    EMBEDDING_QUOTIENT_BOUNDS, Error, MODULI, Result, Role, profile_digest,
};
use sha2::{Digest, Sha256};
const REQUEST: &[u8; 8] = b"BFVRELQ1";
const OUTPUT: &[u8; 8] = b"BFVRELR1";
const AUX: &[u8; 8] = b"BFVRELC1";
pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn representation(role: Role) -> u8 {
    match role {
        Role::Embed => 1,
        Role::AccumulateAndAdd => 2,
    }
}
fn header(
    magic: &[u8; 8],
    role: Role,
    binding: [u8; 32],
    keyset: [u8; 32],
    capacity: usize,
    aux: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(magic);
    out.extend(profile_digest(role));
    out.extend(binding);
    out.extend(keyset);
    out.extend([
        role as u8,
        if aux { 3 } else { representation(role) },
        role.input_moduli().len() as u8,
        role.output_moduli().len() as u8,
        0,
        0,
        0,
        0,
    ]);
    out
}
fn read_header(bytes: &[u8], magic: &[u8; 8], aux: bool) -> Result<(Role, [u8; 32], [u8; 32])> {
    if bytes.len() < 112 || &bytes[..8] != magic || bytes[108..112] != [0; 4] {
        return Err(Error::Shape);
    }
    let role = match bytes[104] {
        1 => Role::Embed,
        2 => Role::AccumulateAndAdd,
        _ => return Err(Error::Shape),
    };
    let expected_representation = if aux { 3 } else { representation(role) };
    if bytes[105] != expected_representation
        || bytes[106] != role.input_moduli().len() as u8
        || bytes[107] != role.output_moduli().len() as u8
    {
        return Err(Error::Shape);
    }
    if bytes[8..40] != profile_digest(role) {
        return Err(Error::Profile);
    }
    Ok((
        role,
        bytes[40..72].try_into().unwrap(),
        bytes[72..104].try_into().unwrap(),
    ))
}
fn values(bytes: &[u8], moduli: &[u64]) -> Result<Vec<u64>> {
    if bytes.len() != moduli.len() * DEGREE * 8 {
        return Err(Error::Shape);
    }
    let mut out = Vec::with_capacity(moduli.len() * DEGREE);
    for (i, b) in bytes.as_chunks::<8>().0.iter().enumerate() {
        let v = u64::from_le_bytes(*b);
        if v >= moduli[i / DEGREE] {
            return Err(Error::NonCanonicalResidue);
        }
        out.push(v);
    }
    Ok(out)
}
#[derive(Clone)]
pub struct Request {
    pub(crate) role: Role,
    pub(crate) binding: [u8; 32],
    pub(crate) keyset: [u8; 32],
    pub(crate) input: Vec<u64>,
}
impl Request {
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    /// Exact externally supplied identity bytes, not same-secret or owner authority.
    pub fn keyset_context(&self) -> [u8; 32] {
        self.keyset
    }
    pub fn input(&self) -> &[u64] {
        &self.input
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = header(
            REQUEST,
            self.role,
            self.binding,
            self.keyset,
            self.role.request_bytes(),
            false,
        );
        for &v in &self.input {
            out.extend(v.to_le_bytes());
        }
        out
    }
}
pub fn encode_request(
    role: Role,
    binding: [u8; 32],
    keyset_context: [u8; 32],
    input: &[u64],
) -> Result<Vec<u8>> {
    if input.len() != role.input_coefficients() {
        return Err(Error::Shape);
    }
    for (i, &v) in input.iter().enumerate() {
        if v >= role.input_moduli()[i / DEGREE] {
            return Err(Error::NonCanonicalResidue);
        }
    }
    let mut out = header(
        REQUEST,
        role,
        binding,
        keyset_context,
        role.request_bytes(),
        false,
    );
    for &v in input {
        out.extend(v.to_le_bytes());
    }
    Ok(out)
}
pub fn decode_request(bytes: &[u8]) -> Result<Request> {
    if ![
        Role::Embed.request_bytes(),
        Role::AccumulateAndAdd.request_bytes(),
    ]
    .contains(&bytes.len())
    {
        return Err(Error::Shape);
    }
    let (role, binding, keyset) = read_header(bytes, REQUEST, false)?;
    if bytes.len() != role.request_bytes() {
        return Err(Error::Shape);
    }
    let input = values(&bytes[112..], role.input_moduli())?;
    Ok(Request {
        role,
        binding,
        keyset,
        input,
    })
}
#[derive(Clone)]
pub struct Output {
    pub(crate) role: Role,
    pub(crate) binding: [u8; 32],
    pub(crate) keyset: [u8; 32],
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
    /// Byte identity only; no key consistency or authority is established.
    pub fn keyset_context(&self) -> [u8; 32] {
        self.keyset
    }
    pub fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = header(
            OUTPUT,
            self.role,
            self.binding,
            self.keyset,
            self.role.output_bytes(),
            false,
        );
        out.extend(self.input_digest);
        for &v in &self.coefficients {
            out.extend(v.to_le_bytes());
        }
        out
    }
}
pub fn decode_output(bytes: &[u8]) -> Result<Output> {
    if ![
        Role::Embed.output_bytes(),
        Role::AccumulateAndAdd.output_bytes(),
    ]
    .contains(&bytes.len())
    {
        return Err(Error::Shape);
    }
    let (role, binding, keyset) = read_header(bytes, OUTPUT, false)?;
    if bytes.len() != role.output_bytes() {
        return Err(Error::Shape);
    }
    let coefficients = values(&bytes[144..], role.output_moduli())?;
    Ok(Output {
        role,
        binding,
        keyset,
        input_digest: bytes[112..144].try_into().unwrap(),
        coefficients,
    })
}
#[derive(Clone, Debug)]
pub struct AccumulationRow {
    pub(crate) quotients: [u64; 10],
    pub(crate) carries: [[u32; CARRIES]; 10],
}
impl AccumulationRow {
    pub fn quotients(&self) -> &[u64; 10] {
        &self.quotients
    }
    pub fn carries(&self) -> &[[u32; CARRIES]; 10] {
        &self.carries
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self
            .quotients
            .iter()
            .enumerate()
            .any(|(i, &q)| q >= 5 * MODULI[i / 2])
            || self.carries.iter().flatten().any(|&d| d >= 1 << 25)
        {
            Err(Error::AuxiliaryRange)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone)]
pub(crate) enum Rows {
    Embed(Vec<[u8; 25]>),
    Accumulate(Vec<AccumulationRow>),
}
#[derive(Clone)]
pub struct Aux {
    pub(crate) role: Role,
    pub(crate) binding: [u8; 32],
    pub(crate) keyset: [u8; 32],
    pub(crate) input_digest: [u8; 32],
    pub(crate) output_digest: [u8; 32],
    pub(crate) rows: Rows,
}
impl Aux {
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    /// Externally supplied setup identity only, never a key-validation result.
    pub fn keyset_context(&self) -> [u8; 32] {
        self.keyset
    }
    pub fn embedding_rows(&self) -> Option<&[[u8; 25]]> {
        match &self.rows {
            Rows::Embed(rows) => Some(rows),
            _ => None,
        }
    }
    pub fn accumulation_rows(&self) -> Option<&[AccumulationRow]> {
        match &self.rows {
            Rows::Accumulate(rows) => Some(rows),
            _ => None,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = header(
            AUX,
            self.role,
            self.binding,
            self.keyset,
            self.role.aux_bytes(),
            true,
        );
        out.extend(self.input_digest);
        out.extend(self.output_digest);
        match &self.rows {
            Rows::Embed(rows) => {
                for row in rows {
                    out.extend(row);
                }
            }
            Rows::Accumulate(rows) => {
                for row in rows {
                    for &q in &row.quotients {
                        out.extend(&q.to_le_bytes()[..6]);
                    }
                    for chain in &row.carries {
                        for &d in chain {
                            out.extend(d.to_le_bytes());
                        }
                    }
                }
            }
        }
        out
    }
}
fn check_embedding(row: &[u8; 25]) -> Result<()> {
    for (i, &t) in row.iter().enumerate() {
        if t > EMBEDDING_QUOTIENT_BOUNDS[i / 5][i % 5] {
            return Err(Error::AuxiliaryRange);
        }
    }
    Ok(())
}
pub fn decode_aux(bytes: &[u8]) -> Result<Aux> {
    if ![Role::Embed.aux_bytes(), Role::AccumulateAndAdd.aux_bytes()].contains(&bytes.len()) {
        return Err(Error::Shape);
    }
    let (role, binding, keyset) = read_header(bytes, AUX, true)?;
    if bytes.len() != role.aux_bytes() {
        return Err(Error::Shape);
    }
    let rows = match role {
        Role::Embed => {
            let mut rows = Vec::with_capacity(DEGREE);
            for b in bytes[176..].as_chunks::<EMBEDDING_AUXILIARY_ROW_BYTES>().0 {
                let row = *b;
                check_embedding(&row)?;
                rows.push(row);
            }
            Rows::Embed(rows)
        }
        Role::AccumulateAndAdd => {
            let mut rows = Vec::with_capacity(DEGREE);
            for b in bytes[176..]
                .as_chunks::<ACCUMULATION_AUXILIARY_ROW_BYTES>()
                .0
            {
                let row = AccumulationRow {
                    quotients: core::array::from_fn(|i| {
                        let mut q = [0u8; 8];
                        q[..6].copy_from_slice(&b[6 * i..6 * i + 6]);
                        u64::from_le_bytes(q)
                    }),
                    carries: core::array::from_fn(|i| {
                        core::array::from_fn(|j| {
                            u32::from_le_bytes(
                                b[60 + 20 * i + 4 * j..64 + 20 * i + 4 * j]
                                    .try_into()
                                    .unwrap(),
                            )
                        })
                    }),
                };
                row.validate()?;
                rows.push(row);
            }
            Rows::Accumulate(rows)
        }
    };
    Ok(Aux {
        role,
        binding,
        keyset,
        input_digest: bytes[112..144].try_into().unwrap(),
        output_digest: bytes[144..176].try_into().unwrap(),
        rows,
    })
}
pub struct Evaluation {
    pub output: Output,
    pub aux: Aux,
}
/// Complete byte identities and canonical ranges only, not arithmetic or key authority.
pub(crate) fn check_binding(r: &Request, o: &Output, a: &Aux) -> Result<()> {
    if r.role != o.role
        || r.role != a.role
        || r.binding != o.binding
        || r.binding != a.binding
        || r.keyset != o.keyset
        || r.keyset != a.keyset
        || o.input_digest != digest(&r.encode())
        || a.input_digest != o.input_digest
        || a.output_digest != digest(&o.encode())
    {
        return Err(Error::Binding);
    }
    match (&a.rows, r.role) {
        (Rows::Embed(rows), Role::Embed) => {
            if rows.len() != DEGREE {
                return Err(Error::Shape);
            }
            for row in rows {
                check_embedding(row)?;
            }
        }
        (Rows::Accumulate(rows), Role::AccumulateAndAdd) => {
            if rows.len() != DEGREE {
                return Err(Error::Shape);
            }
            for row in rows {
                row.validate()?;
            }
        }
        _ => return Err(Error::Shape),
    }
    Ok(())
}
