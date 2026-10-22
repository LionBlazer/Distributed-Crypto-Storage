//! Exact integer certificates for the pinned SDK's PUBLIC PB scaler steps only.
//! All decoded values are untrusted. Success is not Source, product, SQL, or finality authority.
mod constants;
mod math;
use crate::{
    Error, Result,
    geometry::{N, P, Q, QP, validate_polynomials},
};
pub(crate) use math::{evaluate, reconstruct, verify_certificate};
use sha2::{Digest, Sha256};
pub(crate) fn profile_digest(role: Role) -> [u8; 32] {
    constants::profile_digest(role)
}
const HEADER_BYTES: usize = 144;
pub(crate) const ROW_BYTES: usize = 32;
pub(crate) const CERTIFICATE_BYTES: usize = HEADER_BYTES + N * ROW_BYTES;
const W_OFFSET: u64 = 1 << 45;
const K_OFFSET: u128 = 1 << 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Role {
    Extend2To4 = 1,
    Scale4To2 = 2,
}
impl Role {
    pub(crate) const fn input_moduli(self) -> &'static [u64] {
        match self {
            Self::Extend2To4 => &Q,
            Self::Scale4To2 => &QP,
        }
    }
    pub(crate) const fn output_moduli(self) -> &'static [u64] {
        match self {
            Self::Extend2To4 => &QP,
            Self::Scale4To2 => &Q,
        }
    }
    const fn computed_moduli(self) -> &'static [u64; 2] {
        match self {
            Self::Extend2To4 => &P,
            Self::Scale4To2 => &Q,
        }
    }
    const fn computed_offset(self) -> usize {
        match self {
            Self::Extend2To4 => 2,
            Self::Scale4To2 => 0,
        }
    }
}
/// Natural PowerBasis rows, in the complete role-specific ordered basis.
#[derive(Clone)]
pub(crate) struct Request {
    role: Role,
    binding: [u8; 32],
    input: Vec<Vec<u64>>,
}
impl Request {
    pub(crate) fn new(role: Role, binding: [u8; 32], input: Vec<Vec<u64>>) -> Result<Self> {
        validate_polynomials(&input, role.input_moduli())?;
        Ok(Self {
            role,
            binding,
            input,
        })
    }
    pub(crate) fn rows(&self) -> &[Vec<u64>] {
        &self.input
    }
}
#[derive(Clone)]
pub(crate) struct Output {
    role: Role,
    binding: [u8; 32],
    input_digest: [u8; 32],
    coefficients: Vec<Vec<u64>>,
}
impl Output {
    pub(crate) fn new(request: &Request, coefficients: Vec<Vec<u64>>) -> Result<Self> {
        validate_polynomials(&coefficients, request.role.output_moduli())?;
        Ok(Self {
            role: request.role,
            binding: request.binding,
            input_digest: request_digest(request),
            coefficients,
        })
    }
    pub(crate) fn rows(&self) -> &[Vec<u64>] {
        &self.coefficients
    }
}
/// Canonical public quotient witnesses, NOT a cryptographic grant.
/// Remainders and AIR carry chains are absent: the verifier derives bounded remainders
/// with checked signed256-bit linear equations and never divides to obtain these witnesses.
#[derive(Clone)]
struct Quotients {
    v: u64,
    biased_w: u64,
    biased_k: [u128; 2],
}
impl Quotients {
    fn validate(&self) -> Result<()> {
        if self.biased_w >= (1 << 46) || self.biased_k.iter().any(|&k| k >= (1 << 66)) {
            return Err(Error::Arithmetic);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(crate) struct PublicCertificate {
    role: Role,
    binding: [u8; 32],
    input_digest: [u8; 32],
    output_digest: [u8; 32],
    rows: Vec<Quotients>,
}
impl PublicCertificate {
    pub(crate) fn reductions(&self) -> Result<Vec<[u128; 2]>> {
        if self.rows.len() != N {
            return Err(Error::Shape);
        }
        self.rows
            .iter()
            .map(|row| {
                row.validate()?;
                Ok(row.biased_k)
            })
            .collect()
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if self.rows.len() != N {
            return Err(Error::Shape);
        }
        let mut out = Vec::with_capacity(CERTIFICATE_BYTES);
        out.extend_from_slice(b"DCSUSC01");
        out.push(self.role as u8);
        out.extend_from_slice(&[0; 7]);
        out.extend_from_slice(&self.binding);
        out.extend_from_slice(&constants::profile_digest(self.role));
        out.extend_from_slice(&self.input_digest);
        out.extend_from_slice(&self.output_digest);
        for row in &self.rows {
            row.validate()?;
            out.extend_from_slice(&row.v.to_le_bytes());
            out.extend_from_slice(&row.biased_w.to_le_bytes()[..6]);
            for k in row.biased_k {
                out.extend_from_slice(&k.to_le_bytes()[..9]);
            }
        }
        Ok(out)
    }
    /// Exact-size, reserved-zero, profile-bound decode before any row allocation.
    #[cfg(test)]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CERTIFICATE_BYTES || &bytes[..8] != b"DCSUSC01" || bytes[9..16] != [0; 7]
        {
            return Err(Error::Shape);
        }
        let role = match bytes[8] {
            1 => Role::Extend2To4,
            2 => Role::Scale4To2,
            _ => return Err(Error::Shape),
        };
        if bytes[48..80] != constants::profile_digest(role) {
            return Err(Error::Binding);
        }
        let array32 = |at| -> [u8; 32] { bytes[at..at + 32].try_into().expect("fixed frame") };
        let mut rows = Vec::with_capacity(N);
        for row in bytes[HEADER_BYTES..].as_chunks::<ROW_BYTES>().0 {
            let v = u64::from_le_bytes(row[..8].try_into().expect("fixed row"));
            let mut w = [0; 8];
            w[..6].copy_from_slice(&row[8..14]);
            let biased_k = core::array::from_fn(|j| {
                let mut k = [0; 16];
                k[..9].copy_from_slice(&row[14 + 9 * j..23 + 9 * j]);
                u128::from_le_bytes(k)
            });
            let values = Quotients {
                v,
                biased_w: u64::from_le_bytes(w),
                biased_k,
            };
            values.validate()?;
            rows.push(values);
        }
        Ok(Self {
            role,
            binding: array32(16),
            input_digest: array32(80),
            output_digest: array32(112),
            rows,
        })
    }
}
pub(crate) struct Evaluation {
    pub(crate) output: Output,
    pub(crate) certificate: PublicCertificate,
}
fn coefficient_digest(
    domain: &[u8],
    role: Role,
    binding: &[u8; 32],
    input_digest: Option<&[u8; 32]>,
    rows: &[Vec<u64>],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(constants::profile_digest(role));
    h.update([role as u8]);
    h.update(binding);
    if let Some(input) = input_digest {
        h.update(input);
    }
    for row in rows {
        for &x in row {
            h.update(x.to_le_bytes());
        }
    }
    h.finalize().into()
}
fn request_digest(request: &Request) -> [u8; 32] {
    coefficient_digest(
        b"DCS/EXPERIMENT/UNREL-SCALER/input/v1",
        request.role,
        &request.binding,
        None,
        &request.input,
    )
}
fn output_digest(output: &Output) -> [u8; 32] {
    coefficient_digest(
        b"DCS/EXPERIMENT/UNREL-SCALER/output/v1",
        output.role,
        &output.binding,
        Some(&output.input_digest),
        &output.coefficients,
    )
}
fn check_bindings(
    request: &Request,
    output: &Output,
    certificate: &PublicCertificate,
) -> Result<()> {
    validate_polynomials(&request.input, request.role.input_moduli())?;
    validate_polynomials(&output.coefficients, request.role.output_moduli())?;
    let input_digest = request_digest(request);
    if request.role != output.role
        || request.role != certificate.role
        || request.binding != output.binding
        || request.binding != certificate.binding
        || input_digest != output.input_digest
        || input_digest != certificate.input_digest
        || output_digest(output) != certificate.output_digest
    {
        return Err(Error::Binding);
    }
    if certificate.rows.len() != N {
        return Err(Error::Shape);
    }
    if request.role == Role::Extend2To4 && output.coefficients[..2] != request.input {
        return Err(Error::Arithmetic);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
