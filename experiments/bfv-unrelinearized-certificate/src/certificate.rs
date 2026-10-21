//! One bounded complete public arithmetic certificate, with closed full-byte binding.
use crate::{
    Error, Polynomial, Result,
    geometry::{N, P, QP},
    pit::{self, ProductCertificate},
    scale::{self, Role},
    statement::Statement,
};
use sha2::{Digest, Sha256, Sha512};

const MAGIC: &[u8; 8] = b"UCPITC01";
const HEADER: usize = 256;
const EXTENDED_P_BYTES: usize = 4 * 2 * N * 62 / 8;
const PRODUCTS_BYTES: usize = 3 * N * (30 + 30 + 62 + 62) / 8;
const QUOTIENTS_BYTES: usize = (3 * (N - 1) * (30 + 30 + 62 + 62)).div_ceil(8);
pub(crate) const FRAME_BYTES: usize =
    HEADER + EXTENDED_P_BYTES + PRODUCTS_BYTES + QUOTIENTS_BYTES + 7 * scale::CERTIFICATE_BYTES;
struct Certificate {
    extended_p: [Polynomial; 4],
    product: ProductCertificate,
    scalers: [scale::PublicCertificate; 7],
}
fn job_binding(statement: &Statement, ordinal: usize) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/UNREL-PIT/v1/exact-rounding-job/");
    h.update(statement.binding());
    h.update(Sha512::digest(statement.request_wire()));
    h.update(Sha512::digest(statement.output_wire()));
    h.update((ordinal as u32).to_le_bytes());
    h.finalize().into()
}
fn header(statement: &Statement) -> [u8; HEADER] {
    let mut bytes = [0; HEADER];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..72].copy_from_slice(&crate::profile_digest());
    bytes[72..104].copy_from_slice(&statement.binding());
    bytes[104..168].copy_from_slice(&Sha512::digest(statement.request_wire()));
    bytes[168..232].copy_from_slice(&Sha512::digest(statement.output_wire()));
    bytes[232..240].copy_from_slice(&(FRAME_BYTES as u64).to_le_bytes());
    bytes[240..244].copy_from_slice(&(N as u32).to_le_bytes());
    bytes[244..248].copy_from_slice(&(pit::POINTS as u32).to_le_bytes());
    bytes
}
struct Packer {
    bytes: Vec<u8>,
    word: u128,
    bits: usize,
}
impl Packer {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            word: 0,
            bits: 0,
        }
    }
    fn put(&mut self, value: u64, p: u64) -> Result<()> {
        if value >= p {
            return Err(Error::Arithmetic);
        }
        let width = (64 - (p - 1).leading_zeros()) as usize;
        self.word |= u128::from(value) << self.bits;
        self.bits += width;
        while self.bits >= 8 {
            self.bytes.push(self.word as u8);
            self.word >>= 8;
            self.bits -= 8;
        }
        Ok(())
    }
    fn polynomial(&mut self, rows: &Polynomial, moduli: &[u64], length: usize) -> Result<()> {
        if rows.len() != moduli.len() {
            return Err(Error::Shape);
        }
        for (row, &p) in rows.iter().zip(moduli) {
            if row.len() != length {
                return Err(Error::Shape);
            }
            for &value in row {
                self.put(value, p)?;
            }
        }
        Ok(())
    }
    fn finish(mut self) -> Vec<u8> {
        if self.bits != 0 {
            self.bytes.push(self.word as u8);
        }
        self.bytes
    }
}
struct Unpacker<'a> {
    bytes: &'a [u8],
    at: usize,
    word: u128,
    bits: usize,
}
impl<'a> Unpacker<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            at: 0,
            word: 0,
            bits: 0,
        }
    }
    fn get(&mut self, p: u64) -> Result<u64> {
        let width = (64 - (p - 1).leading_zeros()) as usize;
        while self.bits < width {
            self.word |= u128::from(*self.bytes.get(self.at).ok_or(Error::Shape)?) << self.bits;
            self.bits += 8;
            self.at += 1;
        }
        let value = (self.word & ((1u128 << width) - 1)) as u64;
        self.word >>= width;
        self.bits -= width;
        if value >= p {
            return Err(Error::Arithmetic);
        }
        Ok(value)
    }
    fn polynomial(&mut self, moduli: &[u64], length: usize) -> Result<Polynomial> {
        moduli
            .iter()
            .map(|&p| (0..length).map(|_| self.get(p)).collect())
            .collect()
    }
    fn finish(self) -> Result<()> {
        if self.at != self.bytes.len() || self.word != 0 {
            Err(Error::Shape)
        } else {
            Ok(())
        }
    }
}
fn encode(statement: &Statement, certificate: &Certificate) -> Result<Vec<u8>> {
    let mut pack = Packer::new();
    for polynomial in &certificate.extended_p {
        pack.polynomial(polynomial, &P, N)?;
    }
    for polynomial in &certificate.product.products {
        pack.polynomial(polynomial, &QP, N)?;
    }
    for polynomial in &certificate.product.quotients {
        pack.polynomial(polynomial, &QP, N - 1)?;
    }
    let mut bytes = header(statement).to_vec();
    bytes.extend_from_slice(&pack.finish());
    for scaler in &certificate.scalers {
        bytes.extend_from_slice(&scaler.encode()?);
    }
    if bytes.len() != FRAME_BYTES {
        return Err(Error::Shape);
    }
    Ok(bytes)
}
fn decode(statement: &Statement, bytes: &[u8]) -> Result<Certificate> {
    if bytes.len() != FRAME_BYTES || bytes[..HEADER] != header(statement) {
        return Err(Error::Binding);
    }
    let end = HEADER + EXTENDED_P_BYTES + PRODUCTS_BYTES + QUOTIENTS_BYTES;
    let mut pack = Unpacker::new(&bytes[HEADER..end]);
    let mut extended_p = Vec::with_capacity(4);
    for _ in 0..4 {
        extended_p.push(pack.polynomial(&P, N)?);
    }
    let mut products = Vec::with_capacity(3);
    let mut quotients = Vec::with_capacity(3);
    for _ in 0..3 {
        products.push(pack.polynomial(&QP, N)?);
    }
    for _ in 0..3 {
        quotients.push(pack.polynomial(&QP, N - 1)?);
    }
    pack.finish()?;
    let mut scalers = Vec::with_capacity(7);
    for chunk in bytes[end..].as_chunks::<{ scale::CERTIFICATE_BYTES }>().0 {
        scalers.push(scale::PublicCertificate::decode(chunk)?);
    }
    Ok(Certificate {
        extended_p: extended_p.try_into().map_err(|_| Error::Shape)?,
        product: ProductCertificate {
            products: products.try_into().map_err(|_| Error::Shape)?,
            quotients: quotients.try_into().map_err(|_| Error::Shape)?,
        },
        scalers: scalers.try_into().map_err(|_| Error::Shape)?,
    })
}
pub(crate) fn produce(statement: &Statement) -> Result<Vec<u8>> {
    let mut extended = Vec::with_capacity(4);
    let mut scalers = Vec::with_capacity(7);
    for i in 0..4 {
        let request = scale::Request::new(
            Role::Extend2To4,
            job_binding(statement, i),
            statement.input(i).clone(),
        )?;
        let evaluation = scale::evaluate(&request)?;
        if &evaluation.output.rows()[..2] != request.rows() {
            return Err(Error::Arithmetic);
        }
        extended.push(evaluation.output.rows().to_vec());
        scalers.push(evaluation.certificate);
    }
    let extended: [Polynomial; 4] = extended.try_into().map_err(|_| Error::Shape)?;
    let product = pit::produce(&extended)?;
    for i in 0..3 {
        let request = scale::Request::new(
            Role::Scale4To2,
            job_binding(statement, 4 + i),
            product.products[i].clone(),
        )?;
        let evaluation = scale::evaluate(&request)?;
        if evaluation.output.rows() != statement.output(i) {
            return Err(Error::Arithmetic);
        }
        scalers.push(evaluation.certificate);
    }
    let certificate = Certificate {
        extended_p: std::array::from_fn(|i| extended[i][2..].to_vec()),
        product,
        scalers: scalers.try_into().map_err(|_| Error::Shape)?,
    };
    encode(statement, &certificate)
}

/// Experimental public arithmetic checks only. It grants no assessed protocol,
/// key, Source, hidden-program, database, freshness or SQL authority.
pub(crate) fn check(statement: &Statement, frame: &[u8]) -> Result<()> {
    let certificate = decode(statement, frame)?;
    let extended: [Polynomial; 4] = std::array::from_fn(|i| {
        let mut rows = statement.input(i).clone();
        rows.extend_from_slice(&certificate.extended_p[i]);
        rows
    });
    for (i, rows) in extended.iter().enumerate() {
        let request = scale::Request::new(
            Role::Extend2To4,
            job_binding(statement, i),
            statement.input(i).clone(),
        )?;
        let output = scale::Output::new(&request, rows.clone())?;
        scale::verify_certificate(&request, &output, &certificate.scalers[i])?;
    }
    for i in 0..3 {
        let request = scale::Request::new(
            Role::Scale4To2,
            job_binding(statement, i + 4),
            certificate.product.products[i].clone(),
        )?;
        let output = scale::Output::new(&request, statement.output(i).clone())?;
        scale::verify_certificate(&request, &output, &certificate.scalers[i + 4])?;
    }
    // This is the only caller of the PIT checker. Hash the SAME complete frame
    // after bounded canonical decoding, not caller-provided challenge metadata.
    let prefix = pit::transcript_prefix(statement, frame);
    pit::check(&extended, &certificate.product, &prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::Q;
    #[test]
    fn bitpacking_checks_every_basis_boundary_and_rejects_noncanonical_values() -> Result<()> {
        let mut pack = Packer::new();
        for p in QP {
            pack.put(p - 1, p)?;
        }
        let bytes = pack.finish();
        let mut read = Unpacker::new(&bytes);
        for p in QP {
            assert_eq!(read.get(p)?, p - 1);
        }
        read.finish()?;
        let mut bad = Packer::new();
        assert!(bad.put(Q[0], Q[0]).is_err());
        let mut padding = Packer::new();
        padding.put(1, Q[0])?;
        let mut bytes = padding.finish();
        *bytes.last_mut().unwrap() |= 0x80;
        let mut read = Unpacker::new(&bytes);
        assert_eq!(read.get(Q[0])?, 1);
        assert!(read.finish().is_err());
        Ok(())
    }
    #[test]
    fn genuine_sdk_certificate_is_independently_checked_and_repaired_mutations_fail() -> Result<()>
    {
        let example = crate::fixture::example()?;
        example.complete()?;
        let statement = example.statement;
        let frame = produce(&statement)?;
        check(&statement, &frame)?;
        for change in 0..4 {
            let mut c = decode(&statement, &frame)?;
            match change {
                0 => {
                    c.product.products[2][3][N - 1] = (c.product.products[2][3][N - 1] + 1) % QP[3]
                }
                1 => {
                    c.product.quotients[1][0][N - 2] =
                        (c.product.quotients[1][0][N - 2] + 1) % QP[0]
                }
                2 => c.extended_p[3][1][N - 1] = (c.extended_p[3][1][N - 1] + 1) % P[1],
                _ => c.scalers.swap(0, 1),
            }
            let repaired = encode(&statement, &c)?;
            assert!(
                check(&statement, &repaired).is_err(),
                "Repairing outer hashes is not arithmetic authority"
            );
        }
        assert!(check(&statement, &frame[..frame.len() - 1]).is_err());
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(check(&statement, &trailing).is_err());
        // A hostile peer repairs the output AND every exact scalar certificate.
        // Only the independent product identity remains false. All inputs still
        // come from the same actual freshly encrypted SDK endpoints.
        let mut forged = decode(&statement, &frame)?;
        forged.product.products[2][0][N - 1] =
            (forged.product.products[2][0][N - 1] + Q[0] / 2) % Q[0];
        let fake_outputs: [Polynomial; 3] = std::array::from_fn(|i| {
            let r = scale::Request::new(
                Role::Scale4To2,
                [0x52; 32],
                forged.product.products[i].clone(),
            )
            .unwrap();
            scale::evaluate(&r).unwrap().output.rows().to_vec()
        });
        assert!(
            fake_outputs
                .iter()
                .enumerate()
                .any(|(i, row)| row != statement.output(i))
        );
        let forged_statement = statement.with_public_test_outputs(&fake_outputs)?;
        let mut repaired_scalers = Vec::with_capacity(7);
        for i in 0..4 {
            let request = scale::Request::new(
                Role::Extend2To4,
                job_binding(&forged_statement, i),
                forged_statement.input(i).clone(),
            )?;
            let evaluation = scale::evaluate(&request)?;
            scale::verify_certificate(&request, &evaluation.output, &evaluation.certificate)?;
            repaired_scalers.push(evaluation.certificate);
        }
        for i in 0..3 {
            let request = scale::Request::new(
                Role::Scale4To2,
                job_binding(&forged_statement, i + 4),
                forged.product.products[i].clone(),
            )?;
            let evaluation = scale::evaluate(&request)?;
            assert_eq!(evaluation.output.rows(), forged_statement.output(i));
            scale::verify_certificate(&request, &evaluation.output, &evaluation.certificate)?;
            repaired_scalers.push(evaluation.certificate);
        }
        forged.scalers = repaired_scalers.try_into().map_err(|_| Error::Shape)?;
        let repaired = encode(&forged_statement, &forged)?;
        assert!(matches!(
            check(&forged_statement, &repaired),
            Err(Error::Arithmetic)
        ));
        Ok(())
    }
}
