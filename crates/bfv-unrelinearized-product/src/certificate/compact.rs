//! One canonical wire encoding of the unchanged full arithmetic transcript.
#[cfg(test)]
use super::encode_logical;
use super::{
    Certificate, Expected, PRODUCTS_BYTES, Packer, ProductCertificate, QUOTIENTS_BYTES, Role,
    Unpacker, job_binding, scale,
};
use crate::{
    Error, Polynomial, Result,
    geometry::{N, QP},
};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"UCPITC02";
const HEADER: usize = 320;
const ROW: usize = 18;
const REDUCTIONS: usize = 7 * N * ROW;
pub(crate) const FRAME_BYTES: usize = HEADER + PRODUCTS_BYTES + QUOTIENTS_BYTES + REDUCTIONS;
const REDUCTIONS_FIRST: usize = HEADER + PRODUCTS_BYTES + QUOTIENTS_BYTES;

pub(crate) fn wire_profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"DCS/UNREL-PIT/compact-wire/v2/UCPITC02/no-legacy-wire-fallback");
    h.update(crate::profile_digest());
    h.update(b"all-Y3xQP4096/H3xQP4095;7x4096x2-biasedK66LE9;recover-v-w-by-signed-shifts127/y=A-p*k/canonical-integer-bounds;recreate-original-full-logical-frame-before-unchanged-scalar-and-full-transcript-PIT;no-SDK-division-NTT-query-replay-or-verdict");
    for n in [HEADER, ROW, FRAME_BYTES, super::LOGICAL_FRAME_BYTES] {
        h.update((n as u64).to_le_bytes());
    }
    h.finalize().into()
}
fn header(statement: &Expected) -> [u8; HEADER] {
    let mut out = [0; HEADER];
    out[..super::HEADER].copy_from_slice(&super::header(statement));
    out[..8].copy_from_slice(MAGIC);
    out[232..240].copy_from_slice(&(FRAME_BYTES as u64).to_le_bytes());
    out[256..288].copy_from_slice(&wire_profile_digest());
    out[288..296].copy_from_slice(&(super::LOGICAL_FRAME_BYTES as u64).to_le_bytes());
    out[296..304].copy_from_slice(&(ROW as u64).to_le_bytes());
    out[304..312].copy_from_slice(&7u64.to_le_bytes());
    out
}
pub(super) fn encode(statement: &Expected, c: &Certificate) -> Result<Vec<u8>> {
    let mut pack = Packer::new();
    for poly in &c.product.products {
        pack.polynomial(poly, &QP, N)?;
    }
    for poly in &c.product.quotients {
        pack.polynomial(poly, &QP, N - 1)?;
    }
    let mut out = Vec::with_capacity(FRAME_BYTES);
    out.extend(header(statement));
    out.extend(pack.finish());
    if out.len() != REDUCTIONS_FIRST {
        return Err(Error::Shape);
    }
    for certificate in &c.scalers {
        for row in certificate.reductions()? {
            for k in row {
                out.extend_from_slice(&k.to_le_bytes()[..9]);
            }
        }
    }
    if out.len() != FRAME_BYTES {
        return Err(Error::Shape);
    }
    Ok(out)
}
pub(super) fn decode(statement: &Expected, frame: &[u8]) -> Result<Certificate> {
    // All extent/profile/reserved/binding checks precede any decoded allocation.
    if frame.len() != FRAME_BYTES || frame[..HEADER] != header(statement) {
        return Err(Error::Binding);
    }
    let mut pack = Unpacker::new(&frame[HEADER..REDUCTIONS_FIRST]);
    let mut products = Vec::with_capacity(3);
    let mut quotients = Vec::with_capacity(3);
    for _ in 0..3 {
        products.push(pack.polynomial(&QP, N)?);
    }
    for _ in 0..3 {
        quotients.push(pack.polynomial(&QP, N - 1)?);
    }
    pack.finish()?;
    let product = ProductCertificate {
        products: products.try_into().map_err(|_| Error::Shape)?,
        quotients: quotients.try_into().map_err(|_| Error::Shape)?,
    };
    let mut extended_p = Vec::with_capacity(4);
    let mut scalers = Vec::with_capacity(7);
    for (job, rows) in frame[REDUCTIONS_FIRST..]
        .as_chunks::<{ N * ROW }>()
        .0
        .iter()
        .enumerate()
    {
        let mut reductions = Vec::with_capacity(N);
        for bytes in rows.as_chunks::<ROW>().0 {
            let mut k = [0u128; 2];
            for (at, out) in k.iter_mut().enumerate() {
                let mut word = [0; 16];
                word[..9].copy_from_slice(&bytes[9 * at..9 * at + 9]);
                *out = u128::from_le_bytes(word);
                if *out >= (1u128 << 66) {
                    return Err(Error::Arithmetic);
                }
            }
            reductions.push(k);
        }
        let (role, input): (Role, Polynomial) = if job < 4 {
            (Role::Extend2To4, statement.input(job).clone())
        } else {
            (Role::Scale4To2, product.products[job - 4].clone())
        };
        let request = scale::Request::new(role, job_binding(statement, job), input)?;
        let restored = scale::reconstruct(&request, reductions)?;
        if job < 4 {
            extended_p.push(restored.output.rows()[2..].to_vec());
        } else if restored.output.rows() != statement.output(job - 4) {
            return Err(Error::Arithmetic);
        }
        scalers.push(restored.certificate);
    }
    Ok(Certificate {
        extended_p: extended_p.try_into().map_err(|_| Error::Shape)?,
        product,
        scalers: scalers.try_into().map_err(|_| Error::Shape)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn genuine_compact_wire_expands_to_the_exact_original_division_producer_transcript()
    -> Result<()> {
        let example = crate::tests::fixture::example()?;
        let original = super::super::build_certificate(&example.statement)?;
        let logical = encode_logical(&example.statement, &original)?;
        let wire = encode(&example.statement, &original)?;
        let restored = decode(&example.statement, &wire)?;
        assert_eq!(encode_logical(&example.statement, &restored)?, logical);
        assert_eq!(wire.len(), 1_081_595);
        assert_eq!(logical.len(), 1_737_899);
        crate::check_arithmetic(&example.statement, &wire)?;
        assert!(crate::check_arithmetic(&example.statement, &logical).is_err());
        let original = super::super::decode_logical(&example.statement, &logical)?;
        assert_eq!(encode(&example.statement, &original)?, wire);
        for len in [0, 7, HEADER - 1, HEADER, FRAME_BYTES - 1] {
            assert!(crate::check_arithmetic(&example.statement, &wire[..len]).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(crate::check_arithmetic(&example.statement, &trailing).is_err());
        for at in [
            0, 7, 8, 71, 72, 103, 104, 167, 168, 231, 232, 247, 248, 255, 256, 287, 288, 303, 304,
            311, 312, 319,
        ] {
            let mut bad = wire.clone();
            bad[at] ^= 1;
            assert!(
                crate::check_arithmetic(&example.statement, &bad).is_err(),
                "header {at}"
            );
        }
        for job in 0..7 {
            for component in 0..2 {
                let at = REDUCTIONS_FIRST + job * N * ROW + (N - 1) * ROW + 9 * component;
                let mut bad = wire.clone();
                bad[at] ^= 1;
                assert!(
                    crate::check_arithmetic(&example.statement, &bad).is_err(),
                    "last reduction {job}/{component}"
                );
                for high_bit in [0x04, 0x80] {
                    let mut bad = wire.clone();
                    bad[at + 8] |= high_bit;
                    assert!(
                        crate::check_arithmetic(&example.statement, &bad).is_err(),
                        "high reduction bits {job}/{component}/{high_bit}"
                    );
                }
            }
        }
        Ok(())
    }
}
