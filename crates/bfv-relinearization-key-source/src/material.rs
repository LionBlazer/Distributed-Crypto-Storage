//! Complete fixed-envelope validation precedes every decoded coefficient allocation.
use crate::{
    COEFFICIENTS, DEGREE, Error, KEY_COMPONENTS, MAX_KEY_BYTES, MAX_POLYNOMIAL_BYTES, MODULI,
    PACKED_POLYNOMIAL_BYTES, Result, cursor::Cursor,
};
use bfv_query_core::{Geometry, PublicRelinearizationMaterial};

/// Public bytes and complete c0 PowerBasis rows from one canonical seeded key.
/// This is not a same-secret, authorization, NTT, relinearization or SQL proof.
pub struct UnverifiedSeededRelinearizationKey<'a> {
    material: PublicRelinearizationMaterial<'a>,
    seed: [u8; 32],
    c0: [Vec<u64>; KEY_COMPONENTS],
}

/// Parse the original key bytes from the borrowed setup, requiring its COMPLETE
/// identity to match an independently obtained expected identity before parsing.
///
/// This accepts only level0/0, log_base0, five c0 NttShoup envelopes, a seed32 and
/// no c1. Wire coefficients are PowerBasis despite the NttShoup tag. All lengths,
/// tags, counts, canonical defaults and every residue are checked without a vector
/// allocation first. Only then are the fixed five complete c0 vectors allocated.
pub fn decode_seeded<'a>(
    material: PublicRelinearizationMaterial<'a>,
    independently_expected_keyset_id: [u8; 32],
) -> Result<UnverifiedSeededRelinearizationKey<'a>> {
    if material.keyset_id() != independently_expected_keyset_id {
        return Err(Error::SetupMismatch);
    }
    let bytes = material.relinearization_key();
    if bytes.is_empty() || bytes.len() > MAX_KEY_BYTES {
        return Err(Error::ByteLimit);
    }
    let mut outer = Cursor::new(bytes);
    outer.tag(0x0a)?;
    let ksk = outer.delimited(MAX_KEY_BYTES)?;
    outer.finish()?;
    let mut ksk = Cursor::new(ksk);
    let mut packed = [&[][..]; KEY_COMPONENTS];
    for polynomial in &mut packed {
        ksk.tag(0x0a)?;
        *polynomial = polynomial_payload(ksk.delimited(MAX_POLYNOMIAL_BYTES)?)?;
    }
    ksk.tag(0x1a)?;
    let seed = ksk
        .delimited(32)?
        .try_into()
        .map_err(|_| Error::CanonicalEncoding)?;
    // A sixth c0, any c1, unknown fields, explicit zero levels/logbase or trailing
    // fields all fail the exact tag/order/finish contract above or here.
    ksk.finish()?;

    // This pass is deliberately before array::from_fn/Vec::with_capacity.
    for polynomial in packed {
        for (basis, modulus) in MODULI.into_iter().enumerate() {
            if row(polynomial, basis).any(|value| value >= modulus) {
                return Err(Error::Residue);
            }
        }
    }
    let c0 = core::array::from_fn(|index| {
        let mut values = Vec::with_capacity(COEFFICIENTS);
        for basis in 0..KEY_COMPONENTS {
            values.extend(row(packed[index], basis));
        }
        values
    });
    Ok(UnverifiedSeededRelinearizationKey { material, seed, c0 })
}

fn polynomial_payload(bytes: &[u8]) -> Result<&[u8]> {
    let mut rq = Cursor::new(bytes);
    rq.tag(0x08)?;
    if rq.varint()? != 3 {
        return Err(Error::CanonicalEncoding);
    }
    rq.tag(0x10)?;
    if rq.varint()? != DEGREE as u64 {
        return Err(Error::CanonicalEncoding);
    }
    rq.tag(0x1a)?;
    let coefficients = rq.delimited(PACKED_POLYNOMIAL_BYTES)?;
    if coefficients.len() != PACKED_POLYNOMIAL_BYTES {
        return Err(Error::CanonicalEncoding);
    }
    // Canonical prost bool: false is omitted; true is exactly tag32/value1.
    if !rq.is_finished() {
        rq.tag(0x20)?;
        if rq.varint()? != 1 {
            return Err(Error::CanonicalEncoding);
        }
    }
    rq.finish()?;
    Ok(coefficients)
}

fn row(packed: &[u8], basis: usize) -> impl ExactSizeIterator<Item = u64> + '_ {
    let width = (u64::BITS - (MODULI[basis] - 1).leading_zeros()) as usize;
    let offset = MODULI[..basis]
        .iter()
        .map(|q| (u64::BITS - (q - 1).leading_zeros()) as usize * DEGREE / 8)
        .sum::<usize>();
    let bytes = &packed[offset..offset + width * DEGREE / 8];
    (0..DEGREE).map(move |index| {
        let bit = index * width;
        let first = bit / 8;
        let shift = bit % 8;
        let count = (shift + width).div_ceil(8);
        let value = bytes[first..first + count]
            .iter()
            .enumerate()
            .fold(0u64, |value, (i, byte)| {
                value | (u64::from(*byte) << (8 * i))
            });
        (value >> shift) & ((1u64 << width) - 1)
    })
}

impl<'a> UnverifiedSeededRelinearizationKey<'a> {
    /// Original fixed parameter bytes from the borrowed complete setup.
    pub fn parameters(&self) -> &'a [u8] {
        self.material.parameters()
    }
    /// Original complete public relinearization protobuf, never reconstructed.
    pub fn relinearization_key(&self) -> &'a [u8] {
        self.material.relinearization_key()
    }
    /// Existing setup geometry, without source/query coverage authority.
    pub fn geometry(&self) -> Geometry {
        self.material.geometry()
    }
    /// Complete setup identity; matching it does not authenticate a sender.
    pub fn keyset_id(&self) -> [u8; 32] {
        self.material.keyset_id()
    }
    /// Public master seed of the exact pinned five-element expansion.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }
    /// Complete original Q5 PowerBasis c0 for decomposition index0..4, modulus-major.
    pub fn c0_power_basis(&self, decomposition: usize) -> Option<&[u64]> {
        self.c0.get(decomposition).map(Vec::as_slice)
    }
}
