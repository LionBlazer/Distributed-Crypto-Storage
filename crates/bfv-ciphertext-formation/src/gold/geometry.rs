use super::{Error, Request, Result};
use sha2::{Digest, Sha512};
pub const N: usize = 4096;
pub const Q: [u64; 2] = [1073692673, 1073668097];
pub const T: u64 = 65537;
pub const SCALE: u64 = 16389;
pub(super) const DELTA: [u64; 2] = [536854528, 282551134];
pub(super) type Polynomial = Vec<Vec<u64>>;
pub(super) fn validate_polynomials(rows: &[Vec<u64>], moduli: &[u64; 2]) -> Result<()> {
    if rows.len() != 2 || rows.iter().any(|r| r.len() != N) {
        return Err(Error::Shape);
    }
    if rows
        .iter()
        .zip(moduli)
        .any(|(r, &p)| r.iter().any(|&v| v >= p))
    {
        return Err(Error::Arithmetic);
    }
    Ok(())
}
#[derive(Clone)]
pub(super) struct Inputs<'a> {
    pub(super) nonce: [u8; 32],
    pub(super) identity: [u8; 64],
    pub(super) kind: super::relation::RelationKind,
    pub(super) components: Vec<[&'a [u64]; 2]>,
}
impl<'a> Inputs<'a> {
    pub(super) fn new(request: &'a Request) -> Result<Self> {
        for c in 0..4 {
            validate_polynomials(request.input(c), &Q)?;
        }
        let mut h = Sha512::new();
        h.update(b"DCS/CoreGold/private-original-request/v1");
        h.update((request.bytes().len() as u64).to_le_bytes());
        h.update(request.bytes());
        Ok(Self {
            nonce: request.nonce(),
            identity: h.finalize().into(),
            kind: super::relation::RelationKind::Pair,
            components: (0..4)
                .map(|c| core::array::from_fn(|b| request.input(c)[b].as_slice()))
                .collect(),
        })
    }
    pub(super) fn data(request: &'a super::data::Request) -> Result<Self> {
        for c in 0..2 {
            validate_polynomials(request.input(c), &Q)?;
        }
        let mut h = Sha512::new();
        h.update(b"DCS/CoreGold/DATA-private-original-request/v1");
        h.update((request.bytes().len() as u64).to_le_bytes());
        h.update(request.bytes());
        Ok(Self {
            nonce: request.nonce(),
            identity: h.finalize().into(),
            kind: super::relation::RelationKind::Data,
            components: (0..2)
                .map(|c| core::array::from_fn(|b| request.input(c)[b].as_slice()))
                .collect(),
        })
    }
    pub(super) fn validate(&self) -> Result<()> {
        if self.components.len() != self.kind.operands() * 2 {
            return Err(Error::Shape);
        }
        if self.nonce == [0; 32] {
            return Err(Error::Binding);
        }
        for component in &self.components {
            for (b, row) in component.iter().enumerate() {
                if row.len() != N {
                    return Err(Error::Shape);
                }
                if row.iter().any(|&v| v >= Q[b]) {
                    return Err(Error::Arithmetic);
                }
            }
        }
        Ok(())
    }
}
