use super::{Error, Request, Result, Val, profile_digest};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha2::{Digest, Sha512};
#[derive(Clone)]
pub struct Expected {
    request: Request,
    association: [u8; 64],
    contexts: [[Val; 8]; 3],
    roots: [[Val; 4]; 3],
    binding: [u8; 64],
    values: Vec<Val>,
}
impl Expected {
    /// Independently retained mathematical expectations, never Source/key/SQL authority.
    pub fn checked(
        request: Request,
        association: [u8; 64],
        contexts: [[Val; 8]; 3],
        roots: [[Val; 4]; 3],
    ) -> Result<Self> {
        let mut h = Sha512::new();
        h.update(b"DCS/CoreGold/complete-Expected/v1");
        h.update(profile_digest());
        h.update((request.bytes().len() as u64).to_le_bytes());
        h.update(request.bytes());
        h.update(association);
        for row in &contexts {
            for v in row {
                h.update(v.as_canonical_u64().to_le_bytes());
            }
        }
        for row in &roots {
            for v in row {
                h.update(v.as_canonical_u64().to_le_bytes());
            }
        }
        let binding: [u8; 64] = h.finalize().into();
        let profile = profile_digest();
        let mut values = Vec::with_capacity(36);
        for word in profile.as_chunks::<4>().0 {
            values.push(Val::from_u32(u32::from_le_bytes(*word)));
        }
        for word in binding.as_chunks::<4>().0 {
            values.push(Val::from_u32(u32::from_le_bytes(*word)));
        }
        for root in [roots[2], roots[0], roots[1]] {
            values.extend(root);
        }
        if values.len() != 36 {
            return Err(Error::Shape);
        }
        Ok(Self {
            request,
            association,
            contexts,
            roots,
            binding,
            values,
        })
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn contexts(&self) -> [[Val; 8]; 3] {
        self.contexts
    }
    pub fn roots(&self) -> [[Val; 4]; 3] {
        self.roots
    }
    pub fn values(&self) -> &[Val] {
        &self.values
    }
    pub fn binding(&self) -> [u8; 64] {
        self.binding
    }
    pub(super) fn require_same(&self, other: &Self) -> Result<()> {
        if self.request.bytes() != other.request.bytes()
            || self.association != other.association
            || self.contexts != other.contexts
            || self.roots != other.roots
            || self.values != other.values
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
