//! Test-private complete Stmt96 -> salted Cw4112 mathematical inventory.
//! No owner witness, proof producer, receiving capability or runtime API exists.
mod air;
mod assessment;
mod layout;
mod snapshot;
mod tests;

use crate::Val;
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};

const PROFILE_DOMAIN: &[u8] = b"DCS/research/QueryMaskEncoding/WordStmt96-Cw4112/v1/full4208/526P2/H1024/MAIN649/PP49/PUBLIC33/overwrite8-cap4/reverse256-scale16389-mod65537/high3840zero/all-padding-zero/no-owner-no-formation-no-authority";
const QUERY_ROLE: u32 = 0x514d_0001;
const PUBLIC_COUNT: usize = 33;
const PUBLIC_ROLE: usize = 8;
const PUBLIC_STATEMENT: usize = 9;
const PUBLIC_VECTOR: usize = 13;
const PUBLIC_CONTEXT: usize = 17;
const PUBLIC_NONCE: usize = 25;

fn profile() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PROFILE_DOMAIN);
    // The inner Stmt96 format remains the original Word profile, not this one.
    h.update(super::profile());
    h.finalize().into()
}
fn profile_words() -> [Val; 8] {
    let digest = profile();
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            digest[4 * i..4 * i + 4].try_into().expect("profile word"),
        ))
    })
}

/// Independently retained PUBLIC labels, not checked openings or authority.
/// The nonce is bound to this mathematical proof's PUBLIC values. Deriving a
/// context from the entire original request/Cs belongs to the future typed join.
struct Expected {
    statement: [Val; 4],
    vector: [Val; 4],
    context: [Val; 8],
    nonce: [u8; 32],
}
impl Expected {
    fn checked(
        statement: [Val; 4],
        vector: [Val; 4],
        context: [Val; 8],
        nonce: [u8; 32],
    ) -> Result<Self, &'static str> {
        if nonce == [0; 32] {
            return Err("query-mask:zero-nonce");
        }
        Ok(Self {
            statement,
            vector,
            context,
            nonce,
        })
    }
    fn values(&self) -> [Val; PUBLIC_COUNT] {
        let mut values = [Val::ZERO; PUBLIC_COUNT];
        values[..8].copy_from_slice(&profile_words());
        values[PUBLIC_ROLE] = Val::from_u32(QUERY_ROLE);
        values[PUBLIC_STATEMENT..PUBLIC_VECTOR].copy_from_slice(&self.statement);
        values[PUBLIC_VECTOR..PUBLIC_CONTEXT].copy_from_slice(&self.vector);
        values[PUBLIC_CONTEXT..PUBLIC_NONCE].copy_from_slice(&self.context);
        for (i, word) in self.nonce.as_chunks::<4>().0.iter().enumerate() {
            values[PUBLIC_NONCE + i] = Val::from_u32(u32::from_le_bytes(*word));
        }
        values
    }
}
