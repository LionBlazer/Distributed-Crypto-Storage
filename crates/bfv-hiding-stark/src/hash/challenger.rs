//! Full event-prefix SHA-512, not a rolling-hash or duplex construction.
use crate::{Challenge, Val};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::MerkleCap;
use sha2::{Digest, Sha512};

pub const DOMAIN: &[u8] = b"DCS/research/hash-hiding-FRI/FS-SHA512/full-prefix/v1\0";
const FIELD: u8 = 1;
const CAP: u8 = 2;
const SAMPLE: u8 = 3;
const DRAW: u8 = 4;

/// Retains the unfinalized SHA state of every observed/accepted-sample event.
/// Cloning that state hashes the entire prefix, without retaining a transcript Vec.
#[derive(Clone)]
pub struct Challenger {
    prefix: Sha512,
    draws: u64,
}

impl Default for Challenger {
    fn default() -> Self {
        Self::new()
    }
}

impl Challenger {
    pub fn new() -> Self {
        let mut prefix = Sha512::new();
        prefix.update(DOMAIN);
        Self { prefix, draws: 0 }
    }

    fn field(&mut self) -> Val {
        let counter = self.draws;
        let value = rejection_sample(|retry| {
            let mut hash = self.prefix.clone();
            hash.update([DRAW]);
            hash.update(counter.to_le_bytes());
            hash.update(retry.to_le_bytes());
            let digest = hash.finalize();
            u64::from_le_bytes(digest[..8].try_into().expect("fixed digest prefix"))
        });
        self.draws = counter.checked_add(1).expect("challenge counter overflow");
        self.prefix.update([SAMPLE]);
        self.prefix.update(counter.to_le_bytes());
        self.prefix.update(value.as_canonical_u64().to_le_bytes());
        value
    }
}

fn rejection_sample(mut draw: impl FnMut(u64) -> u64) -> Val {
    let mut retry = 0u64;
    loop {
        let candidate = draw(retry);
        if candidate < Val::ORDER_U64 {
            return Val::from_u64(candidate);
        }
        retry = retry.checked_add(1).expect("rejection counter overflow");
    }
}

impl CanObserve<Val> for Challenger {
    fn observe(&mut self, value: Val) {
        self.prefix.update([FIELD]);
        self.prefix.update(value.as_canonical_u64().to_le_bytes());
    }
}
impl CanObserve<&MerkleCap<Val, [u8; 32]>> for Challenger {
    fn observe(&mut self, cap: &MerkleCap<Val, [u8; 32]>) {
        self.prefix.update([CAP]);
        self.prefix.update(
            u64::try_from(cap.num_roots())
                .expect("cap root count fits u64")
                .to_le_bytes(),
        );
        for digest in cap.roots() {
            self.prefix.update(digest);
        }
    }
}
impl CanObserve<MerkleCap<Val, [u8; 32]>> for Challenger {
    fn observe(&mut self, cap: MerkleCap<Val, [u8; 32]>) {
        self.observe(&cap);
    }
}
impl CanSample<Val> for Challenger {
    fn sample(&mut self) -> Val {
        self.field()
    }
}
impl CanSample<Challenge> for Challenger {
    fn sample(&mut self) -> Challenge {
        Challenge::from_basis_coefficients_fn(|_| self.field())
    }
}
impl CanSampleBits<usize> for Challenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!(bits < 64 && bits < usize::BITS as usize);
        (self.field().as_canonical_u64() & ((1u64 << bits) - 1)) as usize
    }
}
impl FieldChallenger<Val> for Challenger {}
impl GrindingChallenger for Challenger {
    type Witness = Val;

    fn grind(&mut self, bits: usize) -> Val {
        // All sites in the closed candidate are zero. Positive difficulty is
        // unsupported, never simulated and never accepted by check_witness.
        assert_eq!(bits, 0, "candidate supports only zero grinding");
        Val::ZERO
    }

    fn check_witness(&mut self, bits: usize, witness: Val) -> bool {
        bits == 0 && witness == Val::ZERO
    }
}

#[cfg(test)]
mod tests;
