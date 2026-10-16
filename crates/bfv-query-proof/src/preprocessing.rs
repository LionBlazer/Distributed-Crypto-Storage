//! Bounded reuse of locally derived public commitments, never proof acceptance.
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};

use p3_uni_stark::PreprocessedVerifierKey;
use sha2::{Digest, Sha256};

use crate::{Operation, PROOF_PROFILE_ID, circuit::Config};

type DigestKey = [u8; 32];
type VerifierKey = PreprocessedVerifierKey<Config>;
const CACHE_ENTRIES: usize = 128;
pub(super) static PREPROCESSING_CACHE: PreprocessingCache = PreprocessingCache::new();

pub(super) fn cache_key(operation: Operation, hashes: &[[u8; 32]; 3]) -> DigestKey {
    let mut digest = Sha256::new();
    digest.update(b"dcs/bfv-query-proof/local-preprocessing/v1");
    digest.update(PROOF_PROFILE_ID);
    digest.update(operation.proof_magic());
    // Three fixed-size hashes make the empty addition certificate unambiguous.
    for hash in hashes {
        digest.update(hash);
    }
    digest.finalize().into()
}

pub(super) struct PreprocessingCache {
    entries: Mutex<Entries>,
}
struct Entries {
    // SDK verifier keys contain only width, degree and the public commitment.
    keys: BTreeMap<DigestKey, VerifierKey>,
    order: VecDeque<DigestKey>,
}
impl PreprocessingCache {
    pub(super) const fn new() -> Self {
        Self {
            entries: Mutex::new(Entries {
                keys: BTreeMap::new(),
                order: VecDeque::new(),
            }),
        }
    }
    pub(super) fn get(&self, digest: DigestKey, operation: Operation) -> Option<VerifierKey> {
        let entries = self.entries.lock().ok()?;
        entries
            .keys
            .get(&digest)
            .filter(|key| valid_shape(key, operation))
            .cloned()
    }
    pub(super) fn insert(&self, digest: DigestKey, operation: Operation, key: VerifierKey) {
        if !valid_shape(&key, operation) {
            return;
        }
        // Cache unavailability is a miss, not a verification failure or success.
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if let Some(existing) = entries.keys.get_mut(&digest) {
            *existing = key;
            return;
        }
        if entries.order.len() == CACHE_ENTRIES
            && let Some(oldest) = entries.order.pop_front()
        {
            entries.keys.remove(&oldest);
        }
        entries.keys.insert(digest, key);
        entries.order.push_back(digest);
    }
}
fn valid_shape(key: &VerifierKey, operation: Operation) -> bool {
    key.width == operation.public_columns() && key.degree_bits == operation.log_height()
}

#[cfg(test)]
mod tests;
