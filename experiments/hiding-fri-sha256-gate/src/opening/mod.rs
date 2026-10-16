//! Experimental whole-pair private AEAD byte-opening. No live accepting path.
//! Public canonical ciphertext is checked outside AIR; ALL private key/AEAD/XOR
//! and salted commitment links are constrained inside one hiding relation.
pub(crate) mod air;
mod commitment;
mod fixture;
mod poseidon;
pub(crate) mod schedule;
pub(crate) mod statement;
#[cfg(test)]
mod tests;
mod trace;
pub(crate) const DATA_BYTES: usize = 12;
pub(crate) const INDEX_BYTES: usize = 2336;
pub(crate) const PLAINTEXT_WORDS: usize = 587;
pub(crate) const KEY_DOMAIN: [u8; 16] = *b"DCS/KEY/PAIR/v1!";
pub(crate) const OPEN_DOMAIN: [u8; 16] = *b"DCS/OPEN/PAIR/v1";
pub(crate) const VERSION: u32 = 1;
pub(crate) const DATA_SCHEMA: [u8; 16] = *b"CQAGEAMOUNT00001";
pub(crate) const INDEX_SCHEMA: [u8; 16] = *b"CQAGEINDEX000003";

/// Pins the candidate construction, constants, geometry and complete public schedule.
/// This is an unreleased experiment profile, not the production BFV/kernel profile.
pub(crate) fn profile(hash: &mut sha2::Sha256) {
    use sha2::Digest;
    hash.update(b"CSTORE-whole-pair-byte-opening/experimental-v1/no-SQL-acceptance");
    hash.update(KEY_DOMAIN);
    hash.update(OPEN_DOMAIN);
    hash.update(VERSION.to_le_bytes());
    hash.update(DATA_SCHEMA);
    hash.update(INDEX_SCHEMA);
    hash.update(b"source-u32LE/commitment-canonical-u64LE/key26+6/open674+6/87prefix");
    hash.update(b"P2-native12-initialMDS-4full-22partial-4full/x7-cube/overwrite8-cap4-digest4");
    hash.update(b"same-K-both-pages/packet-revision-AAD106/full-padded-hibit/raw-private-salts4+4");
    hash.update(b"Cha7x81x6/immutable-K-SK-PK/boundary-CURRENT/skip-NEXT-boundary-copy");
    hash.update(b"carry-CURRENT/skip-NEXT-capture-copy/reset-sponge-capacity/embedded-head28");
    for n in [
        DATA_BYTES,
        INDEX_BYTES,
        PLAINTEXT_WORDS,
        691,
        air::WIDTH,
        512,
        3,
        256,
        4096,
        4,
        26,
        32,
        674,
        680,
        87,
        5, // conservative declaration; actual composed inference is a later gate
    ] {
        hash.update((n as u64).to_le_bytes());
    }
    for row in 0..512 {
        hash.update((row as u64).to_le_bytes());
        match schedule::absorb(row) {
            Some((key, block)) => {
                hash.update([1, u8::from(key)]);
                hash.update((block as u64).to_le_bytes());
            }
            None => hash.update([0, 0]),
        }
        match schedule::mac(row) {
            schedule::Mac::Block { page, block } => {
                hash.update([1, page as u8]);
                hash.update((block as u64).to_le_bytes());
            }
            schedule::Mac::Final(page) => hash.update([2, page as u8]),
            schedule::Mac::Idle => hash.update([0, 0]),
        }
    }
    for index in 0..42 {
        match schedule::job(index) {
            schedule::Job::H(page) => hash.update([0, page as u8]),
            schedule::Job::Cha { page, counter } => {
                hash.update([1, page as u8]);
                hash.update(counter.to_le_bytes());
            }
        }
    }
    for indices in crate::chacha::SCHEDULE {
        for index in indices {
            hash.update((index as u64).to_le_bytes());
        }
    }
    for row in schedule::CAPTURES {
        hash.update((row as u64).to_le_bytes());
    }
}

pub(crate) fn gate(mode: &str) -> Result<(), crate::backend::Error> {
    use crate::backend::{Backend, Error};
    use std::time::Instant;
    let (statement, witness) = fixture::fixture()?;
    crate::security(&statement, "fixed-four-row-pair")?;
    println!(
        "{{\"stage\":\"candidate_geometry\",\"public_values\":691,\"periodic_columns\":512,\"periodic_payload_bytes\":2097152,\"periodic_lde_payload_estimate_bytes\":33554432,\"declared_degree_bound\":5,\"private_plaintext_bytes\":2348,\"cha_jobs\":42,\"mac_blocks\":163}}"
    );
    if mode == "prove" {
        let backend = Backend::new(&statement)?;
        let started = Instant::now();
        let proof = backend.prove_with_trace(&statement, || witness.trace(&statement))?;
        let proving = started.elapsed();
        let started = Instant::now();
        backend.verify(&statement, &proof)?;
        println!(
            "{{\"stage\":\"verified_experimental_pair_byte_opening\",\"proving_ms\":{},\"verification_ms\":{}}}",
            proving.as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0
        );
    } else if mode != "security" {
        return Err(Error::Shape);
    }
    Ok(())
}
