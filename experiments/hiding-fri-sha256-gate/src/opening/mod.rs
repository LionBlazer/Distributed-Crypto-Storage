//! Experimental whole-pair private AEAD byte-opening. No live accepting path.
//! Public canonical ciphertext is checked outside AIR; ALL private key/AEAD/XOR
//! and salted commitment links are constrained inside one hiding relation.
pub(crate) mod air;
pub(crate) mod basis_convolution;
pub(crate) mod canonical;
mod layout;
pub(crate) use layout::PACKED_WIDTH;
#[cfg(test)]
mod canonical_tests;
mod commitment;
pub(crate) mod factorized;
#[cfg(test)]
mod factorized_tests;
mod fixture;
pub(crate) mod key_transform;
pub(crate) mod locking;
#[cfg(test)]
mod packed_tests;
mod poseidon;
pub(crate) mod schedule;
pub(crate) mod selection;
pub(crate) mod state;
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

/// Fixed bounded research relations; none is a production accepting API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Relation {
    Bytes,
    CanonicalIndex,
    PackedCanonicalIndex,
    FactorizedPackedCanonicalIndex,
    StateCertificate,
}
impl Relation {
    fn kind(self) -> crate::primitive::Kind {
        match self {
            Self::Bytes => crate::primitive::Kind::PairOpening,
            Self::CanonicalIndex => crate::primitive::Kind::CanonicalIndexOpening,
            Self::PackedCanonicalIndex => crate::primitive::Kind::PackedCanonicalIndexOpening,
            Self::FactorizedPackedCanonicalIndex => {
                crate::primitive::Kind::FactorizedPackedCanonicalIndexOpening
            }
            Self::StateCertificate => crate::primitive::Kind::StateCertificate,
        }
    }
    fn packed(self) -> bool {
        matches!(
            self,
            Self::PackedCanonicalIndex
                | Self::FactorizedPackedCanonicalIndex
                | Self::StateCertificate
        )
    }
    fn factorized(self) -> bool {
        matches!(self, Self::FactorizedPackedCanonicalIndex)
    }
    fn is_canonical(self) -> bool {
        !matches!(self, Self::Bytes)
    }
    fn width(self) -> usize {
        match self {
            Self::Bytes => air::WIDTH,
            Self::CanonicalIndex => canonical::WIDTH,
            Self::PackedCanonicalIndex
            | Self::FactorizedPackedCanonicalIndex
            | Self::StateCertificate => layout::PACKED_WIDTH,
        }
    }
}

/// Distinct unreleased relation; the original profile byte strings remain untouched.
pub(crate) fn packed_index_profile(hash: &mut sha2::Sha256) {
    use sha2::Digest;
    hash.update(b"CSTORE-canonical-age-index-N4/packed-u32-v1/no-SQL-acceptance");
    hash.update(KEY_DOMAIN);
    hash.update(OPEN_DOMAIN);
    hash.update(DATA_SCHEMA);
    hash.update(INDEX_SCHEMA);
    hash.update(b"same-K-both-pages/AAD106/padded-full-hibit/LE-source-u32/salts4+4");
    hash.update(b"Cha7x82x6/QR0..79/final80/NEXT-feedforward-bits81/CURRENT-capture81/resetNEXT82");
    hash.update(b"plaintext112-u32/immutable-K8-SK16-PK16/selected-PK-view256/raw-clamp-unchanged");
    hash.update(crate::poly1305::CLAMP);
    hash.update(b"one-byte-postings/padding8/histogram256/offsets257/sorted-age-ordinal4");
    hash.update(b"TableId-two-u32sum-halves/ID-u32sum-nonzero/6pairs-8wordzero-inverse-count");
    hash.update(b"P2-native12/overwrite8-cap4/x7-cube/4full22partial4full/key32/open680");
    let c = layout::Columns::new(true);
    let ci = layout::CanonicalColumns::new(true);
    for value in [
        VERSION as usize,
        DATA_BYTES,
        INDEX_BYTES,
        PLAINTEXT_WORDS,
        691,
        c.buffers,
        c.banks,
        c.master,
        c.subkey,
        c.polykey,
        c.polykey_bits,
        c.poly,
        c.poseidon,
        c.checkpoint,
        c.carry,
        c.salts,
        c.width,
        ci.ages,
        ci.permutation,
        ci.sort,
        ci.header,
        ci.identity,
        ci.table_half,
        ci.width,
        512,
        82,
        80,
        81,
        42,
        163,
        2196,
        2208,
        2336,
        4,
        8,
        32,
        5,
    ] {
        hash.update((value as u64).to_le_bytes());
    }
    let schedule = schedule::Schedule::new(true);
    for row in 0..512 {
        hash.update((row as u64).to_le_bytes());
        match schedule.absorb(row) {
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
    for word in crate::chacha::CONSTANTS {
        hash.update(word.to_le_bytes());
    }
    for word in crate::chacha::HCHACHA_OUTPUT {
        hash.update((word as u64).to_le_bytes());
    }
    for row in schedule.captures() {
        hash.update((row as u64).to_le_bytes());
    }
}

pub(crate) fn index_profile(hash: &mut sha2::Sha256) {
    use sha2::Digest;
    profile(hash);
    hash.update(b"CSTORE-canonical-age-index-N4/experimental-v1/no-SQL-acceptance");
    hash.update(b"index-v3/header2196/capacity8/aligned2208/total2336");
    hash.update(b"all-counts256/all-prefix-offsets257/sorted-age-ordinal-permutation4");
    hash.update(b"canonical-one-byte-postings4/padding8/nonzero-TableId/distinct-nonzero-RowIds4");
    hash.update(b"ages-constant-all-rows/bind80/TableId-half-capture80-NEXT-skip/check161/IDs485");
    hash.update(b"header-exact-existing-P2-stream-slots/no-global-identity-or-history-claim");
    for value in [
        canonical::WIDTH,
        canonical::WIDTH - air::WIDTH,
        442,
        4,
        32,
        256,
        257,
    ] {
        hash.update((value as u64).to_le_bytes());
    }
}

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
    gate_relation(mode, Relation::Bytes)
}
pub(crate) fn canonical_gate(mode: &str) -> Result<(), crate::backend::Error> {
    gate_relation(mode, Relation::CanonicalIndex)
}
pub(crate) fn packed_canonical_gate(mode: &str) -> Result<(), crate::backend::Error> {
    gate_relation(mode, Relation::PackedCanonicalIndex)
}
pub(crate) fn factorized_canonical_gate(mode: &str) -> Result<(), crate::backend::Error> {
    gate_relation(mode, Relation::FactorizedPackedCanonicalIndex)
}
fn gate_relation(mode: &str, relation: Relation) -> Result<(), crate::backend::Error> {
    use crate::backend::Error;
    use std::time::Instant;
    let (statement, witness) = match relation {
        Relation::Bytes => fixture::fixture()?,
        Relation::CanonicalIndex => fixture::canonical_fixture()?,
        Relation::PackedCanonicalIndex => fixture::packed_canonical_fixture()?,
        Relation::FactorizedPackedCanonicalIndex => fixture::factorized_canonical_fixture()?,
        Relation::StateCertificate => return Err(Error::Shape),
    };
    let backend = crate::prepare_gate(
        &statement,
        mode,
        match relation {
            Relation::Bytes => "fixed-four-row-pair",
            Relation::CanonicalIndex => "canonical-four-row-index",
            Relation::PackedCanonicalIndex => "packed-canonical-four-row-index",
            Relation::FactorizedPackedCanonicalIndex => {
                "factorized-packed-canonical-four-row-index"
            }
            Relation::StateCertificate => return Err(Error::Shape),
        },
    )?;
    let (periodics, periodic_bytes) = if relation.factorized() {
        (factorized::COLUMNS, factorized::PAYLOAD_BYTES)
    } else {
        (512, 2_097_152)
    };
    println!(
        "{{\"stage\":\"candidate_geometry\",\"public_values\":691,\"periodic_columns\":{},\"periodic_payload_bytes\":{},\"periodic_lde_payload_estimate_bytes\":{},\"declared_degree_bound\":5,\"private_plaintext_bytes\":2348,\"cha_jobs\":42,\"mac_blocks\":163}}",
        periodics,
        periodic_bytes,
        periodics * 8192 * std::mem::size_of::<crate::backend::Val>()
    );
    if let Some(backend) = backend {
        let started = Instant::now();
        let proof = backend.prove_with_trace(&statement, || witness.trace(&statement))?;
        let proving = started.elapsed();
        let started = Instant::now();
        backend.verify(&statement, &proof)?;
        let stage = match relation {
            Relation::Bytes => "verified_experimental_pair_byte_opening",
            Relation::CanonicalIndex => "verified_experimental_canonical_index_opening",
            Relation::PackedCanonicalIndex => {
                "verified_experimental_packed_canonical_index_opening"
            }
            Relation::FactorizedPackedCanonicalIndex => {
                "verified_experimental_factorized_packed_canonical_index_opening"
            }
            Relation::StateCertificate => return Err(Error::Shape),
        };
        println!(
            "{{\"stage\":\"{}\",\"proving_ms\":{},\"verification_ms\":{}}}",
            stage,
            proving.as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    Ok(())
}
